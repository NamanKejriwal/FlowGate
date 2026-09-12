package com.packetanalyzer.engine;

import com.packetanalyzer.io.PcapReader;
import com.packetanalyzer.io.PcapWriter;
import com.packetanalyzer.parser.PacketParser;
import com.packetanalyzer.rules.RuleManager;
import com.packetanalyzer.tracking.GlobalConnectionTable;
import com.packetanalyzer.types.DPIStats;
import com.packetanalyzer.types.FiveTuple;
import com.packetanalyzer.types.PacketAction;
import com.packetanalyzer.types.PacketJob;
import com.packetanalyzer.types.ParsedPacket;
import com.packetanalyzer.types.AppType;
import com.packetanalyzer.io.ByteUtils;
import com.packetanalyzer.analytics.AnalyticsManager;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class DpiEngine {

    public static class Config {
        public int numLoadBalancers = 2;
        public int fpsPerLb = 2;
        public int queueSize = 10000;
        public String rulesFile = "";
        public boolean verbose = false;
        public long flowTimeoutSec = 300;
        public long cleanupWindowSec = 10;
    }

    private final Config config;
    private RuleManager ruleManager;
    private GlobalConnectionTable globalConnTable;

    private final List<FastPathProcessor> fastPathProcessors = new ArrayList<>();
    private final List<LoadBalancer> loadBalancers = new ArrayList<>();

    private final LinkedBlockingQueue<PacketJob> outputQueue = new LinkedBlockingQueue<>(10000);
    private Thread outputThread;
    private PcapWriter pcapWriter;

    private final DPIStats stats = new DPIStats();
    private final AtomicBoolean running = new AtomicBoolean(false);

    public DpiEngine(Config config) {
        this.config = config;

        System.out.println("\n╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                    DPI ENGINE v1.4                           ║");
        System.out.println("║               Deep Packet Inspection System                  ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println("║ CONFIGURATION                                                ║");
        System.out.println(String.format("║   Load Balancers:                %15d             ║", config.numLoadBalancers));
        System.out.println(String.format("║   FPs per LB:                    %15d             ║", config.fpsPerLb));
        System.out.println(String.format("║   Total FP threads:              %15d             ║", config.numLoadBalancers * config.fpsPerLb));
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
    }

    public boolean initialize() {
        ruleManager = new RuleManager();
        if (config.rulesFile != null && !config.rulesFile.isEmpty()) {
            ruleManager.loadRules(config.rulesFile);
            
            RuleManager.RuleStats rstats = ruleManager.getStats();
            System.out.println("\n╔══════════════════════════════════════════════════════════════╗");
            System.out.println("║ RULE ENGINE INITIALIZATION                                   ║");
            System.out.println("╠══════════════════════════════════════════════════════════════╣");
            String rulesStr = config.rulesFile.length() > 41 ? config.rulesFile.substring(0, 38) + "..." : config.rulesFile;
            System.out.println("║ Loaded from: " + String.format("%-47s", rulesStr) + " ║");
            System.out.println(String.format("║   Domains:                       %15d             ║", rstats.blockedDomains));
            System.out.println(String.format("║   IPs:                           %15d             ║", rstats.blockedIps));
            System.out.println(String.format("║   Ports:                         %15d             ║", rstats.blockedPorts));
            System.out.println(String.format("║   Applications:                  %15d             ║", rstats.blockedApps));
            System.out.println("╚══════════════════════════════════════════════════════════════╝");
        }

        int totalFps = config.numLoadBalancers * config.fpsPerLb;
        globalConnTable = new GlobalConnectionTable(totalFps);

        FastPathProcessor.PacketOutputCallback outputCb = (job, action, reason) -> handleOutput(job, action, reason);

        List<LinkedBlockingQueue<PacketJob>> allFpQueues = new ArrayList<>();

        for (int i = 0; i < totalFps; i++) {
            FastPathProcessor fp = new FastPathProcessor(
                i, ruleManager, stats, config.verbose, 
                config.flowTimeoutSec, config.cleanupWindowSec, outputCb
            );
            fastPathProcessors.add(fp);
            allFpQueues.add(fp.getInputQueue());
            globalConnTable.registerTracker(i, fp.getConnectionTracker());
        }

        for (int i = 0; i < config.numLoadBalancers; i++) {
            int fpStart = i * config.fpsPerLb;
            List<LinkedBlockingQueue<PacketJob>> lbFpQueues = allFpQueues.subList(fpStart, fpStart + config.fpsPerLb);
            LoadBalancer lb = new LoadBalancer(i, lbFpQueues, fpStart);
            loadBalancers.add(lb);
        }

        System.out.println("[DPIEngine] Initialized successfully");
        return true;
    }

    public void start() {
        if (running.get()) return;
        running.set(true);

        outputThread = new Thread(this::outputThreadFunc, "OutputWriter");
        outputThread.start();

        for (FastPathProcessor fp : fastPathProcessors) {
            fp.start();
        }

        for (LoadBalancer lb : loadBalancers) {
            lb.start();
        }

        System.out.println("[DPIEngine] All threads started");
    }

    public void stop() {
        if (!running.get()) return;
        running.set(false);

        for (LoadBalancer lb : loadBalancers) {
            lb.stop();
        }

        for (FastPathProcessor fp : fastPathProcessors) {
            fp.stop();
        }

        if (outputThread != null) {
            try {
                outputThread.join(2000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        System.out.println("[DPIEngine] All threads stopped");
    }

    public boolean processFile(String inputFile, String outputFile) {
        long startTime = System.currentTimeMillis();
        System.out.println("\n[DPIEngine] Processing: " + inputFile);
        System.out.println("[DPIEngine] Output to:  " + outputFile + "\n");

        if (ruleManager == null) {
            if (!initialize()) return false;
        }

        pcapWriter = new PcapWriter(outputFile);
        if (!pcapWriter.open()) {
            System.err.println("[DPIEngine] Error: Cannot open output file");
            return false;
        }

        start();

        Thread readerThread = new Thread(() -> readerThreadFunc(inputFile), "PcapReader");
        readerThread.start();

        try {
            readerThread.join();
            
            // Wait for queues to drain
            while (!allQueuesEmpty()) {
                Thread.sleep(100);
            }
            Thread.sleep(500); // Give FPs a chance to finish last packets
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        stop();

        if (pcapWriter != null) {
            pcapWriter.close();
        }

        System.out.print(generateReport());
        System.out.print(globalConnTable.generateReport());

        long runtimeMs = System.currentTimeMillis() - startTime;
        AnalyticsManager.exportAll(stats, globalConnTable, ruleManager, inputFile, runtimeMs, config.flowTimeoutSec);

        return true;
    }

    private boolean allQueuesEmpty() {
        for (LoadBalancer lb : loadBalancers) {
            if (!lb.getInputQueue().isEmpty()) return false;
        }
        for (FastPathProcessor fp : fastPathProcessors) {
            if (!fp.getInputQueue().isEmpty()) return false;
        }
        return outputQueue.isEmpty();
    }

    private void readerThreadFunc(String inputFile) {
        PcapReader reader = new PcapReader(inputFile);
        if (!reader.open()) {
            System.err.println("[Reader] Error: Cannot open input file");
            return;
        }

        try {
            pcapWriter.writeGlobalHeader(reader.getGlobalHeader());
        } catch (IOException e) {
            System.err.println("[Reader] Error writing PCAP header");
            return;
        }

        ParsedPacket parsed = new ParsedPacket();
        int packetId = 0;

        System.out.println("[Reader] Starting packet processing...");

        PcapReader.RawPacket raw;
        while ((raw = reader.readNextPacket()) != null) {
            if (!PacketParser.parse(raw.data, raw.tsSec, raw.tsUsec, parsed)) {
                continue;
            }

            if (!parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp)) {
                continue;
            }

            PacketJob job = createPacketJob(raw, parsed, packetId++);

            stats.totalPackets.incrementAndGet();
            stats.totalBytes.addAndGet(raw.data.length);

            if (parsed.hasTcp) stats.tcpPackets.incrementAndGet();
            else if (parsed.hasUdp) stats.udpPackets.incrementAndGet();

            int lbIndex = selectLB(job.tuple);
            try {
                loadBalancers.get(lbIndex).getInputQueue().put(job);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }

        System.out.println("[Reader] Finished reading " + packetId + " packets");
        reader.close();
    }

    private int selectLB(FiveTuple tuple) {
        long hash = tuple.hashCode() & 0xFFFFFFFFL;
        return (int) (hash % loadBalancers.size());
    }

    private PacketJob createPacketJob(PcapReader.RawPacket raw, ParsedPacket parsed, int packetId) {
        PacketJob job = new PacketJob();
        job.packetId = packetId;
        job.tsSec = raw.tsSec;
        job.tsUsec = raw.tsUsec;
        
        job.tuple.srcIp = ByteUtils.parseIp(parsed.srcIp);
        job.tuple.dstIp = ByteUtils.parseIp(parsed.destIp);
        job.tuple.srcPort = parsed.srcPort;
        job.tuple.dstPort = parsed.destPort;
        job.tuple.protocol = parsed.protocol;
        
        job.tcpFlags = parsed.tcpFlags;
        job.data = raw.data;
        
        job.ethOffset = 0;
        job.ipOffset = 14;
        
        if (raw.data.length > 14) {
            int ipIhl = raw.data[14] & 0x0F;
            int ipHeaderLen = ipIhl * 4;
            job.transportOffset = 14 + ipHeaderLen;
            
            if (parsed.hasTcp && raw.data.length > job.transportOffset) {
                int tcpDataOffset = (raw.data[job.transportOffset + 12] >> 4) & 0x0F;
                int tcpHeaderLen = tcpDataOffset * 4;
                job.payloadOffset = job.transportOffset + tcpHeaderLen;
            } else if (parsed.hasUdp) {
                job.payloadOffset = job.transportOffset + 8;
            }
            
            if (job.payloadOffset < raw.data.length) {
                job.payloadLength = raw.data.length - job.payloadOffset;
            }
        }
        
        return job;
    }

    private void handleOutput(PacketJob job, PacketAction action, RuleManager.BlockReason reason) {
        if (action == PacketAction.DROP) {
            stats.droppedPackets.incrementAndGet();
            return;
        }
        stats.forwardedPackets.incrementAndGet();
        try {
            outputQueue.put(job);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void outputThreadFunc() {
        while (running.get() || !outputQueue.isEmpty()) {
            try {
                PacketJob job = outputQueue.poll(100, TimeUnit.MILLISECONDS);
                if (job != null) {
                    synchronized (pcapWriter) {
                        pcapWriter.writePacket(job.tsSec, job.tsUsec, job.data);
                    }
                }
            } catch (InterruptedException e) {
                if (!running.get()) break;
                Thread.currentThread().interrupt();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public String generateReport() {
        StringBuilder ss = new StringBuilder();
        
        ss.append("\n╔══════════════════════════════════════════════════════════════╗\n");
        ss.append("║                    DPI ENGINE STATISTICS                     ║\n");
        ss.append("╠══════════════════════════════════════════════════════════════╣\n");
        
        ss.append("║ PACKET STATISTICS                                            ║\n");
        ss.append(String.format("║   Total Packets:                 %15d             ║\n", stats.totalPackets.get()));
        ss.append(String.format("║   Total Bytes:                   %15d             ║\n", stats.totalBytes.get()));
        ss.append(String.format("║   TCP Packets:                   %15d             ║\n", stats.tcpPackets.get()));
        ss.append(String.format("║   UDP Packets:                   %15d             ║\n", stats.udpPackets.get()));
        
        long lbReceived = 0, lbDispatched = 0;
        for (LoadBalancer lb : loadBalancers) {
            LoadBalancer.LBStats lstats = lb.getStats();
            lbReceived += lstats.packetsReceived;
            lbDispatched += lstats.packetsDispatched;
        }
        
        long fpProcessed = 0, fpForwarded = 0, fpDropped = 0, activeConnections = 0, evictedConnections = 0;
        for (FastPathProcessor fp : fastPathProcessors) {
            FastPathProcessor.FPStats fstats = fp.getStats();
            fpProcessed += fstats.packetsProcessed;
            fpForwarded += fstats.packetsForwarded;
            fpDropped += fstats.packetsDropped;
            activeConnections += fstats.connectionsTracked;
            evictedConnections += fstats.evictedConnections;
        }

        ss.append("╠══════════════════════════════════════════════════════════════╣\n");
        ss.append("║ PIPELINE STATISTICS                                          ║\n");
        ss.append(String.format("║   LB Received:                   %15d             ║\n", lbReceived));
        ss.append(String.format("║   LB Dispatched:                 %15d             ║\n", lbDispatched));
        ss.append(String.format("║   FP Processed:                  %15d             ║\n", fpProcessed));
        ss.append(String.format("║   FP Forwarded:                  %15d             ║\n", fpForwarded));
        ss.append(String.format("║   FP Dropped:                    %15d             ║\n", fpDropped));
        
        ss.append("╠══════════════════════════════════════════════════════════════╣\n");
        ss.append("║ FILTERING STATISTICS                                         ║\n");
        ss.append(String.format("║   Forwarded:                     %15d             ║\n", stats.forwardedPackets.get()));
        ss.append(String.format("║   Dropped/Blocked:               %15d             ║\n", stats.droppedPackets.get()));
        
        long total = stats.totalPackets.get();
        if (total > 0) {
            double dropRate = 100.0 * stats.droppedPackets.get() / total;
            ss.append(String.format("║   Drop Rate:                     %14.2f%%             ║\n", dropRate));
        }
        
        ss.append("╠══════════════════════════════════════════════════════════════╣\n");
        ss.append("║ FLOW LIFECYCLE STATISTICS                                    ║\n");
        ss.append(String.format("║   Active Flows:                  %15d             ║\n", activeConnections));
        ss.append(String.format("║   Evicted Flows:                 %15d             ║\n", evictedConnections));
        ss.append(String.format("║   Flow Timeout:                  %11d sec             ║\n", config.flowTimeoutSec));

        if (ruleManager != null) {
            RuleManager.RuleStats rstats = ruleManager.getStats();
            long loadedRules = rstats.blockedDomains + rstats.blockedIps + rstats.blockedPorts + rstats.blockedApps;
            long totalBlockedFlows = stats.blockedByDomain.get() + stats.blockedByIp.get() + stats.blockedByPort.get() + stats.blockedByApp.get();
            ss.append("╠══════════════════════════════════════════════════════════════╣\n");
            ss.append("║ RULE STATISTICS                                              ║\n");
            ss.append(String.format("║   Loaded Rules:                  %15d             ║\n", loadedRules));
            ss.append(String.format("║   Hit - By Domain:               %15d             ║\n", stats.blockedByDomain.get()));
            ss.append(String.format("║   Hit - By IP:                   %15d             ║\n", stats.blockedByIp.get()));
            ss.append(String.format("║   Hit - By Port:                 %15d             ║\n", stats.blockedByPort.get()));
            ss.append(String.format("║   Hit - By App:                  %15d             ║\n", stats.blockedByApp.get()));
            ss.append(String.format("║   Total Blocked Flows:           %15d             ║\n", totalBlockedFlows));

            java.util.Map<String, Long> ruleHits = ruleManager.getRuleHitCounts();
            if (!ruleHits.isEmpty()) {
                ss.append("║                                                              ║\n");
                ss.append("║   Top Triggered Rules:                                       ║\n");
                List<java.util.Map.Entry<String, Long>> sortedRules = new ArrayList<>(ruleHits.entrySet());
                sortedRules.sort((a, b) -> b.getValue().compareTo(a.getValue()));
                int count = 0;
                for (java.util.Map.Entry<String, Long> entry : sortedRules) {
                    if (count >= 5) break;
                    String ruleStr = entry.getKey();
                    if (ruleStr.length() > 30) {
                        ruleStr = ruleStr.substring(0, 27) + "...";
                    }
                    ss.append(String.format("║     %-30s %15d             ║\n", ruleStr, entry.getValue()));
                    count++;
                }
            }
        }

        ss.append("╠══════════════════════════════════════════════════════════════╣\n");
        ss.append("║ EXPORT STATUS                                                ║\n");
        ss.append("║   Reports Directory:                 reports/                ║\n");
        ss.append(String.format("║   CSV Files:                     %15d             ║\n", 5));
        ss.append(String.format("║   JSON Files:                    %15d             ║\n", 4));
        ss.append("╚══════════════════════════════════════════════════════════════╝\n");
        
        return ss.toString();
    }
}
