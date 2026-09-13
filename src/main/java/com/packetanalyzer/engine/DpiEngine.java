package com.packetanalyzer.engine;

import com.flowgate.diagnostics.ConnectionHealthAnalyzer;
import com.flowgate.diagnostics.ConnectionHealthAnalyzer.DiagnosticReport;
import com.flowgate.policy.PolicyDecision;
import com.flowgate.policy.ThrottlePolicy;
import com.flowgate.quota.QuotaManager;
import com.flowgate.quota.SubscriberRegistry;
import com.flowgate.util.FlowGateLogger;
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
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
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
        // FlowGate settings (optional — FlowGate is disabled if subscribersFile is empty)
        public String subscribersFile   = "";
        public String throttlePolicyFile = "";
    }

    private final Config config;
    private RuleManager ruleManager;
    private QuotaManager quotaManager;  // null if FlowGate disabled
    private GlobalConnectionTable globalConnTable;

    private final List<FastPathProcessor> fastPathProcessors = new ArrayList<>();
    private final List<LoadBalancer> loadBalancers = new ArrayList<>();

    private final LinkedBlockingQueue<PacketJob> outputQueue = new LinkedBlockingQueue<>(10000);
    private Thread outputThread;
    private PcapWriter pcapWriter;

    private final DPIStats stats = new DPIStats();
    private final AtomicBoolean running = new AtomicBoolean(false);

    /**
     * Collects the last {@value #MAX_DECISIONS_PER_IP} PolicyDecisions per subscriber IP.
     * Populated by handleOutput(); consumed by runDiagnostics() after processing completes.
     * Thread-safe: outer map is ConcurrentHashMap; inner list is synchronized.
     */
    private static final int MAX_DECISIONS_PER_IP = 50;
    private final ConcurrentHashMap<Integer, List<PolicyDecision>> decisionsByIp =
            new ConcurrentHashMap<>();

    public DpiEngine(Config config) {
        this.config = config;

        System.out.println("\n╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                     FLOWGATE v1.0.0                          ║");
        System.out.println("║               Subscriber-Aware Policy Engine                 ║");
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

        // Initialize FlowGate QuotaManager (optional — only if subscribers file provided)
        if (config.subscribersFile != null && !config.subscribersFile.isEmpty()) {
            try {
                SubscriberRegistry registry = SubscriberRegistry.loadFromFile(config.subscribersFile);
                ThrottlePolicy policy = config.throttlePolicyFile != null && !config.throttlePolicyFile.isEmpty()
                        ? ThrottlePolicy.loadFromFile(config.throttlePolicyFile)
                        : ThrottlePolicy.defaults();
                quotaManager = new QuotaManager(registry, policy);
                FlowGateLogger.info("DpiEngine", "FlowGate policy engine active. " +
                        registry.getSubscriberCount() + " subscribers loaded.");
            } catch (Exception e) {
                System.err.println("[DpiEngine] FlowGate init failed: " + e.getMessage());
                return false;
            }
        } else {
            FlowGateLogger.info("DpiEngine", "FlowGate disabled (no --subscribers flag). Running as pure DPI.");
        }

        int totalFps = config.numLoadBalancers * config.fpsPerLb;
        globalConnTable = new GlobalConnectionTable(totalFps);

        FastPathProcessor.PacketOutputCallback outputCb = (job, action, reason) -> handleOutput(job, action, reason);

        List<LinkedBlockingQueue<PacketJob>> allFpQueues = new ArrayList<>();

        for (int i = 0; i < totalFps; i++) {
            FastPathProcessor fp = new FastPathProcessor(
                i, ruleManager, quotaManager, stats, config.verbose, 
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
        if (quotaManager != null) {
            runDiagnostics();
        }

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
            // Check if this was a FlowGate hard-drop vs a rule-based drop
            if (job.policyDecision != null) {
                stats.hardDroppedPackets.incrementAndGet();
                collectDecision(job.policyDecision);
            }
            stats.droppedPackets.incrementAndGet();
            return;
        }

        if (action == PacketAction.DELAY && job.policyDecision != null) {
            // Simulate throttling: shift the output PCAP timestamp forward by the calculated delay.
            // This makes packet-analysis tools (Wireshark, etc.) "see" the packet
            // arriving later in simulated time — visually demonstrating the bandwidth limit.
            long delayUsec = job.policyDecision.simulatedDelayUsec();
            long newTsUsec = job.tsUsec + delayUsec;
            job.tsSec  = job.tsSec + (newTsUsec / 1_000_000L);
            job.tsUsec = newTsUsec % 1_000_000L;
            stats.throttledPackets.incrementAndGet();
            collectDecision(job.policyDecision);
        }

        if (action == PacketAction.FORWARD && job.policyDecision != null) {
            collectDecision(job.policyDecision);
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

    /**
     * Records a PolicyDecision in the per-IP ring buffer (max {@value #MAX_DECISIONS_PER_IP} entries).
     * Thread-safe because the inner list is synchronised on itself.
     */
    private void collectDecision(PolicyDecision decision) {
        List<PolicyDecision> list = decisionsByIp.computeIfAbsent(
                decision.subscriberIp(), k -> Collections.synchronizedList(new ArrayList<>()));
        synchronized (list) {
            list.add(decision);
            // Keep only the tail — older decisions are less relevant for diagnostics
            while (list.size() > MAX_DECISIONS_PER_IP) {
                list.remove(0);
            }
        }
    }

    /**
     * Runs the Phase 6 Diagnostic Engine across every subscriber for which decisions were collected.
     * Prints one {@link DiagnosticReport} per subscriber to stdout.
     */
    private void runDiagnostics() {
        if (decisionsByIp.isEmpty()) return;

        System.out.println("\n╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║          FLOWGATE DIAGNOSTIC REPORT (Phase 6)                ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");

        for (Map.Entry<Integer, List<PolicyDecision>> entry : decisionsByIp.entrySet()) {
            List<PolicyDecision> decisions;
            synchronized (entry.getValue()) {
                decisions = new ArrayList<>(entry.getValue());
            }
            DiagnosticReport report = ConnectionHealthAnalyzer.analyse(decisions, stats);

            // Convert IP int to dotted notation (Little Endian → dotted decimal)
            int ipInt = entry.getKey();
            String ipStr = String.format("%d.%d.%d.%d",
                     ipInt        & 0xFF,
                    (ipInt >>  8) & 0xFF,
                    (ipInt >> 16) & 0xFF,
                    (ipInt >> 24) & 0xFF);

            System.out.printf("║ Subscriber: %-47s ║%n", ipStr);
            System.out.printf("║   Cause  : %-48s ║%n", report.cause());
            System.out.printf("║   Usage  : %-47s ║%n", String.format("%.1f%%", report.quotaUsagePct()));
            System.out.printf("║   Delayed: %-5d  Dropped: %-5d  Sampled: %-14d ║%n",
                    report.delayedPackets(), report.droppedPackets(), report.sampledPackets());
            // Word-wrap the message at ~58 chars
            String msg = report.message();
            while (msg.length() > 58) {
                System.out.printf("║   %s ║%n", String.format("%-58s", msg.substring(0, 58)));
                msg = msg.substring(58);
            }
            System.out.printf("║   %-58s ║%n", msg);
            System.out.println("╠══════════════════════════════════════════════════════════════╣");
        }
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
    }

    public String generateReport() {
        StringBuilder ss = new StringBuilder();
        
        ss.append("\n╔══════════════════════════════════════════════════════════════╗\n");
        ss.append("║                    FLOWGATE STATISTICS                       ║\n");
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
        ss.append(String.format("║   Throttled (ASIT DELAY):        %15d             ║\n", stats.throttledPackets.get()));
        ss.append(String.format("║   Hard-Dropped (Quota 2x):       %15d             ║\n", stats.hardDroppedPackets.get()));
        
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
