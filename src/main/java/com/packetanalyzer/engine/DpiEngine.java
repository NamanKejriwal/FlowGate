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
    private ThrottlePolicy activePolicy;
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
    }

    static class ProcessedRecord {
        int packetId;
        com.packetanalyzer.types.FiveTuple tuple;
        int workerId;
        com.packetanalyzer.types.AppType app;
        com.flowgate.policy.ThrottlePolicy.Tier tier;
        String source;
        com.flowgate.policy.PolicyVerdict verdict;
        com.flowgate.policy.ReasonCode reason;
        com.flowgate.policy.FupState fupState;
        long usageBytes;
        double usagePct;
    }
    private final java.util.List<ProcessedRecord> processedRecords = java.util.Collections.synchronizedList(new java.util.ArrayList<>());

    public boolean initialize() {
        ruleManager = new RuleManager();
        if (config.rulesFile != null && !config.rulesFile.isEmpty()) {
            ruleManager.loadRules(config.rulesFile);
        }

        // Initialize FlowGate QuotaManager (optional — only if subscribers file provided)
        if (config.subscribersFile != null && !config.subscribersFile.isEmpty()) {
            try {
                SubscriberRegistry registry = SubscriberRegistry.loadFromFile(config.subscribersFile);
                ThrottlePolicy policy = config.throttlePolicyFile != null && !config.throttlePolicyFile.isEmpty()
                        ? ThrottlePolicy.loadFromFile(config.throttlePolicyFile)
                        : ThrottlePolicy.defaults();
                activePolicy = policy;
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
    }

    public boolean processFile(String inputFile, String outputFile) {
        long startTime = System.currentTimeMillis();

        if (ruleManager == null) {
            if (!initialize()) return false;
        }

        pcapWriter = new PcapWriter(outputFile);
        if (!pcapWriter.open()) {
            System.err.println("[DpiEngine] Error: Cannot open output file");
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

        System.out.print(generateReport(inputFile, outputFile));
        //System.out.print(globalConnTable.generateReport());
        if (quotaManager != null) {
            runDiagnostics();
        }

        long runtimeMs = System.currentTimeMillis() - startTime;
        AnalyticsManager.exportAll(stats, globalConnTable, ruleManager, inputFile, runtimeMs, config.flowTimeoutSec);

        System.out.println("\n----------------------------------------------------------------");
        System.out.println("OUTPUT");
        System.out.println("----------------------------------------------------------------\n");
        System.out.printf("  Output PCAP       : %s%n", outputFile);
        System.out.println("  Analytics         : reports/");
        System.out.println("  Status            : COMPLETE");
        System.out.printf("  Processing Time   : %.2f s%n%n", runtimeMs / 1000.0);
        System.out.println("================================================================");
        System.out.println("                    FLOWGATE DEMO COMPLETE");
        System.out.println("================================================================");

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

    private PcapReader.GlobalHeader globalHeader;

    private void readerThreadFunc(String inputFile) {
        PcapReader reader = new PcapReader(inputFile);
        if (!reader.open()) {
            System.err.println("[Reader] Error: Cannot open input file");
            return;
        }

        try {
            globalHeader = reader.getGlobalHeader();
            pcapWriter.writeGlobalHeader(globalHeader);
        } catch (IOException e) {
            System.err.println("[Reader] Error writing PCAP header");
            return;
        }

        ParsedPacket parsed = new ParsedPacket();
        int packetId = 0;

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

        if (job.policyDecision != null) {
            ProcessedRecord rec = new ProcessedRecord();
            rec.packetId = job.packetId;
            rec.tuple = job.tuple;
            rec.workerId = job.workerId;
            rec.app = job.policyDecision.appType();
            rec.tier = job.policyDecision.tier();
            rec.source = job.classificationSource;
            rec.verdict = job.policyDecision.verdict();
            rec.reason = job.policyDecision.reasonCode();
            rec.fupState = job.policyDecision.fupState();
            rec.usageBytes = job.policyDecision.usageBytes();
            rec.usagePct = job.policyDecision.usagePct();
            processedRecords.add(rec);
        }

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
        } else if (action == PacketAction.FORWARD) {
            stats.forwardedPackets.incrementAndGet();
            if (job.policyDecision != null) {
                collectDecision(job.policyDecision);
            }
        }

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
     * Runs the diagnostic engine across every subscriber for which policy decisions were collected,
     * printing a brief per-subscriber health report.
     */
    private void runDiagnostics() {
        if (decisionsByIp.isEmpty()) return;

        System.out.println("DIAGNOSTIC");
        System.out.println("----------------------------------------------------------------");

        for (Map.Entry<Integer, List<PolicyDecision>> entry : decisionsByIp.entrySet()) {
            List<PolicyDecision> decisions;
            synchronized (entry.getValue()) {
                decisions = new ArrayList<>(entry.getValue());
            }
            DiagnosticReport report = ConnectionHealthAnalyzer.analyse(decisions, stats);

            int ipInt = entry.getKey();
            String ipStr = String.format("%d.%d.%d.%d",
                     ipInt        & 0xFF,
                    (ipInt >>  8) & 0xFF,
                    (ipInt >> 16) & 0xFF,
                    (ipInt >> 24) & 0xFF);

            System.out.printf("  Subscriber      : %s%n", ipStr);
            System.out.printf("  Cause           : %s%n", report.cause());
            System.out.printf("  Usage           : %.1f%%%n", report.quotaUsagePct());
            System.out.printf("  Delayed/Dropped : %d / %d  (sampled: %d)%n",
                    report.delayedPackets(), report.droppedPackets(), report.sampledPackets());
            
            // Format message wrapping
            String msg = report.message();
            System.out.print("  Explanation     : ");
            int lineLen = 0;
            String[] words = msg.split(" ");
            for (int i = 0; i < words.length; i++) {
                if (lineLen + words[i].length() > 50 && i > 0) {
                    System.out.print("\n                    ");
                    lineLen = 0;
                }
                System.out.print(words[i] + " ");
                lineLen += words[i].length() + 1;
            }
            System.out.println("\n");
        }
    }

    public String generateReport(String inputFile, String outputFile) {
        long fpProcessed = 0, fpForwarded = 0, fpDropped = 0, activeConnections = 0;
        StringBuilder workerStats = new StringBuilder();
        int workerIdx = 0;
        for (FastPathProcessor fp : fastPathProcessors) {
            FastPathProcessor.FPStats fstats = fp.getStats();
            fpProcessed += fstats.packetsProcessed;
            fpForwarded += fstats.packetsForwarded;
            fpDropped += fstats.packetsDropped;
            activeConnections += fstats.connectionsTracked;
            if (workerIdx > 0) workerStats.append(", ");
            workerStats.append(String.format("FP-%d (%d pkts)", workerIdx, fstats.packetsProcessed));
            workerIdx++;
        }

        long total = stats.totalPackets.get();
        long dropped = stats.droppedPackets.get();
        double dropRate = total > 0 ? 100.0 * dropped / total : 0.0;

        StringBuilder ss = new StringBuilder();

        ss.append("\n================================================================\n");
        ss.append("                        FLOWGATE  v1.0.0\n");
        ss.append("             Subscriber-Aware Traffic Policy Engine\n");
        ss.append("================================================================\n\n");

        ss.append("INITIALIZATION\n");
        ss.append("----------------------------------------------------------------\n");
        ss.append(String.format("  Input           : %s%n", inputFile));
        ss.append(String.format("  Output          : %s%n", outputFile));
        String subFile = (config.subscribersFile != null && !config.subscribersFile.isEmpty())
                ? config.subscribersFile : "none (pure DPI mode)";
        ss.append(String.format("  Subscribers     : %s%n", subFile));
        ss.append(String.format("  Load Balancers  : %d%n", config.numLoadBalancers));
        ss.append(String.format("  Fast Paths      : %d%n", config.numLoadBalancers * config.fpsPerLb));
        ss.append("\n  Policy Tiers\n");
        if (activePolicy != null) {
            ss.append("    ESSENTIAL     : unlimited\n");
            long std = activePolicy.getBandwidthLimitKbps(ThrottlePolicy.Tier.STANDARD);
            long ent = activePolicy.getBandwidthLimitKbps(ThrottlePolicy.Tier.ENTERTAINMENT);
            ss.append(String.format("    STANDARD      : %s Kbps (post-FUP)%n", std > 0 ? std + "" : "unlimited"));
            ss.append(String.format("    ENTERTAINMENT : %s Kbps (post-FUP)%n", ent > 0 ? ent + "" : "unlimited"));
        } else {
            ss.append("    ESSENTIAL     : unlimited\n");
            ss.append("    STANDARD      : 256 Kbps (post-FUP)\n");
            ss.append("    ENTERTAINMENT : 64 Kbps (post-FUP)\n");
        }
        ss.append(String.format("  Status          : READY%n%n"));

        ss.append("PROCESSING\n");
        ss.append("----------------------------------------------------------------\n");
        if (globalHeader != null) {
            ss.append(String.format("  PCAP Version    : %d.%d%n", globalHeader.versionMajor(), globalHeader.versionMinor()));
            ss.append(String.format("  Snaplen         : %d%n", globalHeader.snaplen()));
            ss.append(String.format("  Link type       : %d%n\n", globalHeader.network()));
        }
        ss.append(String.format("  Packets Read    : %d%n", total));
        ss.append(String.format("  TCP / UDP       : %d / %d%n", stats.tcpPackets.get(), stats.udpPackets.get()));
        ss.append(String.format("  Flow Affinity   : 5-tuple hashing%n"));
        ss.append(String.format("  Worker Stats    : %s%n%n", workerStats.toString()));

        
        java.util.List<ProcessedRecord> sortedRecs = new java.util.ArrayList<>(processedRecords);
        sortedRecs.sort(java.util.Comparator.comparingInt(r -> r.packetId));

        // Build per-app tier and source map from actual runtime processedRecords
        java.util.Map<com.packetanalyzer.types.AppType, com.flowgate.policy.ThrottlePolicy.Tier> appTierMap = new java.util.LinkedHashMap<>();
        java.util.Map<com.packetanalyzer.types.AppType, String> appSourceMap = new java.util.LinkedHashMap<>();
        java.util.Map<com.packetanalyzer.types.AppType, Long> appCountMap = new java.util.LinkedHashMap<>();
        for (ProcessedRecord r : sortedRecs) {
            appTierMap.put(r.app, r.tier);
            if (r.source != null && !r.source.equals("Unknown")) {
                appSourceMap.put(r.app, r.source);
            }
            appCountMap.merge(r.app, 1L, Long::sum);
        }

        ss.append("APPLICATION IDENTIFICATION (runtime)\n");
        ss.append("----------------------------------------------------------------\n");
        ss.append(String.format("  %-14s  %-7s  %-12s  %s%n", "Application", "Pkts", "Source", "Tier"));
        ss.append("  " + "-".repeat(56) + "\n");
        com.packetanalyzer.types.AppType[] sixApps = {
            com.packetanalyzer.types.AppType.GPAY, com.packetanalyzer.types.AppType.WHATSAPP, 
            com.packetanalyzer.types.AppType.GOOGLE, com.packetanalyzer.types.AppType.GMAIL, 
            com.packetanalyzer.types.AppType.NETFLIX, com.packetanalyzer.types.AppType.SPOTIFY};
        for (com.packetanalyzer.types.AppType a : sixApps) {
            long cnt = appCountMap.getOrDefault(a, 0L);
            String tierStr = appTierMap.containsKey(a) ? appTierMap.get(a).name() : "(not seen)";
            String sourceStr = appSourceMap.getOrDefault(a, "Unknown");
            ss.append(String.format("  %-14s  %-7d  %-12s  %s%n", a.getDisplayName(), cnt, sourceStr, tierStr));
        }
        ss.append("\n");

        ss.append("5-TUPLE -> WORKER AFFINITY\n");
        ss.append("----------------------------------------------------------------\n");
        java.util.Map<com.packetanalyzer.types.FiveTuple, java.util.List<ProcessedRecord>> flows = new java.util.LinkedHashMap<>();
        for (ProcessedRecord r : sortedRecs) flows.computeIfAbsent(r.tuple, k -> new java.util.ArrayList<>()).add(r);
        
        for (java.util.Map.Entry<com.packetanalyzer.types.FiveTuple, java.util.List<ProcessedRecord>> e : flows.entrySet()) {
            if (e.getValue().size() >= 2) {
                ss.append(String.format("  Flow %s:%d -> %s:%d%n", 
                        com.packetanalyzer.io.ByteUtils.ipToString(e.getKey().srcIp), e.getKey().srcPort,
                        com.packetanalyzer.io.ByteUtils.ipToString(e.getKey().dstIp), e.getKey().dstPort));
                for (ProcessedRecord r : e.getValue()) {
                    ss.append(String.format("    Packet %d assigned to FP-%d%n", r.packetId + 1, r.workerId));
                }
                break; // Only show one example
            }
        }
        ss.append("\n");

        if (quotaManager != null) {
            ss.append("QUOTA / FUP\n");
            ss.append("----------------------------------------------------------------\n");
            ss.append("  Cumulative usage in PCAP packet order (FUP accounting is sequenced).\n");
            ss.append(String.format("  %-10s  %-16s  %-12s  %s%n", "Pkt", "FUP State", "Usage (B)", "Quota Used"));
            ss.append("  " + "-".repeat(60) + "\n");
            for (ProcessedRecord r : sortedRecs) {
                ss.append(String.format("  %-10d  %-16s  %-12d  %.1f%%%n",
                        r.packetId + 1, r.fupState, r.usageBytes, r.usagePct));
            }
            double finalPct = sortedRecs.isEmpty() ? 0.0 : sortedRecs.get(sortedRecs.size() - 1).usagePct;
            ss.append(String.format("  Final Usage   : %.1f%%%n\n", finalPct));
        }

        ss.append("POLICY DECISIONS (runtime)\n");
        ss.append("----------------------------------------------------------------\n");
        ss.append("  DPI is concurrent with 5-tuple affinity; FUP quota is applied in\n");
        ss.append("  PCAP packet order so essential protection is observable.\n");
        ss.append(String.format("  %-4s %-11s %-13s %-9s %-7s %s%n",
                "Pkt", "App", "Tier", "FUP", "Verdict", "Reason"));
        ss.append("  " + "-".repeat(70) + "\n");
        for (ProcessedRecord r : sortedRecs) {
            ss.append(String.format("  %-4d %-11s %-13s %-9s %-7s %s%n",
                    r.packetId + 1,
                    r.app.getDisplayName(),
                    r.tier,
                    r.fupState,
                    r.verdict,
                    r.reason));
        }
        ss.append("\n");

        ss.append("POLICY RESULTS\n");
        ss.append("----------------------------------------------------------------\n");
        ss.append(String.format("  FORWARD         : %d%n", stats.forwardedPackets.get()));
        ss.append(String.format("  DELAY           : %d%n", stats.throttledPackets.get()));
        ss.append(String.format("  DROP            : %d%n", stats.hardDroppedPackets.get()));
        ss.append(String.format("  Packet Drop Rate: %.2f%%%n%n", dropRate));



        return ss.toString();
    }
}
