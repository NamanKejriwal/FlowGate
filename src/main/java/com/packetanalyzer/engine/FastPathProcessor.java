package com.packetanalyzer.engine;

import com.packetanalyzer.extractors.DnsExtractor;
import com.packetanalyzer.extractors.HttpHostExtractor;
import com.packetanalyzer.extractors.SniExtractor;
import com.packetanalyzer.rules.RuleManager;
import com.packetanalyzer.tracking.ConnectionTracker;
import com.packetanalyzer.types.*;
import com.packetanalyzer.io.ByteUtils;

import java.util.Optional;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

public class FastPathProcessor implements Runnable {

    public interface PacketOutputCallback {
        void onPacketProcessed(PacketJob job, PacketAction action, RuleManager.BlockReason reason);
    }

    private final int fpId;
    private final LinkedBlockingQueue<PacketJob> inputQueue;
    private final ConnectionTracker connTracker;
    private final RuleManager ruleManager;
    private final PacketOutputCallback outputCallback;

    private final AtomicLong packetsProcessed = new AtomicLong(0);
    private final AtomicLong packetsForwarded = new AtomicLong(0);
    private final AtomicLong packetsDropped = new AtomicLong(0);
    private final AtomicLong sniExtractions = new AtomicLong(0);
    private final AtomicLong classificationHits = new AtomicLong(0);

    private final AtomicBoolean running = new AtomicBoolean(false);
    private Thread thread;

    private final boolean verbose;
    private final DPIStats globalStats;
    private final long flowTimeoutSec;
    private final long cleanupWindowSec;

    public FastPathProcessor(int fpId, RuleManager ruleManager, DPIStats globalStats, boolean verbose, long flowTimeoutSec, long cleanupWindowSec, PacketOutputCallback outputCallback) {
        this.fpId = fpId;
        this.inputQueue = new LinkedBlockingQueue<>(10000);
        this.connTracker = new ConnectionTracker(fpId, 50000); // Max connections per FP
        this.ruleManager = ruleManager;
        this.globalStats = globalStats;
        this.verbose = verbose;
        this.flowTimeoutSec = flowTimeoutSec;
        this.cleanupWindowSec = cleanupWindowSec;
        this.outputCallback = outputCallback;
    }

    public void start() {
        if (running.get()) return;

        running.set(true);
        thread = new Thread(this, "FP-" + fpId);
        thread.start();

        System.out.println("[FP" + fpId + "] Started");
    }

    public void stop() {
        if (!running.get()) return;

        running.set(false);
        if (thread != null) {
            try {
                thread.join(1000);
                thread.interrupt();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        System.out.println("[FP" + fpId + "] Stopped (processed " + packetsProcessed.get() + " packets)");
    }

    public LinkedBlockingQueue<PacketJob> getInputQueue() {
        return inputQueue;
    }

    public ConnectionTracker getConnectionTracker() {
        return connTracker;
    }

    public static class FPStats {
        public long packetsProcessed;
        public long packetsForwarded;
        public long packetsDropped;
        public long connectionsTracked;
        public long evictedConnections;
        public long sniExtractions;
        public long classificationHits;
    }

    public FPStats getStats() {
        FPStats stats = new FPStats();
        stats.packetsProcessed = packetsProcessed.get();
        stats.packetsForwarded = packetsForwarded.get();
        stats.packetsDropped = packetsDropped.get();
        stats.connectionsTracked = connTracker.getActiveCount();
        stats.evictedConnections = connTracker.getStats().evictedConnections;
        stats.sniExtractions = sniExtractions.get();
        stats.classificationHits = classificationHits.get();
        return stats;
    }

    @Override
    public void run() {
        while (running.get()) {
            try {
                PacketJob job = inputQueue.poll(100, TimeUnit.MILLISECONDS);
                if (job == null) {
                    continue; // Timeout sweep removed, relying on PCAP timestamps
                }

                packetsProcessed.incrementAndGet();

                RuleManager.BlockReason reason = processPacket(job);
                PacketAction action = (reason == null) ? PacketAction.FORWARD : PacketAction.DROP;

                if (outputCallback != null) {
                    outputCallback.onPacketProcessed(job, action, reason);
                }

                if (action == PacketAction.DROP) {
                    packetsDropped.incrementAndGet();
                } else {
                    packetsForwarded.incrementAndGet();
                }

            } catch (InterruptedException e) {
                if (!running.get()) {
                    break;
                }
                Thread.currentThread().interrupt();
            }
        }
    }

    private RuleManager.BlockReason processPacket(PacketJob job) {
        Connection conn = connTracker.getOrCreateConnection(job.tuple, job.tsSec);
        if (conn == null) {
            return null; // FORWARD
        }

        // Outbound is true for simplistic updating
        connTracker.updateConnection(conn, job.data.length, true, job.tsSec);

        // PCAP Time-based cleanup
        long currentTs = connTracker.getCurrentPcapTsSec();
        if (currentTs - connTracker.getLastCleanupTsSec() >= cleanupWindowSec) {
            connTracker.cleanupStale(currentTs, flowTimeoutSec);
            connTracker.setLastCleanupTsSec(currentTs);
        }

        if (job.tuple.protocol == 6) { // TCP
            updateTCPState(conn, job.tcpFlags);
        }

        if (conn.state == ConnectionState.BLOCKED) {
            return new RuleManager.BlockReason(RuleManager.BlockReason.Type.APP, "Flow already blocked"); // We just return something so it gets dropped
        }

        if (conn.state != ConnectionState.CLASSIFIED && job.payloadLength > 0) {
            inspectPayload(job, conn);
        }

        return checkRules(job, conn);
    }

    private void inspectPayload(PacketJob job, Connection conn) {
        if (job.payloadLength == 0 || job.payloadOffset >= job.data.length) {
            return;
        }

        if (tryExtractSNI(job, conn)) return;
        if (tryExtractHTTPHost(job, conn)) return;

        if (job.tuple.dstPort == 53 || job.tuple.srcPort == 53) {
            Optional<String> domain = DnsExtractor.extractQuery(job.data, job.payloadOffset, job.payloadLength);
            if (domain.isPresent()) {
                connTracker.classifyConnection(conn, AppType.DNS, domain.get(), ConfidenceLevel.MEDIUM);
                return;
            }
        }

        if (job.tuple.dstPort == 80) {
            connTracker.classifyConnection(conn, AppType.HTTP, "", ConfidenceLevel.LOW);
        } else if (job.tuple.dstPort == 443) {
            connTracker.classifyConnection(conn, AppType.HTTPS, "", ConfidenceLevel.LOW);
        }
    }

    private boolean tryExtractSNI(PacketJob job, Connection conn) {
        if (job.tuple.dstPort != 443 && job.payloadLength < 50) return false;
        if (job.payloadOffset >= job.data.length || job.payloadLength == 0) return false;

        Optional<String> sniOpt = SniExtractor.extract(job.data, job.payloadOffset, job.payloadLength);
        if (sniOpt.isPresent()) {
            String sni = sniOpt.get();
            sniExtractions.incrementAndGet();

            AppType app = AppType.fromSni(sni);
            ConfidenceLevel conf = (app != AppType.UNKNOWN && app != AppType.HTTPS) ? ConfidenceLevel.HIGH : ConfidenceLevel.MEDIUM;
            connTracker.classifyConnection(conn, app, sni, conf);

            if (app != AppType.UNKNOWN && app != AppType.HTTPS) {
                classificationHits.incrementAndGet();
            }
            return true;
        }
        return false;
    }

    private boolean tryExtractHTTPHost(PacketJob job, Connection conn) {
        if (job.tuple.dstPort != 80) return false;
        if (job.payloadOffset >= job.data.length || job.payloadLength == 0) return false;

        Optional<String> hostOpt = HttpHostExtractor.extract(job.data, job.payloadOffset, job.payloadLength);
        if (hostOpt.isPresent()) {
            String host = hostOpt.get();
            AppType app = AppType.fromSni(host);
            ConfidenceLevel conf = (app != AppType.UNKNOWN && app != AppType.HTTP) ? ConfidenceLevel.HIGH : ConfidenceLevel.MEDIUM;
            connTracker.classifyConnection(conn, app, host, conf);

            if (app != AppType.UNKNOWN && app != AppType.HTTP) {
                classificationHits.incrementAndGet();
            }
            return true;
        }
        return false;
    }

    private RuleManager.BlockReason checkRules(PacketJob job, Connection conn) {
        if (ruleManager == null) return null;

        Optional<RuleManager.BlockReason> reasonOpt = ruleManager.shouldBlock(
                job.tuple.srcIp, job.tuple.dstPort, conn.appType, conn.sni
        );

        if (reasonOpt.isPresent()) {
            RuleManager.BlockReason br = reasonOpt.get();
            ruleManager.recordHit(br);
            if (verbose) {
                System.out.println("[BLOCKED]");
                System.out.println("Flow: " + ByteUtils.ipToString(job.tuple.srcIp) + ":" + job.tuple.srcPort + " -> " + 
                    (conn.sni != null && !conn.sni.isEmpty() ? conn.sni : ByteUtils.ipToString(job.tuple.dstIp) + ":" + job.tuple.dstPort));
                System.out.println("Rule: " + br.getFormattedRule());
            }
            connTracker.blockConnection(conn);
            
            if (globalStats != null) {
                switch (br.type) {
                    case IP: globalStats.blockedByIp.incrementAndGet(); break;
                    case APP: globalStats.blockedByApp.incrementAndGet(); break;
                    case DOMAIN: globalStats.blockedByDomain.incrementAndGet(); break;
                    case PORT: globalStats.blockedByPort.incrementAndGet(); break;
                }
            }
            return br;
        }
        return null;
    }

    private void updateTCPState(Connection conn, int tcpFlags) {
        final int SYN = 0x02;
        final int ACK = 0x10;
        final int FIN = 0x01;
        final int RST = 0x04;

        if ((tcpFlags & SYN) != 0) {
            if ((tcpFlags & ACK) != 0) {
                conn.synAckSeen = true;
            } else {
                conn.synSeen = true;
            }
        }

        if (conn.synSeen && conn.synAckSeen && (tcpFlags & ACK) != 0) {
            if (conn.state == ConnectionState.NEW) {
                conn.state = ConnectionState.ESTABLISHED;
            }
        }

        if ((tcpFlags & FIN) != 0) {
            conn.finSeen = true;
        }

        if ((tcpFlags & RST) != 0) {
            conn.state = ConnectionState.CLOSED;
        }

        if (conn.finSeen && (tcpFlags & ACK) != 0) {
            conn.state = ConnectionState.CLOSED;
        }
    }
}
