package com.packetanalyzer.tracking;

import com.packetanalyzer.types.AppType;
import com.packetanalyzer.types.ConfidenceLevel;
import com.packetanalyzer.types.Connection;
import com.packetanalyzer.types.ConnectionState;
import com.packetanalyzer.types.FiveTuple;
import com.packetanalyzer.types.PacketAction;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

public class ConnectionTracker {

    private final int fpId;
    private final int maxConnections;
    private final HashMap<FiveTuple, Connection> connections = new HashMap<>();
    
    private long totalSeen = 0;
    private long classifiedCount = 0;
    private long blockedCount = 0;
    private long evictedCount = 0;

    private long currentPcapTsSec = 0;
    private long lastCleanupTsSec = 0;

    // Cumulative Accumulators for Analytics
    public static class AppStats {
        public long connections = 0;
        public long packets = 0;
        public long bytes = 0;
    }

    private final Map<AppType, AppStats> cumulativeAppStats = new HashMap<>();
    private final Map<String, Long> cumulativeDomainStats = new HashMap<>();
    private final Map<Integer, Long> cumulativeTopTalkers = new HashMap<>();
    
    // Configurable limit to prevent DGA/randomized SNI domain exhaustion
    private static final int MAX_TRACKED_DOMAINS = 50000;

    public static class TrackerStats {
        public int activeConnections;
        public long totalConnectionsSeen;
        public long classifiedConnections;
        public long blockedConnections;
        public long evictedConnections;
    }

    public ConnectionTracker(int fpId, int maxConnections) {
        this.fpId = fpId;
        this.maxConnections = maxConnections;
    }

    public Connection getOrCreateConnection(FiveTuple tuple, long tsSec) {
        Connection conn = connections.get(tuple);
        if (conn != null) {
            return conn;
        }

        if (connections.size() >= maxConnections) {
            evictOldest();
        }

        conn = new Connection();
        conn.tuple = tuple;
        conn.firstSeenSec = tsSec;
        conn.lastSeenSec = tsSec;
        
        connections.put(tuple, conn);
        totalSeen++;
        
        return conn;
    }

    public Connection getConnection(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) {
            return conn;
        }
        
        return connections.get(tuple.reverse());
    }

    public void updateConnection(Connection conn, int packetSize, boolean isOutbound, long tsSec) {
        if (conn == null) return;
        
        conn.lastSeenSec = tsSec;
        currentPcapTsSec = Math.max(currentPcapTsSec, tsSec);
        
        if (isOutbound) {
            conn.packetsOut++;
            conn.bytesOut += packetSize;
        } else {
            conn.packetsIn++;
            conn.bytesIn += packetSize;
        }
    }

    public void classifyConnection(Connection conn, AppType app, String sni, ConfidenceLevel confidence) {
        if (conn == null) return;
        
        if (conn.state != ConnectionState.CLASSIFIED) {
            conn.appType = app;
            conn.sni = sni;
            conn.confidence = confidence;
            conn.state = ConnectionState.CLASSIFIED;
            classifiedCount++;
        }
    }

    public void blockConnection(Connection conn) {
        if (conn == null) return;
        
        conn.state = ConnectionState.BLOCKED;
        conn.action = PacketAction.DROP;
        blockedCount++;
    }

    public void closeConnection(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) {
            conn.state = ConnectionState.CLOSED;
        }
    }

    private void recordEvictedConnection(Connection conn) {
        if (conn == null) return;
        
        // Accumulate Application Stats
        AppStats appStats = cumulativeAppStats.computeIfAbsent(conn.appType, k -> new AppStats());
        appStats.connections++;
        appStats.packets += (conn.packetsIn + conn.packetsOut);
        appStats.bytes += (conn.bytesIn + conn.bytesOut);

        // Accumulate Domain Stats
        if (conn.sni != null && !conn.sni.isEmpty()) {
            if (cumulativeDomainStats.size() >= MAX_TRACKED_DOMAINS && !cumulativeDomainStats.containsKey(conn.sni)) {
                cumulativeDomainStats.put("<OTHER>", cumulativeDomainStats.getOrDefault("<OTHER>", 0L) + 1);
            } else {
                cumulativeDomainStats.put(conn.sni, cumulativeDomainStats.getOrDefault(conn.sni, 0L) + 1);
            }
        }
        
        // Accumulate Top Talkers (Source IP)
        cumulativeTopTalkers.put(conn.tuple.srcIp, cumulativeTopTalkers.getOrDefault(conn.tuple.srcIp, 0L) + 1);
    }

    public int cleanupStale(long currentTsSec, long flowTimeoutSec) {
        int removed = 0;
        
        var it = connections.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<FiveTuple, Connection> entry = it.next();
            Connection conn = entry.getValue();
            
            if ((currentTsSec - conn.lastSeenSec) > flowTimeoutSec || conn.state == ConnectionState.CLOSED) {
                recordEvictedConnection(conn);
                it.remove();
                removed++;
                evictedCount++;
            }
        }
        
        return removed;
    }

    public List<Connection> getAllConnections() {
        return new ArrayList<>(connections.values());
    }

    public int getActiveCount() {
        return connections.size();
    }

    public TrackerStats getStats() {
        TrackerStats stats = new TrackerStats();
        stats.activeConnections = connections.size();
        stats.totalConnectionsSeen = totalSeen;
        stats.classifiedConnections = classifiedCount;
        stats.blockedConnections = blockedCount;
        stats.evictedConnections = evictedCount;
        return stats;
    }

    public void forEach(Consumer<Connection> callback) {
        for (Connection conn : connections.values()) {
            callback.accept(conn);
        }
    }

    public void clear() {
        for (Connection conn : connections.values()) {
            recordEvictedConnection(conn);
        }
        connections.clear();
    }

    private void evictOldest() {
        if (connections.isEmpty()) return;
        
        FiveTuple oldestKey = null;
        long oldestTime = Long.MAX_VALUE;
        Connection oldestConn = null;
        
        for (Map.Entry<FiveTuple, Connection> entry : connections.entrySet()) {
            if (entry.getValue().lastSeenSec < oldestTime) {
                oldestTime = entry.getValue().lastSeenSec;
                oldestKey = entry.getKey();
                oldestConn = entry.getValue();
            }
        }
        
        if (oldestKey != null) {
            recordEvictedConnection(oldestConn);
            connections.remove(oldestKey);
            evictedCount++;
        }
    }

    public Map<AppType, AppStats> getCumulativeAppStats() {
        return cumulativeAppStats;
    }

    public Map<String, Long> getCumulativeDomainStats() {
        return cumulativeDomainStats;
    }

    public Map<Integer, Long> getCumulativeTopTalkers() {
        return cumulativeTopTalkers;
    }

    public long getCurrentPcapTsSec() {
        return currentPcapTsSec;
    }

    public long getLastCleanupTsSec() {
        return lastCleanupTsSec;
    }

    public void setLastCleanupTsSec(long tsSec) {
        this.lastCleanupTsSec = tsSec;
    }
}
