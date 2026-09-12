package com.packetanalyzer.analytics;

import com.packetanalyzer.tracking.ConnectionTracker;
import com.packetanalyzer.tracking.GlobalConnectionTable;
import com.packetanalyzer.types.AppType;
import com.packetanalyzer.types.Connection;

import java.util.HashMap;
import java.util.Map;

public class AnalyticsCollector {

    public static class GlobalAppStats {
        public long connections = 0;
        public long packets = 0;
        public long bytes = 0;
    }

    private final Map<AppType, GlobalAppStats> appStats = new HashMap<>();
    private final Map<String, Long> domainStats = new HashMap<>();
    private final Map<Integer, Long> topTalkers = new HashMap<>();
    
    private long activeFlows = 0;
    private long evictedFlows = 0;

    public void collect(GlobalConnectionTable globalConnTable) {
        for (ConnectionTracker tracker : globalConnTable.getTrackers()) {
            if (tracker == null) continue;

            ConnectionTracker.TrackerStats stats = tracker.getStats();
            activeFlows += stats.activeConnections;
            evictedFlows += stats.evictedConnections;

            // 1. Process active connections
            for (Connection conn : tracker.getAllConnections()) {
                // Apps
                GlobalAppStats aStats = appStats.computeIfAbsent(conn.appType, k -> new GlobalAppStats());
                aStats.connections++;
                aStats.packets += (conn.packetsIn + conn.packetsOut);
                aStats.bytes += (conn.bytesIn + conn.bytesOut);

                // Domains
                if (conn.sni != null && !conn.sni.isEmpty()) {
                    domainStats.put(conn.sni, domainStats.getOrDefault(conn.sni, 0L) + 1);
                }

                // Top Talkers
                topTalkers.put(conn.tuple.srcIp, topTalkers.getOrDefault(conn.tuple.srcIp, 0L) + 1);
            }

            // 2. Process evicted connections
            for (Map.Entry<AppType, ConnectionTracker.AppStats> entry : tracker.getCumulativeAppStats().entrySet()) {
                GlobalAppStats aStats = appStats.computeIfAbsent(entry.getKey(), k -> new GlobalAppStats());
                aStats.connections += entry.getValue().connections;
                aStats.packets += entry.getValue().packets;
                aStats.bytes += entry.getValue().bytes;
            }

            for (Map.Entry<String, Long> entry : tracker.getCumulativeDomainStats().entrySet()) {
                domainStats.put(entry.getKey(), domainStats.getOrDefault(entry.getKey(), 0L) + entry.getValue());
            }

            for (Map.Entry<Integer, Long> entry : tracker.getCumulativeTopTalkers().entrySet()) {
                topTalkers.put(entry.getKey(), topTalkers.getOrDefault(entry.getKey(), 0L) + entry.getValue());
            }
        }
    }

    public Map<AppType, GlobalAppStats> getAppStats() { return appStats; }
    public Map<String, Long> getDomainStats() { return domainStats; }
    public Map<Integer, Long> getTopTalkers() { return topTalkers; }
    
    public long getActiveFlows() { return activeFlows; }
    public long getEvictedFlows() { return evictedFlows; }
}
