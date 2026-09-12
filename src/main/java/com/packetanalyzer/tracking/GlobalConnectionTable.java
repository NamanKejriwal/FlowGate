package com.packetanalyzer.tracking;

import com.packetanalyzer.types.AppType;

import java.util.*;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class GlobalConnectionTable {

    private final List<ConnectionTracker> trackers = new ArrayList<>();
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    public static class GlobalStats {
        public long totalActiveConnections;
        public long totalConnectionsSeen;
        public Map<AppType, Long> appDistribution = new HashMap<>();
        public List<Map.Entry<String, Long>> topDomains = new ArrayList<>();
    }

    public GlobalConnectionTable(int numFps) {
        for (int i = 0; i < numFps; i++) {
            trackers.add(null);
        }
    }

    public List<ConnectionTracker> getTrackers() {
        return trackers;
    }

    public void registerTracker(int fpId, ConnectionTracker tracker) {
        lock.writeLock().lock();
        try {
            if (fpId >= 0 && fpId < trackers.size()) {
                trackers.set(fpId, tracker);
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    public GlobalStats getGlobalStats() {
        lock.readLock().lock();
        try {
            GlobalStats stats = new GlobalStats();
            Map<String, Long> domainCounts = new HashMap<>();

            for (ConnectionTracker tracker : trackers) {
                if (tracker == null) continue;

                ConnectionTracker.TrackerStats trackerStats = tracker.getStats();
                stats.totalActiveConnections += trackerStats.activeConnections;
                stats.totalConnectionsSeen += trackerStats.totalConnectionsSeen;

                tracker.forEach(conn -> {
                    stats.appDistribution.put(conn.appType, 
                        stats.appDistribution.getOrDefault(conn.appType, 0L) + 1);
                    
                    if (conn.sni != null && !conn.sni.isEmpty()) {
                        domainCounts.put(conn.sni, domainCounts.getOrDefault(conn.sni, 0L) + 1);
                    }
                });
            }

            List<Map.Entry<String, Long>> domainList = new ArrayList<>(domainCounts.entrySet());
            domainList.sort((a, b) -> b.getValue().compareTo(a.getValue()));

            int count = Math.min(domainList.size(), 20);
            stats.topDomains = domainList.subList(0, count);

            return stats;
        } finally {
            lock.readLock().unlock();
        }
    }

    public String generateReport() {
        GlobalStats stats = getGlobalStats();

        StringBuilder ss = new StringBuilder();
        ss.append("\n╔══════════════════════════════════════════════════════════════╗\n");
        ss.append("║               CONNECTION STATISTICS REPORT                    ║\n");
        ss.append("╠══════════════════════════════════════════════════════════════╣\n");

        ss.append(String.format("║ Active Connections:     %10d                          ║\n", stats.totalActiveConnections));
        ss.append(String.format("║ Total Connections Seen: %10d                          ║\n", stats.totalConnectionsSeen));

        ss.append("╠══════════════════════════════════════════════════════════════╣\n");
        ss.append("║                    APPLICATION BREAKDOWN                      ║\n");
        ss.append("╠══════════════════════════════════════════════════════════════╣\n");

        long total = stats.appDistribution.values().stream().mapToLong(Long::longValue).sum();

        List<Map.Entry<AppType, Long>> sortedApps = new ArrayList<>(stats.appDistribution.entrySet());
        sortedApps.sort((a, b) -> b.getValue().compareTo(a.getValue()));

        for (Map.Entry<AppType, Long> entry : sortedApps) {
            double pct = total > 0 ? (100.0 * entry.getValue() / total) : 0;
            ss.append(String.format("║ %-20s %10d (%.1f%%)           ║\n", 
                entry.getKey().getDisplayName(), entry.getValue(), pct));
        }

        if (!stats.topDomains.isEmpty()) {
            ss.append("╠══════════════════════════════════════════════════════════════╣\n");
            ss.append("║                      TOP DOMAINS                             ║\n");
            ss.append("╠══════════════════════════════════════════════════════════════╣\n");

            for (Map.Entry<String, Long> entry : stats.topDomains) {
                String domain = entry.getKey();
                if (domain.length() > 35) {
                    domain = domain.substring(0, 32) + "...";
                }
                ss.append(String.format("║ %-40s %10d           ║\n", domain, entry.getValue()));
            }
        }

        ss.append("╚══════════════════════════════════════════════════════════════╝\n");

        return ss.toString();
    }
}
