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
        ss.append("----------------------------------------------------------------\n");
        ss.append("APPLICATION BREAKDOWN\n");
        ss.append("----------------------------------------------------------------\n\n");
        ss.append(String.format("  %-22s  %8s   %s%n", "Application", "Packets", "Share"));
        ss.append("  " + "-".repeat(45) + "\n");

        long total = stats.appDistribution.values().stream().mapToLong(Long::longValue).sum();

        List<Map.Entry<AppType, Long>> sortedApps = new ArrayList<>(stats.appDistribution.entrySet());
        sortedApps.sort((a, b) -> b.getValue().compareTo(a.getValue()));

        for (Map.Entry<AppType, Long> entry : sortedApps) {
            double pct = total > 0 ? (100.0 * entry.getValue() / total) : 0;
            ss.append(String.format("  %-22s  %8d   %.1f%%%n",
                    entry.getKey().getDisplayName(), entry.getValue(), pct));
        }

        if (!stats.topDomains.isEmpty()) {
            ss.append("\n  Top Domains\n");
            ss.append("  " + "-".repeat(45) + "\n");
            for (Map.Entry<String, Long> entry : stats.topDomains) {
                String domain = entry.getKey();
                if (domain.length() > 38) domain = domain.substring(0, 35) + "...";
                ss.append(String.format("  %-38s  %d%n", domain, entry.getValue()));
            }
        }

        ss.append("\n");
        return ss.toString();
    }
}
