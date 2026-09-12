package com.packetanalyzer.rules;

import com.packetanalyzer.io.ByteUtils;
import com.packetanalyzer.types.AppType;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.regex.Pattern;

public class RuleManager {

    private final Set<Integer> blockedIps = new HashSet<>();
    private final ReentrantReadWriteLock ipLock = new ReentrantReadWriteLock();

    private final Set<AppType> blockedApps = EnumSet.noneOf(AppType.class);
    private final ReentrantReadWriteLock appLock = new ReentrantReadWriteLock();

    private final Set<String> blockedDomains = new HashSet<>();
    private final List<String> domainPatterns = new ArrayList<>();
    private final ReentrantReadWriteLock domainLock = new ReentrantReadWriteLock();

    private final Set<Integer> blockedPorts = new HashSet<>();
    private final ReentrantReadWriteLock portLock = new ReentrantReadWriteLock();

    private final ConcurrentHashMap<String, AtomicLong> ruleHitCounts = new ConcurrentHashMap<>();

    public static class BlockReason {
        public enum Type { IP, APP, DOMAIN, PORT }
        public Type type;
        public String detail;

        public BlockReason(Type type, String detail) {
            this.type = type;
            this.detail = detail;
        }

        public String getFormattedRule() {
            return "BLOCK_" + type.name() + "=" + detail;
        }
    }

    public static class RuleStats {
        public int blockedIps;
        public int blockedApps;
        public int blockedDomains;
        public int blockedPorts;
    }

    public void recordHit(BlockReason reason) {
        if (reason == null) return;
        ruleHitCounts.computeIfAbsent(reason.getFormattedRule(), k -> new AtomicLong(0))
                     .incrementAndGet();
    }

    public Map<String, Long> getRuleHitCounts() {
        Map<String, Long> result = new HashMap<>();
        for (Map.Entry<String, AtomicLong> entry : ruleHitCounts.entrySet()) {
            result.put(entry.getKey(), entry.getValue().get());
        }
        return result;
    }

    public void blockIP(String ip) {
        blockIP(ByteUtils.parseIp(ip));
    }

    public void blockIP(int ip) {
        ipLock.writeLock().lock();
        try {
            blockedIps.add(ip);
        } finally {
            ipLock.writeLock().unlock();
        }
    }

    public void unblockIP(String ip) {
        unblockIP(ByteUtils.parseIp(ip));
    }

    public void unblockIP(int ip) {
        ipLock.writeLock().lock();
        try {
            blockedIps.remove(ip);
        } finally {
            ipLock.writeLock().unlock();
        }
    }

    public boolean isIPBlocked(int ip) {
        ipLock.readLock().lock();
        try {
            return blockedIps.contains(ip);
        } finally {
            ipLock.readLock().unlock();
        }
    }

    public void blockApp(AppType app) {
        appLock.writeLock().lock();
        try {
            blockedApps.add(app);
        } finally {
            appLock.writeLock().unlock();
        }
    }

    public void unblockApp(AppType app) {
        appLock.writeLock().lock();
        try {
            blockedApps.remove(app);
        } finally {
            appLock.writeLock().unlock();
        }
    }

    public boolean isAppBlocked(AppType app) {
        appLock.readLock().lock();
        try {
            return blockedApps.contains(app);
        } finally {
            appLock.readLock().unlock();
        }
    }

    public void blockDomain(String domain) {
        domainLock.writeLock().lock();
        try {
            if (domain.startsWith("*.")) {
                domainPatterns.add(domain.substring(2).toLowerCase());
            } else {
                blockedDomains.add(domain.toLowerCase());
            }
        } finally {
            domainLock.writeLock().unlock();
        }
    }

    public void unblockDomain(String domain) {
        domainLock.writeLock().lock();
        try {
            if (domain.startsWith("*.")) {
                domainPatterns.remove(domain.substring(2).toLowerCase());
            } else {
                blockedDomains.remove(domain.toLowerCase());
            }
        } finally {
            domainLock.writeLock().unlock();
        }
    }

    public boolean isDomainBlocked(String domain) 
    {
        if (domain == null || domain.isEmpty()) return false;

        String lowerDomain = domain.toLowerCase();

        domainLock.readLock().lock();
        try {

        // Exact match
        if (blockedDomains.contains(lowerDomain)) {
            return true;
        }

        // Wildcard patterns (*.facebook.com)
        for (String pattern : domainPatterns) {
            if (lowerDomain.equals(pattern) ||
                lowerDomain.endsWith("." + pattern)) {
                return true;
            }
        }

        // Root domain -> subdomain matching
        for (String blockedDomain : blockedDomains) {
            if (lowerDomain.endsWith("." + blockedDomain)) {
                return true;
            }
        }

        return false;

        } finally {
            domainLock.readLock().unlock();
        }
    }

    public void blockPort(int port) {
        portLock.writeLock().lock();
        try {
            blockedPorts.add(port);
        } finally {
            portLock.writeLock().unlock();
        }
    }

    public boolean isPortBlocked(int port) {
        portLock.readLock().lock();
        try {
            return blockedPorts.contains(port);
        } finally {
            portLock.readLock().unlock();
        }
    }

    public Optional<BlockReason> shouldBlock(int srcIp, int dstPort, AppType app, String domain) {
        if (isIPBlocked(srcIp)) {
            return Optional.of(new BlockReason(BlockReason.Type.IP, ByteUtils.ipToString(srcIp)));
        }
        if (isPortBlocked(dstPort)) {
            return Optional.of(new BlockReason(BlockReason.Type.PORT, String.valueOf(dstPort)));
        }
        if (isAppBlocked(app)) {
            return Optional.of(new BlockReason(BlockReason.Type.APP, app.getDisplayName()));
        }
        if (isDomainBlocked(domain)) {
            return Optional.of(new BlockReason(BlockReason.Type.DOMAIN, domain));
        }
        return Optional.empty();
    }

    public boolean loadRules(String filename) {
        // Read the first non-blank line to detect format
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line;
            boolean isNewFormat = false;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                if (line.contains("=")) {
                    isNewFormat = true;
                }
                break; // Detected first line
            }
            
            if (isNewFormat) {
                RuleFileParser.parseAndLoad(filename, this);
                return true;
            }
        } catch (IOException e) {
            return false;
        }

        // Fallback to INI format parsing
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line;
            String section = "";
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;

                if (line.startsWith("[") && line.endsWith("]")) {
                    section = line.substring(1, line.length() - 1);
                    continue;
                }

                switch (section) {
                    case "BLOCKED_IPS":
                        blockIP(line);
                        break;
                    case "BLOCKED_APPS":
                        AppType app = AppType.fromDisplayName(line);
                        if (app != AppType.UNKNOWN) {
                            blockApp(app);
                        } else {
                            try {
                                blockApp(AppType.valueOf(line.toUpperCase()));
                            } catch (IllegalArgumentException ignored) {}
                        }
                        break;
                    case "BLOCKED_DOMAINS":
                        blockDomain(line);
                        break;
                    case "BLOCKED_PORTS":
                        try {
                            blockPort(Integer.parseInt(line));
                        } catch (NumberFormatException ignored) {}
                        break;
                }
            }
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    public boolean saveRules(String filename) {
        try (FileWriter writer = new FileWriter(filename)) {
            writer.write("[BLOCKED_IPS]\n");
            ipLock.readLock().lock();
            try {
                for (int ip : blockedIps) {
                    writer.write(ByteUtils.ipToString(ip) + "\n");
                }
            } finally {
                ipLock.readLock().unlock();
            }

            writer.write("\n[BLOCKED_APPS]\n");
            appLock.readLock().lock();
            try {
                for (AppType app : blockedApps) {
                    writer.write(app.name() + "\n");
                }
            } finally {
                appLock.readLock().unlock();
            }

            writer.write("\n[BLOCKED_DOMAINS]\n");
            domainLock.readLock().lock();
            try {
                for (String domain : blockedDomains) {
                    writer.write(domain + "\n");
                }
                for (String pattern : domainPatterns) {
                    writer.write("*." + pattern + "\n");
                }
            } finally {
                domainLock.readLock().unlock();
            }

            writer.write("\n[BLOCKED_PORTS]\n");
            portLock.readLock().lock();
            try {
                for (int port : blockedPorts) {
                    writer.write(port + "\n");
                }
            } finally {
                portLock.readLock().unlock();
            }

            return true;
        } catch (IOException e) {
            return false;
        }
    }

    public void clearAll() {
        ipLock.writeLock().lock();
        blockedIps.clear();
        ipLock.writeLock().unlock();

        appLock.writeLock().lock();
        blockedApps.clear();
        appLock.writeLock().unlock();

        domainLock.writeLock().lock();
        blockedDomains.clear();
        domainPatterns.clear();
        domainLock.writeLock().unlock();

        portLock.writeLock().lock();
        blockedPorts.clear();
        portLock.writeLock().unlock();
    }

    public RuleStats getStats() {
        RuleStats stats = new RuleStats();
        
        ipLock.readLock().lock();
        stats.blockedIps = blockedIps.size();
        ipLock.readLock().unlock();
        
        appLock.readLock().lock();
        stats.blockedApps = blockedApps.size();
        appLock.readLock().unlock();
        
        domainLock.readLock().lock();
        stats.blockedDomains = blockedDomains.size() + domainPatterns.size();
        domainLock.readLock().unlock();
        
        portLock.readLock().lock();
        stats.blockedPorts = blockedPorts.size();
        portLock.readLock().unlock();
        
        return stats;
    }
}
