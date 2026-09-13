package com.flowgate.quota;

import com.flowgate.util.FlowGateException.SubscriberLoadException;
import com.flowgate.util.FlowGateLogger;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Loads and holds the mapping of subscriber IP addresses to their Plans.
 * Loaded once at startup; treated as read-only during packet processing.
 *
 * <p>File format (subscribers.txt):
 * <pre>
 *   # Comments start with #
 *   DEFAULT_PLAN=Basic
 *   192.168.1.10=Premium
 *   192.168.1.22=Basic
 * </pre>
 */
public final class SubscriberRegistry {

    private static final String COMPONENT = "SubscriberRegistry";

    private final Map<Integer, Plan> planByIp;   // IP as int → Plan
    private final Plan defaultPlan;

    private SubscriberRegistry(Map<Integer, Plan> planByIp, Plan defaultPlan) {
        this.planByIp    = Collections.unmodifiableMap(planByIp);
        this.defaultPlan = defaultPlan;
    }

    /**
     * Loads the registry from a file.
     *
     * @param filePath path to subscribers.txt
     * @return a fully-loaded SubscriberRegistry
     * @throws SubscriberLoadException if the file cannot be read or parsed
     */
    public static SubscriberRegistry loadFromFile(String filePath) throws SubscriberLoadException {
        Map<Integer, Plan> map = new HashMap<>();
        Plan defaultPlan = Plan.basic();  // Fallback if DEFAULT_PLAN not specified

        try {
            var lines = Files.readAllLines(Paths.get(filePath));
            int lineNum = 0;

            for (String raw : lines) {
                lineNum++;
                String line = raw.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;

                String[] parts = line.split("=", 2);
                if (parts.length != 2) {
                    FlowGateLogger.warn(COMPONENT, "Skipping malformed line " + lineNum + ": " + line);
                    continue;
                }

                String key   = parts[0].trim();
                String value = parts[1].trim();

                if (key.equalsIgnoreCase("DEFAULT_PLAN")) {
                    defaultPlan = resolvePlan(value, lineNum);
                    continue;
                }

                // Parse IP address
                int ipInt = ipToInt(key, lineNum);
                if (ipInt == -1) continue;

                Plan plan = resolvePlan(value, lineNum);
                map.put(ipInt, plan);
                FlowGateLogger.debug(COMPONENT, "Registered " + key + " → " + plan.getName());
            }

        } catch (IOException e) {
            throw new SubscriberLoadException("Cannot read subscribers file: " + filePath, e);
        }

        FlowGateLogger.info(COMPONENT, "Loaded " + map.size() + " subscribers. Default plan: " + defaultPlan.getName());
        return new SubscriberRegistry(map, defaultPlan);
    }

    /**
     * Returns the Plan for the given IP. Never returns null — falls back to the default plan.
     *
     * @param ipInt IP address as a 32-bit integer
     */
    public Plan getPlan(int ipInt) {
        return planByIp.getOrDefault(ipInt, defaultPlan);
    }

    public Plan getDefaultPlan()         { return defaultPlan; }
    public int getSubscriberCount()      { return planByIp.size(); }
    public Set<Integer> getAllIps()       { return planByIp.keySet(); }

    // ── Private Helpers ───────────────────────────────────────────────────────

    private static Plan resolvePlan(String name, int lineNum) {
        return switch (name.toLowerCase()) {
            case "premium"  -> Plan.premium();
            case "standard" -> Plan.standard();
            case "business" -> Plan.business();
            case "basic"    -> Plan.basic();
            case "demo"     -> Plan.demo();
            default -> {
                FlowGateLogger.warn(COMPONENT, "Unknown plan '" + name + "' at line " + lineNum + ", defaulting to Basic");
                yield Plan.basic();
            }
        };
    }

    private static int ipToInt(String ip, int lineNum) {
        try {
            byte[] bytes = InetAddress.getByName(ip).getAddress();
            if (bytes.length != 4) return -1;
            // PacketParser uses Little Endian to mimic x86 C++ memcpy. We must match it.
            return (bytes[0] & 0xFF) |
                  ((bytes[1] & 0xFF) << 8) |
                  ((bytes[2] & 0xFF) << 16) |
                  ((bytes[3] & 0xFF) << 24);
        } catch (UnknownHostException e) {
            FlowGateLogger.warn(COMPONENT, "Cannot parse IP at line " + lineNum + ": " + ip);
            return -1;
        }
    }
}
