package com.flowgate.policy;

import com.flowgate.util.FlowGateException.ConfigurationException;
import com.flowgate.util.FlowGateLogger;
import com.packetanalyzer.types.AppType;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.EnumMap;
import java.util.Map;

/**
 * Defines the App-Selective Intelligent Throttling (ASIT) configuration.
 *
 * <p>Maps each {@link AppType} to a {@link Tier}, and each Tier to a bandwidth limit.
 * Loaded from {@code throttle-policy.txt} or constructed with built-in defaults.
 *
 * <p>File format:
 * <pre>
 *   # Bandwidth limits per tier (Kbps). -1 = unlimited.
 *   LIMIT_ESSENTIAL=-1
 *   LIMIT_STANDARD=256
 *   LIMIT_ENTERTAINMENT=64
 *
 *   # App → Tier mappings
 *   WHATSAPP=ESSENTIAL
 *   YOUTUBE=ENTERTAINMENT
 * </pre>
 */
public final class ThrottlePolicy {

    private static final String COMPONENT = "ThrottlePolicy";

    /** The three ASIT traffic tiers. */
    public enum Tier {
        /**
         * Critical traffic: messaging, DNS, essential services.
         * Always forwarded at full speed, even during FUP throttling.
         */
        ESSENTIAL,

        /**
         * Productivity traffic: work tools, cloud services, development.
         * Throttled to a moderate bandwidth limit during FUP.
         */
        STANDARD,

        /**
         * Entertainment traffic: video streaming, social media, gaming.
         * Throttled to a low bandwidth limit during FUP.
         */
        ENTERTAINMENT
    }

    private final Map<AppType, Tier> tierByApp;
    private final long essentialLimitKbps;     // -1 = unlimited
    private final long standardLimitKbps;
    private final long entertainmentLimitKbps;

    private ThrottlePolicy(Map<AppType, Tier> tierByApp,
                           long essentialLimitKbps,
                           long standardLimitKbps,
                           long entertainmentLimitKbps) {
        this.tierByApp              = tierByApp;
        this.essentialLimitKbps     = essentialLimitKbps;
        this.standardLimitKbps      = standardLimitKbps;
        this.entertainmentLimitKbps = entertainmentLimitKbps;
    }

    /**
     * Returns the ASIT tier for a given application.
     * Any unrecognised app defaults to {@link Tier#ENTERTAINMENT}.
     */
    public Tier getTier(AppType appType) {
        return tierByApp.getOrDefault(appType, Tier.ENTERTAINMENT);
    }

    /**
     * Returns the configured bandwidth limit in Kbps for the given tier.
     * Returns -1 for ESSENTIAL (unlimited).
     */
    public long getBandwidthLimitKbps(Tier tier) {
        return switch (tier) {
            case ESSENTIAL     -> essentialLimitKbps;
            case STANDARD      -> standardLimitKbps;
            case ENTERTAINMENT -> entertainmentLimitKbps;
        };
    }

    // ── Factory methods ───────────────────────────────────────────────────────

    /**
     * Loads the policy from a file. Falls back to defaults on any parse error.
     */
    public static ThrottlePolicy loadFromFile(String filePath) throws ConfigurationException {
        Map<AppType, Tier> map        = defaultTierMap();
        long essentialLimit     = -1L;
        long standardLimit      = 256L;
        long entertainmentLimit = 64L;

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

                String key   = parts[0].trim().toUpperCase();
                String value = parts[1].trim();

                switch (key) {
                    case "LIMIT_ESSENTIAL"     -> essentialLimit     = parseLong(value, lineNum);
                    case "LIMIT_STANDARD"      -> standardLimit      = parseLong(value, lineNum);
                    case "LIMIT_ENTERTAINMENT" -> entertainmentLimit = parseLong(value, lineNum);
                    default -> {
                        // Try to parse as AppType=Tier mapping
                        try {
                            AppType app  = AppType.valueOf(key);
                            Tier    tier = Tier.valueOf(value.toUpperCase());
                            map.put(app, tier);
                            FlowGateLogger.debug(COMPONENT, app + " → " + tier);
                        } catch (IllegalArgumentException e) {
                            FlowGateLogger.warn(COMPONENT, "Unknown app or tier at line " + lineNum + ": " + line);
                        }
                    }
                }
            }

        } catch (IOException e) {
            throw new ConfigurationException("Cannot read throttle-policy file: " + filePath, e);
        }

        FlowGateLogger.info(COMPONENT, "Loaded. ESSENTIAL=-1, STANDARD=" + standardLimit
                + " Kbps, ENTERTAINMENT=" + entertainmentLimit + " Kbps");

        return new ThrottlePolicy(map, essentialLimit, standardLimit, entertainmentLimit);
    }

    /**
     * Returns sensible built-in defaults without requiring a config file.
     * Used when {@code --throttle-policy} flag is not passed.
     */
    public static ThrottlePolicy defaults() {
        FlowGateLogger.info(COMPONENT, "Using built-in ASIT defaults.");
        return new ThrottlePolicy(defaultTierMap(), -1L, 256L, 64L);
    }

    // ── Private Helpers ───────────────────────────────────────────────────────

    private static Map<AppType, Tier> defaultTierMap() {
        Map<AppType, Tier> map = new EnumMap<>(AppType.class);

        // ESSENTIAL — Always full speed
        map.put(AppType.WHATSAPP,   Tier.ESSENTIAL);
        map.put(AppType.TELEGRAM,   Tier.ESSENTIAL);
        map.put(AppType.DNS,        Tier.ESSENTIAL);

        // STANDARD — Moderate throttle
        map.put(AppType.GOOGLE,     Tier.STANDARD);
        map.put(AppType.GITHUB,     Tier.STANDARD);
        map.put(AppType.MICROSOFT,  Tier.STANDARD);
        map.put(AppType.AMAZON,     Tier.STANDARD);
        map.put(AppType.APPLE,      Tier.STANDARD);
        map.put(AppType.CLOUDFLARE, Tier.STANDARD);
        map.put(AppType.ZOOM,       Tier.STANDARD);

        // ENTERTAINMENT — Heavy throttle
        map.put(AppType.YOUTUBE,    Tier.ENTERTAINMENT);
        map.put(AppType.NETFLIX,    Tier.ENTERTAINMENT);
        map.put(AppType.INSTAGRAM,  Tier.ENTERTAINMENT);
        map.put(AppType.FACEBOOK,   Tier.ENTERTAINMENT);
        map.put(AppType.TWITTER,    Tier.ENTERTAINMENT);
        map.put(AppType.TIKTOK,     Tier.ENTERTAINMENT);
        map.put(AppType.SPOTIFY,    Tier.ENTERTAINMENT);
        map.put(AppType.DISCORD,    Tier.ENTERTAINMENT);

        return map;
    }

    private static long parseLong(String value, int lineNum) {
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException e) {
            FlowGateLogger.warn(COMPONENT, "Invalid number at line " + lineNum + ": " + value + ", using -1");
            return -1L;
        }
    }
}
