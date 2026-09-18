package com.flowgate.policy;

import com.flowgate.quota.Plan;
import com.packetanalyzer.types.AppType;

/** Immutable record describing FlowGate's decision for a single packet. */
public record PolicyDecision(
        int          subscriberIp,
        String       planName,
        AppType      appType,
        ThrottlePolicy.Tier tier,
        long         usageBytes,
        long         quotaBytes,
        double       usagePct,
        FupState     fupState,
        long         bandwidthLimitKbps,
        PolicyVerdict verdict,
        ReasonCode   reasonCode,
        String       explanation,
        long         simulatedDelayUsec,
        long         pcapTimestampSec
) {
    /**
     * Convenience factory: forward decision with no rate limiting.
     */
    public static PolicyDecision forward(int ip, String plan, AppType app,
                                         ThrottlePolicy.Tier tier, long usage,
                                         long quota, double pct, FupState state,
                                         ReasonCode reason, String explanation,
                                         long pcapTs) {
        return new PolicyDecision(ip, plan, app, tier, usage, quota, pct, state,
                -1L, PolicyVerdict.FORWARD, reason, explanation, 0L, pcapTs);
    }

    /**
     * Convenience factory: delay (throttle) decision.
     */
    public static PolicyDecision delay(int ip, String plan, AppType app,
                                       ThrottlePolicy.Tier tier, long usage,
                                       long quota, double pct, FupState state,
                                       long bandwidthKbps, long delayUsec,
                                       ReasonCode reason, String explanation,
                                       long pcapTs) {
        return new PolicyDecision(ip, plan, app, tier, usage, quota, pct, state,
                bandwidthKbps, PolicyVerdict.DELAY, reason, explanation, delayUsec, pcapTs);
    }

    /**
     * Convenience factory: hard-drop decision.
     */
    public static PolicyDecision drop(int ip, String plan, AppType app,
                                      ThrottlePolicy.Tier tier, long usage,
                                      long quota, double pct,
                                      ReasonCode reason, String explanation,
                                      long pcapTs) {
        return new PolicyDecision(ip, plan, app, tier, usage, quota, pct,
                FupState.HARD_DROP, -1L, PolicyVerdict.DROP, reason, explanation, 0L, pcapTs);
    }

    /** Formats usage as "1.2 GB / 1.5 GB (80.0%)" for display. */
    public String usageSummary() {
        String usedStr  = formatBytes(usageBytes);
        String quotaStr = quotaBytes == -1 ? "UNLIMITED" : formatBytes(quotaBytes);
        String pctStr   = quotaBytes == -1 ? "" : String.format(" (%.1f%%)", usagePct);
        return usedStr + " / " + quotaStr + pctStr;
    }

    private static String formatBytes(long bytes) {
        if (bytes < 0) return "UNLIMITED";
        if (bytes >= Plan.BYTES_PER_GB) return String.format("%.2f GB", (double) bytes / Plan.BYTES_PER_GB);
        return String.format("%.2f MB", (double) bytes / (1024 * 1024));
    }
}
