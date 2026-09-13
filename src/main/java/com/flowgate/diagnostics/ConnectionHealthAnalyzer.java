package com.flowgate.diagnostics;

import com.flowgate.policy.FupState;
import com.flowgate.policy.PolicyDecision;
import com.flowgate.policy.PolicyVerdict;
import com.flowgate.policy.ReasonCode;
import com.flowgate.policy.ThrottlePolicy.Tier;
import com.packetanalyzer.types.DPIStats;

import java.util.List;

/**
 * Evidence-Based Diagnostic Engine for FlowGate.
 *
 * <p>Answers "Why is my internet slow?" by examining the last N {@link PolicyDecision}s
 * for a subscriber and returning a structured {@link DiagnosticReport} that classifies
 * the root cause of any degradation.
 *
 * <p>Root causes in priority order:
 * <ol>
 *   <li>{@link Cause#HARD_DROP}           — subscriber exceeded 2× quota; traffic is being dropped.</li>
 *   <li>{@link Cause#FUP_ENTERTAINMENT}   — throttled, app is ENTERTAINMENT tier (e.g. YouTube).</li>
 *   <li>{@link Cause#FUP_STANDARD}        — throttled, app is STANDARD tier (e.g. GitHub).</li>
 *   <li>{@link Cause#FUP_WARNING}         — quota &gt; 80% but no throttle yet.</li>
 *   <li>{@link Cause#ESSENTIAL_PROTECTED} — essential app forwarded during throttle.</li>
 *   <li>{@link Cause#HEALTHY}             — everything looks fine.</li>
 * </ol>
 *
 * <p>All inputs are validated defensively; a null/empty decision list returns a
 * {@link Cause#HEALTHY} report rather than throwing.
 *
 * <p>Note: {@code globalStats} is accepted for future extension (e.g. real congestion
 * detection via queue-depth telemetry) but is not used in current classification.
 * {@link Cause#NETWORK_CONGESTION} is reserved and documented below but not emitted
 * until a genuine network-level signal is available.
 */
public final class ConnectionHealthAnalyzer {

    // Non-instantiable utility class
    private ConnectionHealthAnalyzer() {}

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Analyses recent policy decisions for a single subscriber.
     *
     * @param recentDecisions Up to N most-recent {@link PolicyDecision}s for the subscriber
     *                        (must all belong to the same subscriber IP).
     * @param globalStats     Reserved for future congestion detection; currently unused.
     * @return A {@link DiagnosticReport} describing the root cause of any degradation.
     */
    public static DiagnosticReport analyse(List<PolicyDecision> recentDecisions,
                                           DPIStats globalStats) {

        if (recentDecisions == null || recentDecisions.isEmpty()) {
            return new DiagnosticReport(Cause.IDLE, "No recent traffic data — subscriber is idle.", 0.0, -1L, 0L, 0L, 0L);
        }

        // --- Derive aggregates from the decision window ---

        long totalDecisions    = recentDecisions.size();
        long delayCount        = countVerdict(recentDecisions, PolicyVerdict.DELAY);
        long dropCount         = countVerdict(recentDecisions, PolicyVerdict.DROP);

        // Use the most recent decision as the authoritative quota/state snapshot
        PolicyDecision latest  = recentDecisions.get(recentDecisions.size() - 1);
        FupState fupState      = latest.fupState();
        double usagePct        = latest.usagePct();

        // --- Priority 1: HARD_DROP ---
        if (fupState == FupState.HARD_DROP || dropCount > 0) {
            return new DiagnosticReport(
                    Cause.HARD_DROP,
                    String.format(
                            "Subscriber has exceeded the hard-drop threshold (%.1f%% of quota). "
                          + "%d/%d recent packets were hard-dropped. "
                          + "Traffic remains subject to the hard-drop policy while usage remains above the configured threshold.",
                            usagePct, dropCount, totalDecisions),
                    usagePct,
                    latest.bandwidthLimitKbps(),
                    delayCount,
                    dropCount,
                    totalDecisions);
        }

        // --- Priority 2: FUP throttle (ENTERTAINMENT or STANDARD tier) ---
        if (fupState == FupState.THROTTLE && delayCount > 0) {
            Tier tier = latest.tier();

            if (tier == Tier.ENTERTAINMENT) {
                return new DiagnosticReport(
                        Cause.FUP_ENTERTAINMENT,
                        String.format(
                                "FUP quota exceeded (%.1f%%). App '%s' is in the ENTERTAINMENT tier "
                              + "and is being throttled to %d Kbps. "
                              + "%d/%d recent packets received a DELAY verdict.",
                                usagePct, latest.appType().getDisplayName(),
                                latest.bandwidthLimitKbps(), delayCount, totalDecisions),
                        usagePct,
                        latest.bandwidthLimitKbps(),
                        delayCount,
                        dropCount,
                        totalDecisions);
            }

            if (tier == Tier.STANDARD) {
                return new DiagnosticReport(
                        Cause.FUP_STANDARD,
                        String.format(
                                "FUP quota exceeded (%.1f%%). App '%s' is in the STANDARD tier "
                              + "and is being throttled to %d Kbps. "
                              + "%d/%d recent packets received a DELAY verdict.",
                                usagePct, latest.appType().getDisplayName(),
                                latest.bandwidthLimitKbps(), delayCount, totalDecisions),
                        usagePct,
                        latest.bandwidthLimitKbps(),
                        delayCount,
                        dropCount,
                        totalDecisions);
            }
        }

        // --- Priority 3: ESSENTIAL traffic protected during throttle ---
        if (fupState == FupState.THROTTLE
                && latest.reasonCode() == ReasonCode.ESSENTIAL_TRAFFIC_PROTECTED) {
            return new DiagnosticReport(
                    Cause.ESSENTIAL_PROTECTED,
                    String.format(
                            "Subscriber is FUP-throttled (%.1f%%) but app '%s' is in the ESSENTIAL tier "
                          + "and is forwarded at full speed by policy. "
                          + "Other non-essential apps on this plan will be throttled.",
                            usagePct, latest.appType().getDisplayName()),
                    usagePct,
                    -1L,
                    delayCount,
                    dropCount,
                    totalDecisions);
        }

        // --- Priority 4: FUP WARNING (>80% but not yet throttled) ---
        if (fupState == FupState.WARNING) {
            return new DiagnosticReport(
                    Cause.FUP_WARNING,
                    String.format(
                            "Subscriber has used %.1f%% of their daily quota. "
                          + "No throttling yet, but ASIT rate limiting will activate at 100%%. "
                          + "Consider reducing usage of ENTERTAINMENT-tier apps to avoid throttling.",
                            usagePct),
                    usagePct,
                    -1L,
                    delayCount,
                    dropCount,
                    totalDecisions);
        }

        // --- Priority 5: Healthy ---
        // NOTE: A NETWORK_CONGESTION cause was considered here but deferred.
        // DPIStats.throttledPackets and hardDroppedPackets are FlowGate FUP/ASIT policy
        // outcomes — they are not evidence of physical network congestion.
        // True congestion detection would require queue-depth telemetry or packet-loss
        // counters sourced outside the policy engine. That instrumentation does not
        // currently exist in this system.
        return DiagnosticReport.healthy(
                String.format("Subscriber is operating normally (%.1f%% quota used). "
                            + "No throttling or hard-drop detected.", usagePct));
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private static long countVerdict(List<PolicyDecision> decisions, PolicyVerdict verdict) {
        return decisions.stream()
                .filter(d -> d.verdict() == verdict)
                .count();
    }

    // ── Root-cause classification ─────────────────────────────────────────────

    /**
     * The classified root cause of a subscriber's perceived degradation.
     */
    public enum Cause {
        /** All traffic is being dropped — subscriber exceeded 2× quota. */
        HARD_DROP,
        /** FUP quota exceeded; ENTERTAINMENT-tier app throttled (e.g. YouTube, Netflix). */
        FUP_ENTERTAINMENT,
        /** FUP quota exceeded; STANDARD-tier app throttled (e.g. GitHub, Zoom). */
        FUP_STANDARD,
        /** Quota usage between 80–100%; no throttle yet but approaching limit. */
        FUP_WARNING,
        /** App is ESSENTIAL-tier and is protected even during FUP throttle. */
        ESSENTIAL_PROTECTED,
        /**
         * Reserved for future use. Would indicate elevated physical-network drop rate
         * unrelated to FUP/ASIT policy. Not currently emitted — DPIStats does not
         * expose a genuine network-level congestion signal.
         */
        NETWORK_CONGESTION,
        /** No recent traffic data. */
        IDLE,
        /** No issue detected. */
        HEALTHY
    }

    // ── Report ────────────────────────────────────────────────────────────────

    /**
     * Structured output of the diagnostic engine.
     *
     * @param cause              Classified root cause.
     * @param message            Human-readable explanation suitable for a dashboard or ISP support ticket.
     * @param quotaUsagePct      Subscriber's quota usage at diagnosis time (0 if unlimited).
     * @param effectiveKbps      Active bandwidth limit in Kbps (-1 if none).
     * @param delayedPackets     Number of DELAY verdicts in the sample window.
     * @param droppedPackets     Number of DROP verdicts (or global drops if congestion).
     * @param sampledPackets     Total packets in the analysis window.
     */
    public record DiagnosticReport(
            Cause  cause,
            String message,
            double quotaUsagePct,
            long   effectiveKbps,
            long   delayedPackets,
            long   droppedPackets,
            long   sampledPackets
    ) {
        /** Returns true when no degradation is detected. */
        public boolean isHealthy() {
            return cause == Cause.HEALTHY;
        }

        /** Formats the report for terminal display. */
        public String toDisplayString() {
            return String.format(
                    "[Diagnostic] Cause: %-20s | Usage: %5.1f%% | Limit: %s | "
                  + "Delayed: %d | Dropped: %d | Sampled: %d%n"
                  + "             %s",
                    cause,
                    quotaUsagePct,
                    effectiveKbps < 0 ? "unlimited" : effectiveKbps + " Kbps",
                    delayedPackets,
                    droppedPackets,
                    sampledPackets,
                    message);
        }

        /** Convenience factory for a healthy (no-issue) report. */
        static DiagnosticReport healthy(String message) {
            return new DiagnosticReport(Cause.HEALTHY, message, 0.0, -1L, 0L, 0L, 0L);
        }
    }
}
