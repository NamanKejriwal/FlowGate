package com.flowgate.diagnostics;

import com.flowgate.diagnostics.ConnectionHealthAnalyzer.Cause;
import com.flowgate.diagnostics.ConnectionHealthAnalyzer.DiagnosticReport;
import com.flowgate.policy.*;
import com.packetanalyzer.types.AppType;
import com.packetanalyzer.types.DPIStats;

import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the Phase 6 Diagnostic Engine.
 *
 * Strategy:
 *  - Build a synthetic PolicyDecision using the PolicyDecision record factories.
 *  - Optionally inject specific DPIStats values.
 *  - Call ConnectionHealthAnalyzer.analyse() and assert the Cause.
 *
 * We do not depend on a running pipeline, a PCAP file, or the QuotaManager.
 * All state is constructed inline.
 */
class ConnectionHealthAnalyzerTest {

    // ── helpers ───────────────────────────────────────────────────────────────

    private static final int DEMO_IP   = 0xC0A80164; // arbitrary test IP
    private static final long NO_QUOTA = -1L;

    /** Build a FORWARD decision for a given state */
    private PolicyDecision forward(FupState state, AppType app, ThrottlePolicy.Tier tier,
                                   double usagePct, long usageBytes, long quotaBytes,
                                   ReasonCode rc) {
        return PolicyDecision.forward(
                DEMO_IP, "Demo", app, tier,
                usageBytes, quotaBytes, usagePct, state, rc,
                "test", System.currentTimeMillis() / 1000L);
    }

    /** Build a DELAY decision for a given state */
    private PolicyDecision delay(FupState state, AppType app, ThrottlePolicy.Tier tier,
                                 double usagePct, long usageBytes, long quotaBytes,
                                 long bandwidthKbps, long delayUsec) {
        return PolicyDecision.delay(
                DEMO_IP, "Demo", app, tier,
                usageBytes, quotaBytes, usagePct, state,
                bandwidthKbps, delayUsec,
                ReasonCode.FUP_QUOTA_EXCEEDED, "test",
                System.currentTimeMillis() / 1000L);
    }

    /** Build a DROP (hard-drop) decision */
    private PolicyDecision drop(AppType app, ThrottlePolicy.Tier tier,
                                double usagePct, long usageBytes, long quotaBytes) {
        return PolicyDecision.drop(
                DEMO_IP, "Demo", app, tier,
                usageBytes, quotaBytes, usagePct,
                ReasonCode.HARD_DROP_THRESHOLD, "test",
                System.currentTimeMillis() / 1000L);
    }

    private DPIStats cleanStats() {
        return new DPIStats(); // all counters zero
    }

    // ── 1. Empty / null input ─────────────────────────────────────────────────

    @Test
    void null_decisions_returns_healthy() {
        DiagnosticReport r = ConnectionHealthAnalyzer.analyse(null, cleanStats());
        assertEquals(Cause.HEALTHY, r.cause());
        assertTrue(r.isHealthy());
    }

    @Test
    void empty_decisions_returns_healthy() {
        DiagnosticReport r = ConnectionHealthAnalyzer.analyse(Collections.emptyList(), cleanStats());
        assertEquals(Cause.HEALTHY, r.cause());
    }

    // ── 2. HARD_DROP ──────────────────────────────────────────────────────────

    @Test
    void hard_drop_fup_state_returns_hard_drop_cause() {
        PolicyDecision d = drop(AppType.YOUTUBE, ThrottlePolicy.Tier.ENTERTAINMENT,
                                210.0, 4200, 2000);
        DiagnosticReport r = ConnectionHealthAnalyzer.analyse(List.of(d), cleanStats());
        assertEquals(Cause.HARD_DROP, r.cause());
        assertFalse(r.isHealthy());
        // hard-drop stats
        assertEquals(0, r.delayedPackets());  // it is a DROP, not DELAY
        assertEquals(1, r.droppedPackets());  // 1 dropped packet
    }

    // ── 3. FUP_ENTERTAINMENT ─────────────────────────────────────────────────

    @Test
    void throttle_with_delay_entertainment_tier_returns_fup_entertainment() {
        PolicyDecision d = delay(FupState.THROTTLE, AppType.YOUTUBE, ThrottlePolicy.Tier.ENTERTAINMENT,
                                 110.0, 2200, 2000, 1L, 3_200_000L);
        DiagnosticReport r = ConnectionHealthAnalyzer.analyse(List.of(d), cleanStats());
        assertEquals(Cause.FUP_ENTERTAINMENT, r.cause());
        assertEquals(1, r.delayedPackets());
        assertEquals(1L, r.effectiveKbps());
        assertTrue(r.message().contains("ENTERTAINMENT"));
    }

    // ── 4. FUP_STANDARD ──────────────────────────────────────────────────────

    @Test
    void throttle_with_delay_standard_tier_returns_fup_standard() {
        PolicyDecision d = delay(FupState.THROTTLE, AppType.GITHUB, ThrottlePolicy.Tier.STANDARD,
                                 130.0, 2600, 2000, 2L, 1_600_000L);
        DiagnosticReport r = ConnectionHealthAnalyzer.analyse(List.of(d), cleanStats());
        assertEquals(Cause.FUP_STANDARD, r.cause());
        assertEquals(2L, r.effectiveKbps());
        assertTrue(r.message().contains("STANDARD"));
    }

    // ── 5. ESSENTIAL_PROTECTED ───────────────────────────────────────────────

    @Test
    void essential_tier_forward_during_throttle_returns_essential_protected() {
        PolicyDecision d = forward(FupState.THROTTLE, AppType.TELEGRAM,
                                   ThrottlePolicy.Tier.ESSENTIAL,
                                   150.0, 3000, 2000,
                                   ReasonCode.ESSENTIAL_TRAFFIC_PROTECTED);
        DiagnosticReport r = ConnectionHealthAnalyzer.analyse(List.of(d), cleanStats());
        assertEquals(Cause.ESSENTIAL_PROTECTED, r.cause());
        assertTrue(r.message().contains("ESSENTIAL"));
    }

    // ── 6. FUP_WARNING ───────────────────────────────────────────────────────

    @Test
    void warning_state_forward_returns_fup_warning() {
        PolicyDecision d = forward(FupState.WARNING, AppType.GOOGLE,
                                   ThrottlePolicy.Tier.STANDARD,
                                   85.0, 1700, 2000,
                                   ReasonCode.FUP_WARNING);
        DiagnosticReport r = ConnectionHealthAnalyzer.analyse(List.of(d), cleanStats());
        assertEquals(Cause.FUP_WARNING, r.cause());
        assertTrue(r.message().contains("80%") || r.message().contains("100%"));
    }

    // ── 7. NETWORK_CONGESTION (deferred — not currently emitted) ────────────

    @Test
    void saturated_global_stats_does_not_produce_network_congestion_cause() {
        // NETWORK_CONGESTION is deferred: DPIStats.throttledPackets/hardDroppedPackets
        // are FUP policy outcomes, not genuine network-level congestion signals.
        // A NORMAL subscriber with saturated global stats must still return HEALTHY.
        PolicyDecision d = forward(FupState.NORMAL, AppType.GITHUB,
                                   ThrottlePolicy.Tier.STANDARD,
                                   20.0, 400, 2000,
                                   ReasonCode.NORMAL_OPERATION);

        DPIStats saturatedStats = new DPIStats();
        saturatedStats.totalPackets.set(10);
        saturatedStats.throttledPackets.set(8);
        saturatedStats.hardDroppedPackets.set(0);

        DiagnosticReport r = ConnectionHealthAnalyzer.analyse(List.of(d), saturatedStats);
        // Must NOT return NETWORK_CONGESTION — that cause is not currently emitted
        assertNotEquals(Cause.NETWORK_CONGESTION, r.cause());
        assertEquals(Cause.HEALTHY, r.cause());
    }

    @Test
    void null_global_stats_does_not_throw_and_returns_healthy_for_normal_subscriber() {
        PolicyDecision d = forward(FupState.NORMAL, AppType.GITHUB,
                                   ThrottlePolicy.Tier.STANDARD,
                                   20.0, 400, 2000,
                                   ReasonCode.NORMAL_OPERATION);
        // Passing null globalStats must be safe (API contract)
        DiagnosticReport r = ConnectionHealthAnalyzer.analyse(List.of(d), null);
        assertEquals(Cause.HEALTHY, r.cause());
    }

    // ── 8. HEALTHY ───────────────────────────────────────────────────────────

    @Test
    void normal_subscriber_with_clean_stats_returns_healthy() {
        PolicyDecision d = forward(FupState.NORMAL, AppType.GITHUB,
                                   ThrottlePolicy.Tier.STANDARD,
                                   50.0, 1000, 2000,
                                   ReasonCode.NORMAL_OPERATION);
        DiagnosticReport r = ConnectionHealthAnalyzer.analyse(List.of(d), cleanStats());
        assertEquals(Cause.HEALTHY, r.cause());
        assertTrue(r.isHealthy());
    }

    // ── 9. Priority ordering ─────────────────────────────────────────────────

    @Test
    void hard_drop_takes_priority_over_entertainment_delay_in_mixed_window() {
        // Window contains one DELAY (entertainment) and one hard-DROP
        PolicyDecision delayDecision = delay(FupState.THROTTLE, AppType.YOUTUBE,
                                             ThrottlePolicy.Tier.ENTERTAINMENT,
                                             110.0, 2200, 2000, 1L, 3_200_000L);
        PolicyDecision dropDecision  = drop(AppType.GOOGLE, ThrottlePolicy.Tier.STANDARD,
                                            210.0, 4200, 2000);

        // Latest decision (last in list) is the drop — HARD_DROP should win
        DiagnosticReport r = ConnectionHealthAnalyzer.analyse(
                List.of(delayDecision, dropDecision), cleanStats());
        assertEquals(Cause.HARD_DROP, r.cause());
    }

    // ── 10. DiagnosticReport helpers ─────────────────────────────────────────

    @Test
    void diagnostic_report_to_display_string_does_not_throw() {
        DiagnosticReport r = DiagnosticReport.healthy("all clear");
        assertNotNull(r.toDisplayString());
        assertTrue(r.toDisplayString().contains("HEALTHY"));
    }
}
