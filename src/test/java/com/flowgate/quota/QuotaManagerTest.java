package com.flowgate.quota;

import com.flowgate.policy.FupState;
import com.flowgate.policy.PolicyDecision;
import com.flowgate.policy.PolicyVerdict;
import com.flowgate.policy.ReasonCode;
import com.flowgate.policy.ThrottlePolicy;
import com.packetanalyzer.types.AppType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class QuotaManagerTest {

    private QuotaManager manager;
    private final int TEST_IP = 12345;
    
    // We will use 1000 bytes for basic testing
    private final long ONE_GB = Plan.BYTES_PER_GB;

    @BeforeEach
    void setUp() throws Exception {
        // Load the real configs from test directory (or real config dir since we're in root)
        SubscriberRegistry registry = SubscriberRegistry.loadFromFile("config/subscribers.txt");
        ThrottlePolicy policy = ThrottlePolicy.loadFromFile("config/throttle-policy.txt");
        manager = new QuotaManager(registry, policy);
    }

    @Test
    void normal_traffic_is_forwarded() {
        // 192.168.1.22 is a Basic plan in subscribers.txt
        int ip = ipToInt(192, 168, 1, 22);
        
        PolicyDecision decision = manager.evaluate(ip, AppType.GOOGLE, 1000, 1000L);
        
        assertEquals(PolicyVerdict.FORWARD, decision.verdict());
        assertEquals(FupState.NORMAL, decision.fupState());
        assertEquals(ReasonCode.NORMAL_OPERATION, decision.reasonCode());
        assertEquals(1000L, decision.usageBytes());
    }

    @Test
    void premium_plan_is_always_normal() {
        // 192.168.1.10 is Premium in subscribers.txt (unlimited)
        int ip = ipToInt(192, 168, 1, 10);
        
        // Inject 5000 GB of usage
        manager.injectUsage(ip, 5000L * ONE_GB);
        
        PolicyDecision decision = manager.evaluate(ip, AppType.YOUTUBE, 1000, 1000L);
        
        assertEquals(PolicyVerdict.FORWARD, decision.verdict());
        assertEquals(FupState.NORMAL, decision.fupState());
        assertEquals(0.0, decision.usagePct()); // Unlimited pct is 0.0
    }

    @Test
    void exceeding_80_percent_triggers_warning_but_forwards() {
        int ip = ipToInt(192, 168, 1, 22); // Basic (1.5 GB limit)
        
        // Inject 1.3 GB (approx 86%)
        long injectedUsage = (long) (1.3 * ONE_GB);
        manager.injectUsage(ip, injectedUsage);
        
        PolicyDecision decision = manager.evaluate(ip, AppType.GOOGLE, 1000, 1000L);
        
        assertEquals(FupState.WARNING, decision.fupState());
        assertEquals(PolicyVerdict.FORWARD, decision.verdict());
        assertEquals(ReasonCode.FUP_WARNING, decision.reasonCode());
    }

    @Test
    void exceeding_quota_throttles_entertainment_apps() {
        int ip = ipToInt(192, 168, 1, 22); // Basic
        
        // Inject 1.6 GB (over 1.5 GB limit -> THROTTLE state)
        manager.injectUsage(ip, (long) (1.6 * ONE_GB));
        
        // Burst 1: TokenBucket starts full, so the first few packets are allowed
        PolicyDecision burst = manager.evaluate(ip, AppType.YOUTUBE, 8000, 1000L);
        assertEquals(FupState.THROTTLE, burst.fupState());
        assertEquals(PolicyVerdict.FORWARD, burst.verdict()); // Still tokens left
        assertEquals(ReasonCode.FUP_QUOTA_EXCEEDED, burst.reasonCode());
        
        // Next packet at exact same timestamp (no token refill) should be DELAYED
        PolicyDecision delayed = manager.evaluate(ip, AppType.YOUTUBE, 1000, 1000L);
        assertEquals(PolicyVerdict.DELAY, delayed.verdict());
        assertTrue(delayed.simulatedDelayUsec() > 0);
        assertEquals(64L, delayed.bandwidthLimitKbps()); // YOUTUBE limit
    }

    @Test
    void exceeding_quota_protects_essential_apps() {
        int ip = ipToInt(192, 168, 1, 22); // Basic
        manager.injectUsage(ip, (long) (1.6 * ONE_GB)); // In THROTTLE state
        
        // WHATSAPP is Essential, so it shouldn't hit the token bucket at all
        PolicyDecision decision = manager.evaluate(ip, AppType.WHATSAPP, 50000, 1000L);
        
        assertEquals(FupState.THROTTLE, decision.fupState());
        assertEquals(PolicyVerdict.FORWARD, decision.verdict());
        assertEquals(ReasonCode.ESSENTIAL_TRAFFIC_PROTECTED, decision.reasonCode());
    }

    @Test
    void exceeding_quota_throttles_standard_apps() {
        int ip = ipToInt(192, 168, 1, 22); // Basic
        manager.injectUsage(ip, (long) (1.6 * ONE_GB)); // In THROTTLE state
        
        // GITHUB maps to STANDARD tier
        // Drain the burst capacity first (256 Kbps = 32,000 bytes/sec burst)
        manager.evaluate(ip, AppType.GITHUB, 32000, 1000L);
        
        // Next packet at the exact same timestamp must be delayed
        PolicyDecision delayed = manager.evaluate(ip, AppType.GITHUB, 1000, 1000L);
        
        assertEquals(FupState.THROTTLE, delayed.fupState());
        assertEquals(PolicyVerdict.DELAY, delayed.verdict());
        assertEquals(256L, delayed.bandwidthLimitKbps()); // Verifies it correctly applied STANDARD limit
        assertTrue(delayed.simulatedDelayUsec() > 0);
    }

    @Test
    void exceeding_double_quota_triggers_hard_drop() {
        int ip = ipToInt(192, 168, 1, 22); // Basic (1.5 GB limit, drops at 3.0 GB)
        
        // Inject 3.1 GB
        manager.injectUsage(ip, (long) (3.1 * ONE_GB));
        
        PolicyDecision decision = manager.evaluate(ip, AppType.GOOGLE, 1000, 1000L);
        
        assertEquals(FupState.HARD_DROP, decision.fupState());
        assertEquals(PolicyVerdict.DROP, decision.verdict());
        assertEquals(ReasonCode.HARD_DROP_THRESHOLD, decision.reasonCode());
    }

    @Test
    void off_peak_traffic_does_not_increment_usage() {
        int ip = ipToInt(192, 168, 1, 22); // Basic (Off peak is 2AM - 6AM)
        manager.injectUsage(ip, 1000L); // Start with 1000 bytes
        
        // Fake a timestamp that equals 03:00:00 UTC
        // 3 hours = 10800 seconds
        long tsUsec = 10800L * 1_000_000L;
        
        PolicyDecision decision = manager.evaluate(ip, AppType.GOOGLE, 5000, tsUsec);
        
        assertEquals(PolicyVerdict.FORWARD, decision.verdict());
        assertEquals(ReasonCode.OFF_PEAK_TRAFFIC, decision.reasonCode());
        
        // Usage should still be exactly 1000L (the 5000 was not added)
        assertEquals(1000L, decision.usageBytes());
    }

    // Helper: convert 4 octets to a 32-bit int
    private int ipToInt(int a, int b, int c, int d) {
        return (a << 24) | (b << 16) | (c << 8) | d;
    }
}
