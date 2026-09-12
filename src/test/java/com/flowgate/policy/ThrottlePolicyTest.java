package com.flowgate.policy;

import com.packetanalyzer.types.AppType;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ThrottlePolicyTest {

    @Test
    void defaults_whatsapp_is_essential() {
        ThrottlePolicy policy = ThrottlePolicy.defaults();
        assertEquals(ThrottlePolicy.Tier.ESSENTIAL, policy.getTier(AppType.WHATSAPP));
    }

    @Test
    void defaults_youtube_is_entertainment() {
        ThrottlePolicy policy = ThrottlePolicy.defaults();
        assertEquals(ThrottlePolicy.Tier.ENTERTAINMENT, policy.getTier(AppType.YOUTUBE));
    }

    @Test
    void defaults_github_is_standard() {
        ThrottlePolicy policy = ThrottlePolicy.defaults();
        assertEquals(ThrottlePolicy.Tier.STANDARD, policy.getTier(AppType.GITHUB));
    }

    @Test
    void defaults_unknown_app_falls_back_to_entertainment() {
        ThrottlePolicy policy = ThrottlePolicy.defaults();
        // UNKNOWN app type should default to ENTERTAINMENT
        assertEquals(ThrottlePolicy.Tier.ENTERTAINMENT, policy.getTier(AppType.UNKNOWN));
    }

    @Test
    void defaults_essential_bandwidth_is_unlimited() {
        ThrottlePolicy policy = ThrottlePolicy.defaults();
        assertEquals(-1L, policy.getBandwidthLimitKbps(ThrottlePolicy.Tier.ESSENTIAL));
    }

    @Test
    void defaults_standard_bandwidth_is_256kbps() {
        ThrottlePolicy policy = ThrottlePolicy.defaults();
        assertEquals(256L, policy.getBandwidthLimitKbps(ThrottlePolicy.Tier.STANDARD));
    }

    @Test
    void defaults_entertainment_bandwidth_is_64kbps() {
        ThrottlePolicy policy = ThrottlePolicy.defaults();
        assertEquals(64L, policy.getBandwidthLimitKbps(ThrottlePolicy.Tier.ENTERTAINMENT));
    }

    @Test
    void loadFromFile_reads_config_correctly() throws Exception {
        // Load the real config file from the project
        ThrottlePolicy policy = ThrottlePolicy.loadFromFile("config/throttle-policy.txt");
        assertEquals(ThrottlePolicy.Tier.ESSENTIAL,     policy.getTier(AppType.WHATSAPP));
        assertEquals(ThrottlePolicy.Tier.ENTERTAINMENT, policy.getTier(AppType.NETFLIX));
        assertEquals(ThrottlePolicy.Tier.STANDARD,      policy.getTier(AppType.GOOGLE));
        assertEquals(64L,  policy.getBandwidthLimitKbps(ThrottlePolicy.Tier.ENTERTAINMENT));
        assertEquals(256L, policy.getBandwidthLimitKbps(ThrottlePolicy.Tier.STANDARD));
    }
}
