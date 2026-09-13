package com.flowgate.quota;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class SubscriberRegistryTest {

    @Test
    void loadFromFile_loads_four_subscribers() throws Exception {
        SubscriberRegistry reg = SubscriberRegistry.loadFromFile("config/subscribers.txt");
        assertEquals(4, reg.getSubscriberCount());
    }

    @Test
    void loadFromFile_premium_ip_gets_premium_plan() throws Exception {
        SubscriberRegistry reg = SubscriberRegistry.loadFromFile("config/subscribers.txt");
        // 192.168.1.10 = Premium
        int ip = ipToInt(192, 168, 1, 10);
        assertEquals("Premium", reg.getPlan(ip).getName());
    }

    @Test
    void loadFromFile_basic_ip_gets_basic_plan() throws Exception {
        SubscriberRegistry reg = SubscriberRegistry.loadFromFile("config/subscribers.txt");
        int ip = ipToInt(192, 168, 1, 22);
        assertEquals("Basic", reg.getPlan(ip).getName());
    }

    @Test
    void unregistered_ip_gets_default_plan() throws Exception {
        SubscriberRegistry reg = SubscriberRegistry.loadFromFile("config/subscribers.txt");
        int unknownIp = ipToInt(10, 0, 0, 99);
        // DEFAULT_PLAN=Basic in config
        assertEquals("Basic", reg.getPlan(unknownIp).getName());
    }

    @Test
    void premium_plan_is_unlimited() {
        Plan p = Plan.premium();
        assertTrue(p.isUnlimited());
    }

    @Test
    void basic_plan_has_correct_quota() {
        Plan p = Plan.basic();
        long expectedBytes = (long)(1.5 * Plan.BYTES_PER_GB);
        assertEquals(expectedBytes, p.getDailyQuotaBytes());
    }

    @Test
    void basic_plan_off_peak_hours_2_to_6() {
        Plan p = Plan.basic();
        assertTrue(p.isOffPeak(2));
        assertTrue(p.isOffPeak(3));
        assertTrue(p.isOffPeak(5));
        assertFalse(p.isOffPeak(6));  // End is exclusive
        assertFalse(p.isOffPeak(12));
        assertFalse(p.isOffPeak(23));
    }

    @Test
    void premium_plan_never_off_peak() {
        Plan p = Plan.premium();
        // Start == End == 0, so isOffPeak always returns false
        assertFalse(p.isOffPeak(3));
        assertFalse(p.isOffPeak(0));
    }

    // Helper: convert 4 octets to a 32-bit int (Little Endian to match x86 memcpy)
    private int ipToInt(int a, int b, int c, int d) {
        return (a & 0xFF) | ((b & 0xFF) << 8) | ((c & 0xFF) << 16) | ((d & 0xFF) << 24);
    }
}
