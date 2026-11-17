package com.flowgate.shaping;

import com.flowgate.shaping.TokenBucket.Outcome;
import com.flowgate.shaping.TokenBucket.Result;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class TokenBucketTest {

    // 64 Kbps = 8,000 bytes per second, so the bucket holds 8,000 bytes.
    private static final long KBPS_64 = 64L;

    @Test
    void starts_full() {
        TokenBucket bucket = new TokenBucket(KBPS_64, 0L);

        assertEquals(8000L, bucket.getCapacityBytes());
        assertEquals(8000L, bucket.getBytesPerSecond());
        assertEquals(8000L, bucket.getCurrentTokens());
        assertEquals(100, bucket.getFillPercent());
        assertEquals(TokenBucket.DEFAULT_MAX_DELAY_USEC, bucket.getMaxDelayUsec());
    }

    @Test
    void sends_now_when_enough_tokens() {
        TokenBucket bucket = new TokenBucket(KBPS_64, 0L);

        Result r = bucket.admit(1000, 0L);

        assertEquals(Outcome.SEND_NOW, r.outcome());
        assertEquals(0L, r.delayUsec());
        assertEquals(7000L, bucket.getCurrentTokens());
    }

    @Test
    void delays_packet_when_bucket_is_empty() {
        TokenBucket bucket = new TokenBucket(KBPS_64, 0L);
        bucket.admit(8000, 0L); // empty the bucket

        Result r = bucket.admit(1000, 0L);

        // 1,000 bytes at 8,000 bytes/s = 125 ms
        assertEquals(Outcome.DELAY, r.outcome());
        assertEquals(125_000L, r.delayUsec());
        assertEquals(-1000L, bucket.getCurrentTokens()); // 1,000 bytes waiting
    }

    @Test
    void waiting_packets_queue_behind_each_other() {
        TokenBucket bucket = new TokenBucket(KBPS_64, 0L);
        bucket.admit(8000, 0L);

        Result first  = bucket.admit(1000, 0L);
        Result second = bucket.admit(1000, 0L);

        // The second packet waits behind the first one
        assertEquals(125_000L, first.delayUsec());
        assertEquals(250_000L, second.delayUsec());
    }

    @Test
    void drops_when_wait_would_exceed_queue_limit_and_gives_tokens_back() {
        TokenBucket bucket = new TokenBucket(KBPS_64, 0L); // 500 ms limit
        bucket.admit(8000, 0L);

        Result fits = bucket.admit(4000, 0L); // exactly 500 ms
        assertEquals(Outcome.DELAY, fits.outcome());
        assertEquals(500_000L, fits.delayUsec());

        Result tooLong = bucket.admit(1, 0L);
        assertEquals(Outcome.QUEUE_FULL, tooLong.outcome());
        assertEquals(-4000L, bucket.getCurrentTokens()); // the dropped byte was refunded
    }

    @Test
    void refills_with_time_but_never_above_capacity() {
        TokenBucket bucket = new TokenBucket(KBPS_64, 0L);
        bucket.admit(8000, 0L);

        bucket.admit(0, 500_000L); // half a second later
        assertEquals(4000L, bucket.getCurrentTokens());

        bucket.admit(0, 10_000_000L); // much later
        assertEquals(8000L, bucket.getCurrentTokens());
    }

    @Test
    void small_gaps_between_packets_still_refill() {
        // A packet every 50 microseconds earns only 0.4 bytes each time.
        // Those fractions must add up instead of being rounded away.
        TokenBucket bucket = new TokenBucket(KBPS_64, 0L);
        bucket.admit(8000, 0L);

        for (long t = 50; t <= 1_000_000L; t += 50) {
            bucket.admit(0, t);
        }

        assertEquals(8000L, bucket.getCurrentTokens()); // one full second of refill
    }

    @Test
    void earlier_timestamp_does_not_add_tokens() {
        TokenBucket bucket = new TokenBucket(KBPS_64, 1_000_000L);
        bucket.admit(8000, 1_000_000L);

        bucket.admit(0, 500_000L); // timestamp goes backwards

        assertEquals(0L, bucket.getCurrentTokens());
    }

    @Test
    void output_rate_stays_at_the_limit_when_input_is_faster() {
        // 1 Mbps input (1,500-byte packet every 12 ms) throttled to 64 Kbps, for 60 seconds.
        TokenBucket bucket = new TokenBucket(KBPS_64, 0L);
        long durationUsec = 60_000_000L;
        long windowStart  = 30_000_000L; // measure after the start-up burst
        long bytesOutInWindow = 0;
        long maxDelay = 0;
        int dropped = 0;

        for (long ts = 0; ts < durationUsec; ts += 12_000L) {
            Result r = bucket.admit(1500, ts);
            if (r.outcome() == Outcome.QUEUE_FULL) {
                dropped++;
                continue;
            }
            long leavesAt = ts + r.delayUsec();
            maxDelay = Math.max(maxDelay, r.delayUsec());
            if (leavesAt >= windowStart && leavesAt < durationUsec) {
                bytesOutInWindow += 1500;
            }
        }

        double outputKbps = bytesOutInWindow * 8.0 / 1000.0 / 30.0;
        assertEquals(64.0, outputKbps, 64.0 * 0.02, "output should be 64 Kbps (within 2%)");
        assertTrue(maxDelay <= TokenBucket.DEFAULT_MAX_DELAY_USEC, "no packet waits longer than 500 ms");
        assertTrue(dropped > 0, "the excess traffic is dropped");
    }

    @Test
    void traffic_under_the_limit_is_not_delayed() {
        // 30 Kbps input against a 64 Kbps limit
        TokenBucket bucket = new TokenBucket(KBPS_64, 0L);

        for (long ts = 0; ts < 60_000_000L; ts += 400_000L) {
            assertEquals(Outcome.SEND_NOW, bucket.admit(1500, ts).outcome());
        }
    }

    @Test
    void invalid_inputs_throw() {
        assertThrows(IllegalArgumentException.class, () -> new TokenBucket(0L, 0L));
        assertThrows(IllegalArgumentException.class, () -> new TokenBucket(-10L, 0L));
        assertThrows(IllegalArgumentException.class, () -> new TokenBucket(64L, 0L, -1L));

        TokenBucket bucket = new TokenBucket(64L, 0L);
        assertThrows(IllegalArgumentException.class, () -> bucket.admit(-50, 0L));
    }
}
