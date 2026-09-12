package com.flowgate.shaping;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

class TokenBucketTest {

    @Test
    void initial_state_is_full() {
        // 64 Kbps = 8,000 bytes per second
        TokenBucket bucket = new TokenBucket(64L, 1000L);
        assertEquals(8000L, bucket.getCapacityBytes());
        assertEquals(8000L, bucket.getCurrentTokens());
        assertEquals(8000L, bucket.getBytesPerSecond());
        assertEquals(100, bucket.getFillPercent());
    }

    @Test
    void tryConsume_allows_packet_when_tokens_exist() {
        // 64 Kbps = 8,000 bytes/sec burst capacity
        TokenBucket bucket = new TokenBucket(64L, 1000L);
        
        // Consume a 1000 byte packet at the exact same timestamp (no refill yet)
        boolean allowed = bucket.tryConsume(1000, 1000L);
        
        assertTrue(allowed);
        assertEquals(7000L, bucket.getCurrentTokens());
    }

    @Test
    void tryConsume_rejects_packet_when_empty() {
        TokenBucket bucket = new TokenBucket(64L, 1000L);
        assertTrue(bucket.tryConsume(8000, 1000L));
        assertEquals(0L, bucket.getCurrentTokens());
        assertFalse(bucket.tryConsume(1000, 1000L));
    }

    @Test
    void invalid_inputs_throw_exceptions() {
        assertThrows(IllegalArgumentException.class, () -> new TokenBucket(-10L, 0L));
        assertThrows(IllegalArgumentException.class, () -> new TokenBucket(0L, 0L));
        
        TokenBucket bucket = new TokenBucket(64L, 0L);
        assertThrows(IllegalArgumentException.class, () -> bucket.tryConsume(-50, 0L));
    }

    @Test
    void calculateDelay_returns_correct_microseconds_based_on_deficit() {
        // 64 Kbps = 8,000 bytes/sec
        TokenBucket bucket = new TokenBucket(64L, 0L);
        
        // Initially full (8000 tokens). Packet size 9000. Deficit = 1000.
        // Delay for 1000 byte deficit:
        // (1000 / 8000) * 1,000,000 = 125,000 microseconds
        long delayUsec = bucket.calculateDelayUsec(9000);
        assertEquals(125_000L, delayUsec);
        
        // If packet fits completely, delay is 0
        assertEquals(0L, bucket.calculateDelayUsec(5000));
        
        // Empty the bucket entirely
        bucket.tryConsume(8000, 0L); 
        
        // Now bucket is empty (0 tokens). Packet size 1000. Deficit = 1000.
        assertEquals(125_000L, bucket.calculateDelayUsec(1000));
    }

    @Test
    void tryConsume_thread_safety_under_concurrent_load() throws InterruptedException {
        // 80,000 bytes capacity (simulating 640 Kbps)
        TokenBucket bucket = new TokenBucket(640L, 0L);
        
        int numThreads = 10;
        int packetsPerThread = 100;
        int packetSize = 50; // Total consumed: 10 * 100 * 50 = 50,000 bytes
        
        ExecutorService executor = Executors.newFixedThreadPool(numThreads);
        CountDownLatch latch = new CountDownLatch(numThreads);
        AtomicInteger successCount = new AtomicInteger(0);
        
        for (int i = 0; i < numThreads; i++) {
            executor.submit(() -> {
                for (int p = 0; p < packetsPerThread; p++) {
                    // All threads hit the bucket at the same timestamp (simulating burst)
                    if (bucket.tryConsume(packetSize, 0L)) {
                        successCount.incrementAndGet();
                    }
                }
                latch.countDown();
            });
        }
        
        latch.await(5, TimeUnit.SECONDS);
        executor.shutdown();
        
        // All packets should have been allowed since 50k < 80k capacity
        assertEquals(1000, successCount.get());
        
        // Bucket should have exactly 30,000 tokens left (80,000 - 50,000)
        assertEquals(30000L, bucket.getCurrentTokens());
    }
}
