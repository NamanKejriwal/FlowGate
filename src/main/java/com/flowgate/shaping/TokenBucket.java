package com.flowgate.shaping;

import java.util.concurrent.atomic.AtomicLong;

/**
 * A thread-safe Token Bucket rate limiter synchronized to PCAP timestamps.
 * Uses atomic CAS operations for concurrent access (not a formal lock-free proof).
 */
public final class TokenBucket {

    /** Maximum burst size: 1 second of full-speed traffic at the configured rate. */
    private static final long BURST_MULTIPLIER_USEC = 1_000_000L; // 1 second in microseconds

    private final long capacityBytes;  // Max tokens the bucket can hold (burst ceiling)
    private final long bytesPerSecond; // For delay math

    // Current token count in bytes (atomic for CAS operations)
    private final AtomicLong tokens;

    // PCAP timestamp of the last refill, in microseconds
    private final AtomicLong lastRefillTsUsec;

    /**
     * Creates a TokenBucket for the given bandwidth limit.
     *
     * @param bandwidthKbps  Target bandwidth in Kilobits per second (e.g. 64 for 64 Kbps)
     * @param initialTsUsec  The PCAP timestamp (in microseconds) when this bucket is created.
     */
    public TokenBucket(long bandwidthKbps, long initialTsUsec) {
        if (bandwidthKbps <= 0) {
            throw new IllegalArgumentException("Bandwidth limit must be > 0 Kbps");
        }
        this.bytesPerSecond    = (bandwidthKbps * 1000L) / 8L; // Kbps → bytes/sec
        this.capacityBytes     = bytesPerSecond;  // Burst = 1 full second of data
        this.tokens            = new AtomicLong(capacityBytes); // Start full
        this.lastRefillTsUsec  = new AtomicLong(initialTsUsec);
    }

    /**
     * Attempts to consume {@code packetBytes} tokens from the bucket.
     * Refills the bucket first based on elapsed PCAP time.
     *
     * <p>Uses a CAS retry loop: read current state → compute new state → atomically swap.
     *
     * @param packetBytes    Size of the incoming packet in bytes
     * @param currentTsUsec  Current PCAP timestamp in microseconds
     * @return {@code true} if the packet fits within the budget (forward it),
     *         {@code false} if the bucket is empty (delay or drop it)
     */
    public boolean tryConsume(int packetBytes, long currentTsUsec) {
        if (packetBytes < 0) {
            throw new IllegalArgumentException("Packet size cannot be negative");
        }
        if (packetBytes == 0) return true; // Empty packets (like TCP ACKs with no payload) are free

        while (true) {
            long lastRefill   = lastRefillTsUsec.get();
            long currentTokens = tokens.get();

            // Refill based on elapsed PCAP time
            long elapsedUsec   = Math.max(0, currentTsUsec - lastRefill);
            long tokensToAdd   = (elapsedUsec * bytesPerSecond) / BURST_MULTIPLIER_USEC;
            long refilled      = Math.min(capacityBytes, currentTokens + tokensToAdd);

            // Check if packet fits in budget
            long afterConsume  = refilled - packetBytes;
            if (afterConsume < 0) {
                // Not enough tokens — update timestamp without consuming
                if (tokensToAdd > 0) {
                    lastRefillTsUsec.compareAndSet(lastRefill, currentTsUsec);
                    tokens.compareAndSet(currentTokens, refilled);
                }
                return false;
            }

            // Atomically commit state
            if (lastRefillTsUsec.compareAndSet(lastRefill, currentTsUsec)) {
                if (tokens.compareAndSet(currentTokens, afterConsume)) {
                    return true; // Success
                }
                lastRefillTsUsec.set(lastRefill);
            }
        }
    }

    /**
     * Calculates how many microseconds to add to the output PCAP timestamp
     * to simulate this packet being delayed by the rate limiter.
     * 
     * Uses the token deficit to calculate exactly how long the packet must wait.
     *
     * @param packetBytes Size of the packet in bytes
     * @return Simulated delay in microseconds
     */
    public long calculateDelayUsec(int packetBytes) {
        long currentTokens = tokens.get();
        long deficit = packetBytes - currentTokens;
        
        if (deficit <= 0) return 0; // No delay needed if we have enough tokens
        
        return (deficit * BURST_MULTIPLIER_USEC) / bytesPerSecond;
    }

    /** Returns the current token count (for diagnostics/dashboard). */
    public long getCurrentTokens() { return tokens.get(); }

    /** Returns the bucket capacity in bytes. */
    public long getCapacityBytes() { return capacityBytes; }

    /** Returns the configured rate in bytes per second. */
    public long getBytesPerSecond() { return bytesPerSecond; }

    /** Returns fill percentage (0–100) for dashboard display. */
    public int getFillPercent() {
        return (int)((tokens.get() * 100L) / capacityBytes);
    }
}
