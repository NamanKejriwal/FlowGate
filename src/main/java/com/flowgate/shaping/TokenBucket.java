package com.flowgate.shaping;

/**
 * Token bucket traffic shaper that runs on PCAP time.
 *
 * <p>Picture a jar of byte-tokens. It refills at the configured speed and holds at most
 * one second's worth. Every packet pays tokens equal to its size:
 * <ul>
 *   <li><b>Enough tokens:</b> the packet is sent now.</li>
 *   <li><b>Not enough:</b> the packet still pays, so the balance goes below zero. The negative
 *       balance is the bytes already waiting in the queue. The packet is delayed until the
 *       bucket has earned that debt back.</li>
 *   <li><b>Wait would be too long:</b> if the delay would exceed the queue limit, the packet is
 *       dropped and its tokens are given back.</li>
 * </ul>
 * Because waiting packets pay up front, the output can never run faster than the configured
 * speed, however fast packets arrive.
 *
 * <p><b>Not thread-safe.</b> {@link com.flowgate.quota.QuotaManager} evaluates one packet at a
 * time in capture order, so a bucket is never used by two threads at once.
 */
public final class TokenBucket {

    /** Default queue limit: a packet may be held for at most 500 ms. */
    public static final long DEFAULT_MAX_DELAY_USEC = 500_000L;

    private static final long MICROS_PER_SECOND = 1_000_000L;

    /** What happens to a packet. */
    public enum Outcome { SEND_NOW, DELAY, QUEUE_FULL }

    /** Result for one packet: the outcome and, for {@link Outcome#DELAY}, how long to hold it. */
    public record Result(Outcome outcome, long delayUsec) {
        static final Result SEND = new Result(Outcome.SEND_NOW, 0L);
        static final Result FULL = new Result(Outcome.QUEUE_FULL, 0L);
    }

    private final long bytesPerSecond;
    private final long capacityBytes;
    private final long maxDelayUsec;

    // Tokens are stored in micro-bytes (bytes x 1,000,000), so refilling for a few
    // microseconds never rounds down to zero. A negative value means bytes are queued.
    private long microTokens;
    private long lastRefillTsUsec;

    /** Creates a full bucket with the default 500 ms queue limit. */
    public TokenBucket(long bandwidthKbps, long initialTsUsec) {
        this(bandwidthKbps, initialTsUsec, DEFAULT_MAX_DELAY_USEC);
    }

    /**
     * @param bandwidthKbps  speed limit in kilobits per second (e.g. 64)
     * @param initialTsUsec  PCAP time, in microseconds, when the bucket is created
     * @param maxDelayUsec   longest time a packet may wait before it is dropped instead
     */
    public TokenBucket(long bandwidthKbps, long initialTsUsec, long maxDelayUsec) {
        if (bandwidthKbps <= 0) {
            throw new IllegalArgumentException("Bandwidth limit must be > 0 Kbps");
        }
        if (maxDelayUsec < 0) {
            throw new IllegalArgumentException("Max delay cannot be negative");
        }
        this.bytesPerSecond   = (bandwidthKbps * 1000L) / 8L;   // Kbps -> bytes per second
        this.capacityBytes    = bytesPerSecond;                  // burst = one second of traffic
        this.maxDelayUsec     = maxDelayUsec;
        this.microTokens      = capacityBytes * MICROS_PER_SECOND; // start full
        this.lastRefillTsUsec = initialTsUsec;
    }

    /**
     * Decides what to do with one packet at the given PCAP time.
     *
     * @param packetBytes    size of the packet in bytes
     * @param currentTsUsec  PCAP timestamp of the packet in microseconds
     */
    public Result admit(int packetBytes, long currentTsUsec) {
        if (packetBytes < 0) {
            throw new IllegalArgumentException("Packet size cannot be negative");
        }
        refill(currentTsUsec);
        if (packetBytes == 0) {
            return Result.SEND;
        }

        long cost = packetBytes * MICROS_PER_SECOND;
        microTokens -= cost;                      // pay first, even if the packet has to wait
        if (microTokens >= 0) {
            return Result.SEND;
        }

        // Time for the bucket to earn the debt back: micro-bytes / (bytes per second) = microseconds.
        long delayUsec = Math.ceilDiv(-microTokens, bytesPerSecond);
        if (delayUsec > maxDelayUsec) {
            microTokens += cost;                  // queue full: drop and give the tokens back
            return Result.FULL;
        }
        return new Result(Outcome.DELAY, delayUsec);
    }

    /** Adds the tokens earned since the last packet, never going above a full bucket. */
    private void refill(long currentTsUsec) {
        if (currentTsUsec <= lastRefillTsUsec) {
            return;                               // same or earlier timestamp: no time has passed
        }
        long elapsedUsec = currentTsUsec - lastRefillTsUsec;
        lastRefillTsUsec = currentTsUsec;

        long full = capacityBytes * MICROS_PER_SECOND;
        long missing = full - microTokens;
        if (elapsedUsec >= Math.ceilDiv(missing, bytesPerSecond)) {
            microTokens = full;                   // enough time passed to fill the bucket
        } else {
            microTokens += elapsedUsec * bytesPerSecond;
        }
    }

    /** Current balance in bytes. Negative means that many bytes are waiting in the queue. */
    public long getCurrentTokens() { return microTokens / MICROS_PER_SECOND; }

    /** Bucket size in bytes (one second of traffic). */
    public long getCapacityBytes() { return capacityBytes; }

    /** Configured speed in bytes per second. */
    public long getBytesPerSecond() { return bytesPerSecond; }

    /** Longest time a packet may wait before it is dropped. */
    public long getMaxDelayUsec() { return maxDelayUsec; }

    /** Fill level from 0 to 100, for reports. 0 also covers a negative balance. */
    public int getFillPercent() {
        return (int) Math.max(0, (microTokens * 100L) / (capacityBytes * MICROS_PER_SECOND));
    }
}
