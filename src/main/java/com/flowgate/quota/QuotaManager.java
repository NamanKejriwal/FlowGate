package com.flowgate.quota;

import com.flowgate.policy.*;
import com.flowgate.shaping.TokenBucket;
import com.packetanalyzer.types.AppType;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Evaluates packets against subscriber limits and ASIT policies.
 *
 * <p>DPI may run on multiple FastPath workers, but FUP accounting is applied in
 * PCAP/reader packet order via {@link #evaluateInOrder} so cumulative usage and
 * state transitions stay deterministic.
 */
public final class QuotaManager {

    private final SubscriberRegistry registry;
    private final ThrottlePolicy throttlePolicy;

    // Tracks total bytes used per IP (Thread-safe)
    private final ConcurrentHashMap<Integer, AtomicLong> usageByIp = new ConcurrentHashMap<>();

    // Tracks token buckets per IP and per Tier. Key = "IP_TIER"
    // We separate buckets by Tier so YouTube and GitHub don't share the same bandwidth pool.
    private final ConcurrentHashMap<String, TokenBucket> buckets = new ConcurrentHashMap<>();

    /** Ensures evaluate/skip run in ascending packetId order across workers. */
    private final Object packetOrderLock = new Object();
    private int nextPacketId = 0;

    public QuotaManager(SubscriberRegistry registry, ThrottlePolicy throttlePolicy) {
        this.registry = registry;
        this.throttlePolicy = throttlePolicy;
    }

    /**
     * Same as {@link #evaluate}, but waits until all lower {@code packetId} values
     * have been evaluated or skipped. Use from FastPath workers so FUP state
     * follows PCAP order while DPI remains concurrent.
     */
    public PolicyDecision evaluateInOrder(int packetId, int ipInt, AppType appType,
                                          int packetBytes, long pcapTsUsec) {
        awaitPacketTurn(packetId);
        try {
            return evaluate(ipInt, appType, packetBytes, pcapTsUsec);
        } finally {
            advancePacketTurn();
        }
    }

    /**
     * Advances the packet-order gate without changing quota (e.g. firewall DROP
     * before FlowGate evaluation). Prevents workers from stalling on gaps.
     */
    public void skipInOrder(int packetId) {
        awaitPacketTurn(packetId);
        advancePacketTurn();
    }

    private void awaitPacketTurn(int packetId) {
        synchronized (packetOrderLock) {
            while (packetId != nextPacketId) {
                try {
                    packetOrderLock.wait(100);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException(
                            "Interrupted waiting for packet-order turn " + packetId, e);
                }
            }
        }
    }

    private void advancePacketTurn() {
        synchronized (packetOrderLock) {
            nextPacketId++;
            packetOrderLock.notifyAll();
        }
    }

    /**
     * Evaluates a packet against the subscriber's quota and current network policies.
     *
     * @param ipInt       Source IP of the packet
     * @param appType     Detected application type (e.g., YOUTUBE)
     * @param packetBytes Size of the packet payload
     * @param pcapTsUsec  The embedded PCAP timestamp in microseconds
     * @return A complete, explainable record of what to do with this packet
     */
    public PolicyDecision evaluate(int ipInt, AppType appType, int packetBytes, long pcapTsUsec) {
        Plan plan = registry.getPlan(ipInt);
        ThrottlePolicy.Tier tier = throttlePolicy.getTier(appType);
        long pcapTsSec = pcapTsUsec / 1_000_000L;

        // Determine off-peak hours.
        int hourOfDay = (int) ((pcapTsSec % 86400) / 3600);
        boolean isOffPeak = plan.isOffPeak(hourOfDay);

        // Increment usage (skip during off-peak).
        AtomicLong usageCounter = usageByIp.computeIfAbsent(ipInt, k -> new AtomicLong(0));
        long currentUsage = isOffPeak ? usageCounter.get() : usageCounter.addAndGet(packetBytes);

        // Determine FUP State.
        FupState state = calculateFupState(currentUsage, plan);
        double usagePct = plan.isUnlimited() ? 0.0 : ((double) currentUsage / plan.getDailyQuotaBytes()) * 100.0;

        // Fast Path: Off-Peak Traffic
        if (isOffPeak) {
            return PolicyDecision.forward(ipInt, plan.getName(), appType, tier, currentUsage, 
                    plan.getDailyQuotaBytes(), usagePct, state, ReasonCode.OFF_PEAK_TRAFFIC, 
                    "Free off-peak usage", pcapTsSec);
        }

        // Hard-drop limit reached -> drop packet.
        if (state == FupState.HARD_DROP) {
            return PolicyDecision.drop(ipInt, plan.getName(), appType, tier, currentUsage, 
                    plan.getDailyQuotaBytes(), usagePct, ReasonCode.HARD_DROP_THRESHOLD, 
                    "Exceeded hard drop limit (2x quota)", pcapTsSec);
        }

        // Normal or Warning states
        if (state == FupState.NORMAL || state == FupState.WARNING) {
            ReasonCode rc = (state == FupState.WARNING) ? ReasonCode.FUP_WARNING : ReasonCode.NORMAL_OPERATION;
            return PolicyDecision.forward(ipInt, plan.getName(), appType, tier, currentUsage, 
                    plan.getDailyQuotaBytes(), usagePct, state, rc, 
                    "Within daily quota", pcapTsSec);
        }

        // Essential apps bypass the throttle
        if (tier == ThrottlePolicy.Tier.ESSENTIAL) {
            return PolicyDecision.forward(ipInt, plan.getName(), appType, tier, currentUsage, 
                    plan.getDailyQuotaBytes(), usagePct, state, ReasonCode.ESSENTIAL_TRAFFIC_PROTECTED, 
                    "Essential app protected during FUP", pcapTsSec);
        }

        long bandwidthKbps = throttlePolicy.getBandwidthLimitKbps(tier);
        if (bandwidthKbps <= 0) {
            // Unlimited tier - bypass rate limiting
            return PolicyDecision.forward(ipInt, plan.getName(), appType, tier, currentUsage, 
                    plan.getDailyQuotaBytes(), usagePct, state, ReasonCode.NORMAL_OPERATION, 
                    "Tier has no bandwidth limit", pcapTsSec);
        }

        // Apply Token Bucket Rate Limiting
        String bucketKey = ipInt + "_" + tier.name();
        TokenBucket bucket = buckets.computeIfAbsent(bucketKey, 
                k -> new TokenBucket(bandwidthKbps, pcapTsUsec));

        if (bucket.tryConsume(packetBytes, pcapTsUsec)) {
            return PolicyDecision.forward(ipInt, plan.getName(), appType, tier, currentUsage, 
                    plan.getDailyQuotaBytes(), usagePct, state, ReasonCode.FUP_QUOTA_EXCEEDED, 
                    "Throttled but tokens available", pcapTsSec);
        } else {
            // Bucket empty! Packet must be delayed.
            long delayUsec = bucket.calculateDelayUsec(packetBytes);
            return PolicyDecision.delay(ipInt, plan.getName(), appType, tier, currentUsage, 
                    plan.getDailyQuotaBytes(), usagePct, state, bandwidthKbps, delayUsec, 
                    ReasonCode.FUP_QUOTA_EXCEEDED, "Delayed by ASIT Token Bucket", pcapTsSec);
        }
    }

    private FupState calculateFupState(long usage, Plan plan) {
        if (plan.isUnlimited()) return FupState.NORMAL;
        if (plan.getHardDropThresholdBytes() > 0 && usage >= plan.getHardDropThresholdBytes()) {
            return FupState.HARD_DROP;
        }
        if (usage >= plan.getThrottleThresholdBytes()) {
            return FupState.THROTTLE;
        }
        if (usage >= (plan.getThrottleThresholdBytes() * 0.8)) {
            return FupState.WARNING;
        }
        return FupState.NORMAL;
    }
    
    /** For tests only - inject a synthetic usage value. */
    public void injectUsage(int ipInt, long bytes) {
        usageByIp.put(ipInt, new AtomicLong(bytes));
    }
}
