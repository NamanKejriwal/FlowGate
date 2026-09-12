package com.flowgate.quota;

import com.flowgate.policy.*;
import com.flowgate.shaping.TokenBucket;
import com.packetanalyzer.types.AppType;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The central brain of FlowGate.
 * Connects Subscriber limits, ASIT Throttle policies, and Token Buckets
 * to produce a definitive PolicyDecision for every incoming packet.
 */
public final class QuotaManager {

    private final SubscriberRegistry registry;
    private final ThrottlePolicy throttlePolicy;

    // Tracks total bytes used per IP (Thread-safe)
    private final ConcurrentHashMap<Integer, AtomicLong> usageByIp = new ConcurrentHashMap<>();

    // Tracks token buckets per IP and per Tier. Key = "IP_TIER"
    // We separate buckets by Tier so YouTube and GitHub don't share the same bandwidth pool.
    private final ConcurrentHashMap<String, TokenBucket> buckets = new ConcurrentHashMap<>();

    public QuotaManager(SubscriberRegistry registry, ThrottlePolicy throttlePolicy) {
        this.registry = registry;
        this.throttlePolicy = throttlePolicy;
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

        // 1. Off-Peak calculation (using simple UTC hour extraction from epoch timestamp)
        int hourOfDay = (int) ((pcapTsSec % 86400) / 3600);
        boolean isOffPeak = plan.isOffPeak(hourOfDay);

        // 2. Increment usage (if not off-peak)
        AtomicLong usageCounter = usageByIp.computeIfAbsent(ipInt, k -> new AtomicLong(0));
        long currentUsage = isOffPeak ? usageCounter.get() : usageCounter.addAndGet(packetBytes);

        // 3. Determine FUP State
        FupState state = calculateFupState(currentUsage, plan);
        double usagePct = plan.isUnlimited() ? 0.0 : ((double) currentUsage / plan.getDailyQuotaBytes()) * 100.0;

        // 4. Fast Path: Off-Peak Traffic
        if (isOffPeak) {
            return PolicyDecision.forward(ipInt, plan.getName(), appType, tier, currentUsage, 
                    plan.getDailyQuotaBytes(), usagePct, state, ReasonCode.OFF_PEAK_TRAFFIC, 
                    "Free off-peak usage", pcapTsSec);
        }

        // 5. Fast Path: Hard Drop limit reached
        if (state == FupState.HARD_DROP) {
            return PolicyDecision.drop(ipInt, plan.getName(), appType, tier, currentUsage, 
                    plan.getDailyQuotaBytes(), usagePct, ReasonCode.HARD_DROP_THRESHOLD, 
                    "Exceeded hard drop limit (2x quota)", pcapTsSec);
        }

        // 6. Fast Path: Normal or Warning states (below throttle threshold)
        if (state == FupState.NORMAL || state == FupState.WARNING) {
            ReasonCode rc = (state == FupState.WARNING) ? ReasonCode.FUP_WARNING : ReasonCode.NORMAL_OPERATION;
            return PolicyDecision.forward(ipInt, plan.getName(), appType, tier, currentUsage, 
                    plan.getDailyQuotaBytes(), usagePct, state, rc, 
                    "Within daily quota", pcapTsSec);
        }

        // ---------------------------------------------------------
        // 7. THROTTLE STATE LOGIC (Quota exceeded)
        // ---------------------------------------------------------

        // Essential apps bypass the throttle
        if (tier == ThrottlePolicy.Tier.ESSENTIAL) {
            return PolicyDecision.forward(ipInt, plan.getName(), appType, tier, currentUsage, 
                    plan.getDailyQuotaBytes(), usagePct, state, ReasonCode.ESSENTIAL_TRAFFIC_PROTECTED, 
                    "Essential app protected during FUP", pcapTsSec);
        }

        long bandwidthKbps = throttlePolicy.getBandwidthLimitKbps(tier);
        if (bandwidthKbps <= 0) {
            // Failsafe for unlimited tier config
            return PolicyDecision.forward(ipInt, plan.getName(), appType, tier, currentUsage, 
                    plan.getDailyQuotaBytes(), usagePct, state, ReasonCode.NORMAL_OPERATION, 
                    "Tier has no bandwidth limit", pcapTsSec);
        }

        // 8. Apply Token Bucket Rate Limiting
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
    
    /** Used for unit tests to artificially set usage. */
    public void injectUsage(int ipInt, long bytes) {
        usageByIp.put(ipInt, new AtomicLong(bytes));
    }
}
