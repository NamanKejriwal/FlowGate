package com.flowgate.policy;

/**
 * Machine-readable reason codes produced by the FlowGate policy engine.
 * Every PolicyDecision carries exactly one ReasonCode.
 */
public enum ReasonCode {

    /** Subscriber has not hit any limit. Traffic flows normally. */
    NORMAL_OPERATION,

    /** Subscriber has used more than 80% of their daily quota. Warning only — not throttled yet. */
    FUP_WARNING,

    /** Subscriber exceeded their daily quota. ASIT throttling is now active. */
    FUP_QUOTA_EXCEEDED,

    /** Subscriber usage is more than 2x their quota. Hard-drop active. */
    HARD_DROP_THRESHOLD,

    /**
     * Subscriber is throttled and the packet would have to wait longer than the
     * throttle queue allows, so it is dropped instead of delayed.
     */
    THROTTLE_QUEUE_FULL,

    /**
     * The application is in the ESSENTIAL tier (e.g. WhatsApp, DNS).
     * Even if the subscriber is throttled, this traffic is protected at full speed.
     */
    ESSENTIAL_TRAFFIC_PROTECTED,

    /** The application is zero-rated. Bytes are not counted against the daily quota. */
    ZERO_RATED_TRAFFIC,

    /**
     * The packet arrived during the subscriber's off-peak window.
     * Bytes are not counted against the daily quota.
     */
    OFF_PEAK_TRAFFIC,

    /** The source IP is not registered in subscribers.txt. Default plan is applied. */
    UNKNOWN_SUBSCRIBER
}
