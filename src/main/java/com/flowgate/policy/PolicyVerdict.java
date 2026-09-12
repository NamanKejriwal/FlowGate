package com.flowgate.policy;

/** The final action the pipeline takes on a packet after the policy decision. */
public enum PolicyVerdict {
    /** Forward packet at full speed. */
    FORWARD,
    /**
     * Simulate throttling by modifying the output PCAP timestamp.
     * The packet is still written to the output file but delayed in simulated time.
     */
    DELAY,
    /** Drop the packet entirely (hard-drop due to extreme quota breach). */
    DROP
}
