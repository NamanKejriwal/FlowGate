package com.packetanalyzer.types;

public enum PacketAction {
    FORWARD,
    DELAY,   // FlowGate: forward with mutated PCAP timestamp (simulated throttle)
    DROP,
    INSPECT,
    LOG_ONLY
}
