package com.packetanalyzer.types;

import java.util.concurrent.atomic.AtomicLong;

public class DPIStats {
    public final AtomicLong totalPackets = new AtomicLong(0);
    public final AtomicLong totalBytes = new AtomicLong(0);
    public final AtomicLong forwardedPackets = new AtomicLong(0);
    public final AtomicLong droppedPackets = new AtomicLong(0);
    public final AtomicLong tcpPackets = new AtomicLong(0);
    public final AtomicLong udpPackets = new AtomicLong(0);
    public final AtomicLong otherPackets = new AtomicLong(0);
    public final AtomicLong activeConnections = new AtomicLong(0);

    // Dynamic Rule Engine counters
    public final AtomicLong blockedByDomain = new AtomicLong(0);
    public final AtomicLong blockedByIp = new AtomicLong(0);
    public final AtomicLong blockedByPort = new AtomicLong(0);
    public final AtomicLong blockedByApp = new AtomicLong(0);

    // FlowGate policy counters
    public final AtomicLong throttledPackets  = new AtomicLong(0); // DELAY verdict (token bucket active)
    public final AtomicLong hardDroppedPackets = new AtomicLong(0); // DROP by quota hard limit
}
