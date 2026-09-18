package com.packetanalyzer.types;

import com.flowgate.policy.PolicyDecision;

public class PacketJob {
    public int packetId;
    public FiveTuple tuple = new FiveTuple();
    
    public byte[] data;
    
    public int ethOffset;
    public int ipOffset;
    public int transportOffset;
    public int payloadOffset;
    public int payloadLength;
    
    public int tcpFlags;
    
    public long tsSec;
    public long tsUsec;
    
    public String classificationSource = "Unknown";
    public int workerId = -1;

    /** Set by QuotaManager after policy evaluation. Null if FlowGate is disabled. */
    public PolicyDecision policyDecision;

    public void reset() {
        packetId = 0;
        data = null;
        ethOffset = 0;
        ipOffset = 0;
        transportOffset = 0;
        payloadOffset = 0;
        payloadLength = 0;
        tcpFlags = 0;
        tsSec = 0;
        tsUsec = 0;
    }
}
