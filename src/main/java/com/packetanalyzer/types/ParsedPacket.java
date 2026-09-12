package com.packetanalyzer.types;

public class ParsedPacket {
    public long timestampSec;
    public long timestampUsec;
    
    public String srcMac;
    public String destMac;
    public int etherType;
    
    public boolean hasIp;
    public int ipVersion;
    public String srcIp;
    public String destIp;
    public int protocol;
    public int ttl;
    
    public boolean hasTcp;
    public boolean hasUdp;
    public int srcPort;
    public int destPort;
    
    public int tcpFlags;
    public long seqNumber;
    public long ackNumber;
    
    public int payloadLength;
    public int payloadOffset;

    public void reset() {
        timestampSec = 0;
        timestampUsec = 0;
        srcMac = null;
        destMac = null;
        etherType = 0;
        hasIp = false;
        ipVersion = 0;
        srcIp = null;
        destIp = null;
        protocol = 0;
        ttl = 0;
        hasTcp = false;
        hasUdp = false;
        srcPort = 0;
        destPort = 0;
        tcpFlags = 0;
        seqNumber = 0;
        ackNumber = 0;
        payloadLength = 0;
        payloadOffset = 0;
    }
}
