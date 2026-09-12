package com.packetanalyzer.types;

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
