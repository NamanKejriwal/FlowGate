package com.packetanalyzer.types;

public class Connection {
    public FiveTuple tuple;
    public ConnectionState state = ConnectionState.NEW;
    public AppType appType = AppType.UNKNOWN;
    public String sni = "";
    
    public long packetsIn;
    public long packetsOut;
    public long bytesIn;
    public long bytesOut;
    
    public long firstSeenSec;
    public long lastSeenSec;
    
    public PacketAction action = PacketAction.FORWARD;
    
    public ConfidenceLevel confidence = ConfidenceLevel.LOW;
    
    public boolean synSeen;
    public boolean synAckSeen;
    public boolean finSeen;

    public Connection() {
        // Timestamps will be initialized explicitly by ConnectionTracker using PCAP time
    }
}
