package com.packetanalyzer.types;

public class FiveTuple {
    public int srcIp;
    public int dstIp;
    public int srcPort;
    public int dstPort;
    public int protocol;

    public FiveTuple() {}

    public FiveTuple(int srcIp, int dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocol = protocol;
    }

    public FiveTuple reverse() {
        return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FiveTuple that = (FiveTuple) o;
        return srcIp == that.srcIp &&
               dstIp == that.dstIp &&
               srcPort == that.srcPort &&
               dstPort == that.dstPort &&
               protocol == that.protocol;
    }

    @Override
    public int hashCode() {
        int h = 0;
        h ^= hashField(srcIp) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= hashField(dstIp) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= hashField(srcPort) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= hashField(dstPort) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= hashField(protocol) + 0x9e3779b9 + (h << 6) + (h >> 2);
        return h;
    }

    private int hashField(int val) {
        return Integer.hashCode(val);
    }

    public static String ipToString(int ip) {
        return (ip & 0xFF) + "." +
               ((ip >> 8) & 0xFF) + "." +
               ((ip >> 16) & 0xFF) + "." +
               ((ip >> 24) & 0xFF);
    }

    @Override
    public String toString() {
        return ipToString(srcIp) + ":" + srcPort + " -> " +
               ipToString(dstIp) + ":" + dstPort + " [" + protocol + "]";
    }
}
