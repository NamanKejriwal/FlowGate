package com.packetanalyzer.io;

import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;

public class PcapReader {
    private DataInputStream in;
    private boolean needsByteSwap;
    private GlobalHeader globalHeader;
    private String filename;

    public record GlobalHeader(long magicNumber, int versionMajor, int versionMinor, long snaplen, long network) {}

    public static class RawPacket {
        public long tsSec;
        public long tsUsec;
        public int inclLen;
        public int origLen;
        public byte[] data;
    }

    public PcapReader(String filename) {
        this.filename = filename;
    }

    public boolean open() {
        try {
            in = new DataInputStream(new FileInputStream(filename));
            byte[] headerData = new byte[24];
            if (in.read(headerData) != 24) {
                return false;
            }

            long magicNumber = ByteUtils.readUint32BE(headerData, 0);
            if (magicNumber == 0xa1b2c3d4L) {
                needsByteSwap = false;
            } else if (magicNumber == 0xd4c3b2a1L) {
                needsByteSwap = true;
                magicNumber = 0xa1b2c3d4L; // Correct it
            } else {
                System.err.println("Not a valid PCAP file (magic number mismatch).");
                return false;
            }

            int vMaj = needsByteSwap ? ByteUtils.readUint16LE(headerData, 4) : ByteUtils.readUint16BE(headerData, 4);
            int vMin = needsByteSwap ? ByteUtils.readUint16LE(headerData, 6) : ByteUtils.readUint16BE(headerData, 6);
            long snaplen = needsByteSwap ? ByteUtils.readUint32LE(headerData, 16) : ByteUtils.readUint32BE(headerData, 16);
            long network = needsByteSwap ? ByteUtils.readUint32LE(headerData, 20) : ByteUtils.readUint32BE(headerData, 20);

            globalHeader = new GlobalHeader(magicNumber, vMaj, vMin, snaplen, network);

            System.out.println("PCAP version: " + vMaj + "." + vMin);
            System.out.println("Snaplen: " + snaplen);
            System.out.println("Link type: " + network);

            return true;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    public RawPacket readNextPacket() {
        if (in == null) return null;
        try {
            byte[] ph = new byte[16];
            int read = 0;
            while (read < 16) {
                int r = in.read(ph, read, 16 - read);
                if (r == -1) {
                    if (read == 0) return null;
                    return null;
                }
                read += r;
            }

            RawPacket pkt = new RawPacket();
            if (needsByteSwap) {
                pkt.tsSec = ByteUtils.readUint32LE(ph, 0);
                pkt.tsUsec = ByteUtils.readUint32LE(ph, 4);
                pkt.inclLen = (int) ByteUtils.readUint32LE(ph, 8);
                pkt.origLen = (int) ByteUtils.readUint32LE(ph, 12);
            } else {
                pkt.tsSec = ByteUtils.readUint32BE(ph, 0);
                pkt.tsUsec = ByteUtils.readUint32BE(ph, 4);
                pkt.inclLen = (int) ByteUtils.readUint32BE(ph, 8);
                pkt.origLen = (int) ByteUtils.readUint32BE(ph, 12);
            }

            if (pkt.inclLen > globalHeader.snaplen() || pkt.inclLen > 65535 || pkt.inclLen < 0) {
                System.err.println("Invalid packet length: " + pkt.inclLen);
                return null;
            }

            pkt.data = new byte[pkt.inclLen];
            in.readFully(pkt.data);

            return pkt;
        } catch (IOException e) {
            return null;
        }
    }

    public void close() {
        if (in != null) {
            try {
                in.close();
            } catch (IOException e) {
                // Ignore
            }
        }
    }

    public GlobalHeader getGlobalHeader() {
        return globalHeader;
    }

    public boolean needsByteSwap() {
        return needsByteSwap;
    }
}
