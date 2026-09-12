package com.packetanalyzer.io;

import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;

public class PcapWriter {
    private DataOutputStream out;
    private String filename;

    public PcapWriter(String filename) {
        this.filename = filename;
    }

    public boolean open() {
        try {
            out = new DataOutputStream(new FileOutputStream(filename));
            return true;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    public void writeGlobalHeader(PcapReader.GlobalHeader header) throws IOException {
        byte[] h = new byte[24];
        ByteUtils.writeUint32LE(h, 0, 0xa1b2c3d4L);
        ByteUtils.writeUint16LE(h, 4, header.versionMajor());
        ByteUtils.writeUint16LE(h, 6, header.versionMinor());
        ByteUtils.writeUint32LE(h, 8, 0); // thiszone
        ByteUtils.writeUint32LE(h, 12, 0); // sigfigs
        ByteUtils.writeUint32LE(h, 16, header.snaplen());
        ByteUtils.writeUint32LE(h, 20, header.network());
        out.write(h);
    }

    public void writePacket(long tsSec, long tsUsec, byte[] data) throws IOException {
        byte[] ph = new byte[16];
        ByteUtils.writeUint32LE(ph, 0, tsSec);
        ByteUtils.writeUint32LE(ph, 4, tsUsec);
        ByteUtils.writeUint32LE(ph, 8, data.length);
        ByteUtils.writeUint32LE(ph, 12, data.length);
        out.write(ph);
        out.write(data);
    }

    public void close() {
        if (out != null) {
            try {
                out.close();
            } catch (IOException e) {
                // Ignore
            }
        }
    }
}
