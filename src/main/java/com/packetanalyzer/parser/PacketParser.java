package com.packetanalyzer.parser;

import com.packetanalyzer.io.ByteUtils;
import com.packetanalyzer.types.ParsedPacket;

public class PacketParser {

    public static boolean parse(byte[] rawData, long tsSec, long tsUsec, ParsedPacket parsed) {
        parsed.reset();
        parsed.timestampSec = tsSec;
        parsed.timestampUsec = tsUsec;

        if (rawData == null || rawData.length < 14) {
            return false;
        }

        parsed.destMac = ByteUtils.macToString(rawData, 0);
        parsed.srcMac = ByteUtils.macToString(rawData, 6);
        parsed.etherType = ByteUtils.readUint16BE(rawData, 12);

        if (parsed.etherType == 0x0800) { // IPv4
            if (rawData.length < 34) return false;
            
            parsed.hasIp = true;
            int vIhl = ByteUtils.readUnsignedByte(rawData[14]);
            parsed.ipVersion = vIhl >> 4;
            int ihl = vIhl & 0x0F;
            int ipHeaderLen = ihl * 4;

            if (rawData.length < 14 + ipHeaderLen) return false;

            parsed.ttl = ByteUtils.readUnsignedByte(rawData[22]);
            parsed.protocol = ByteUtils.readUnsignedByte(rawData[23]);

            // The C++ code uses memcpy to copy 4 bytes to uint32_t, which results in Little Endian on x86
            // We'll mimic this behavior using our LSB-first parsing.
            int srcIp = (int) ByteUtils.readUint32LE(rawData, 26);
            int destIp = (int) ByteUtils.readUint32LE(rawData, 30);
            
            parsed.srcIp = ByteUtils.ipToString(srcIp);
            parsed.destIp = ByteUtils.ipToString(destIp);

            int transportOffset = 14 + ipHeaderLen;

            if (parsed.protocol == 6) { // TCP
                if (rawData.length < transportOffset + 20) return false;
                
                parsed.hasTcp = true;
                parsed.srcPort = ByteUtils.readUint16BE(rawData, transportOffset);
                parsed.destPort = ByteUtils.readUint16BE(rawData, transportOffset + 2);
                parsed.seqNumber = ByteUtils.readUint32BE(rawData, transportOffset + 4);
                parsed.ackNumber = ByteUtils.readUint32BE(rawData, transportOffset + 8);
                
                int dataOffsetAndFlags = ByteUtils.readUnsignedByte(rawData[transportOffset + 12]);
                int tcpHeaderLen = (dataOffsetAndFlags >> 4) * 4;
                parsed.tcpFlags = ByteUtils.readUnsignedByte(rawData[transportOffset + 13]);

                parsed.payloadOffset = transportOffset + tcpHeaderLen;
                if (parsed.payloadOffset <= rawData.length) {
                    parsed.payloadLength = rawData.length - parsed.payloadOffset;
                }
            } else if (parsed.protocol == 17) { // UDP
                if (rawData.length < transportOffset + 8) return false;
                
                parsed.hasUdp = true;
                parsed.srcPort = ByteUtils.readUint16BE(rawData, transportOffset);
                parsed.destPort = ByteUtils.readUint16BE(rawData, transportOffset + 2);

                parsed.payloadOffset = transportOffset + 8;
                if (parsed.payloadOffset <= rawData.length) {
                    parsed.payloadLength = rawData.length - parsed.payloadOffset;
                }
            }
        }

        return true;
    }

    public static String protocolToString(int protocol) {
        return switch (protocol) {
            case 1 -> "ICMP";
            case 6 -> "TCP";
            case 17 -> "UDP";
            default -> "Unknown (" + protocol + ")";
        };
    }

    public static String tcpFlagsToString(int flags) {
        StringBuilder sb = new StringBuilder();
        if ((flags & 0x02) != 0) sb.append("SYN ");
        if ((flags & 0x10) != 0) sb.append("ACK ");
        if ((flags & 0x01) != 0) sb.append("FIN ");
        if ((flags & 0x04) != 0) sb.append("RST ");
        if ((flags & 0x08) != 0) sb.append("PSH ");
        if ((flags & 0x20) != 0) sb.append("URG ");
        return sb.toString().trim();
    }
}
