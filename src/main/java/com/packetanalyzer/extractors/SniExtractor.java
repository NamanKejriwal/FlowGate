package com.packetanalyzer.extractors;

import com.packetanalyzer.io.ByteUtils;
import java.util.Optional;

public class SniExtractor {

    public static boolean isTLSClientHello(byte[] payload, int offset, int length) {
        if (length < 9) return false;
        return payload[offset] == 0x16 && payload[offset + 5] == 0x01;
    }

    public static Optional<String> extract(byte[] payload, int offset, int length) {
        if (!isTLSClientHello(payload, offset, length)) {
            return Optional.empty();
        }

        try {
            int current = offset + 5; // Skip TLS record header
            current += 4; // Skip handshake header
            current += 2; // Skip client version
            current += 32; // Skip random

            if (current >= offset + length) return Optional.empty();

            int sessionIdLength = ByteUtils.readUnsignedByte(payload[current]);
            current += 1 + sessionIdLength;

            if (current + 2 > offset + length) return Optional.empty();

            int cipherSuitesLength = ByteUtils.readUint16BE(payload, current);
            current += 2 + cipherSuitesLength;

            if (current + 1 > offset + length) return Optional.empty();

            int compMethodsLength = ByteUtils.readUnsignedByte(payload[current]);
            current += 1 + compMethodsLength;

            if (current + 2 > offset + length) return Optional.empty();

            int extensionsLength = ByteUtils.readUint16BE(payload, current);
            current += 2;

            int extensionsEnd = Math.min(current + extensionsLength, offset + length);

            while (current + 4 <= extensionsEnd) {
                int extType = ByteUtils.readUint16BE(payload, current);
                int extLen = ByteUtils.readUint16BE(payload, current + 2);
                current += 4;

                if (extType == 0x0000) { // SNI
                    if (current + 2 <= extensionsEnd) {
                        int listLen = ByteUtils.readUint16BE(payload, current);
                        int p = current + 2;
                        if (p + 3 <= extensionsEnd) {
                            int nameType = ByteUtils.readUnsignedByte(payload[p]);
                            int nameLen = ByteUtils.readUint16BE(payload, p + 1);
                            p += 3;

                            if (nameType == 0 && p + nameLen <= extensionsEnd) { // Hostname
                                return Optional.of(new String(payload, p, nameLen));
                            }
                        }
                    }
                }
                current += extLen;
            }
        } catch (Exception e) {
            // Out of bounds or malformed packet
        }

        return Optional.empty();
    }
}
