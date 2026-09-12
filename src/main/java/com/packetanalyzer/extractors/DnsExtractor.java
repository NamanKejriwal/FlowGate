package com.packetanalyzer.extractors;

import com.packetanalyzer.io.ByteUtils;
import java.util.Optional;

public class DnsExtractor {

    public static boolean isDNSQuery(byte[] payload, int offset, int length) {
        if (length < 12) return false;
        int flags = ByteUtils.readUint16BE(payload, offset + 2);
        return (flags & 0x8000) == 0; // QR bit is 0
    }

    public static Optional<String> extractQuery(byte[] payload, int offset, int length) {
        if (!isDNSQuery(payload, offset, length)) {
            return Optional.empty();
        }

        try {
            int qdcount = ByteUtils.readUint16BE(payload, offset + 4);
            if (qdcount == 0) return Optional.empty();

            StringBuilder domain = new StringBuilder();
            int current = offset + 12;

            while (current < offset + length) {
                int len = ByteUtils.readUnsignedByte(payload[current]);
                if (len == 0) break;

                // Handle compression pointer (if length >= 192, top two bits set)
                if ((len & 0xC0) == 0xC0) {
                    // It's a pointer, we don't fully resolve it for simple extraction
                    break; 
                }

                current++;
                if (current + len > offset + length) return Optional.empty();

                if (domain.length() > 0) {
                    domain.append('.');
                }
                domain.append(new String(payload, current, len));
                current += len;
            }

            if (domain.length() > 0) {
                return Optional.of(domain.toString());
            }
        } catch (Exception e) {
            // Ignore
        }

        return Optional.empty();
    }
}
