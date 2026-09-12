package com.packetanalyzer.extractors;

import java.util.Optional;

public class HttpHostExtractor {

    public static boolean isHTTPRequest(byte[] payload, int offset, int length) {
        if (length < 4) return false;
        String start = new String(payload, offset, 4);
        return start.equals("GET ") || start.equals("POST") || start.equals("PUT ") ||
               start.equals("HEAD") || start.equals("DELE") || start.equals("PATC") ||
               start.equals("OPTI");
    }

    public static Optional<String> extract(byte[] payload, int offset, int length) {
        if (!isHTTPRequest(payload, offset, length)) {
            return Optional.empty();
        }

        String content = new String(payload, offset, length);
        int hostIdx = content.toLowerCase().indexOf("\r\nhost: ");
        if (hostIdx == -1) {
            hostIdx = content.toLowerCase().indexOf("\nhost: "); // Handle edge case
        }
        
        if (hostIdx != -1) {
            int start = hostIdx + content.substring(hostIdx).indexOf(':') + 1;
            while (start < content.length() && content.charAt(start) == ' ') start++;
            
            int end = content.indexOf('\r', start);
            if (end == -1) end = content.indexOf('\n', start);
            
            if (end != -1) {
                String host = content.substring(start, end).trim();
                int colonIdx = host.indexOf(':');
                if (colonIdx != -1) {
                    host = host.substring(0, colonIdx);
                }
                return Optional.of(host);
            }
        }

        return Optional.empty();
    }
}
