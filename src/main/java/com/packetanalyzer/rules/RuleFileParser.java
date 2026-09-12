package com.packetanalyzer.rules;

import com.packetanalyzer.types.AppType;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

public class RuleFileParser {

    public static void parseAndLoad(String filename, RuleManager manager) {
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                
                // Ignore blank lines and comments
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                
                int equalsIdx = line.indexOf('=');
                if (equalsIdx == -1) {
                    System.err.println("[Rules] WARNING: Invalid rule format -> " + line);
                    continue;
                }
                
                String key = line.substring(0, equalsIdx).trim().toUpperCase();
                String value = line.substring(equalsIdx + 1).trim();
                
                if (value.isEmpty()) {
                    System.err.println("[Rules] WARNING: Empty rule value -> " + line);
                    continue;
                }

                try {
                    switch (key) {
                        case "BLOCK_DOMAIN":
                            manager.blockDomain(value);
                            break;
                            
                        case "BLOCK_IP":
                            // Simple IP validation check
                            if (value.split("\\.").length != 4) {
                                throw new IllegalArgumentException("Invalid IP format");
                            }
                            manager.blockIP(value);
                            break;
                            
                        case "BLOCK_PORT":
                            int port = Integer.parseInt(value);
                            if (port < 0 || port > 65535) {
                                throw new IllegalArgumentException("Port out of range");
                            }
                            manager.blockPort(port);
                            break;
                            
                        case "BLOCK_APP":
                            AppType app = AppType.fromDisplayName(value);
                            if (app == AppType.UNKNOWN) {
                                // Try fallback to enum name parsing
                                app = AppType.valueOf(value.toUpperCase().replace(" ", "_"));
                            }
                            manager.blockApp(app);
                            break;
                            
                        default:
                            System.err.println("[Rules] WARNING: Unknown rule type -> " + line);
                            break;
                    }
                } catch (Exception e) {
                    System.err.println("[Rules] WARNING: Invalid " + key.replace("BLOCK_", "").toLowerCase() + " rule -> " + line);
                }
            }
        } catch (IOException e) {
            System.err.println("[Rules] ERROR: Failed to read rules file -> " + filename);
        }
    }
}
