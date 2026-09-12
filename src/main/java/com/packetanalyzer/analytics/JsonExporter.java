package com.packetanalyzer.analytics;

import com.packetanalyzer.types.AppType;
import com.packetanalyzer.types.DPIStats;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Locale;

public class JsonExporter {

    public static void exportSummary(String outputDir, DPIStats stats, long totalConnections, long runtimeMs, long activeFlows, long evictedFlows, long flowTimeoutSec) throws IOException {
        long blockedFlows = stats.blockedByDomain.get() + stats.blockedByIp.get() + stats.blockedByPort.get() + stats.blockedByApp.get();
        
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"totalPackets\": ").append(stats.totalPackets.get()).append(",\n");
        sb.append("  \"tcpPackets\": ").append(stats.tcpPackets.get()).append(",\n");
        sb.append("  \"udpPackets\": ").append(stats.udpPackets.get()).append(",\n");
        sb.append("  \"connections\": ").append(totalConnections).append(",\n");
        sb.append("  \"activeFlows\": ").append(activeFlows).append(",\n");
        sb.append("  \"evictedFlows\": ").append(evictedFlows).append(",\n");
        sb.append("  \"blockedFlows\": ").append(blockedFlows).append(",\n");
        sb.append("  \"flowTimeoutSec\": ").append(flowTimeoutSec).append(",\n");
        sb.append("  \"runtimeMs\": ").append(runtimeMs).append("\n");
        sb.append("}\n");
        
        Files.writeString(Paths.get(outputDir, "summary.json"), sb.toString());
    }

    public static void exportAppDistribution(String outputDir, Map<AppType, AnalyticsCollector.GlobalAppStats> appStats) throws IOException {
        long totalConns = appStats.values().stream().mapToLong(s -> s.connections).sum();
        
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        
        List<Map.Entry<AppType, AnalyticsCollector.GlobalAppStats>> sorted = new ArrayList<>(appStats.entrySet());
        sorted.sort((a, b) -> Long.compare(b.getValue().connections, a.getValue().connections));
        
        for (int i = 0; i < sorted.size(); i++) {
            Map.Entry<AppType, AnalyticsCollector.GlobalAppStats> entry = sorted.get(i);
            double pct = totalConns > 0 ? (100.0 * entry.getValue().connections / totalConns) : 0.0;
            sb.append(String.format(Locale.US, "  \"%s\": %.2f", entry.getKey().getDisplayName(), pct));
            if (i < sorted.size() - 1) sb.append(",");
            sb.append("\n");
        }
        
        sb.append("}\n");
        Files.writeString(Paths.get(outputDir, "application-distribution.json"), sb.toString());
    }

    public static void exportDomainDistribution(String outputDir, Map<String, Long> domainStats) throws IOException {
        long totalHits = domainStats.values().stream().mapToLong(Long::longValue).sum();
        
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        
        List<Map.Entry<String, Long>> sorted = new ArrayList<>(domainStats.entrySet());
        sorted.sort((a, b) -> b.getValue().compareTo(a.getValue()));
        
        int count = Math.min(sorted.size(), 1000);
        for (int i = 0; i < count; i++) {
            Map.Entry<String, Long> entry = sorted.get(i);
            double pct = totalHits > 0 ? (100.0 * entry.getValue() / totalHits) : 0.0;
            String cleanKey = entry.getKey().replace("\"", "\\\"");
            sb.append(String.format(Locale.US, "  \"%s\": %.2f", cleanKey, pct));
            if (i < count - 1) sb.append(",");
            sb.append("\n");
        }
        
        sb.append("}\n");
        Files.writeString(Paths.get(outputDir, "domain-distribution.json"), sb.toString());
    }
    
    public static void exportMetadata(String outputDir, String inputFile, long runtimeMs) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"engineVersion\": \"v1.4\",\n");
        sb.append("  \"generatedAt\": \"").append(java.time.Instant.now().toString()).append("\",\n");
        sb.append("  \"inputFile\": \"").append(inputFile.replace("\\", "\\\\").replace("\"", "\\\"")).append("\",\n");
        sb.append("  \"processingTimeMs\": ").append(runtimeMs).append("\n");
        sb.append("}\n");
        
        Files.writeString(Paths.get(outputDir, "report-metadata.json"), sb.toString());
    }
}
