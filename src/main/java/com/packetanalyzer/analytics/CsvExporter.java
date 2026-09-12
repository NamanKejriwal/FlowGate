package com.packetanalyzer.analytics;

import com.packetanalyzer.io.ByteUtils;
import com.packetanalyzer.tracking.GlobalConnectionTable;
import com.packetanalyzer.tracking.ConnectionTracker;
import com.packetanalyzer.rules.RuleManager;
import com.packetanalyzer.types.AppType;
import com.packetanalyzer.types.Connection;
import com.packetanalyzer.types.DPIStats;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class CsvExporter {

    public static void exportApplications(String outputDir, Map<AppType, AnalyticsCollector.GlobalAppStats> appStats) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("Application,Connections,Packets,Bytes,Percentage\n");
        
        long totalConns = appStats.values().stream().mapToLong(s -> s.connections).sum();
        
        List<Map.Entry<AppType, AnalyticsCollector.GlobalAppStats>> sorted = new ArrayList<>(appStats.entrySet());
        sorted.sort((a, b) -> Long.compare(b.getValue().connections, a.getValue().connections));
        
        for (Map.Entry<AppType, AnalyticsCollector.GlobalAppStats> entry : sorted) {
            double pct = totalConns > 0 ? (100.0 * entry.getValue().connections / totalConns) : 0.0;
            sb.append(String.format("%s,%d,%d,%d,%.2f\n", 
                entry.getKey().getDisplayName(), 
                entry.getValue().connections, 
                entry.getValue().packets, 
                entry.getValue().bytes, 
                pct));
        }
        
        Files.writeString(Paths.get(outputDir, "applications.csv"), sb.toString());
    }

    public static void exportDomains(String outputDir, Map<String, Long> domainStats) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("Domain,Connections,Percentage\n");
        
        long totalHits = domainStats.values().stream().mapToLong(Long::longValue).sum();
        
        List<Map.Entry<String, Long>> sorted = new ArrayList<>(domainStats.entrySet());
        sorted.sort((a, b) -> b.getValue().compareTo(a.getValue()));
        
        for (Map.Entry<String, Long> entry : sorted) {
            double pct = totalHits > 0 ? (100.0 * entry.getValue() / totalHits) : 0.0;
            sb.append(String.format("%s,%d,%.2f\n", entry.getKey(), entry.getValue(), pct));
        }
        
        Files.writeString(Paths.get(outputDir, "domains.csv"), sb.toString());
    }

    public static void exportConnections(String outputDir, GlobalConnectionTable globalConnTable) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("SourceIP,DestinationIP,Application,PacketCount,State,Confidence\n");
        
        for (ConnectionTracker tracker : globalConnTable.getTrackers()) {
            if (tracker == null) continue;
            for (Connection conn : tracker.getAllConnections()) {
                sb.append(String.format("%s,%s,%s,%d,%s,%s\n",
                    ByteUtils.ipToString(conn.tuple.srcIp),
                    ByteUtils.ipToString(conn.tuple.dstIp),
                    conn.appType.getDisplayName(),
                    conn.packetsIn + conn.packetsOut,
                    conn.state.name(),
                    conn.confidence.name()
                ));
            }
        }
        
        Files.writeString(Paths.get(outputDir, "connections.csv"), sb.toString());
    }

    public static void exportTopTalkers(String outputDir, Map<Integer, Long> topTalkers) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("IP,ConnectionCount\n");
        
        List<Map.Entry<Integer, Long>> sorted = new ArrayList<>(topTalkers.entrySet());
        sorted.sort((a, b) -> b.getValue().compareTo(a.getValue()));
        
        for (Map.Entry<Integer, Long> entry : sorted) {
            sb.append(String.format("%s,%d\n", ByteUtils.ipToString(entry.getKey()), entry.getValue()));
        }
        
        Files.writeString(Paths.get(outputDir, "top-talkers.csv"), sb.toString());
    }

    public static void exportRules(String outputDir, RuleManager ruleManager) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("Rule,Type,HitCount\n");
        
        if (ruleManager != null) {
            Map<String, Long> hits = ruleManager.getRuleHitCounts();
            List<Map.Entry<String, Long>> sorted = new ArrayList<>(hits.entrySet());
            sorted.sort((a, b) -> b.getValue().compareTo(a.getValue()));
            
            for (Map.Entry<String, Long> entry : sorted) {
                String ruleStr = entry.getKey();
                String type = ruleStr.startsWith("BLOCK_") ? ruleStr.substring(6, ruleStr.indexOf('=')) : "UNKNOWN";
                sb.append(String.format("%s,%s,%d\n", ruleStr, type, entry.getValue()));
            }
        }
        
        Files.writeString(Paths.get(outputDir, "rules.csv"), sb.toString());
    }
}
