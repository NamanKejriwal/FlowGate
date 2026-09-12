package com.packetanalyzer.analytics;

import com.packetanalyzer.tracking.GlobalConnectionTable;
import com.packetanalyzer.types.DPIStats;
import com.packetanalyzer.rules.RuleManager;

import java.io.File;
import java.io.IOException;

public class AnalyticsManager {
    
    public static void exportAll(DPIStats stats, GlobalConnectionTable globalConnTable, RuleManager ruleManager, String inputFile, long runtimeMs, long flowTimeoutSec) {
        String outputDir = "reports";
        File dir = new File(outputDir);
        if (!dir.exists()) {
            dir.mkdirs();
        }
        
        try {
            AnalyticsCollector collector = new AnalyticsCollector();
            collector.collect(globalConnTable);
            
            long totalConnections = collector.getAppStats().values().stream().mapToLong(s -> s.connections).sum();
            
            JsonExporter.exportSummary(outputDir, stats, totalConnections, runtimeMs, collector.getActiveFlows(), collector.getEvictedFlows(), flowTimeoutSec);
            JsonExporter.exportMetadata(outputDir, inputFile, runtimeMs);
            JsonExporter.exportAppDistribution(outputDir, collector.getAppStats());
            JsonExporter.exportDomainDistribution(outputDir, collector.getDomainStats());
            
            CsvExporter.exportApplications(outputDir, collector.getAppStats());
            CsvExporter.exportDomains(outputDir, collector.getDomainStats());
            CsvExporter.exportConnections(outputDir, globalConnTable);
            CsvExporter.exportTopTalkers(outputDir, collector.getTopTalkers());
            CsvExporter.exportRules(outputDir, ruleManager);
            
            System.out.println("\n[AnalyticsManager] Reports successfully exported to " + outputDir + "/");
        } catch (IOException e) {
            System.err.println("\n[AnalyticsManager] ERROR exporting reports: " + e.getMessage());
        }
    }
}
