package com.packetanalyzer;

import com.packetanalyzer.engine.DpiEngine;
import com.packetanalyzer.engine.DpiEngine.Config;

import java.io.File;

public class Main {
    public static void main(String[] args) {
        if (args.length < 2) {
            printUsage();
            System.exit(1);
        }

        String inputFile = args[0];
        String outputFile = args[1];

        if (!new File(inputFile).exists()) {
            System.err.println("Error: Input file does not exist: " + inputFile);
            System.exit(1);
        }

        Config config = new Config();
        config.numLoadBalancers = 2;
        config.fpsPerLb = 2;
        config.queueSize = 10000;
        config.verbose = false;

        // Parse optional arguments
        for (int i = 2; i < args.length; i++) {
            String arg = args[i];
            if (arg.equals("-r") || arg.equals("--rules")) {
                if (i + 1 < args.length) {
                    config.rulesFile = args[++i];
                }
            } else if (arg.equals("-lb")) {
                if (i + 1 < args.length) {
                    config.numLoadBalancers = Integer.parseInt(args[++i]);
                }
            } else if (arg.equals("-fp")) {
                if (i + 1 < args.length) {
                    config.fpsPerLb = Integer.parseInt(args[++i]);
                }
            } else if (arg.equals("-v") || arg.equals("--verbose")) {
                config.verbose = true;
            }
        }

        System.out.println("Starting DPI Engine Migration (Java Port)...");

        DpiEngine engine = new DpiEngine(config);
        
        long startTime = System.currentTimeMillis();
        boolean success = engine.processFile(inputFile, outputFile);
        long endTime = System.currentTimeMillis();

        if (success) {
            double duration = (endTime - startTime) / 1000.0;
            System.out.println("\nProcessing completed successfully in " + String.format("%.2f", duration) + " seconds.");
        } else {
            System.err.println("\nProcessing failed.");
            System.exit(1);
        }
    }

    private static void printUsage() {
        System.out.println("Usage: java -jar dpi-engine.jar <input.pcap> <output.pcap> [options]");
        System.out.println("Options:");
        System.out.println("  -r, --rules <file>   Path to rules file");
        System.out.println("  -lb <num>            Number of load balancer threads (default: 2)");
        System.out.println("  -fp <num>            Number of fast path threads per LB (default: 2)");
        System.out.println("  -v,  --verbose       Enable verbose logging");
    }
}
