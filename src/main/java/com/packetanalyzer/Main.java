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

        String inputFile  = args[0];
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
            switch (arg) {
                case "-r", "--rules" -> {
                    if (i + 1 < args.length) config.rulesFile = args[++i];
                }
                case "--subscribers" -> {
                    if (i + 1 < args.length) config.subscribersFile = args[++i];
                }
                case "--throttle-policy" -> {
                    if (i + 1 < args.length) config.throttlePolicyFile = args[++i];
                }
                case "-lb" -> {
                    if (i + 1 < args.length) config.numLoadBalancers = Integer.parseInt(args[++i]);
                }
                case "-fp" -> {
                    if (i + 1 < args.length) config.fpsPerLb = Integer.parseInt(args[++i]);
                }
                case "-v", "--verbose" -> config.verbose = true;
            }
        }

        System.out.println("Starting FlowGate v1.0.0 — Subscriber-Aware Traffic Policy Engine");

        DpiEngine engine = new DpiEngine(config);

        long startTime = System.currentTimeMillis();
        boolean success = engine.processFile(inputFile, outputFile);
        long endTime = System.currentTimeMillis();

        if (success) {
            double duration = (endTime - startTime) / 1000.0;
            System.out.println("\nProcessing completed in " + String.format("%.2f", duration) + " seconds.");
        } else {
            System.err.println("\nProcessing failed.");
            System.exit(1);
        }
    }

    private static void printUsage() {
        System.out.println("FlowGate v1.0.0 — Usage:");
        System.out.println("  java -jar flowgate.jar <input.pcap> <output.pcap> [options]");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  -r, --rules <file>            Path to firewall rules file");
        System.out.println("  --subscribers <file>          Enable FlowGate: path to subscribers.txt");
        System.out.println("  --throttle-policy <file>      Path to throttle-policy.txt (optional, uses defaults)");
        System.out.println("  -lb <num>                     Number of load balancer threads (default: 2)");
        System.out.println("  -fp <num>                     Fast path threads per LB (default: 2)");
        System.out.println("  -v,  --verbose                Enable verbose packet logging");
    }
}
