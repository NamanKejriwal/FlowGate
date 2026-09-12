package com.packetanalyzer.engine;

import com.packetanalyzer.types.FiveTuple;
import com.packetanalyzer.types.PacketJob;

import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

public class LoadBalancer implements Runnable {

    private final int lbId;
    private final int fpStartId;
    private final int numFps;

    private final LinkedBlockingQueue<PacketJob> inputQueue;
    private final List<LinkedBlockingQueue<PacketJob>> fpQueues;

    private final AtomicLong packetsReceived = new AtomicLong(0);
    private final AtomicLong packetsDispatched = new AtomicLong(0);
    private final long[] perFpCounts;

    private final AtomicBoolean running = new AtomicBoolean(false);
    private Thread thread;

    public LoadBalancer(int lbId, List<LinkedBlockingQueue<PacketJob>> fpQueues, int fpStartId) {
        this.lbId = lbId;
        this.fpStartId = fpStartId;
        this.numFps = fpQueues.size();
        this.inputQueue = new LinkedBlockingQueue<>(10000);
        this.fpQueues = fpQueues;
        this.perFpCounts = new long[fpQueues.size()];
    }

    public void start() {
        if (running.get()) return;

        running.set(true);
        thread = new Thread(this, "LB-" + lbId);
        thread.start();

        System.out.println("[LB" + lbId + "] Started (serving FP" + fpStartId + "-FP" + (fpStartId + numFps - 1) + ")");
    }

    public void stop() {
        if (!running.get()) return;

        running.set(false);
        if (thread != null) {
            try {
                thread.join(1000); // give it a moment to finish gracefully
                thread.interrupt();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        System.out.println("[LB" + lbId + "] Stopped");
    }

    public LinkedBlockingQueue<PacketJob> getInputQueue() {
        return inputQueue;
    }

    public static class LBStats {
        public long packetsReceived;
        public long packetsDispatched;
        public long[] perFpPackets;
    }

    public LBStats getStats() {
        LBStats stats = new LBStats();
        stats.packetsReceived = packetsReceived.get();
        stats.packetsDispatched = packetsDispatched.get();
        stats.perFpPackets = perFpCounts.clone();
        return stats;
    }

    @Override
    public void run() {
        while (running.get()) {
            try {
                PacketJob job = inputQueue.poll(100, TimeUnit.MILLISECONDS);
                if (job == null) continue;

                packetsReceived.incrementAndGet();

                int fpIndex = selectFP(job.tuple);

                // Add to FP queue (block if full)
                fpQueues.get(fpIndex).put(job);

                packetsDispatched.incrementAndGet();
                perFpCounts[fpIndex]++;
            } catch (InterruptedException e) {
                if (!running.get()) {
                    break;
                }
                Thread.currentThread().interrupt();
            }
        }
    }

    private int selectFP(FiveTuple tuple) {
        // We ensure hash is positive
        long hash = tuple.hashCode() & 0xFFFFFFFFL;
        return (int) (hash % numFps);
    }
}
