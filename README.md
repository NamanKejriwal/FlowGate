<div align="center">

# FlowGate v1.0.0

**Subscriber-Aware Traffic Policy & Diagnostics Engine**

[![Java](https://img.shields.io/badge/Java-21-orange.svg)](#)
[![Maven](https://img.shields.io/badge/Maven-3.9+-C71A36.svg)](#)

A concurrent Deep Packet Inspection (DPI) system built in Java 21 for offline network traffic analysis, Fair Usage Policy (FUP) enforcement, Application-Specific Intelligent Throttling (ASIT), and evidence-based connection diagnostics.

</div>

---

## Highlights

- Multi-threaded DPI Engine (Java 21)
- Five-Tuple Flow Tracking & Layer 7 App Identification
- Lock-Free, CAS-based Token Bucket Rate Limiting
- Fair Usage Policy (FUP) State Machine
- Application-Specific Intelligent Throttling (ASIT)
- PCAP-Time Delay Simulation
- Evidence-Based Diagnostics Engine

---

## What Problem Does FlowGate Solve?

Traditional firewalls either allow or block traffic. ISPs, however, need nuanced control over subscriber data. FlowGate simulates an ISP-grade traffic shaping pipeline on offline PCAP files:
1. **Subscriber Awareness:** Traffic is mapped to specific user IP plans.
2. **Quota Tracking:** Data usage is tracked continuously.
3. **ASIT (Application-Specific Intelligent Throttling):** When a user exhausts their quota, FlowGate doesn't just block them. It throttles ENTERTAINMENT apps (YouTube, Netflix) heavily, throttles STANDARD apps (GitHub, Zoom) moderately, and allows ESSENTIAL apps (WhatsApp, DNS) at full speed.
4. **Diagnostics:** If a user complains about slow internet, FlowGate analyzes recent policy decisions and outputs an exact root cause (e.g., `HARD_DROP`, `FUP_ENTERTAINMENT`).

## Architecture & Data Flow

FlowGate uses a highly concurrent Producer-Consumer model optimized for throughput without locking bottlenecks:

```text
[PcapReader Thread] 
   └─> Byte Array
   └─> LoadBalancer (5-tuple hash pinning)
         ├─> [FastPathProcessor 1] -> DPI -> QuotaManager -> TokenBucket
         └─> [FastPathProcessor N] -> DPI -> QuotaManager -> TokenBucket
                 └─> [Output Queue]
                       └─> [PcapWriter Thread] (Applies simulated delays to PCAP timestamps)
```

**Key Architectural Decisions:**
- **Thread Pinning:** 5-tuple hashing guarantees bidirectional packets for a single flow always land on the same worker thread. This eliminates lock contention for connection state.
- **Lock-Free Rate Limiting:** The `TokenBucket` algorithm uses a Compare-And-Swap (CAS) retry loop with `AtomicLong`, ensuring extremely fast concurrent token consumption without blocking.
- **PCAP-Time Simulation:** All flow timeouts and token bucket refill math use the embedded PCAP timestamps, not `System.currentTimeMillis()`. This ensures the offline simulation is perfectly deterministic regardless of CPU speed.

## How to Build

**Prerequisites:** Java 21+ JDK, Maven 3.9.x

```bash
mvn clean package
```
The executable JAR will be located at `target/flowgate-1.0.0.jar`.

## How to Run

**Standard Execution (DPI Only):**
```bash
java -jar target/flowgate-1.0.0.jar input.pcap output.pcap
```

**Subscriber-Aware Policy Execution:**
```bash
java -jar target/flowgate-1.0.0.jar input.pcap output.pcap \
    --subscribers config/subscribers.txt \
    --throttle-policy config/throttle-policy.txt
```

## Running the Deterministic Demo

FlowGate includes a deterministic 7-packet demo sequence that perfectly demonstrates every FUP state transition in order.

Run the automated demo script:
```bash
./run_demo.sh
```

**What the demo demonstrates:**
1. **NORMAL:** 2 packets (ESSENTIAL & STANDARD) pass through normally.
2. **WARNING:** 1 ENTERTAINMENT packet pushes the user to 90% quota.
3. **THROTTLE + DELAY:** 2 packets (ENTERTAINMENT & STANDARD) cross the 100% threshold and are delayed by the ASIT Token Buckets.
4. **ESSENTIAL PROTECTION:** 1 ESSENTIAL packet arrives while the user is throttled, but is forwarded at full speed by policy.
5. **HARD_DROP:** 1 final packet pushes the user past the 200% hard-drop threshold and is discarded.
6. **DIAGNOSTICS:** The `ConnectionHealthAnalyzer` runs at the end, printing exactly why the user's traffic was affected.

## Important Limitations

When evaluating FlowGate, note the following scope boundaries:
- **Offline PCAP Only:** FlowGate is a simulation/analysis engine. It processes offline PCAP files. It does not bind to live network interfaces (e.g., eBPF, DPDK, raw sockets).
- **Plaintext SNI Extraction:** TLS classification relies on extracting the Server Name Indication (SNI) from the plaintext `ClientHello` packet. FlowGate does not perform TLS decryption.
- **Congestion Diagnostics:** The `NETWORK_CONGESTION` diagnostic cause is reserved. True congestion detection requires queue-depth telemetry or physical packet-loss counters that do not exist in standard PCAP files.

---

### License
Licensed under the MIT License. See LICENSE for details.
