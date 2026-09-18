#!/usr/bin/env bash
# run_demo.sh
# Demonstrates FlowGate's Phase 5/6 end-to-end functionality using deterministic traffic.

set -e

echo "=========================================================================="
echo " FlowGate v1.0.0 - Subscriber-Aware Traffic Policy Engine Demo            "
echo "=========================================================================="
echo ""

echo "[1/3] Building FlowGate..."
mvn package -DskipTests -q
echo "  -> Build successful."
echo ""

echo "[2/3] Checking demo PCAP..."
if [ ! -f "samples/flowgate-demo.pcap" ]; then
    echo "  -> Generating samples/flowgate-demo.pcap..."
    python3 tools/generate_pcaps.py
else
    echo "  -> Using existing samples/flowgate-demo.pcap."
fi
echo ""

OUT_PCAP="/tmp/flowgate-demo-out.pcap"

echo "[3/3] Running FlowGate Engine..."
echo "  Command: java -jar target/flowgate-1.0.0.jar samples/flowgate-demo.pcap $OUT_PCAP \\"
echo "                --subscribers config/demo/subscribers-demo.txt \\"
echo "                --throttle-policy config/demo/throttle-policy-demo.txt"
echo ""

java -jar target/flowgate-1.0.0.jar samples/flowgate-demo.pcap "$OUT_PCAP" \
    --subscribers config/demo/subscribers-demo.txt \
    --throttle-policy config/demo/throttle-policy-demo.txt
