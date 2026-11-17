package com.packetanalyzer.engine;

import com.flowgate.policy.PolicyDecision;
import com.packetanalyzer.io.ByteUtils;
import com.packetanalyzer.types.AppType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End to end: requests go subscriber -> server, replies come back server -> subscriber.
 * Every packet, in both directions, must be billed to the subscriber and tagged with the
 * app found on the request.
 */
class DownloadBillingTest {

    private static final String SUBSCRIBER = "192.168.1.100";
    private static final String WHATSAPP_SERVER = "15.15.15.15";
    private static final String NETFLIX_SERVER = "35.153.120.20";
    private static final long START_SEC = 1_700_000_000L; // 22:13 UTC, outside off-peak hours

    @TempDir
    Path dir;

    @Test
    void downloads_are_billed_to_the_subscriber_with_the_app_of_their_request() throws Exception {
        ByteArrayOutputStream pcap = new ByteArrayOutputStream();
        writeGlobalHeader(pcap);
        long t = 0;
        // WhatsApp: one request, three reply packets
        writePacket(pcap, t++, tcp(SUBSCRIBER, WHATSAPP_SERVER, 10001, 80, request("whatsapp.com")));
        for (int i = 0; i < 3; i++) {
            writePacket(pcap, t++, tcp(WHATSAPP_SERVER, SUBSCRIBER, 80, 10001, reply()));
        }
        // Netflix: one request, three reply packets
        writePacket(pcap, t++, tcp(SUBSCRIBER, NETFLIX_SERVER, 10002, 80, request("www.netflix.com")));
        for (int i = 0; i < 3; i++) {
            writePacket(pcap, t++, tcp(NETFLIX_SERVER, SUBSCRIBER, 80, 10002, reply()));
        }

        Path input = dir.resolve("in.pcap");
        Path subscribers = dir.resolve("subscribers.txt");
        Files.write(input, pcap.toByteArray());
        Files.writeString(subscribers, "DEFAULT_PLAN=Basic\n" + SUBSCRIBER + "=Basic\n");

        DpiEngine.Config config = new DpiEngine.Config();
        config.subscribersFile = subscribers.toString();
        config.throttlePolicyFile = "config/throttle-policy.txt";
        DpiEngine engine = new DpiEngine(config);
        assertTrue(engine.processFile(input.toString(), dir.resolve("out.pcap").toString()));

        Map<Integer, List<PolicyDecision>> decisions = engine.getRecentDecisions();

        // Everything is billed to the subscriber; nothing to the servers
        assertEquals(1, decisions.size(), "only the subscriber should be billed");
        List<PolicyDecision> billed = decisions.get(ByteUtils.parseIp(SUBSCRIBER));
        assertNotNull(billed);
        assertEquals(8, billed.size());

        // Replies inherit the app from their request
        assertEquals(4, billed.stream().filter(d -> d.appType() == AppType.WHATSAPP).count());
        assertEquals(4, billed.stream().filter(d -> d.appType() == AppType.NETFLIX).count());
    }

    // ── Tiny PCAP builder ────────────────────────────────────────────────────

    private static byte[] request(String host) {
        return ("GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n").getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] reply() {
        byte[] body = new byte[1200];
        byte[] head = "HTTP/1.1 200 OK\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(head, 0, body, 0, head.length);
        return body;
    }

    /** Ethernet + IPv4 + TCP (PSH/ACK) + payload. */
    private static byte[] tcp(String srcIp, String dstIp, int srcPort, int dstPort, byte[] payload) {
        int ipLen = 20 + 20 + payload.length;
        ByteBuffer b = ByteBuffer.allocate(14 + ipLen).order(ByteOrder.BIG_ENDIAN);
        b.put(new byte[]{0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb});
        b.putShort((short) 0x0800);                       // IPv4
        b.put((byte) 0x45).put((byte) 0).putShort((short) ipLen);
        b.putShort((short) 1).putShort((short) 0);
        b.put((byte) 64).put((byte) 6).putShort((short) 0); // TTL, TCP, checksum
        b.put(octets(srcIp)).put(octets(dstIp));
        b.putShort((short) srcPort).putShort((short) dstPort);
        b.putInt(100).putInt(200);
        b.put((byte) 0x50).put((byte) 0x18).putShort((short) 8192).putShort((short) 0).putShort((short) 0);
        b.put(payload);
        return b.array();
    }

    private static byte[] octets(String ip) {
        String[] p = ip.split("\\.");
        byte[] out = new byte[4];
        for (int i = 0; i < 4; i++) out[i] = (byte) Integer.parseInt(p[i]);
        return out;
    }

    private static void writeGlobalHeader(ByteArrayOutputStream out) {
        ByteBuffer b = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        b.putInt(0xa1b2c3d4).putShort((short) 2).putShort((short) 4)
         .putInt(0).putInt(0).putInt(65535).putInt(1);   // Ethernet link type
        out.writeBytes(b.array());
    }

    private static void writePacket(ByteArrayOutputStream out, long offsetSec, byte[] data) {
        ByteBuffer b = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        b.putInt((int) (START_SEC + offsetSec)).putInt(0).putInt(data.length).putInt(data.length);
        out.writeBytes(b.array());
        out.writeBytes(data);
    }
}
