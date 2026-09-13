import struct
import time

def write_pcap(filename, packets):
    # Global header (24 bytes)
    # Magic Number (0xa1b2c3d4), Major (2), Minor (4), Timezone (0), SigFigs (0), SnapLen (65535), LinkType (1 = Ethernet)
    global_header = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    
    with open(filename, 'wb') as f:
        f.write(global_header)
        for ts_sec, ts_usec, data in packets:
            # Packet header (16 bytes): ts_sec, ts_usec, incl_len, orig_len
            f.write(struct.pack('<IIII', ts_sec, ts_usec, len(data), len(data)))
            f.write(data)

def make_eth_ip(src_ip, dst_ip, proto, total_len):
    # Mac addresses
    eth = b'\x00\x11\x22\x33\x44\x55' + b'\x66\x77\x88\x99\xaa\xbb' + b'\x08\x00'
    
    # IPv4
    ip_ihl = 5
    ip_ver = 4
    vihl = (ip_ver << 4) | ip_ihl
    
    src_bytes = bytes(map(int, src_ip.split('.')))
    dst_bytes = bytes(map(int, dst_ip.split('.')))
    
    ip_header = struct.pack('>BBHHHBBH4s4s',
        vihl, 0, total_len, 1234, 0, 64, proto, 0, src_bytes, dst_bytes
    )
    return eth + ip_header

def make_udp_dns(src_ip, dst_ip, payload):
    base = make_eth_ip(src_ip, dst_ip, 17, 20 + 8 + len(payload))
    udp_header = struct.pack('>HHHH', 12345, 53, 8 + len(payload), 0)
    return base + udp_header + payload

def make_tcp_http(src_ip, dst_ip, host_str, pad_to_length):
    payload = f"GET / HTTP/1.1\r\nHost: {host_str}\r\n\r\n".encode('utf-8')
    padding = b'X' * max(0, pad_to_length - (14 + 20 + 20 + len(payload)))
    payload += padding
    
    total_ip_len = 20 + 20 + len(payload)
    base = make_eth_ip(src_ip, dst_ip, 6, total_ip_len)
    
    # TCP header (20 bytes, no options)
    # Data offset = 5 (20 bytes)
    tcp_header = struct.pack('>HHIIBBHHH',
        12345, 80, 100, 200, (5 << 4), 0x18, 8192, 0, 0
    )
    return base + tcp_header + payload

def make_tcp_syn(src_ip, dst_ip):
    base = make_eth_ip(src_ip, dst_ip, 6, 40)
    tcp_header = struct.pack('>HHIIBBHHH',
        12345, 443, 100, 0, (5 << 4), 0x02, 8192, 0, 0
    )
    return base + tcp_header


# ==========================================
# 1. GENERATE FLOWGATE-DEMO.PCAP
# ==========================================
ts_sec = int(time.time())
ts_usec = 0

demo_packets = []
# Pkt 1: DNS (ESSENTIAL) - 200 bytes -> NORMAL (200/2000)
demo_packets.append((ts_sec, ts_usec, make_udp_dns('192.168.1.100', '8.8.8.8', b'\x00'*(200 - 42))))
ts_usec += 1000

# Pkt 2: Google (STANDARD) - 1300 bytes -> NORMAL (1500/2000)
pkt2 = make_tcp_http('192.168.1.100', '142.250.190.46', 'www.google.com', 1300)
# Fix src_port to force new connection
pkt2 = pkt2[:34] + struct.pack('>H', 10002) + pkt2[36:]
demo_packets.append((ts_sec, ts_usec, pkt2))
ts_usec += 1000

# Pkt 3: Netflix (ENTERTAINMENT) - 300 bytes -> WARNING (1800/2000)
pkt3 = make_tcp_http('192.168.1.100', '35.153.120.20', 'www.netflix.com', 300)
pkt3 = pkt3[:34] + struct.pack('>H', 10003) + pkt3[36:]
demo_packets.append((ts_sec, ts_usec, pkt3))
ts_usec += 1000

# Pkt 4: YouTube (ENTERTAINMENT) - 400 bytes -> THROTTLE + DELAY (2200/2000). 
pkt4 = make_tcp_http('192.168.1.100', '142.250.190.47', 'www.youtube.com', 400)
pkt4 = pkt4[:34] + struct.pack('>H', 10004) + pkt4[36:]
demo_packets.append((ts_sec, ts_usec, pkt4))
ts_usec += 1000

# Pkt 5: GitHub (STANDARD) - 400 bytes -> THROTTLE + DELAY (2600/2000).
pkt5 = make_tcp_http('192.168.1.100', '140.82.112.4', 'github.com', 400)
pkt5 = pkt5[:34] + struct.pack('>H', 10005) + pkt5[36:]
demo_packets.append((ts_sec, ts_usec, pkt5))
ts_usec += 1000

# Pkt 6: Telegram (ESSENTIAL) - 400 bytes -> THROTTLE + FORWARD (3000/2000). 
pkt6 = make_tcp_http('192.168.1.100', '149.154.167.99', 'web.telegram.org', 400)
pkt6 = pkt6[:34] + struct.pack('>H', 10006) + pkt6[36:]
demo_packets.append((ts_sec, ts_usec, pkt6))
ts_usec += 1000

# Pkt 7: Google (STANDARD) - 1200 bytes -> HARD DROP (4200/4000).
pkt7 = make_tcp_http('192.168.1.100', '142.250.190.48', 'www.google.com', 1200)
pkt7 = pkt7[:34] + struct.pack('>H', 10007) + pkt7[36:]
demo_packets.append((ts_sec, ts_usec, pkt7))

write_pcap('samples/flowgate-demo.pcap', demo_packets)
print("Generated samples/flowgate-demo.pcap")


# ==========================================
# 2. GENERATE BASELINE.PCAP
# ==========================================
# A much larger, interleaved PCAP for system load testing
baseline_packets = []
b_ts_usec = 0
for i in range(5000): # 5000 packets
    ip_end = (i % 50) + 1 # 50 concurrent IPs (10.0.0.1 to 10.0.0.50)
    src = f"10.0.0.{ip_end}"
    if i % 3 == 0:
        pkt = make_tcp_syn(src, "8.8.8.8")
    elif i % 5 == 0:
        pkt = make_tcp_http(src, "1.1.1.1", "cloudflare.com", 800)
    else:
        pkt = make_tcp_http(src, "2.2.2.2", "www.facebook.com", 1500)
    
    baseline_packets.append((ts_sec, b_ts_usec, pkt))
    b_ts_usec += 500 # 0.5ms apart

write_pcap('samples/baseline.pcap', baseline_packets)
print("Generated samples/baseline.pcap (5000 packets)")
