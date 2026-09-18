import struct
import time

def write_pcap(filename, packets):
    global_header = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    with open(filename, 'wb') as f:
        f.write(global_header)
        for ts_sec, ts_usec, data in packets:
            f.write(struct.pack('<IIII', ts_sec, ts_usec, len(data), len(data)))
            f.write(data)

def make_eth_ip(src_ip, dst_ip, proto, total_len):
    eth = b'\x00\x11\x22\x33\x44\x55' + b'\x66\x77\x88\x99\xaa\xbb' + b'\x08\x00'
    vihl = (4 << 4) | 5
    src_bytes = bytes(map(int, src_ip.split('.')))
    dst_bytes = bytes(map(int, dst_ip.split('.')))
    ip_header = struct.pack('>BBHHHBBH4s4s', vihl, 0, total_len, 1234, 0, 64, proto, 0, src_bytes, dst_bytes)
    return eth + ip_header

def make_tcp_http(src_ip, dst_ip, host_str, src_port, pad_to_length):
    payload = f"GET / HTTP/1.1\r\nHost: {host_str}\r\n\r\n".encode('utf-8')
    padding = b'X' * max(0, pad_to_length - (14 + 20 + 20 + len(payload)))
    payload += padding
    total_ip_len = 20 + 20 + len(payload)
    base = make_eth_ip(src_ip, dst_ip, 6, total_ip_len)
    tcp_header = struct.pack('>HHIIBBHHH', src_port, 80, 100, 200, (5 << 4), 0x18, 8192, 0, 0)
    return base + tcp_header + payload

ts_sec = int(time.time())
ts_usec = 0

demo_packets = []
# All packets are 600B. Total 7 * 600 = 4200B.
# Usages produced will be 600, 1200, 1800, 2400, 3000, 3600, 4200 regardless of concurrency.
# States: NORMAL, NORMAL, WARNING, THROTTLE, THROTTLE, THROTTLE, HARD_DROP.

p1 = make_tcp_http('192.168.1.100', '15.15.15.15',      'whatsapp.com',   10001, 600)
demo_packets.append((ts_sec, ts_usec, p1)); ts_usec += 1000

p2 = make_tcp_http('192.168.1.100', '142.250.190.46',   'www.google.com', 10002, 600)
demo_packets.append((ts_sec, ts_usec, p2)); ts_usec += 1000

p3 = make_tcp_http('192.168.1.100', '35.153.120.20',    'www.netflix.com',10003, 600)
demo_packets.append((ts_sec, ts_usec, p3)); ts_usec += 1000

p4 = make_tcp_http('192.168.1.100', '142.250.190.47',   'mail.google.com',10004, 600)
demo_packets.append((ts_sec, ts_usec, p4)); ts_usec += 1000

p5 = make_tcp_http('192.168.1.100', '104.154.120.20',   'www.spotify.com',10005, 600)
demo_packets.append((ts_sec, ts_usec, p5)); ts_usec += 1000

p6 = make_tcp_http('192.168.1.100', '142.250.190.48',   'pay.google.com', 10006, 600)
demo_packets.append((ts_sec, ts_usec, p6)); ts_usec += 1000

# Same flow as p2
p7 = make_tcp_http('192.168.1.100', '142.250.190.46',   'www.google.com', 10002, 600)
demo_packets.append((ts_sec, ts_usec, p7))

write_pcap('samples/flowgate-demo.pcap', demo_packets)
print("Generated samples/flowgate-demo.pcap (7x 600B)")
