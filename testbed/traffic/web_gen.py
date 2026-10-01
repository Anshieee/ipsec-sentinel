#!/usr/bin/env python3
"""HTTP/HTTPS web traffic generator.
Simulates web browsing to nginx endpoints.
"""
import argparse
import random
import time
from scapy.all import IP, TCP, Raw, wrpcap, conf

conf.verbose = 0

def generate_web_traffic(target: str, duration: int, variant: str, output: str):
    """Generate HTTP/HTTPS web traffic."""
    print(f"[web] Generating web traffic to {target} for {duration}s")

    packets = []
    start_time = time.time()
    paths = ["/", "/index.html", "/api/data", "/page1", "/page2", "/assets/style.css"]

    while time.time() - start_time < duration:
        port = random.choice([80, 443])
        path = random.choice(paths)

        if port == 80:
            request = f"GET {path} HTTP/1.1\r\nHost: {target}\r\nConnection: keep-alive\r\n\r\n".encode()
        else:
            # TLS-like
            request = bytes([0x16, 0x03, 0x03]) + random.randbytes(random.randint(100, 800))

        pkt = IP(src="10.1.0.10", dst=target) / \
              TCP(sport=random.randint(49152, 65535), dport=port) / \
              Raw(load=request)
        packets.append(pkt)

        time.sleep(random.uniform(0.5, 2.0))

    wrpcap(output, packets)
    print(f"[web] Captured {len(packets)} packets to {output}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Web traffic generator")
    parser.add_argument("--variant", default="v1", help="Test variant")
    parser.add_argument("--duration", type=int, default=10, help="Duration in seconds")
    parser.add_argument("--target", required=True, help="Remote IP address")
    parser.add_argument("--output", required=True, help="Output PCAP file")
    args = parser.parse_args()

    generate_web_traffic(args.target, args.duration, args.variant, args.output)