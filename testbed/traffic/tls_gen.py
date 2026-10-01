#!/usr/bin/env python3
"""TLS traffic generator.
Simulates WhatsApp-like TLS/443 traffic with variable-sized packets.
"""
import argparse
import random
import time
from scapy.all import IP, TCP, Raw, wrpcap, conf

conf.verbose = 0

def generate_tls_traffic(target: str, duration: int, variant: str, output: str):
    """Generate TLS-like traffic patterns."""
    print(f"[tls] Generating TLS traffic to {target} for {duration}s")

    packets = []
    start_time = time.time()

    # Simulate TLS handshake and application data
    while time.time() - start_time < duration:
        # TLS record layer
        tls_data = bytes([0x17, 0x03, 0x03]) + random.randbytes(random.randint(50, 500))

        pkt = IP(src="10.1.0.10", dst=target) / \
              TCP(sport=random.randint(49152, 65535), dport=443) / \
              Raw(load=tls_data)
        packets.append(pkt)

        # Variable inter-packet delay for realistic pattern
        time.sleep(random.uniform(0.01, 0.05))

    wrpcap(output, packets)
    print(f"[tls] Captured {len(packets)} packets to {output}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TLS traffic generator")
    parser.add_argument("--variant", default="v1", help="Test variant")
    parser.add_argument("--duration", type=int, default=10, help="Duration in seconds")
    parser.add_argument("--target", required=True, help="Remote IP address")
    parser.add_argument("--output", required=True, help="Output PCAP file")
    args = parser.parse_args()

    generate_tls_traffic(args.target, args.duration, args.variant, args.output)
