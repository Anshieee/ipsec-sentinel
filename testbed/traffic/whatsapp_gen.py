#!/usr/bin/env python3
"""WhatsApp-like TLS traffic generator.
Simulates TLS on 443 with WhatsApp-like patterns.
"""
import argparse
import random
import time
from scapy.all import IP, TCP, Raw, wrpcap, conf

conf.verbose = 0

def generate_whatsapp_traffic(target: str, duration: int, variant: str, output: str):
    """Generate WhatsApp-like TLS traffic."""
    print(f"[whatsapp] Generating WhatsApp-like TLS traffic to {target} for {duration}s")

    packets = []
    start_time = time.time()

    while time.time() - start_time < duration:
        # TLS record: application data
        tls_header = bytes([0x17, 0x03, 0x03])
        payload_len = random.randint(50, 1000)
        tls_data = tls_header + bytes([payload_len >> 8, payload_len & 0xFF]) + random.randbytes(payload_len)

        pkt = IP(src="10.1.0.10", dst=target) / \
              TCP(sport=random.randint(49152, 65535), dport=443, flags="PA") / \
              Raw(load=tls_data)
        packets.append(pkt)

        # Bursty pattern: several packets then pause
        for _ in range(random.randint(2, 5)):
            tls_data = tls_header + bytes([payload_len >> 8, payload_len & 0xFF]) + random.randbytes(payload_len)
            pkt = IP(src="10.1.0.10", dst=target) / \
                  TCP(sport=random.randint(49152, 65535), dport=443, flags="PA") / \
                  Raw(load=tls_data)
            packets.append(pkt)

        time.sleep(random.uniform(0.05, 0.2))

    wrpcap(output, packets)
    print(f"[whatsapp] Captured {len(packets)} packets to {output}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WhatsApp-like TLS traffic generator")
    parser.add_argument("--variant", default="v1", help="Test variant")
    parser.add_argument("--duration", type=int, default=10, help="Duration in seconds")
    parser.add_argument("--target", required=True, help="Remote IP address")
    parser.add_argument("--output", required=True, help="Output PCAP file")
    args = parser.parse_args()

    generate_whatsapp_traffic(args.target, args.duration, args.variant, args.output)