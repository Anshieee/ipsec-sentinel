#!/usr/bin/env python3
"""VoIP/RTP-like UDP traffic generator.
Simulates RTP streams at 64KB/s with 20ms intervals.
"""
import argparse
import time
from scapy.all import IP, UDP, Raw, wrpcap, conf

conf.verbose = 0

def generate_voip_traffic(target: str, duration: int, variant: str, output: str):
    """Generate VoIP/RTP-like UDP traffic."""
    packet_size = 160  # 64KB/s at 20ms
    interval = 0.020

    print(f"[voip] Generating VoIP traffic to {target} for {duration}s")

    packets = []
    start_time = time.time()
    seq = 0

    while time.time() - start_time < duration:
        rtp_payload = bytes([seq & 0xFF]) * packet_size
        pkt = IP(src="10.1.0.10", dst=target) / \
              UDP(sport=5004, dport=5004) / \
              Raw(load=rtp_payload)
        packets.append(pkt)
        seq += 1
        time.sleep(interval)

    wrpcap(output, packets)
    print(f"[voip] Captured {len(packets)} packets to {output}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VoIP traffic generator")
    parser.add_argument("--variant", default="v1", help="Test variant")
    parser.add_argument("--duration", type=int, default=10, help="Duration in seconds")
    parser.add_argument("--target", required=True, help="Remote IP address")
    parser.add_argument("--output", required=True, help="Output PCAP file")
    args = parser.parse_args()

    generate_voip_traffic(args.target, args.duration, args.variant, args.output)