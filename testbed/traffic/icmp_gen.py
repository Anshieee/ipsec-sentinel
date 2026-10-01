#!/usr/bin/env python3
"""ICMP ping traffic generator.
Simulates ICMP echo requests for v4 and v6.
"""
import argparse
import time
from scapy.all import IP, ICMP, IPv6, wrpcap, conf

conf.verbose = 0

def generate_icmp_traffic(target: str, duration: int, variant: str, output: str):
    """Generate ICMP ping traffic."""
    print(f"[icmp] Generating ICMP traffic to {target} for {duration}s")

    packets = []
    start_time = time.time()
    seq = 0

    while time.time() - start_time < duration:
        if ":" in target:
            # IPv6
            pkt = IPv6(src="fd00:1::10", dst=target) / \
                  ICMPv6EchoRequest()
        else:
            # IPv4
            pkt = IP(src="10.1.0.10", dst=target) / \
                  ICMP(type=8, code=0, id=0x1234, seq=seq)
        packets.append(pkt)
        seq += 1
        time.sleep(1.0)

    wrpcap(output, packets)
    print(f"[icmp] Captured {len(packets)} packets to {output}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ICMP ping generator")
    parser.add_argument("--variant", default="v1", help="Test variant")
    parser.add_argument("--duration", type=int, default=10, help="Duration in seconds")
    parser.add_argument("--target", required=True, help="Remote IP address")
    parser.add_argument("--output", required=True, help="Output PCAP file")
    args = parser.parse_args()

    generate_icmp_traffic(args.target, args.duration, args.variant, args.output)
