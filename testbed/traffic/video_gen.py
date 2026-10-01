#!/usr/bin/env python3
"""Video streaming traffic generator.
Simulates chunked HTTP streaming (HLS/DASH-like).
"""
import argparse
import random
import time
from scapy.all import IP, TCP, Raw, wrpcap, conf

conf.verbose = 0

def generate_video_traffic(target: str, duration: int, variant: str, output: str):
    """Generate video streaming traffic."""
    print(f"[video] Generating video traffic to {target} for {duration}s")

    packets = []
    start_time = time.time()
    chunk_sizes = [4096, 8192, 16384, 32768]

    while time.time() - start_time < duration:
        chunk_size = random.choice(chunk_sizes)

        # HTTP GET for video chunk
        request = f"GET /video/chunk_{random.randint(1,100)}.ts HTTP/1.1\r\nHost: {target}\r\nRange: bytes=0-{chunk_size}\r\n\r\n".encode()

        pkt = IP(src="10.1.0.10", dst=target) / \
              TCP(sport=random.randint(49152, 65535), dport=80) / \
              Raw(load=request)
        packets.append(pkt)

        time.sleep(random.uniform(0.1, 0.5))

    wrpcap(output, packets)
    print(f"[video] Captured {len(packets)} packets to {output}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Video streaming traffic generator")
    parser.add_argument("--variant", default="v1", help="Test variant")
    parser.add_argument("--duration", type=int, default=10, help="Duration in seconds")
    parser.add_argument("--target", required=True, help="Remote IP address")
    parser.add_argument("--output", required=True, help="Output PCAP file")
    args = parser.parse_args()

    generate_video_traffic(args.target, args.duration, args.variant, args.output)