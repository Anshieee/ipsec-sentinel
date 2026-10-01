#!/usr/bin/env python3
"""SMTP/IMAP email traffic generator.
Simulates email protocols via aiosmtpd/Dovecot-like endpoints.
"""
import argparse
import random
import time
from scapy.all import IP, TCP, Raw, wrpcap, conf

conf.verbose = 0

def generate_email_traffic(target: str, duration: int, variant: str, output: str):
    """Generate email traffic."""
    ports = [(25, "smtp"), (143, "imap"), (587, "smtps"), (993, "imaps")]

    print(f"[email] Generating email traffic to {target} for {duration}s")

    packets = []
    start_time = time.time()

    while time.time() - start_time < duration:
        port, protocol = random.choice(ports)

        if protocol in ("smtp", "smtps"):
            payload = f"EHLO client\r\nMAIL FROM:<sender@test.com>\r\nRCPT TO:<user@{target}>\r\nDATA\r\nSubject: Test Email\r\n\r\nTest body\r\n.\r\nQUIT\r\n".encode()
        else:
            payload = b"LOGIN user password\r\nLIST \"\" *\r\nRETR 1\r\nQUIT\r\n"

        pkt = IP(src="10.1.0.10", dst=target) / \
              TCP(sport=random.randint(49152, 65535), dport=port) / \
              Raw(load=payload)
        packets.append(pkt)

        time.sleep(random.uniform(1.0, 3.0))

    wrpcap(output, packets)
    print(f"[email] Captured {len(packets)} packets to {output}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Email traffic generator")
    parser.add_argument("--variant", default="v1", help="Test variant")
    parser.add_argument("--duration", type=int, default=10, help="Duration in seconds")
    parser.add_argument("--target", required=True, help="Remote IP address")
    parser.add_argument("--output", required=True, help="Output PCAP file")
    args = parser.parse_args()

    generate_email_traffic(args.target, args.duration, args.variant, args.output)