#!/bin/sh
# ICMP traffic generator with mixed payload sizes
# Usage: icmp.sh <target> <duration> <variant> <output.pcap>

set -eu

TARGET="$1"
DURATION="$2"
VARIANT="$3"
OUTPUT="$4"

echo "[icmp] Generating ICMP traffic to $TARGET for ${DURATION}s (variant: $VARIANT)"

python3 -c "
import time
from scapy.all import IP, ICMP, IPv6, ICMPv6EchoRequest, wrpcap

conf = __import__('scapy.config').config.conf
conf.verbose = 0

packets = []
start = time.time()
seq = 0

while time.time() - start < $DURATION:
    if ':' in '$TARGET':
        pkt = IPv6(src='fd00:1::10', dst='$TARGET') / ICMPv6EchoRequest()
    else:
        size = [32, 64, 128, 256, 512, 1024][seq % 6]
        pkt = IP(src='10.1.0.10', dst='$TARGET') / ICMP(type=8, code=0, id=0x1234, seq=seq) / ('X' * size)
    packets.append(pkt)
    seq += 1
    time.sleep(1.0)

wrpcap('$OUTPUT', packets)
print(f'[icmp] Captured {len(packets)} packets to $OUTPUT')
"