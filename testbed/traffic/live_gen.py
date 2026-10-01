#!/usr/bin/env python3
"""Live traffic generators for the real testbed (spec M2 "Traffic generators").

Stdlib only (runs inside the testbed container, no scapy). Two roles:

    live_gen.py serve  <type>          # listener, run in the receiving netns
    live_gen.py send   <type> --duration N   # sender, run in the sending netns

Types (spec wording):
  voip      RTP-like UDP, 160 B payload, 20 ms interval
  video     UDP 1200-1400 B packets, bursty 2 s segments
  web       TCP request/response bursts (HTTP GET / TLS-like)
  email     SMTP session with occasional large attachments
  whatsapp  small bidirectional TLS-like records + sparse large media blobs
  icmp      ICMP echo, 64/512/1400 B payloads (uses `ping`)

Endpoints are chosen by the caller (testbed/scripts/real-run.sh): client
subnets for tunnel mode, gateway transit addresses for transport mode
(transport SAs only protect gw<->gw flows - see testbed/DESIGN.md 3).
"""
from __future__ import annotations

import argparse
import random
import socket
import subprocess
import sys
import time

SEED = None  # set per invocation from --seed (anti-leakage: per-run seeds)


def log(msg: str) -> None:
    print(f"[live:{msg}", flush=True)


def _rng(seed: int | None) -> random.Random:
    return random.Random(seed)


# ------------------------------------------------------------------ UDP sink
def serve_udp(port: int, duration: float) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.settimeout(0.5)
    end = time.time() + duration
    while time.time() < end:
        try:
            s.recv(65535)
        except socket.timeout:
            pass
    s.close()


# ------------------------------------------------------------------ TCP roles
def serve_tcp(kind: str, port: int, duration: float) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(8)
    srv.settimeout(0.5)
    end = time.time() + duration
    while time.time() < end:
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        conn.settimeout(2.0)
        try:
            if kind == "web":
                conn.recv(8192)
                conn.sendall(random.randbytes(random.randint(2048, 16384)))
            elif kind == "email":  # SMTP-ish server dialogue
                conn.sendall(b"220 mail.test ESMTP\r\n")
                deadline = time.time() + 5
                in_data = False
                while time.time() < deadline:
                    buf = b""
                    try:
                        buf = conn.recv(65535)
                    except socket.timeout:
                        break
                    if not buf:
                        break
                    if in_data:
                        if buf.rstrip().endswith(b"."):
                            in_data = False
                            conn.sendall(b"250 OK queued\r\n")
                        continue
                    u = buf.upper()
                    if u.startswith(b"EHLO") or u.startswith(b"HELO"):
                        conn.sendall(b"250-mail.test\r\n250 SIZE 26214400\r\n")
                    elif u.startswith(b"MAIL") or u.startswith(b"RCPT"):
                        conn.sendall(b"250 OK\r\n")
                    elif u.startswith(b"DATA"):
                        in_data = True
                        conn.sendall(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    elif u.startswith(b"QUIT"):
                        conn.sendall(b"221 bye\r\n")
                        break
                    else:
                        conn.sendall(b"250 OK\r\n")
            elif kind == "whatsapp":  # small echo records keep both dirs busy
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    conn.sendall(random.randbytes(random.randint(20, 120)))
        except OSError:
            pass
        finally:
            conn.close()
    srv.close()


# ------------------------------------------------------------------ senders
def send_voip(target: str, duration: float, rng: random.Random) -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    end, n, t = time.time() + duration, 0, time.time()
    while time.time() < end:
        s.sendto(rng.randbytes(160), (target, 5004))
        n += 1
        t += 0.020
        d = t - time.time()
        if d > 0:
            time.sleep(d)
    s.close()
    return n


def send_video(target: str, duration: float, rng: random.Random) -> int:
    """2 s segments: ~1 s of 1200-1400 B packets at 10 ms, then idle."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    end, n = time.time() + duration, 0
    while time.time() < end:
        seg_end = time.time() + 1.0
        while time.time() < seg_end and time.time() < end:
            s.sendto(rng.randbytes(rng.randint(1200, 1400)), (target, 5006))
            n += 1
            time.sleep(0.010)
        time.sleep(1.0)  # inter-segment gap (bursty)
    s.close()
    return n


def send_web(target: str, duration: float, rng: random.Random) -> int:
    paths = ["/", "/index.html", "/api/v1/items", "/static/app.js", "/img/hero.png"]
    n = 0
    end = time.time() + duration
    while time.time() < end:
        port = rng.choice([80, 443])
        try:
            c = socket.create_connection((target, port), timeout=3)
            c.settimeout(3.0)
            for _ in range(rng.randint(2, 5)):  # request/response burst (keep-alive)
                if port == 80:
                    req = f"GET {rng.choice(paths)} HTTP/1.1\r\nHost: test\r\nConnection: keep-alive\r\n\r\n"
                    c.sendall(req.encode())
                else:  # TLS client-hello-ish record
                    blob = rng.randbytes(rng.randint(200, 400))
                    c.sendall(bytes([0x16, 0x03, 0x01]) + len(blob).to_bytes(2, "big") + blob)
                if not c.recv(65535):
                    break  # server closed
                n += 1
            c.close()
        except OSError:
            pass
        time.sleep(rng.uniform(0.5, 2.0))
    return n


def tls_records(payload: bytes) -> bytes:
    """TLS-like record framing; chunks to <=16 KB per record (2-byte length)."""
    out = b""
    for i in range(0, len(payload), 16000):
        chunk = payload[i:i + 16000]
        out += bytes([0x17, 0x03, 0x03]) + len(chunk).to_bytes(2, "big") + chunk
    return out


def send_email(target: str, duration: float, rng: random.Random) -> int:
    n = 0
    end = time.time() + duration
    while time.time() < end:
        try:
            c = socket.create_connection((target, 25), timeout=5)
            f = c.makefile("rb")

            def rd():
                try:
                    f.readline()
                except OSError:
                    pass

            rd()  # greeting
            c.sendall(b"EHLO test\r\n"); rd()
            c.sendall(b"MAIL FROM:<a@test>\r\n"); rd()
            c.sendall(b"RCPT TO:<b@test>\r\n"); rd()
            c.sendall(b"DATA\r\n"); rd()
            body = b"Subject: hello\r\n\r\n" + rng.randbytes(rng.randint(200, 2000))
            if n % 3 == 2:  # occasional large attachment
                body += b"\r\n" + rng.randbytes(rng.randint(65536, 262144))
            c.sendall(body + b"\r\n.\r\n"); rd()
            c.sendall(b"QUIT\r\n")
            c.close()
            n += 1
        except OSError:
            pass
        time.sleep(rng.uniform(1.0, 3.0))
    return n


def send_whatsapp(target: str, duration: float, rng: random.Random) -> int:
    n = 0
    end = time.time() + duration
    try:
        c = socket.create_connection((target, 5222), timeout=5)
    except OSError:
        return 0
    c.settimeout(0.5)
    last_blob = time.time()
    while time.time() < end:
        c.sendall(tls_records(rng.randbytes(rng.randint(30, 300))))
        n += 1
        if time.time() - last_blob > rng.uniform(5.0, 8.0):
            c.sendall(tls_records(rng.randbytes(rng.randint(100000, 400000))))
            last_blob = time.time()
            n += 1
        try:
            c.recv(4096)  # small reply from the peer keeps it bidirectional
        except (socket.timeout, OSError):
            pass
        time.sleep(rng.uniform(0.1, 1.0))
    c.close()
    return n


def send_icmp(target: str, duration: float, rng: random.Random) -> int:
    n = 0
    end = time.time() + duration
    sizes = [64, 512, 1400]
    i = 0
    while time.time() < end:
        sz = sizes[i % len(sizes)]
        r = subprocess.run(
            ["ping", "-c", "1", "-W", "2", "-s", str(sz), target],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if r.returncode == 0:
            n += 1
        i += 1
        time.sleep(1.0)
    return n


SENDERS = {
    "voip": send_voip, "video": send_video, "web": send_web,
    "email": send_email, "whatsapp": send_whatsapp, "icmp": send_icmp,
}
UDP_PORT = {"voip": 5004, "video": 5006}
TCP_PORT = {"web": 80, "email": 25, "whatsapp": 5222}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("role", choices=["send", "serve"])
    ap.add_argument("type", choices=sorted(SENDERS))
    ap.add_argument("--target", help="receiver IP (send role)")
    ap.add_argument("--duration", type=float, default=10.0)
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()

    if args.role == "serve":
        if args.type == "icmp":
            log("serve icmp: no listener needed (kernel answers echo)")
            return 0
        if args.type in UDP_PORT:
            log(f"serve udp/{UDP_PORT[args.type]} {args.duration}s")
            serve_udp(UDP_PORT[args.type], args.duration)
        else:
            log(f"serve tcp/{TCP_PORT[args.type]} {args.duration}s")
            serve_tcp(args.type, TCP_PORT[args.type], args.duration)
        return 0

    if not args.target:
        ap.error("--target is required for send")
    n = SENDERS[args.type](args.target, args.duration, _rng(args.seed))
    log(f"send {args.type} -> {args.target}: {n} units in {args.duration}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
