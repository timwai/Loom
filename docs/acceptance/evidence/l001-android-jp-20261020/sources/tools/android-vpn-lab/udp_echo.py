#!/usr/bin/env python3
"""Bounded laboratory echo endpoint; bind only the Android Docker gateway."""
import argparse
import json
import signal
import socket
import time

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--bind", required=True)
p.add_argument("--port", type=int, default=19999)
args = p.parse_args()
deadline = time.monotonic() + 1200
running = True


def stop(*_):
    global running
    running = False


signal.signal(signal.SIGTERM, stop)
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
    endpoint.bind((args.bind, args.port))
    endpoint.settimeout(0.5)
    print(json.dumps({"ready": True, "bind": args.bind, "port": args.port}), flush=True)
    while running and time.monotonic() < deadline:
        try:
            data, peer = endpoint.recvfrom(256)
        except socket.timeout:
            continue
        if data not in (b"LOOM-PROTECTED-ECHO", b"LOOM-UNPROTECTED-TUN-CANARY"):
            continue
        print(json.dumps({"payload": data.decode(), "peer": peer, "time": time.time()}), flush=True)
        endpoint.sendto(data, peer)
