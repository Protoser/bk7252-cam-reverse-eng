#!/usr/bin/env python3
"""cam_reach.py - one-shot reachability + handshake probe for a camera IP.

Answers "is the camera actually there and does it speak pprpc?" without the
video machinery. Tries, in order:
  1. TCP 20190: connect, send a HB, send LanAuth (token or secret), dump raw
  2. UDP 20190: send LanAuth, dump raw
  3. TCP 20023: connect (telnet control), dump banner
Prints raw bytes for everything so we can see partial/garbage replies too.

Usage:
  python tools/cam_reach.py --host 192.168.178.149 --cred cam.json
  python tools/cam_reach.py --host 192.168.178.149 --did <did> --secret <scode>
"""
import argparse
import hashlib
import json
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pprpc

CMD_LANAUTH = 0x0A5A


def pb_str(field, s):
    b = s.encode() if isinstance(s, str) else s
    return bytes([(field << 3) | 2]) + pprpc.encode_varint(len(b)) + b


def credential(did, secret, nonce):
    h = hashlib.md5(("%s-%s-%s" % (did, secret, nonce)).encode()).hexdigest()
    return "$%s$%s" % (nonce, h)


def hexdump(b, n=64):
    b = bytes(b)
    return b[:n].hex() + (" ...(%d more)" % (len(b) - n) if len(b) > n else "")


def probe_tcp(host, port, cred, did, timeout=4.0):
    print("\n=== TCP %s:%d ===" % (host, port))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect((host, port))
    except Exception as e:
        print("  connect FAILED: %s" % e)
        return
    print("  connected in %.2fs" % (time.time() - t0))

    # 1) heartbeat - some stacks answer HB even pre-auth
    try:
        s.sendall(pprpc.pack_hb())
        s.settimeout(1.5)
        try:
            r = s.recv(4096)
            print("  HB reply (%dB): %s" % (len(r), hexdump(r)))
        except socket.timeout:
            print("  HB: no reply")
    except Exception as e:
        print("  HB send error: %s" % e)

    # 2) LanAuth
    pkt = pprpc.pack_cmd(CMD_LANAUTH, pb_str(1, did) + pb_str(3, cred),
                         cmdseq=0, enctype=0, udp=False)
    print("  LanAuth req (%dB): %s" % (len(pkt), hexdump(pkt)))
    try:
        s.sendall(pkt)
        s.settimeout(timeout)
        total = b""
        try:
            while True:
                r = s.recv(4096)
                if not r:
                    break
                total += r
                if len(total) >= 4:
                    break
        except socket.timeout:
            pass
        if total:
            print("  LanAuth reply (%dB): %s" % (len(total), hexdump(total)))
        else:
            print("  LanAuth: NO REPLY (timeout)")
    except Exception as e:
        print("  LanAuth error: %s" % e)
    s.close()


def probe_udp(host, port, cred, did, timeout=3.0):
    print("\n=== UDP %s:%d ===" % (host, port))
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("", 0)); s.settimeout(timeout)
    pkt = pprpc.pack_cmd(CMD_LANAUTH, pb_str(1, did) + pb_str(3, cred),
                         cmdseq=0, enctype=0, udp=True)
    print("  LanAuth req (%dB): %s" % (len(pkt), hexdump(pkt)))
    try:
        s.sendto(pkt, (host, port))
        r, addr = s.recvfrom(4096)
        print("  reply from %s (%dB): %s" % (addr, len(r), hexdump(r)))
    except socket.timeout:
        print("  NO REPLY (timeout)")
    except Exception as e:
        print("  error: %s" % e)
    s.close()


def probe_telnet(host, port=20023, timeout=3.0):
    print("\n=== TCP %s:%d (telnet control) ===" % (host, port))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
    except Exception as e:
        print("  connect FAILED: %s" % e)
        return
    print("  connected")
    try:
        r = s.recv(4096)
        print("  banner (%dB): %r" % (len(r), r[:120]))
    except socket.timeout:
        print("  no banner")
    s.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--did", default="")
    ap.add_argument("--cred", help="token string or path to ble_provision JSON")
    ap.add_argument("--secret", help="raw scode (alternative to --cred)")
    ap.add_argument("--nonce", default="12345")
    ap.add_argument("--port", type=int, default=20190)
    a = ap.parse_args()

    did = a.did
    cred = a.cred
    if cred and os.path.isfile(cred):
        d = json.load(open(cred, encoding="utf-8"))
        cred = d.get("token") or d.get("cred")
        did = did or d.get("did", "")
        print("[*] loaded token from %s (did=%s)" % (a.cred, did))
    if not cred:
        if not (a.secret and did):
            ap.error("need --cred <token/json>, or --secret and --did")
        cred = credential(did, a.secret, a.nonce)
    print("[*] host=%s did=%s cred=%s" % (a.host, did, cred))

    probe_tcp(a.host, a.port, cred, did)
    probe_udp(a.host, a.port, cred, did)
    probe_telnet(a.host, 20023)
    print("\n[done] If TCP/UDP 20190 both time out but connect succeeds, the "
          "listener isn't the camera pprpc server (wrong IP?) or it isn't up "
          "yet. If telnet 20023 gives a banner, that IS the camera.")


if __name__ == "__main__":
    main()
