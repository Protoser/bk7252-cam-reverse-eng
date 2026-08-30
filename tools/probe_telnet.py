#!/usr/bin/env python3
"""probe_telnet.py - poke the pwd>> prompt on TCP 20023 (Telnet-like) and
sanity-check TCP 20190 (the pprpc/KCP video port, expected to stay silent).

Handles the minimal Telnet IAC option negotiation the camera performs
(WILL SUPPRESS-GO-AHEAD, WILL ECHO) by auto-agreeing (DO) to whatever it
proposes, then reads/writes the plaintext underneath.

Usage:
    python tools/probe_telnet.py                  # negotiate + dump the prompt, exit
    python tools/probe_telnet.py --try-passwords   # also try a short candidate list
    python tools/probe_telnet.py --send "foo"      # send one line after the prompt
"""
import argparse
import socket
import sys
import time

HOST = "10.97.112.171"
TELNET_PORT = 20023
VIDEO_PORT = 20190

IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240
OPT_NAMES = {0: "BINARY", 1: "ECHO", 3: "SUPPRESS-GA", 24: "TTYPE", 31: "NAWS", 32: "TSPEED"}


def negotiate_reply(iac_seq):
    """Given a raw IAC WILL/WONT/DO/DONT <opt> triple, build our reply.
    We agree to everything (DO to WILL, WONT to DO) - simplest way to get
    past negotiation and see the plaintext prompt underneath."""
    cmd, opt = iac_seq[1], iac_seq[2]
    name = OPT_NAMES.get(opt, str(opt))
    if cmd == WILL:
        return bytes([IAC, DO, opt]), "WILL %s -> DO" % name
    if cmd == WONT:
        return bytes([IAC, DONT, opt]), "WONT %s -> DONT" % name
    if cmd == DO:
        return bytes([IAC, WONT, opt]), "DO %s -> WONT" % name
    if cmd == DONT:
        return bytes([IAC, WONT, opt]), "DONT %s -> WONT" % name
    return b"", "?"


def strip_and_negotiate(sock, data, verbose=True):
    """Consume IAC sequences from data, auto-replying to each, and return
    the remaining plaintext bytes."""
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i] == IAC and i + 2 < len(data):
            seq = data[i:i + 3]
            reply, desc = negotiate_reply(seq)
            if verbose:
                print("  [telnet] server: %s  ->  us: %s" % (seq.hex(" "), desc))
            if reply:
                sock.sendall(reply)
            i += 3
        else:
            out.append(data[i])
            i += 1
    return bytes(out)


def recv_some(sock, timeout=1.5, maxlen=4096):
    sock.settimeout(timeout)
    try:
        return sock.recv(maxlen)
    except socket.timeout:
        return b""
    except ConnectionError:
        return b""


def probe_video_port():
    print("=== TCP %d (video/pprpc, expected silent) ===" % VIDEO_PORT)
    try:
        s = socket.create_connection((HOST, VIDEO_PORT), timeout=3)
    except OSError as e:
        print("  connect failed: %s" % e)
        return
    first = recv_some(s, 1.0)
    print("  server spoke first: %s" % (first.hex(" ") if first else "(nothing)"))
    s.sendall(b"\x00" * 32)
    reply = recv_some(s, 1.0)
    print("  after 32 nulls: %s" % (reply.hex(" ") if reply else "(nothing / closed)"))
    s.close()
    print()


def probe_telnet_port(passwords=None, one_shot_send=None):
    print("=== TCP %d (telnet-like login) ===" % TELNET_PORT)
    s = socket.create_connection((HOST, TELNET_PORT), timeout=3)

    banner = recv_some(s, 1.5)
    plain = strip_and_negotiate(s, banner)
    if plain:
        print("  plaintext so far: %r" % plain)

    # Sending anything (even empty-ish) seems to trigger the next batch of
    # negotiation + the "pwd>>" text, per the earlier probe. Nudge it.
    s.sendall(b"\r\n")
    time.sleep(0.3)
    more = recv_some(s, 1.5)
    plain += strip_and_negotiate(s, more)
    print("  prompt text: %r" % plain)

    if one_shot_send is not None:
        print("  sending: %r" % one_shot_send)
        s.sendall(one_shot_send.encode() + b"\r\n")
        time.sleep(0.4)
        resp = recv_some(s, 1.5)
        resp_plain = strip_and_negotiate(s, resp)
        print("  response: %r" % resp_plain)
        s.close()
        return

    if passwords:
        for pw in passwords:
            print("  --- trying %r ---" % pw)
            s.sendall(pw.encode() + b"\r\n")
            time.sleep(0.5)
            resp = recv_some(s, 1.5)
            resp_plain = strip_and_negotiate(s, resp)
            print("  response: %r" % resp_plain)
            # Reconnect between attempts in case a wrong password drops the
            # session or the server rate-limits on the same socket.
            if resp_plain and (b"pwd" not in resp_plain.lower() and b">>" not in resp_plain):
                print("  ^ looks different from a re-prompt - stopping here")
                break
            try:
                s.close()
                s = socket.create_connection((HOST, TELNET_PORT), timeout=3)
                banner = recv_some(s, 1.0)
                strip_and_negotiate(s, banner, verbose=False)
                s.sendall(b"\r\n")
                time.sleep(0.3)
                nxt = recv_some(s, 1.0)
                strip_and_negotiate(s, nxt, verbose=False)
            except OSError as e:
                print("  reconnect failed: %s" % e)
                break

    s.close()
    print()


def main():
    global HOST
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--try-passwords", action="store_true",
                    help="try a short candidate list against the pwd>> prompt")
    ap.add_argument("--send", metavar="TEXT", help="send one line after the prompt and show the reply")
    ap.add_argument("--skip-video", action="store_true", help="skip the TCP 20190 sanity check")
    a = ap.parse_args()

    HOST = a.host

    if not a.skip_video:
        probe_video_port()

    candidates = None
    if a.try_passwords:
        candidates = [
            "", "admin", "12345", "123456", "888888", "666666",
            "password", "root", "guest",
            "HL4viXBiGEz8mCBkuhkTQFaK", "e7uJ6Q8uM7ikpUxf",
        ]
    probe_telnet_port(passwords=candidates, one_shot_send=a.send)


if __name__ == "__main__":
    sys.exit(main())
