#!/usr/bin/env python3
"""telnet_shell.py - log into the BK7252 camera's telnet ROOT shell on TCP 20023
using the password recovered from firmware ("123"), then optionally run a recon
batch and a video_buffer probe, saving EVERYTHING to logs/ for later analysis.

Reuses the Telnet IAC negotiation from probe_telnet.py (known to work against
this camera). The camera's finsh shell also spams ~460 B/s of unsolicited log
lines that interleave with command output - this tool does NOT try to filter
them (unlike camterm.py); it captures raw so nothing is lost. We sort it out
afterwards from the saved logs.

Run these WHILE JOINED TO THE CAMERA'S AP (LLM_HA10_06C095 / 12345678),
gateway/host 192.168.9.252:

    python tools/telnet_shell.py                 # 1) login test only (do this first)
    python tools/telnet_shell.py --identity      # pull did/signkey/lslat/scode, no reboot
    python tools/telnet_shell.py --recon         # 2) login + recon batch -> logs/
    python tools/telnet_shell.py --video         # 3) login + video_buffer probe -> logs/
    python tools/telnet_shell.py --interactive   # type commands yourself; /quit to exit
    python tools/telnet_shell.py --send "ps"     # run one command and print the reply

--identity is the one for pulling many units' keys fast (see [[bk7252-per-
device-secret]] memory / docs/protocol.md): the camera's [iot] identity
block (did/signkey/lslat/scode/gdomain/gipaddr) sits as plain ASCII at a
fixed raw-flash offset (0x1F5000, confirmed live 2026-08-30), so `fal read
0x1f5000 512` returns it directly - no reboot needed, no serial, no case-
opening, purely over WiFi+telnet. --identity runs that read, parses the hex
dump, and APPENDS one JSON line per camera to logs/identities.jsonl (keyed
by did) so running it once per unit builds a running inventory - just join
each camera's own AP in turn and re-run.

Options:
    --host 192.168.9.252   --port 20023   --password 123
    --idle 1.2   (seconds of silence that marks a command's reply complete)

Exit code 0 = logged in OK, non-zero = login failed / no connection.
"""
import argparse
import json
import os
import re
import socket
import sys
import time
from datetime import datetime

IAC, DONT, DO, WONT, WILL = 255, 254, 253, 252, 251
OPT_NAMES = {0: "BINARY", 1: "ECHO", 3: "SUPPRESS-GA", 24: "TTYPE", 31: "NAWS", 32: "TSPEED"}

HERE = os.path.dirname(os.path.abspath(__file__))
LOGDIR = os.path.join(os.path.dirname(HERE), "logs")

# Commands run by --recon. Each saved with a header. Purpose in the comment.
RECON_CMDS = [
    "help",                      # full command list (ground truth)
    "ps",                        # threads/tasks
    "free",                      # memory
    "list_device",              # RT-Thread device objects (sensors, sd, etc.)
    "list_fd",                   # open file descriptors / sockets
    "netstat",                   # listening/active sockets
    "ifconfig",                  # interfaces + IPs
    "dns",                       # resolver state
    "df",                        # filesystems / mounts
    "date",                      # clock
    "ls /",                      # root fs
    "ls /appfs",                 # <-- where wifi creds / settings live
    "cat /appfs/setting.json",   # <-- current stored SSID/Key/Mode
    "ls /flash0",
    "ls /flash1",
    "ls /sd",                    # microSD (was failing to init - check)
    "df /sd",
]


def negotiate_reply(seq):
    cmd, opt = seq[1], seq[2]
    if cmd == WILL:
        return bytes([IAC, DO, opt])
    if cmd == WONT:
        return bytes([IAC, DONT, opt])
    if cmd in (DO, DONT):
        return bytes([IAC, WONT, opt])
    return b""


def strip_and_negotiate(sock, data):
    """Consume IAC triples (auto-replying), return the plaintext underneath."""
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i] == IAC and i + 2 < len(data):
            reply = negotiate_reply(data[i:i + 3])
            if reply:
                try:
                    sock.sendall(reply)
                except OSError:
                    pass
            i += 3
        else:
            out.append(data[i])
            i += 1
    return bytes(out)


def drain(sock, idle=2.0, first_byte=45.0, hard_timeout=120.0):
    """Read until `idle` seconds of silence AFTER data starts arriving.

    The camera's telnet FREEZES for long stretches (up to ~30s) while its
    lwIP network thread is blocked doing dead cloud-connect retries
    (iot.dev.glbs, every 8-15s), then flushes everything in a burst. So we
    wait up to `first_byte` seconds for the FIRST byte, and only then use the
    short `idle` gap to detect the end. `hard_timeout` is the overall cap.
    Returns raw bytes with IAC already stripped/answered."""
    chunks = bytearray()
    start = time.time()
    sock.settimeout(0.5)
    got_data = False
    last = time.time()
    while True:
        try:
            b = sock.recv(4096)
            if b:
                chunks += strip_and_negotiate(sock, b)
                got_data = True
                last = time.time()
            else:
                break  # peer closed
        except socket.timeout:
            now = time.time()
            if got_data and now - last >= idle:
                break
            if not got_data and now - start >= first_byte:
                break
            if now - start >= hard_timeout:
                break
        except OSError:
            break
    return bytes(chunks)


def connect_and_login(host, port, password, idle):
    print("[*] connecting to %s:%d ..." % (host, port))
    print("    NOTE: the shell freezes for up to ~30s at a time while the camera")
    print("    blocks on dead cloud-retry connects, then bursts. This is normal -")
    print("    the script now WAITS through the freezes. Recon may take a few min.")
    try:
        s = socket.create_connection((host, port), timeout=5)
    except OSError as e:
        print("[!] connect failed: %s" % e)
        print("    - are you joined to the camera's AP (LLM_HA10_06C095)?")
        print("    - is the host right? gateway is usually 192.168.9.252")
        return None
    banner = drain(s, idle=idle)
    sys.stdout.write(_show(banner))
    # Nudge, then send the password.
    s.sendall(b"\r\n")
    time.sleep(0.3)
    banner += drain(s, idle=idle)
    print("[*] sending password %r" % password)
    s.sendall(password.encode() + b"\r\n")
    time.sleep(0.3)
    resp = drain(s, idle=idle)
    sys.stdout.write(_show(resp))
    low = resp.lower()
    if b"wrong password" in low:
        print("\n[!] LOGIN FAILED - camera said 'Wrong password'. "
              "Firmware analysis says the password is '123'; if that's rejected, "
              "tell me and we re-check the Ghidra finding.")
        s.close()
        return None
    # Success signal: an msh prompt, or simply no rejection. Confirm with a ping cmd.
    s.sendall(b"\r\n")
    probe = drain(s, idle=idle, first_byte=8.0, hard_timeout=20.0)
    if b"msh" in (resp + probe).lower() or b">" in (resp + probe):
        print("\n[+] LOGIN OK - you have the finsh root shell over the network.")
    else:
        print("\n[?] Sent password, no explicit rejection but no clear msh prompt "
              "either. Proceeding; check the saved log to confirm.")
    return s


def _show(b):
    """Printable view of raw bytes for the console."""
    try:
        return b.decode("utf-8", "replace")
    except Exception:
        return repr(b)


def run_cmd(sock, cmd, idle=2.0, first_byte=45.0, hard_timeout=90.0):
    sock.sendall(cmd.encode() + b"\r\n")
    time.sleep(0.2)
    return drain(sock, idle=idle, first_byte=first_byte, hard_timeout=hard_timeout)


def do_recon(sock, idle):
    os.makedirs(LOGDIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = os.path.join(LOGDIR, "telnet-recon-%s.log" % ts)
    with open(path, "w", encoding="utf-8", errors="replace") as f:
        for cmd in RECON_CMDS:
            print("[*] %s" % cmd)
            out = run_cmd(sock, cmd, idle)
            f.write("\n===== $ %s =====\n" % cmd)
            f.write(_show(out))
            f.flush()
    print("[+] recon saved to %s" % path)
    print("    (bring this back - it has setting.json, the /appfs listing, SD "
          "status, list_device, netstat, etc.)")


def do_video(sock, idle):
    """Probe whether video_buffer can be pulled over the (fast) WiFi link.
    Serial (11 KB/s) drowned in the ~300 KB/s stream; WiFi may keep up. We do
    NOT try to rebuild JPEGs here - just measure what read returns, raw."""
    os.makedirs(LOGDIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    txt = os.path.join(LOGDIR, "telnet-video-%s.log" % ts)
    with open(txt, "w", encoding="utf-8", errors="replace") as f:
        for cmd in ["video_buffer", "video_buffer open"]:
            out = run_cmd(sock, cmd, idle)
            f.write("\n===== $ %s =====\n" % cmd)
            f.write(_show(out))
            print("[*] %s ->\n%s" % (cmd, _show(out)))
        # Hammer read a number of times, capture sizes + any frame markers.
        total = 0
        for i in range(40):
            out = run_cmd(sock, "video_buffer read 4096",
                          idle=0.4, first_byte=6.0, hard_timeout=10.0)
            total += len(out)
            has_jpeg = b"\xff\xd8" in out  # JPEG SOI marker
            f.write("\n----- read #%d len=%d jpeg_soi=%s -----\n"
                    % (i, len(out), has_jpeg))
            f.write(repr(out))
            if has_jpeg:
                print("[+] read #%d: %d bytes, JPEG start-of-image marker PRESENT" % (i, len(out)))
            else:
                print("[ ] read #%d: %d bytes" % (i, len(out)))
        run_cmd(sock, "video_buffer close", idle)
    print("[+] video probe saved to %s (total %d bytes captured)" % (txt, total))
    print("    If any read shows 'jpeg_soi=True' / real bytes instead of "
          "'vbuf full!' / 'ret: -5', video-over-telnet is viable - bring it back.")


IDENTITY_OFFSET = 0x1F5000   # raw flash, confirmed live 2026-08-30 (logs/20260830-220350-run.log)
IDENTITY_LEN = 512
_HEXLINE_RE = re.compile(r"\[([0-9A-Fa-f]+)\]((?:\s[0-9A-Fa-f]{2}){1,16})")


def parse_fal_hexdump(text, base_offset, length):
    """Reconstruct raw bytes from `fal read` hexdump output. Keys each row by
    its own printed offset (not line order), so interleaved log spam
    (docs/flash-dump.md - ~460 B/s that can't be silenced) corrupting or
    reordering a line just leaves a gap rather than misaligning everything.
    Missing bytes are filled with 0x00. Returns (bytes, n_bytes_recovered)."""
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    buf = bytearray(length)
    got = bytearray(length)  # 1 where we actually have a byte
    n = 0
    for m in _HEXLINE_RE.finditer(text):
        off = int(m.group(1), 16) - base_offset
        byte_toks = m.group(2).split()
        for i, tok in enumerate(byte_toks):
            pos = off + i
            if 0 <= pos < length:
                buf[pos] = int(tok, 16)
                if not got[pos]:
                    got[pos] = 1
                    n += 1
    return bytes(buf), n


_ID_FIELD_RE = re.compile(r"^(did|signkey|lslat|scode|gdomain|gipaddr)\s*=\s*(.+?)\s*$",
                          re.MULTILINE)


def parse_identity(raw_bytes):
    """Extract the [iot] key=value fields from the reconstructed flash bytes.
    Stops at the first 0xFF (erased-flash padding right after the block)."""
    ff = raw_bytes.find(b"\xff")
    text = raw_bytes[:ff if ff >= 0 else len(raw_bytes)].decode("ascii", "replace")
    fields = dict(_ID_FIELD_RE.findall(text))
    return fields


def do_identity(sock, idle, host):
    """Pull did/signkey/lslat/scode via `fal read` (no reboot) and append a
    record to logs/identities.jsonl. Retries once with an explicit `fal
    probe` if the first read comes back empty (in case this build/unit needs
    a partition probed first - see docs/flash-dump.md)."""
    out = run_cmd(sock, "fal read 0x%x %d" % (IDENTITY_OFFSET, IDENTITY_LEN), idle)
    raw, n = parse_fal_hexdump(out, IDENTITY_OFFSET, IDENTITY_LEN)
    fields = parse_identity(raw) if n else {}
    if not fields.get("did"):
        print("[!] first read got %d/%d bytes and no 'did' field - retrying "
              "with an explicit `fal probe beken_onchip` first..." % (n, IDENTITY_LEN))
        run_cmd(sock, "fal probe beken_onchip", idle)
        out2 = run_cmd(sock, "fal read 0x%x %d" % (IDENTITY_OFFSET, IDENTITY_LEN), idle)
        raw2, n2 = parse_fal_hexdump(out2, IDENTITY_OFFSET, IDENTITY_LEN)
        fields2 = parse_identity(raw2) if n2 else {}
        if fields2.get("did"):
            out, raw, n, fields = out2, raw2, n2, fields2

    os.makedirs(LOGDIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    rawlog = os.path.join(LOGDIR, "telnet-identity-%s.log" % ts)
    with open(rawlog, "w", encoding="utf-8", errors="replace") as f:
        f.write("===== $ fal read 0x%x %d =====\n" % (IDENTITY_OFFSET, IDENTITY_LEN))
        f.write(_show(out))

    if not fields.get("did"):
        print("[!] could not parse an identity block (%d/%d bytes recovered). "
              "Raw shell output saved to %s - check it by hand; the offset "
              "may differ on this unit/build, or the read got interleaved "
              "with too much log spam (retry, or raise --idle)." % (n, IDENTITY_LEN, rawlog))
        return None

    record = dict(fields)
    record["_host"] = host
    record["_captured"] = ts
    jsonl = os.path.join(LOGDIR, "identities.jsonl")
    with open(jsonl, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

    print("\n[+] IDENTITY (%d/%d bytes, raw -> %s, appended -> %s):" %
          (n, IDENTITY_LEN, rawlog, jsonl))
    for k in ("did", "signkey", "lslat", "scode"):
        print("    %-8s = %s" % (k, fields.get(k, "(missing)")))
    return record


def interactive(sock, idle):
    print("[*] interactive shell. Type commands; /quit to exit, /raw shows bytes.")
    while True:
        try:
            line = input("cam> ")
        except (EOFError, KeyboardInterrupt):
            break
        if line.strip() in ("/quit", "/q", "exit"):
            break
        out = run_cmd(sock, line, idle)
        sys.stdout.write(_show(out))
        sys.stdout.write("\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="192.168.9.252")
    ap.add_argument("--port", type=int, default=20023)
    ap.add_argument("--password", default="123")
    ap.add_argument("--idle", type=float, default=2.0,
                    help="seconds of silence marking a reply complete")
    ap.add_argument("--identity", action="store_true",
                    help="pull did/signkey/lslat/scode via `fal read` (no reboot) "
                         "and append to logs/identities.jsonl")
    ap.add_argument("--recon", action="store_true", help="run the recon batch")
    ap.add_argument("--video", action="store_true", help="run the video_buffer probe")
    ap.add_argument("--interactive", action="store_true", help="type commands yourself")
    ap.add_argument("--send", metavar="CMD", help="run one command and print the reply")
    a = ap.parse_args()

    s = connect_and_login(a.host, a.port, a.password, a.idle)
    if s is None:
        return 1
    try:
        if a.send:
            sys.stdout.write(_show(run_cmd(s, a.send, a.idle)))
            sys.stdout.write("\n")
        if a.identity:
            do_identity(s, a.idle, a.host)
        if a.recon:
            do_recon(s, a.idle)
        if a.video:
            do_video(s, a.idle)
        if a.interactive:
            interactive(s, a.idle)
        if not (a.send or a.identity or a.recon or a.video or a.interactive):
            print("\n[i] Login-only run. Re-run with --recon then --video, or "
                  "--interactive. Nothing else sent.")
    finally:
        try:
            s.close()
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
