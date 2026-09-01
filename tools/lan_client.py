#!/usr/bin/env python3
"""lan_client.py - the from-scratch LAN client (option B). Full pprpc handshake
over TCP (the video path; UDP yields conn_id=-2 and cannot stream):

    connect 20190 (no UDP magic)
      -> LanAuth_Req   (cmd 0x0a5a)  credential "$<nonce>$<md5(did-secret-nonce)>"
      <- LanAuth_Resp
      -> SyncConn_Req  (cmd 0x6a)
      <- SyncConn_Resp     (device conn->state becomes 3 = streaming gate open)
      -> VideoPlay_Req (cmd 0x0a32) channel 0
      <- AV frames (pprpc type 6)

The LanAuth secret (identity_struct+0x120, "scode" per firmware) is the one
unknown. Pass it with --secret; sweep a wordlist with --secret-file. A COM5
SerialTap reads the firmware's own "local check auth1 OK!" / "check LanAuth NO
PASS!" so each candidate gets a definitive verdict from the device itself.

    # single try (default secret = captured scode):
    python tools/lan_client.py --secret 307953
    # sweep candidates, stop at first PASS:
    python tools/lan_client.py --secret-file cand.txt
    # on PASS, continue to video and dump frames:
    python tools/lan_client.py --secret <good> --video --out cap.mjpeg
"""
import argparse
import hashlib
import json
import os
import io
import socket
import sys
import time

sys.path.insert(0, "tools")
import pprpc
import av

HOST = "192.168.178.147"
PORT = 20190
DID = "PPHA1006C0955E8FD9"
CRED_OVERRIDE = None   # if set, used verbatim as the LanAuth credential
                       # (e.g. the "$L<idx>$<hash>" token from ble_provision);
                       # bypasses credential()/scode entirely.

CMD_LANAUTH = 0x0A5A
CMD_SYNCCONN = 0x6A
CMD_VIDEOPLAY = 0x0A32
CMD_VIDEOPAUSE = 0x0A33

VIDEO_SECS = 6.0        # how long to capture the AV stream per attempt in --video mode
VIDEO_RETRIES = 3       # retries on a 0-frame capture (see docs/protocol.md "Why --video
                        # sometimes captures 0 frames" - it's a server-side congestion/health
                        # drop, not a parsing bug, so a fresh connection is the actual fix)
VIDEO_RETRY_WAIT = 1.0  # seconds to wait between retries


def pb_str(field, s):
    b = s.encode() if isinstance(s, str) else s
    return bytes([(field << 3) | 2]) + pprpc.encode_varint(len(b)) + b


def pb_varint(field, n):
    return bytes([(field << 3) | 0]) + pprpc.encode_varint(n)


def credential(did, secret, nonce):
    h = hashlib.md5(("%s-%s-%s" % (did, secret, nonce)).encode()).hexdigest()
    return "$%s$%s" % (nonce, h)


class SerialTap:
    """Reads COM5 so we see the firmware's own auth verdict for each attempt."""
    def __init__(self, port="COM5", baud=115200):
        self.buf = bytearray()
        self.ser = None
        try:
            import serial
            self.ser = serial.Serial(port, baud, timeout=0.1)
        except Exception as e:
            print("[serial] unavailable (%s) - no on-device oracle" % e)

    def drain(self):
        if self.ser:
            try:
                self.buf += self.ser.read(65536)
            except Exception:
                pass

    def verdict(self):
        """Return 'PASS' / 'NOPASS' / None from the most recent log window."""
        self.drain()
        txt = bytes(self.buf).decode("utf-8", "replace")
        self.buf = bytearray()
        low = txt.lower()
        self._last = [l.strip() for l in txt.splitlines()
                      if any(k in l.lower() for k in
                             ("lanauth", "syncconn", "auth", "pass", "conn[",
                              "video", "state", "check", "ok!"))]
        if "auth1 ok" in low or "check auth1 ok" in low or ("local check auth" in low and "ok" in low):
            return "PASS"
        if "no pass" in low:
            return "NOPASS"
        return None

    def lines(self):
        return getattr(self, "_last", [])

    def close(self):
        if self.ser:
            self.ser.close()


def recv_pkt(sock, timeout=2.0):
    sock.settimeout(timeout)
    try:
        return pprpc.read_packet(sock, udp=False)
    except socket.timeout:
        return {"error": "timeout"}
    except Exception as e:
        return {"error": str(e)}


def send_cmd(sock, cmdid, payload=b"", seq=0, enc=0):
    sock.sendall(pprpc.pack_cmd(cmdid, payload, cmdseq=seq, enctype=enc, udp=False))


def _connect_and_auth(secret, nonce, tap, verbose=True):
    """One TCP connect + LanAuth + SyncConn attempt. Returns the connected,
    synced socket on success, or None (already closed) on failure. Factored
    out of do_handshake so video capture can retry this from scratch on a
    fresh connection - see VIDEO_RETRIES."""
    cred = CRED_OVERRIDE or credential(DID, secret, nonce)
    if verbose:
        tag = "token" if CRED_OVERRIDE else "secret=%r nonce=%s" % (secret, nonce)
        print("[*] %s cred=%s (TCP)" % (tag, cred))
    if tap:
        tap.drain(); tap.buf = bytearray()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3.0)
    try:
        s.connect((HOST, PORT))
    except Exception as e:
        print("[!] connect failed: %s" % e)
        return None
    # LanAuth (credential is protobuf FIELD 3, not 2)
    send_cmd(s, CMD_LANAUTH, pb_str(1, DID) + pb_str(3, cred))
    resp = recv_pkt(s, 2.5)
    time.sleep(0.8)
    v = tap.verdict() if tap else None
    if verbose:
        print("    LanAuth resp:", {k: resp.get(k) for k in
                                    ("type_name", "cmdid", "code", "error")},
              "| verdict:", v)
        if tap:
            for l in tap.lines()[-6:]:
                print("      serial|", l)
    if v == "NOPASS" or (resp.get("code") not in (0, None) and v != "PASS"):
        s.close()
        return None
    if v != "PASS" and resp.get("error"):
        # no clear pass signal
        s.close()
        return None
    # SyncConn
    send_cmd(s, CMD_SYNCCONN, b"")
    resp = recv_pkt(s, 2.5)
    if verbose:
        print("    SyncConn resp:", {k: resp.get(k) for k in
                                     ("type_name", "cmdid", "code", "error")})
    return s


def _capture_video_once(secret, nonce, tap, out, verbose):
    """Single VideoPlay + capture + VideoPause attempt on a fresh connection.
    Returns the number of complete JPEGs written (0 on failure/drop)."""
    s = _connect_and_auth(secret, nonce, tap, verbose)
    if s is None:
        return 0
    # AV prekey = md5hex("+" + credential). With a ready-made token we derive
    # it straight from the credential string (no scode needed).
    token = (hashlib.md5(("+" + CRED_OVERRIDE).encode()).hexdigest()
             if CRED_OVERRIDE else av.lanauth_token(DID, secret, nonce))  # == the AV prekey
    send_cmd(s, CMD_VIDEOPLAY, pb_varint(1, 0))   # channel 0
    print("[*] VideoPlay sent; token=%s; capturing ~%ss of video..."
          % (token, VIDEO_SECS))
    raw = b""
    s.settimeout(0.6)
    end = time.time() + VIDEO_SECS
    while time.time() < end:
        try:
            d = s.recv(65536)
            if not d:
                break
            raw += d
        except socket.timeout:
            pass
    # Explicitly unsubscribe before closing (VideoPause, 0x0A33) instead of
    # just dropping the TCP connection - relying on the device to notice the
    # close is a plausible contributor to leftover per-conn queue/health
    # state on the NEXT attempt (see docs/protocol.md "Why --video sometimes
    # captures 0 frames"). Best-effort: don't block long on the reply.
    try:
        send_cmd(s, CMD_VIDEOPAUSE, pb_varint(1, 0))
        recv_pkt(s, 0.5)
    except Exception:
        pass
    s.close()
    frames = av.reassemble_frames(raw, prekey=token)
    outdir = out or "frames"
    import os
    os.makedirs(outdir, exist_ok=True)
    n = 0
    for f in frames:
        if not f["jpeg"]:
            continue
        jpg = f["jpeg"]
        eoi = jpg.rfind(b"\xff\xd9")
        if eoi > 0:
            jpg = jpg[:eoi + 2]
        fn = os.path.join(outdir, "frame_%d_%d.jpg" % (f["chan"], f["seq"]))
        open(fn, "wb").write(jpg)
        n += 1
    print("[*] captured %d frame(s), wrote %d complete JPEG(s) to %s/"
          % (len(frames), n, outdir))
    return n


def capture_video(secret, nonce, tap, out=None, verbose=True,
                  retries=VIDEO_RETRIES, retry_wait=VIDEO_RETRY_WAIT):
    """VideoPlay -> capture raw AV stream, decrypt with the LanAuth token, and
    write viewable JPEG frames (see tools/av.py). Retries on a fresh
    connection if a whole attempt yields 0 frames: that's a server-side
    silent slice-drop (congestion/health gate on the device, not a client
    parsing bug - see docs/protocol.md), and it clears on a new connection,
    not by waiting longer on the same one. Returns True if any frames were
    captured within `retries` attempts."""
    for attempt in range(1, retries + 1):
        this_nonce = nonce if attempt == 1 else "%s-r%d" % (nonce, attempt)
        n = _capture_video_once(secret, this_nonce, tap, out, verbose)
        if n > 0:
            return True
        if attempt < retries:
            print("[!] attempt %d/%d: 0 frames (server-side drop, not a client "
                  "bug - see docs/protocol.md); retrying on a fresh connection..."
                  % (attempt, retries))
            time.sleep(retry_wait)
    print("[!] gave up after %d attempt(s), still 0 frames" % retries)
    return False


def do_handshake(secret, nonce, tap, do_video=False, out=None, verbose=True,
                 udp=False, wifi_action=None, new_ssid=None, new_pass=None,
                 video_retries=VIDEO_RETRIES):
    if udp:
        cred = CRED_OVERRIDE or credential(DID, secret, nonce)
        if verbose:
            tag = "token" if CRED_OVERRIDE else "secret=%r nonce=%s" % (secret, nonce)
            print("[*] %s cred=%s (UDP)" % (tag, cred))
        if tap:
            tap.drain(); tap.buf = bytearray()
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("", 0)); s.settimeout(2.5)
        s.sendto(pprpc.pack_cmd(CMD_LANAUTH, pb_str(1, DID) + pb_str(3, cred),
                                udp=True), (HOST, PORT))
        resp = {}
        try:
            r, _ = s.recvfrom(4096)
            resp = {"type_name": "udp", "raw": r[:32].hex()}
        except socket.timeout:
            pass
        time.sleep(1.2)
        v = tap.verdict() if tap else None
        if verbose:
            print("    LanAuth udp resp:", resp, "| verdict:", v)
            if tap:
                for l in tap.lines()[-8:]:
                    print("      serial|", l)
        s.close()
        return v == "PASS"
    if do_video:
        return capture_video(secret, nonce, tap, out=out, verbose=verbose,
                             retries=video_retries)
    s = _connect_and_auth(secret, nonce, tap, verbose)
    if s is None:
        return False
    # WiFi config commands (see tools/wifi.py). These run after LanAuth+SyncConn.
    if wifi_action:
        import wifi
        if wifi_action == "get":
            pkt, fields = wifi.wifi_get(s)
            print("[*] WifiGet resp: code=%s err=%s len=%s" %
                  (pkt.get("code"), pkt.get("error"), pkt.get("length")))
            print(wifi.fmt_fields(fields))
            print("    (this firmware returns no creds here; it also triggers an AP scan)")
        elif wifi_action == "apget":
            pkt, fields = wifi.wifi_ap_get(s)
            print("[*] WifiAPGet resp: code=%s err=%s len=%s" %
                  (pkt.get("code"), pkt.get("error"), pkt.get("length")))
            print(wifi.fmt_fields(fields))
        elif wifi_action == "set":
            print("[!] WifiSet: saving SSID=%r PWD=%r to flash; the camera will "
                  "REBOOT to apply." % (new_ssid, new_pass))
            print("    Watch the device SERIAL for the ground-truth line:")
            print("      read wifi: SSID[%s] , PWD[%s]" % (new_ssid, new_pass))
            pkt, fields = wifi.wifi_set(s, new_ssid, new_pass)
            if pkt.get("error"):
                print("[*] no WifiSet reply (%s) - normal if it rebooted to apply."
                      % pkt.get("error"))
            else:
                print("[*] WifiSet resp: code=%s len=%s" %
                      (pkt.get("code"), pkt.get("length")))
                print(wifi.fmt_fields(fields))
        try:
            s.close()
        except Exception:
            pass
        return True
    # (do_video is handled above, before the connection is even opened here,
    # since a 0-frame capture needs to retry on a brand-new connection.)
    s.close()
    return True


def main():
    global HOST, DID, CRED_OVERRIDE
    ap = argparse.ArgumentParser()
    ap.add_argument("--secret", default="Nd2sFWYPT2nw")   # proven LanAuth secret
    ap.add_argument("--secret-file")
    ap.add_argument("--nonce", default="12345")
    ap.add_argument("--cred", help="use a ready-made LanAuth credential verbatim "
                    "(e.g. the \"$L<idx>$<hash>\" token from ble_provision.py); "
                    "no --secret/scode needed")
    parser_default_did = DID
    ap.add_argument("--did", default=DID)
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--video", action="store_true")
    ap.add_argument("--video-retries", type=int, default=VIDEO_RETRIES,
                    help="retry a 0-frame --video capture this many times on "
                         "fresh connections (default %d); it's a server-side "
                         "congestion/health drop, not a client bug" % VIDEO_RETRIES)
    ap.add_argument("--out")
    ap.add_argument("--no-serial", action="store_true")
    ap.add_argument("--udp", action="store_true", help="LanAuth over UDP (auth oracle path)")
    ap.add_argument("--wifi-get", action="store_true", help="send WifiGet (0x0A2B)")
    ap.add_argument("--wifi-ap-get", action="store_true", help="send WifiAPGet (0x0A29)")
    ap.add_argument("--wifi-set", action="store_true",
                    help="send WifiSet (0x0A2A): saves creds to flash + REBOOTS the cam")
    ap.add_argument("--new-ssid", help="SSID for --wifi-set")
    ap.add_argument("--new-pass", help="password for --wifi-set")
    args = ap.parse_args()
    HOST = args.host
    DID = args.did
    CRED_OVERRIDE = args.cred
    if CRED_OVERRIDE and os.path.isfile(CRED_OVERRIDE):
        with open(CRED_OVERRIDE, encoding="utf-8") as _f:
            _d = json.load(_f)
        CRED_OVERRIDE = _d.get("token") or _d.get("cred")
        if not CRED_OVERRIDE:
            ap.error("%s has no 'token' field" % args.cred)
        if _d.get("did") and args.did == parser_default_did:
            DID = _d["did"]
        print("[*] loaded token from %s (did=%s)" % (args.cred, DID))

    wifi_action = ("get" if args.wifi_get else "apget" if args.wifi_ap_get
                   else "set" if args.wifi_set else None)
    if wifi_action == "set" and (not args.new_ssid or args.new_pass is None):
        ap.error("--wifi-set requires --new-ssid and --new-pass")

    tap = None if args.no_serial else SerialTap()
    time.sleep(0.3)

    if args.secret_file:
        cands = [l.strip() for l in open(args.secret_file)
                 if l.strip() and not l.startswith("#")]
        print("[*] sweeping %d candidate secrets" % len(cands))
        for c in cands:
            ok = do_handshake(c, args.nonce, tap, verbose=True, udp=args.udp)
            if ok:
                print("\n########## PASS with secret = %r ##########" % c)
                break
            time.sleep(0.5)
        else:
            print("\n[!] no candidate passed")
    else:
        do_handshake(args.secret, args.nonce, tap,
                     do_video=args.video, out=args.out, udp=args.udp,
                     wifi_action=wifi_action, new_ssid=args.new_ssid,
                     new_pass=args.new_pass, video_retries=args.video_retries)
    if tap:
        tap.close()


if __name__ == "__main__":
    main()
