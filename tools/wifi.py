#!/usr/bin/env python3
"""wifi.py - WiFi config commands for the BK7252 / XC Things cam over LAN pprpc.

Three commands, reversed from firmware_combined.bin (Ghidra):

  WifiAPGet  CmdID 0x0A29 (2601)  = "get AP list": runs a WiFi SCAN of nearby APs
  WifiSet    CmdID 0x0A2A (2602)  set STATION SSID+PWD -> saves flash + REBOOTS
  WifiGet    CmdID 0x0A2B (2603)  pure log-only STUB (returns code=0, empty body)

Handlers (identified by their own log banners, not just address): dev_on_ipc_WifiSet
= FUN_00082ba8 (banner "ipc_WifiSet_Req" @0x164dd4), dev_on_ipc_WifiGet =
FUN_00082c78 (banner @0x164e91), dev_on_ipc_WifiAPGet = FUN_00082b44 (banner
@0x164d76). NOTE: Ghidra's decompiler mislabels these handlers' string pointers by
+0x10000 (a base-analysis artifact: it shows 0x174xxx, real strings are at 0x164xxx),
so read the raw literal pool, not the PTR_ names.

Backend behavior, code-verified 2026-09-01 (Ghidra):
* WifiGet  (FUN_00082c78): calls ONLY the two logger funcs (FUN_0008288c timestamp,
  FUN_00082864 line) then `return 1`. It does NOT read the stored creds, does NOT
  scan, builds no response body -> the framework sends code=0 with an EMPTY payload.
  A true stub on this firmware. (The AP scan we once saw was WifiAPGet, not this.)
* WifiAPGet (FUN_00082b44): logs "ipc_WifiAPGet_Req" + "channel:%d", then tail-calls
  an xwifi.c routine @0x8725c that grabs the "w0" wlan device (logs "No wlan device"
  if absent) and runs a WiFi SCAN, logging each hit as
  `wifi scan:SSID[%s],qos[%d],rssi[%d]` (qos = security type; string table @0x1820e4:
  OPEN/WPA2/WPA2-EAP-SUITE-B/OSEN/FT-...). The scan is async (results come via the
  WLAN scan-done callback -> serial), so an empty LAN request gets no useful RESP
  body back on the control socket (observed: no reply). This is the scan side-effect
  seen on serial during earlier testing.

dev_on_ipc_WifiSet reads SSID from the decoded request at
struct+0x04 and PWD at struct+0x45 (a fixed WifiSet_Req{char ssid[0x41]; char
pwd[...]}), logs "read wifi: SSID[%s] , PWD[%s]" to serial (0x164e58, our oracle),
stores both via FUN_00081db0 -> writes ~0x1a8 bytes to flash partition 6
(FUN_00081c78), then spawns the xc_reboot thread (FUN_00087044). So WifiSet
re-points the station WiFi and REBOOTS to apply; the new creds persist across the
reboot (a bad SET does NOT self-heal on power cycle - recover via softAP
192.168.9.252 or serial).

WIRE FORMAT: standard protobuf payload inside a pprpc CmdPacket (see pprpc.py).
WifiSet_Req schema CONFIRMED 2026-09-01 (code=0 accept + a real reboot): the
pprpc rx path decodes the payload with nanopb against a per-CmdID descriptor
(decode table @ 0x159608, entry for 0x0A2A -> descriptor @ 0x160058), and a decode
failure is what makes pprpc_rx_dispatch (FUN_00054128) log "ErrorPacket" and drop
the packet BEFORE the handler runs. The real WifiSet_Req fields are:
    field 1  variable string  (struct+0x00; like LanAuth's did - unused here)
    field 2  char[65]  SSID   (struct+0x04)   <-- SSID_FIELD
    field 3  char[65]  PWD    (struct+0x45)   <-- PWD_FIELD
    field 5  char[16]         (struct+0x86; optional)
An earlier guess of SSID=field1/PWD=field2 mis-decoded -> NULL -> ErrorPacket ->
no apply (the serial hexdump we first saw was the raw pre-decode dump, not proof
of a good decode). Sending SSID=field2 + PWD=field3 (this module's defaults) got a
code=0 response and the device rebooted to apply. The two GET requests are empty.
All sent after LanAuth+SyncConn; enctype 0 (plaintext) is accepted.

NOTE: WifiGet returns code=0 with an EMPTY body - the handler is a log-only stub;
this firmware does not hand the stored SSID/PWD back to the LAN client (they only
appear in the device's own serial log). WifiAPGet is the one that runs a scan, and
its scan list is not returned on the control socket either (async, serial-only).
"""
import sys

sys.path.insert(0, "tools")
import pprpc

CMD_WIFI_APGET = 0x0A29
CMD_WIFI_SET = 0x0A2A
CMD_WIFI_GET = 0x0A2B

ENC = pprpc.AESNONE          # control cmds accepted plaintext on the LAN
SSID_FIELD = 2               # CONFIRMED (code=0 + reboot): WifiSet_Req field 2 = SSID char[65]
PWD_FIELD = 3                # CONFIRMED (code=0 + reboot): WifiSet_Req field 3 = PWD  char[65]


# ---- minimal protobuf helpers -----------------------------------------------
def _rvarint(b, i):
    shift = val = 0
    while True:
        c = b[i]; i += 1
        val |= (c & 0x7F) << shift
        if not (c & 0x80):
            return val, i
        shift += 7


def decode_fields(payload):
    """Decode a protobuf message into a list of dicts, one per field on the wire.
    Field-number-agnostic: works even when we don't yet know the schema. String
    fields (wire type 2) are returned both raw and best-effort utf-8 decoded."""
    out = []
    i = 0
    n = len(payload)
    while i < n:
        tag, i = _rvarint(payload, i)
        field, wt = tag >> 3, tag & 7
        if wt == 0:                                   # varint
            v, i = _rvarint(payload, i)
            out.append({"field": field, "wire": wt, "int": v})
        elif wt == 2:                                 # length-delimited (string/bytes/msg)
            ln, i = _rvarint(payload, i)
            raw = payload[i:i + ln]; i += ln
            out.append({"field": field, "wire": wt, "bytes": raw,
                        "str": raw.decode("utf-8", "replace")})
        elif wt == 5:                                 # 32-bit
            out.append({"field": field, "wire": wt, "u32": int.from_bytes(payload[i:i+4], "little")}); i += 4
        elif wt == 1:                                 # 64-bit
            out.append({"field": field, "wire": wt, "u64": int.from_bytes(payload[i:i+8], "little")}); i += 8
        else:
            out.append({"field": field, "wire": wt, "unparsed": payload[i:]}); break
    return out


def pb_str(field, s):
    b = s.encode() if isinstance(s, str) else s
    return bytes([(field << 3) | 2]) + pprpc.encode_varint(len(b)) + b


def fmt_fields(fields):
    lines = []
    for f in fields:
        if "str" in f:
            lines.append("  field %d (string): %r" % (f["field"], f["str"]))
        elif "int" in f:
            lines.append("  field %d (varint): %d" % (f["field"], f["int"]))
        elif "u32" in f:
            lines.append("  field %d (32bit): %d" % (f["field"], f["u32"]))
        elif "u64" in f:
            lines.append("  field %d (64bit): %d" % (f["field"], f["u64"]))
        else:
            lines.append("  field %d (wire %d): %r" % (f["field"], f["wire"], f.get("unparsed")))
    return "\n".join(lines) if lines else "  (empty response)"


# ---- transport ---------------------------------------------------------------
def _send(sock, cmdid, payload=b"", seq=0):
    sock.sendall(pprpc.pack_cmd(cmdid, payload, cmdseq=seq, enctype=ENC, udp=False))


HEARTBEAT_CMDID = 0x6B          # SyncConn timestamp pushes; skip these


def _recv(sock, timeout=2.5, want_cmdid=None):
    """Read one pprpc packet, or - if want_cmdid is given - keep reading (skipping
    0x6B heartbeats and unrelated packets) until the matching RESP arrives or the
    deadline passes. Returns the packet dict (or {'error': ...})."""
    import socket as _s
    import time as _t
    deadline = _t.time() + timeout
    while True:
        sock.settimeout(max(0.1, deadline - _t.time()))
        try:
            pkt = pprpc.read_packet(sock, udp=False)
        except _s.timeout:
            return {"error": "timeout"}
        except Exception as e:
            return {"error": str(e)}
        if want_cmdid is None:
            return pkt
        if pkt.get("cmdid") == want_cmdid:
            return pkt
        if _t.time() >= deadline:
            return {"error": "timeout"}


def _resp_payload(pkt):
    """Return the response's decoded protobuf payload bytes (plaintext or already
    decrypted by pprpc.read_packet)."""
    if "payload" in pkt:            # was enctype!=0, read_packet decrypted it
        return pkt["payload"]
    return pkt.get("rawpayload", b"")


def wifi_get(sock, seq=1):
    """Send WifiGet. The handler (FUN_00082c78) is a log-only stub: it replies
    code=0 with an EMPTY body and does NOT return the stored creds (and does not
    scan - that's WifiAPGet). Returns (pkt, fields)."""
    _send(sock, CMD_WIFI_GET, b"", seq)
    pkt = _recv(sock, timeout=5.0, want_cmdid=CMD_WIFI_GET)
    fields = decode_fields(_resp_payload(pkt)) if "error" not in pkt else []
    return pkt, fields


def wifi_ap_get(sock, seq=1):
    """Send WifiAPGet ("get AP list"). The handler (FUN_00082b44) runs a WiFi SCAN
    via xwifi.c @0x8725c and logs each hit ("wifi scan:SSID[%s],qos[%d],rssi[%d]")
    to the device serial. The scan is async so no useful body comes back on the LAN
    control socket (observed: no reply to an empty request). Returns (pkt, fields)."""
    _send(sock, CMD_WIFI_APGET, b"", seq)
    pkt = _recv(sock, want_cmdid=CMD_WIFI_APGET)
    fields = decode_fields(_resp_payload(pkt)) if "error" not in pkt else []
    return pkt, fields


def build_wifiset_payload(ssid, pwd, ssid_field=SSID_FIELD, pwd_field=PWD_FIELD):
    return pb_str(ssid_field, ssid) + pb_str(pwd_field, pwd)


def wifi_set(sock, ssid, pwd, ssid_field=SSID_FIELD, pwd_field=PWD_FIELD, seq=1):
    """Set the STATION wifi SSID+PWD. On a good decode the device replies code=0,
    then saves to flash and REBOOTS (~30s) to join the new network. Returns
    (pkt, fields); pkt['code']==0 means accepted. (If the field numbers are wrong
    the pprpc rx layer drops the packet as an ErrorPacket and no reply comes - see
    the module docstring.)

    DANGER: wrong ssid/pwd drops the camera off your LAN and PERSISTS across the
    reboot - it comes back on softAP (192.168.9.252) instead. Make sure you can
    reach it via softAP or serial before pointing it at a new network."""
    payload = build_wifiset_payload(ssid, pwd, ssid_field, pwd_field)
    _send(sock, CMD_WIFI_SET, payload, seq)
    pkt = _recv(sock, timeout=4.0, want_cmdid=CMD_WIFI_SET)  # code=0 arrives, then it reboots
    fields = decode_fields(_resp_payload(pkt)) if "error" not in pkt else []
    return pkt, fields
