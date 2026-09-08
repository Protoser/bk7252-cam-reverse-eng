#!/usr/bin/env python3
"""ble_provision.py - Provision the BK7252 / XC Things camera over Bluetooth LE.

What this does (all reversed from dumps/firmware_combined.bin, see
docs/ble-protocol.md):

  1. Scans for / connects to the camera over BLE.
  2. Sends a `bdn_netcfg` provisioning message (pprpc item id 0x2718) carrying
     your WiFi SSID + password (+ optional cloud-host string).
  3. Reads the camera's reply, which contains its `did` (device id) and an
     scode-derived auth token, and prints/saves them.
  4. The camera then joins your WiFi and reboots onto it.

After it is on your LAN you talk to it with tools/lan_client.py (LanAuth +
VideoPlay) to pull the MJPEG video feed.

=============================== IMPORTANT ====================================
* The netcfg wire format here is reverse-engineered and, as of writing, has NOT
  been round-tripped against real hardware. Use --dry-run first to inspect the
  exact bytes. If the camera does not join, capture what it notifies back and
  compare - the codec is small and lives entirely in this file.
* Sending WiFi creds makes the camera SAVE them and REBOOT. Wrong creds drop it
  off the air; it comes back on its softAP (192.168.9.252) or recover via serial
  (COM5) / telnet (port 20023, pw 123). Know your recovery path first.
* BLE hands out did + a ONE-WAY md5 token of the scode, NOT the raw scode. The
  LAN video path (LanAuth) needs the raw per-device `scode`; for this unit it is
  already known to lan_client.py. BLE does not let you recover scode by itself.
==============================================================================

BLE transport (docs/ble-protocol.md):
  Each GATT packet = [total_frags][index(1-based)][payload_len<=0x11] + <=17B.
  Reassembled buffer = [0x03][varint(cipherlen)] + AES-256-CBC(static key) body.
  key = b"UI3lQZ920C57E972YvuvvhRbIea3KXjj"  (32B, @0x0014cfbc)
  iv  = b"YvuvvhRbIea3KXjj"                  (16B, @0x0014cfe0)

ppiot body grammar (verified against encoder FUN_0002a090 @0x2a090 and decoder
FUN_0002998c @0x2998c):
  byte  flags               # 0x04 mandatory; |0x01, |0x02 optional
  byte  len_a; a[len_a]     # top string A (<=25), empty on device's own frames
  byte  len_b; b[len_b]     # top string B (<=25)
  varint v1                 # 0
  varint v2                 # 0
  byte  item_count          # 1
  per item:
     varint item_id         # 0x2718 for netcfg
     byte   sub1_count; sub1_count x varint     # 1 x [0]
     byte   str_count;  str_count x (byte len<=0x80 + string)
                                                # req: ssid,pwd,host  rsp: did,token
     varint blob_len; blob_len bytes            # 0
     byte   cnt3                                # 0 (skips cnt3*4 trailing bytes)

Usage:
  python tools/ble_provision.py --dry-run --ssid MyNet --psk secret123
  python tools/ble_provision.py --scan
  python tools/ble_provision.py --ssid MyNet             # psk from Windows store
  python tools/ble_provision.py --address AA:BB:CC:DD:EE:FF --ssid MyNet --psk pw
"""
import argparse
import asyncio
import hashlib
import json
import re
import subprocess
import sys
import time

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# ---------------------------------------------------------------------------
# Constants reversed from firmware_combined.bin
# ---------------------------------------------------------------------------
AES_KEY = b"UI3lQZ920C57E972YvuvvhRbIea3KXjj"      # @0x0014cfbc, AES-256
AES_IV = b"YvuvvhRbIea3KXjj"                       # @0x0014cfe0, 16B
NETCFG_ITEM_ID = 0x2718                            # bdn_netcfg discriminator
FRAG_CHUNK = 0x11                                  # 17 bytes payload per BLE pkt
FIXHDR_BYTE0 = 0x03                                # FUN_00029598, high bit clear

# Vendor GATT service on this camera (confirmed live on LLM_HA10 units):
#   0xff01 [write]     phone -> device
#   0xff02 [indicate]  device -> phone
#   0xff03 [notify]    device -> phone
# These are 16-bit UUIDs in the vendor-reserved 0xff00-0xffff range. The picker
# below prefers them, but still auto-discovers if a unit differs.
VENDOR_WRITE = "0000ff01-0000-1000-8000-00805f9b34fb"
VENDOR_INDICATE = "0000ff02-0000-1000-8000-00805f9b34fb"
VENDOR_NOTIFY = "0000ff03-0000-1000-8000-00805f9b34fb"

# Nordic UART Service - a fallback hint for other firmware variants.
NUS_WRITE = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"   # phone -> device (write)
NUS_NOTIFY = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"  # device -> phone (notify)

# Standard SIG characteristics we must never treat as the data channel
# (e.g. Service Changed 0x2a05 - Windows denies enabling notify on it).
_SIG_EXCLUDE = {0x2a00, 0x2a01, 0x2a04, 0x2a05, 0x2aa6, 0x2b29, 0x2b2a, 0x2b3a}


# ---------------------------------------------------------------------------
# AES-256-CBC (PKCS7) - uses `cryptography` (present) or pycryptodome
# ---------------------------------------------------------------------------
def _aes_new(key, iv):
    try:
        from Crypto.Cipher import AES  # pycryptodome
        return ("pycrypto", AES.new(key, AES.MODE_CBC, iv))
    except Exception:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        return ("cryptography", Cipher(algorithms.AES(key), modes.CBC(iv)))


def aes_encrypt(plaintext, key=AES_KEY, iv=AES_IV):
    pad = 16 - (len(plaintext) % 16)
    plaintext = plaintext + bytes([pad]) * pad
    kind, c = _aes_new(key, iv)
    if kind == "pycrypto":
        return c.encrypt(plaintext)
    e = c.encryptor()
    return e.update(plaintext) + e.finalize()


def aes_decrypt(ciphertext, key=AES_KEY, iv=AES_IV):
    kind, c = _aes_new(key, iv)
    if kind == "pycrypto":
        out = c.decrypt(ciphertext)
    else:
        d = c.decryptor()
        out = d.update(ciphertext) + d.finalize()
    if out:  # strip PKCS7
        p = out[-1]
        if 1 <= p <= 16:
            out = out[:-p]
    return out


# ---------------------------------------------------------------------------
# varint (standard protobuf base-128, little-endian) - FUN_00012084/FUN_00012264
# ---------------------------------------------------------------------------
def enc_varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def dec_varint(buf, i):
    shift = val = 0
    while True:
        b = buf[i]; i += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            return val, i
        shift += 7


# ---------------------------------------------------------------------------
# ppiot body codec
# ---------------------------------------------------------------------------
def encode_ppiot(item_id, strings, a=b"", b=b"", flags=0x04, sub1=(0,),
                 v1=0, v2=0, blob=b""):
    """Build the (plaintext) ppiot body for a single-item message."""
    if isinstance(a, str): a = a.encode()
    if isinstance(b, str): b = b.encode()
    strings = [s.encode() if isinstance(s, str) else s for s in strings]
    for s in strings:
        if len(s) > 0x80:
            raise ValueError("string too long (>128): %r" % s[:16])
    out = bytearray()
    out.append(flags | 0x04)                 # bit2 mandatory
    out.append(len(a)); out += a
    out.append(len(b)); out += b
    out += enc_varint(v1)
    out += enc_varint(v2)
    out.append(1)                            # item_count = 1
    # ---- item 0 ----
    out += enc_varint(item_id)
    out.append(len(sub1))
    for sv in sub1:
        out += enc_varint(sv)
    out.append(len(strings))
    for s in strings:
        out.append(len(s)); out += s
    out += enc_varint(len(blob)); out += blob
    out.append(0)                            # cnt3 = 0 (no trailing 4B entries)
    return bytes(out)


def decode_ppiot(body):
    """Parse a ppiot body into a dict. Mirrors FUN_0002998c."""
    i = 0
    flags = body[i]; i += 1
    la = body[i]; i += 1; a = body[i:i+la]; i += la
    lb = body[i]; i += 1; b = body[i:i+lb]; i += lb
    v1, i = dec_varint(body, i)
    v2, i = dec_varint(body, i)
    item_count = body[i]; i += 1
    items = []
    for _ in range(item_count):
        item_id, i = dec_varint(body, i)
        sub1_count = body[i]; i += 1
        sub1 = []
        for _ in range(sub1_count):
            sv, i = dec_varint(body, i); sub1.append(sv)
        str_count = body[i]; i += 1
        strings = []
        for _ in range(str_count):
            ln = body[i]; i += 1
            strings.append(body[i:i+ln]); i += ln
        blob_len, i = dec_varint(body, i)
        blob = body[i:i+blob_len]; i += blob_len
        cnt3 = body[i]; i += 1
        i += cnt3 * 4
        items.append({"id": item_id, "sub1": sub1,
                      "strings": strings, "blob": blob})
    return {"flags": flags, "a": a, "b": b, "v1": v1, "v2": v2, "items": items}


# ---------------------------------------------------------------------------
# frame = fixheader + AES(body)
# ---------------------------------------------------------------------------
def build_frame(body):
    ct = aes_encrypt(body)
    return bytes([FIXHDR_BYTE0]) + enc_varint(len(ct)) + ct


def parse_frame(buf):
    if not buf:
        raise ValueError("empty frame")
    if buf[0] & 0x80:
        raise ValueError("fixheader high bit set (device would reject)")
    length, i = dec_varint(buf, 1)
    ct = buf[i:i+length]
    if len(ct) < length:
        raise ValueError("truncated frame: have %d want %d" % (len(ct), length))
    return decode_ppiot(aes_decrypt(ct))


def build_netcfg_request(ssid, pwd, host="", a="", b="", flags=0x04, sub1=(0,)):
    body = encode_ppiot(NETCFG_ITEM_ID, [ssid, pwd, host],
                        a=a, b=b, flags=flags, sub1=sub1)
    return build_frame(body)


def parse_netcfg_response(buf):
    """Return {'did':..., 'token':..., 'raw':<decoded>} from a device reply."""
    dec = parse_frame(buf)
    did = tok = None
    for it in dec["items"]:
        if it["id"] == NETCFG_ITEM_ID and it["strings"]:
            ss = [s.decode("utf-8", "replace") for s in it["strings"]]
            did = ss[0] if len(ss) > 0 else None
            tok = ss[1] if len(ss) > 1 else None
            break
    return {"did": did, "token": tok, "decoded": dec}


# ---------------------------------------------------------------------------
# BLE fragmentation
# ---------------------------------------------------------------------------
def fragment(frame, chunk=FRAG_CHUNK):
    total = (len(frame) + chunk - 1) // chunk
    if total > 0xFF:
        raise ValueError("frame too large to fragment (%d bytes)" % len(frame))
    pkts = []
    for idx in range(total):
        part = frame[idx*chunk:(idx+1)*chunk]
        pkts.append(bytes([total, idx + 1, len(part)]) + part)
    return pkts


class Reassembler:
    """Collects [total][idx][len] fragments into a full frame."""
    def __init__(self):
        self.total = None
        self.slots = {}

    def feed(self, pkt):
        if len(pkt) < 3:
            return None
        total, idx, ln = pkt[0], pkt[1], pkt[2]
        self.total = total
        self.slots[idx] = pkt[3:3+ln]
        if len(self.slots) >= total and all(k in self.slots for k in range(1, total+1)):
            return b"".join(self.slots[k] for k in range(1, total+1))
        return None


# ---------------------------------------------------------------------------
# Windows WiFi passphrase helper (same approach as tools/provision.py)
# ---------------------------------------------------------------------------
_KEY_LABELS = ("Key Content", "Schlusselinhalt", "Schluesselinhalt",
               "Contenu de la cle")


def _netsh(args):
    try:
        out = subprocess.run(["netsh"] + args, capture_output=True, text=True,
                             errors="replace", encoding="utf-8")
        return out.stdout
    except Exception:
        return ""


def current_ssid():
    for line in _netsh(["wlan", "show", "interfaces"]).splitlines():
        m = re.match(r"\s*SSID\s*:\s*(.+?)\s*$", line)
        if m and "BSSID" not in line:
            return m.group(1)
    return None


def profile_key(ssid):
    for line in _netsh(["wlan", "show", "profile", "name=" + ssid,
                        "key=clear"]).splitlines():
        if ":" not in line:
            continue
        label, _, value = line.partition(":")
        label = label.strip().replace("ü", "u").replace("é", "e")
        if any(label.startswith(k) for k in _KEY_LABELS) and value.strip():
            return value.strip()
    return None


# ---------------------------------------------------------------------------
# BLE I/O (bleak)
# ---------------------------------------------------------------------------
def _need_bleak():
    try:
        import bleak  # noqa
        return bleak
    except Exception:
        sys.exit("This step needs the 'bleak' BLE library:  pip install bleak\n"
                 "(You can still use --dry-run to inspect the frame without it.)")


async def scan(timeout=8.0):
    bleak = _need_bleak()
    from bleak import BleakScanner
    print("[*] scanning %.0fs for BLE devices..." % timeout)
    devices = await BleakScanner.discover(timeout=timeout, return_adv=True)
    rows = []
    for addr, (dev, adv) in devices.items():
        rows.append((adv.rssi if adv else 0, addr, dev.name or (adv.local_name if adv else None)))
    for rssi, addr, name in sorted(rows, reverse=True):
        print("  %-20s rssi=%-4s %s" % (addr, rssi, name or "(no name)"))
    return rows


async def find_device(name_filter=None, address=None, timeout=10.0):
    bleak = _need_bleak()
    from bleak import BleakScanner
    if address:
        print("[*] looking for %s ..." % address)
        dev = await BleakScanner.find_device_by_address(address, timeout=timeout)
        if not dev:
            sys.exit("Device %s not found." % address)
        return dev
    print("[*] scanning for a camera (name filter=%r)..." % (name_filter or "any"))
    found = await BleakScanner.discover(timeout=timeout, return_adv=True)
    cands = []
    for addr, (dev, adv) in found.items():
        nm = dev.name or (adv.local_name if adv else "") or ""
        svcs = [s.lower() for s in (adv.service_uuids if adv else [])]
        score = 0
        if name_filter and name_filter.lower() in nm.lower():
            score += 10
        if not name_filter and nm.upper().startswith(("LLM_", "LLM-")):
            score += 8                       # observed camera name prefix
        if any(_short_uuid(s) is not None and 0xFF00 <= _short_uuid(s) <= 0xFFFF
               for s in svcs):
            score += 5                       # vendor 0xffxx service advertised
        if nm:
            score += 1
        cands.append((score, adv.rssi if adv else -999, dev, nm))
    cands.sort(key=lambda x: (x[0], x[1]), reverse=True)
    if not cands or cands[0][0] == 0:
        print("[!] No obvious camera. Devices seen:")
        for _, rssi, dev, nm in cands:
            print("      %-20s rssi=%-5s %s" % (dev.address, rssi, nm or "(no name)"))
        sys.exit("Pass --address <MAC> (or --name <substr>) to pick one.")
    best = cands[0]
    print("[*] picked %s (%s)" % (best[2].address, best[3] or "no name"))
    return best[2]


def _short_uuid(u):
    """Return the 16-bit id if this is a SIG-base UUID, else None (128-bit custom)."""
    s = str(u).lower()
    if s.endswith("-0000-1000-8000-00805f9b34fb"):
        return int(s[:8], 16) & 0xFFFF
    return None


def _pick_chars(client, write_uuid=None, notify_uuid=None):
    """Choose (write_char, [notify_chars], all_chars) from the GATT table.

    Ranks the vendor 0xff01/0xff03 pair first, then NUS, then any custom
    (128-bit) char, and only falls back to standard SIG chars as a last resort.
    Returns a *list* of notify/indicate chars to subscribe to (so we catch the
    reply whether the device uses 0xff02 indicate or 0xff03 notify)."""
    all_chars = [ch for svc in client.services for ch in svc.characteristics]

    def has(ch, *props):
        return any(p in ch.properties for p in props)

    def by_uuid(uuid):
        return next((c for c in all_chars if str(c.uuid).lower() == uuid.lower()), None)

    def write_score(c):
        u = str(c.uuid).lower()
        sid = _short_uuid(c.uuid)
        if u == VENDOR_WRITE: return 100
        if u == NUS_WRITE: return 60
        if sid is not None and 0xFF00 <= sid <= 0xFFFF: return 50
        if sid is None: return 40          # custom 128-bit
        if sid in _SIG_EXCLUDE: return 0
        return 5

    def notify_score(c):
        u = str(c.uuid).lower()
        sid = _short_uuid(c.uuid)
        base = 5 if has(c, "notify") else 0     # prefer notify over indicate
        if sid in _SIG_EXCLUDE: return -1
        if u == VENDOR_NOTIFY: return 100 + base
        if u == VENDOR_INDICATE: return 90 + base
        if u == NUS_NOTIFY: return 60 + base
        if sid is not None and 0xFF00 <= sid <= 0xFFFF: return 50 + base
        if sid is None: return 40 + base
        return 5 + base

    # ---- write characteristic ----
    write_c = by_uuid(write_uuid) if write_uuid else None
    if not write_c:
        cands = [c for c in all_chars if has(c, "write", "write-without-response")
                 and write_score(c) > 0]
        write_c = max(cands, key=write_score) if cands else None

    # ---- notify/indicate characteristics (subscribe to all vendor ones) ----
    if notify_uuid:
        notify_list = [c for c in [by_uuid(notify_uuid)] if c]
    else:
        cands = [c for c in all_chars if has(c, "notify", "indicate")
                 and notify_score(c) > 0]
        cands.sort(key=notify_score, reverse=True)
        # subscribe to the best plus any other vendor-range char (0xff02+0xff03)
        notify_list = []
        for c in cands:
            sid = _short_uuid(c.uuid)
            is_vendor = (sid is not None and 0xFF00 <= sid <= 0xFFFF)
            if not notify_list or is_vendor:
                notify_list.append(c)
        # de-dup preserving order
        seen = set(); notify_list = [c for c in notify_list
                                     if not (str(c.uuid) in seen or seen.add(str(c.uuid)))]

    return write_c, notify_list, all_chars


async def provision(dev, frame, timeout=25.0, write_uuid=None, notify_uuid=None,
                    write_no_resp=None):
    bleak = _need_bleak()
    from bleak import BleakClient

    loop = asyncio.get_running_loop()
    reasm = Reassembler()
    done = loop.create_future()

    async with BleakClient(dev) as client:
        print("[*] connected: %s" % client.address)
        write_c, notify_list, all_chars = _pick_chars(client, write_uuid, notify_uuid)
        print("[*] GATT characteristics:")
        for c in all_chars:
            print("      %s  [%s]" % (c.uuid, ",".join(c.properties)))
        if not write_c or not notify_list:
            sys.exit("Could not find a write + notify characteristic. "
                     "Use --write-uuid / --notify-uuid from the list above.")
        print("[*] write  -> %s" % write_c.uuid)
        print("[*] notify <- %s" % ", ".join(str(c.uuid) for c in notify_list))

        def on_notify(_handle, data):
            full = reasm.feed(bytes(data))
            if full is not None and not done.done():
                loop.call_soon_threadsafe(done.set_result, full)

        subscribed = []
        for c in notify_list:
            try:
                await client.start_notify(c, on_notify)
                subscribed.append(c)
            except Exception as e:
                print("    (could not subscribe %s: %s)" % (c.uuid, e))
        if not subscribed:
            sys.exit("Could not enable notifications on any characteristic.")

        async def _cleanup():
            for c in subscribed:
                try:
                    await client.stop_notify(c)
                except Exception:
                    pass

        if write_no_resp is None:
            write_no_resp = "write-without-response" in write_c.properties and \
                            "write" not in write_c.properties
        pkts = fragment(frame)
        print("[*] sending %d BLE fragment(s), %d frame bytes..." % (len(pkts), len(frame)))
        for p in pkts:
            await client.write_gatt_char(write_c, p, response=not write_no_resp)
            await asyncio.sleep(0.03)

        print("[*] waiting up to %.0fs for the device reply..." % timeout)
        try:
            full = await asyncio.wait_for(done, timeout=timeout)
        except asyncio.TimeoutError:
            await _cleanup()
            return None
        await _cleanup()
        return full


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Provision the BK7252 camera over BLE.")
    ap.add_argument("--scan", action="store_true", help="just list BLE devices and exit")
    ap.add_argument("--address", help="camera BLE MAC/UUID (skip scan)")
    ap.add_argument("--name", help="advertised-name substring filter for auto-pick")
    ap.add_argument("--ssid", help="WiFi SSID to join (default: this PC's WLAN)")
    ap.add_argument("--psk", help="WiFi passphrase (default: read from Windows store)")
    ap.add_argument("--host", default="", help="cloud host/region string (field 3); "
                    "leave empty for app-free use")
    ap.add_argument("--field-a", default="", help="top string A (usually empty)")
    ap.add_argument("--field-b", default="", help="top string B (usually empty)")
    ap.add_argument("--flags", type=lambda x: int(x, 0), default=0x04,
                    help="ppiot flags byte (default 0x04)")
    ap.add_argument("--write-uuid", help="override GATT write characteristic UUID")
    ap.add_argument("--notify-uuid", help="override GATT notify characteristic UUID")
    ap.add_argument("--scan-timeout", type=float, default=10.0)
    ap.add_argument("--reply-timeout", type=float, default=25.0)
    ap.add_argument("--json", help="write did/token result to this JSON file")
    ap.add_argument("--dry-run", action="store_true",
                    help="build + print the frame/fragments, do not touch BLE")
    args = ap.parse_args()

    if args.scan:
        asyncio.run(scan(args.scan_timeout))
        return

    ssid = args.ssid or current_ssid()
    if not ssid:
        sys.exit("Could not determine SSID - pass --ssid.")
    psk = args.psk or profile_key(ssid)
    if psk is None:
        sys.exit("Could not read passphrase for %r from Windows - pass --psk." % ssid)

    def redact(s):
        return s.replace(psk, "<REDACTED>") if psk else s

    print("[*] SSID=%r  psk=%d chars  host=%r" % (ssid, len(psk), args.host))
    frame = build_netcfg_request(ssid, psk, host=args.host, a=args.field_a,
                                 b=args.field_b, flags=args.flags)
    pkts = fragment(frame)

    if args.dry_run:
        print("\n--- dry run: netcfg request (0x2718) ---")
        print("frame (%d bytes): %s" % (len(frame), redact(frame.hex())))
        # show the decrypted body we just built so the layout is auditable
        body = encode_ppiot(NETCFG_ITEM_ID, [ssid, psk, args.host],
                            a=args.field_a, b=args.field_b, flags=args.flags)
        print("plaintext body (%d bytes): %s" % (len(body), redact(body.hex())))
        print("re-decoded:", redact(str(decode_ppiot(body))))
        print("BLE fragments (%d):" % len(pkts))
        for i, p in enumerate(pkts):
            print("  [%d] %s" % (i + 1, redact(p.hex())))
        # self-test the full round trip through AES
        rt = parse_netcfg_response(build_frame(body))
        print("frame round-trip decode ok:", redact(str(rt["decoded"])))
        return

    async def _run():
        dev = await find_device(args.name, args.address, args.scan_timeout)
        return await provision(dev, frame, timeout=args.reply_timeout,
                               write_uuid=args.write_uuid,
                               notify_uuid=args.notify_uuid)

    reply = asyncio.run(_run())

    if reply is None:
        print("\n[!] No reply within timeout. The camera may still have accepted "
              "the creds and rebooted - check if it appears on your WLAN.")
        return

    print("\n[*] raw reply (%d bytes): %s" % (len(reply), reply.hex()))
    try:
        res = parse_netcfg_response(reply)
    except Exception as e:
        print("[!] could not parse reply: %s" % e)
        return

    print("\n================ DEVICE SECRET (over BLE) ================")
    print("  did   : %s" % res["did"])
    print("  token : %s   (== $L<n>$md5(did-scode-<n>); NOT the raw scode)" % res["token"])
    print("=========================================================")
    print("Decoded:", res["decoded"])

    if args.json:
        with open(args.json, "w") as f:
            json.dump({"did": res["did"], "token": res["token"],
                       "ssid": ssid, "when": time.strftime("%Y-%m-%d %H:%M:%S")},
                      f, indent=2)
        print("[*] wrote %s" % args.json)

    print("\nNext: once the camera is on your WLAN, pull video with the raw scode:")
    print("  python tools/lan_client.py --did %s --host <cam-ip> \\" % (res["did"] or "<did>"))
    print("      --secret <raw-scode> --video")
    print("(BLE does not reveal raw scode; for this unit lan_client already has it.)")


if __name__ == "__main__":
    main()
