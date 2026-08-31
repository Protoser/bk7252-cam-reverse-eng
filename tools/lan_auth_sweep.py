#!/usr/bin/env python3
"""lan_auth_sweep.py - sweep LanAuth secret candidates against the REAL device
oracle. Transport that works: plain TCP to 20190, raw pprpc frame (no magic, no
length prefix). The device logs, per attempt:
    conn[1].local state connected, on packet LanAuth_Req
    check LanAuth NO PASS!            (fail)
  or  local check auth1 OK!           (pass) + a LanAuth_Resp on the wire
Read via COM5. Each candidate: fresh TCP conn, flush serial, send LanAuth, watch
~1.5s of serial for the verdict.

The auth string is MD5_hex("<did>-<secret>-<nonce>") -> credential "$<nonce>$<hex>".
We try each secret with lowercase and uppercase hex (in case the device uses %02X).
"""
import sys, socket, time, hashlib
sys.path.insert(0, "tools")
import pprpc
import serial

HOST = "192.168.178.147"; PORT = 20190
DID = "PPHA1006C0955E8FD9"
NONCE = "12345"


def pb_str(f, s):
    b = s.encode() if isinstance(s, str) else s
    return bytes([(f << 3) | 2]) + pprpc.encode_varint(len(b)) + b


def cred(secret, nonce=NONCE, upper=False):
    h = hashlib.md5(("%s-%s-%s" % (DID, secret, nonce)).encode()).hexdigest()
    if upper:
        h = h.upper()
    return "$%s$%s" % (nonce, h)


def attempt(ser, secret, upper=False, nonce=NONCE):
    c = cred(secret, nonce, upper)
    frame = pprpc.pack_cmd(0x0A5A, pb_str(1, DID) + pb_str(2, c), udp=False)
    ser.read(200000)  # flush serial
    try:
        s = socket.socket(); s.settimeout(4.0); s.connect((HOST, PORT))
    except Exception as e:
        return "CONNFAIL:%s" % e
    time.sleep(0.25)
    s.sendall(frame)
    # capture serial + any wire resp for ~1.6s
    verdict = None; wire = b""
    s.settimeout(1.6)
    t = time.time() + 1.8
    buf = b""
    try:
        wire = s.recv(4096)
    except Exception:
        pass
    while time.time() < t:
        buf += ser.read(8192); time.sleep(0.03)
    txt = buf.decode("utf-8", "replace").lower()
    s.close()
    if "no pass" in txt:
        verdict = "NOPASS"
    if "auth1 ok" in txt or "local check auth" in txt and "ok" in txt or "auth1 ok!" in txt:
        verdict = "PASS"
    if wire:
        verdict = (verdict or "") + " +WIRE(%s)" % wire[:24].hex()
    if "on packet lanauth" not in txt and verdict is None:
        verdict = "NOPROC"
    time.sleep(1.2)  # let device close/settle before next
    return verdict or "?"


def main():
    import base64
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    salt = b'HL4viXBiGEz8mCBkuhkTQFaK'; iv = b'e7uJ6Q8uM7ikpUxf'
    key = hashlib.md5(DID.encode() + salt).hexdigest().encode()
    def dec(b64):
        ct = base64.b64decode(b64)
        d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        pt = d.update(ct) + d.finalize()
        p = pt[-1]
        return pt[:-p].decode("latin1") if 1 <= p <= 16 else pt.decode("latin1")

    lslat_dec = dec("ivAygPb4VY5EyGAcYDuMAA==")
    sign_dec = dec("OHkMAuCv/nOXRHwvW9TnSA==")
    cands = [
        ("lslat_dec", lslat_dec),
        ("signkey_dec", sign_dec),
        ("scode", "307953"),
        ("lslat_b64", "ivAygPb4VY5EyGAcYDuMAA=="),
        ("signkey_b64", "OHkMAuCv/nOXRHwvW9TnSA=="),
        ("did", DID),
        ("lslat+sign_dec", lslat_dec + sign_dec),
    ]
    if len(sys.argv) > 1:  # allow extra candidates on cmdline
        cands += [("cli%d" % i, a) for i, a in enumerate(sys.argv[1:])]

    ser = serial.Serial("COM5", 115200, timeout=0.1)
    print("did=%s nonce=%s  key=%s" % (DID, NONCE, key.decode()))
    print("lslat_dec=%r  signkey_dec=%r" % (lslat_dec, sign_dec))
    try:
        for name, sec in cands:
            for upper in (False, True):
                v = attempt(ser, sec, upper)
                tag = "%s%s" % (name, "/UP" if upper else "")
                print("  %-22s secret=%-28r -> %s" % (tag, sec, v))
                if v and "PASS" in v and "NOPASS" not in v:
                    print("\n########## PASS: %s secret=%r upper=%s ##########"
                          % (name, sec, upper))
                    return
    finally:
        ser.close()


if __name__ == "__main__":
    main()
