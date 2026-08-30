#!/usr/bin/env python3
"""cam_probe.py - drive the camera's pprpc UDP server on ONE persistent socket
while capturing the serial (COM5) log, so we see both the wire reply AND the
firmware's own log for each command. This is the RE loop for building the LAN
client (option B). See docs/protocol.md.

Usage: edit SEQUENCE below, then `python tools/cam_probe.py`.
The persistent source UDP port matters: the camera keys "connections" by the
client's ip:port, so reusing one socket lets its connection state machine
(LanAuth -> SyncConn -> state 3) advance instead of treating each packet as a
throwaway conn[-2].
"""
import sys, time, socket, hashlib, io, threading
sys.path.insert(0, "tools")
import pprpc

HOST = "192.168.178.147"
UDP_PORT = 20190
SERIAL_PORT = "COM5"
SERIAL_BAUD = 115200
DID = "PPHA1006C0955E8FD9"
SCODE = "307953"


def pb_str(field, s):
    b = s.encode() if isinstance(s, str) else s
    return bytes([(field << 3) | 2]) + pprpc.encode_varint(len(b)) + b


def pb_varint(field, n):
    return bytes([(field << 3) | 0]) + pprpc.encode_varint(n)


def credential(nonce="12345"):
    h = hashlib.md5(("%s-%s-%s" % (DID, SCODE, nonce)).encode()).hexdigest()
    return "$%s$%s" % (nonce, h)


def decode_reply(d, udp=True):
    body = d[3:] if udp else d
    r = io.BytesIO(body)
    rd = r.read
    ln, _ = pprpc.read_varint(rd)
    seq, _ = pprpc.read_varint(rd)
    cid, _ = pprpc.read_varint(rd)
    cf = rd(1)[0]
    et, rt = cf >> 2, cf & 3
    code = None
    if rt == 1:
        code, _ = pprpc.read_varint(rd)
    rest = rd()
    return dict(len=ln, seq=seq, cid=cid, enc=et, rpc=rt, code=code, payload=rest)


class SerialTap:
    def __init__(self, port=SERIAL_PORT, baud=SERIAL_BAUD):
        self.buf = bytearray()
        self.ser = None
        try:
            import serial
            self.ser = serial.Serial(port, baud, timeout=0.1)
        except Exception as e:
            print("[serial] unavailable (%s) - continuing without log" % e)

    def drain(self):
        if self.ser:
            try:
                self.buf += self.ser.read(16384)
            except Exception:
                pass

    def take(self, keywords):
        self.drain()
        txt = bytes(self.buf).decode("utf-8", "replace")
        self.buf = bytearray()
        out = [l.strip() for l in txt.splitlines()
               if any(k.lower() in l.lower() for k in keywords)]
        return out

    def close(self):
        if self.ser:
            self.ser.close()


def run(sequence, prekey=pprpc.PREKEY, keep_socket=True):
    tap = SerialTap()
    time.sleep(0.3); tap.drain(); tap.buf = bytearray()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("", 0)); s.settimeout(1.5)
    print("[*] client udp src port:", s.getsockname()[1])
    for name, cmdid, payload, enc in sequence:
        pkt = pprpc.pack_cmd(cmdid, payload, enctype=enc, udp=True, prekey=prekey)
        s.sendto(pkt, (HOST, UDP_PORT))
        reply = "(no reply)"
        try:
            r, _ = s.recvfrom(4096)
            d = decode_reply(r)
            reply = "cid=0x%x rpc=%d enc=%d code=%s plen=%d %s" % (
                d["cid"], d["rpc"], d["enc"], d["code"], len(d["payload"]),
                d["payload"][:48].hex())
        except socket.timeout:
            pass
        time.sleep(1.0)
        log = tap.take(("LanAuth", "SyncConn", "auth", "PASS", "conn[", "rc:", "pb_decode", "state"))
        print("\n### %s (cmd 0x%x, enc%d) -> %s" % (name, cmdid, enc, reply))
        for l in log[-8:]:
            print("   ", l)
        if not keep_socket:
            s.close(); s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(("", 0)); s.settimeout(1.5)
    s.close(); tap.close()


if __name__ == "__main__":
    cred = credential()
    print("credential:", cred)
    # Persistent-socket handshake attempt: LanAuth then SyncConn on one conn.
    SEQUENCE = [
        ("LanAuth f1=did f2=cred", 0x0a5a, pb_str(1, DID) + pb_str(2, cred), 0),
        ("SyncConn empty",         0x6a,   b"",                              0),
        ("LanAuth again",          0x0a5a, pb_str(1, DID) + pb_str(2, cred), 0),
    ]
    run(SEQUENCE, keep_socket=True)
