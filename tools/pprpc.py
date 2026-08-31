#!/usr/bin/env python3
"""pprpc.py - minimal Python port of the pprpc wire protocol (github.com/pprpc/core,
packets/*.go), for talking to the XC Things / BK7252 camera on the LAN.

Framing (from cmd_packet.go / fix_header.go / packets.go):
  first byte  = MessageType<<4 | 8            (0x38 HB, 0x48 PBBIN control, 0x68 AV)
  then        = varint(Length)               (protobuf varint, <=4 bytes)
  UDP only prepends magic 0x51 0x70 before the first byte; TCP has NO magic.
Control (CmdPacket) body after the header:
  varint(CmdSeq) varint(CmdID) byte(EncType<<2|RPCType) [varint(Code) if RESP] payload
AV (video) body:
  byte(IFrame<<7|Format) byte(EncType) varint(Chan) varint(Seq) varint(TS)
  varint(EncLength) payload
Crypto: AES-256-CBC (EncType=3). Per-packet key:
  EnKey = md5hex( PREKEY + ",ID:%d-SEQ:%d-RPC:%d" % (CmdID,CmdSeq,RPCType) )  (32 bytes)
  IV    = EnKey[:16]   (AV uses ",AVSeq:%d-TT:%d-AVChannel:%d")

PREKEY = "A2r0i1m1a2M0a1x6toriQue"  -- the *control-channel* prekey. VERIFIED
2026-08-31 by decrypting real device->client packets from a live capture: cmd
0xADC (DevInfo notify: model "INNO-IPC-48N-V2.2", avsdk 3.00.42.01_241230) and
the periodic 0x6B SyncConn timestamp heartbeats all decrypt to clean protobuf
with this prekey + IV=EnKey[:16]. It is a firmware constant at 0x156960 (the
default AV prekey pointer DAT_00058f5c at 0x15695c is the *empty* string; the
prekey getter FUN_00058f08 is what selects "A2r0..." vs a per-session value).
The old guess "P2p0r1p8c0622" was WRONG (produced garbage).

NOTE (AV/video path): AV frames use a DIFFERENT prekey and IV than control. The
encrypted header slice (EncType=3, first ~1040 bytes of the I-frame's slice 1 =
the JPEG headers) uses prekey = the LanAuth SESSION TOKEN (md5hex("+"+
credential), == LanAuth_Resp field 1), key = md5hex(prekey+",AVSeq:..-TT:..-
AVChannel:.."), and IV = key[16:32] (not key[:16]). seq/ts/chan are just the AV
wire-header values. See tools/av.py for the full parser+decrypter (proven: real
640x480 JPEGs, live). Only header slices are encrypted; scan data is plaintext.
"""
import hashlib
import socket

# Control-channel prekey (cmd 0x4-type packets). See module docstring.
PREKEY = b"A2r0i1m1a2M0a1x6toriQue"
UDP_MAGIC = b"\x51\x70"

TYPE_HB, TYPE_PBBIN, TYPE_PBJSON, TYPE_AV, TYPE_CUSTOMER, TYPE_FILE = 3, 4, 5, 6, 7, 8
FLAG = 8
AESNONE, AES256CBC = 0, 3
RPCREQ, RPCRESP = 0, 1
TYPE_NAME = {3: "HB", 4: "PBBIN", 5: "PBJSON", 6: "AV", 7: "CUSTOMER", 8: "FILE"}


def encode_varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def read_varint(rd, maxbytes=4):
    """rd(k)->bytes reader. Mirrors decodeVarint (capped byte count)."""
    raw = bytearray()
    shift = 0
    val = 0
    for _ in range(maxbytes):
        b = rd(1)
        if not b:
            break
        raw += b
        val |= (b[0] & 0x7F) << shift
        if b[0] < 0x80:
            break
        shift += 7
    return val, bytes(raw)


# ---- crypto (AES-256-CBC, PKCS7) --------------------------------------------
def _cmd_enkey(cmdid, cmdseq, rpctype, prekey=PREKEY):
    info = prekey + (",ID:%d-SEQ:%d-RPC:%d" % (cmdid, cmdseq, rpctype)).encode()
    return hashlib.md5(info).hexdigest().encode()   # 32 ascii hex bytes


def _av_enkey(avseq, ts, chan, prekey=PREKEY):
    info = prekey + (",AVSeq:%d-TT:%d-AVChannel:%d" % (avseq, ts, chan)).encode()
    return hashlib.md5(info).hexdigest().encode()


def _aes():
    try:
        from Crypto.Cipher import AES  # pycryptodome
        return AES
    except Exception:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

            class _Shim:
                MODE_CBC = 1

                @staticmethod
                def new(key, mode, iv):
                    class C:
                        def __init__(s):
                            s.e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
                            s.d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()

                        def encrypt(s, b):
                            return s.e.update(b) + s.e.finalize()

                        def decrypt(s, b):
                            return s.d.update(b) + s.d.finalize()

                    return C()
            return _Shim
        except Exception:
            return None


def aes_cbc_encrypt(key, iv, plaintext):
    AES = _aes()
    if AES is None:
        raise RuntimeError("no AES lib: pip install pycryptodome")
    pad = 16 - (len(plaintext) % 16)
    plaintext = plaintext + bytes([pad]) * pad
    return AES.new(key, AES.MODE_CBC, iv[:16]).encrypt(plaintext)


def aes_cbc_decrypt(key, iv, ciphertext):
    AES = _aes()
    if AES is None:
        raise RuntimeError("no AES lib: pip install pycryptodome")
    out = AES.new(key, AES.MODE_CBC, iv[:16]).decrypt(ciphertext)
    if out:  # strip PKCS7
        p = out[-1]
        if 1 <= p <= 16:
            out = out[:-p]
    return out


# ---- packing ----------------------------------------------------------------
def pack_fixheader(msgtype, length, udp=False):
    hdr = bytearray()
    if udp:
        hdr += UDP_MAGIC
    hdr.append((msgtype << 4) | FLAG)
    hdr += encode_varint(length)
    return bytes(hdr)


def pack_hb(udp=False):
    return pack_fixheader(TYPE_HB, 0, udp)


def pack_cmd(cmdid, payload=b"", cmdseq=0, enctype=AESNONE, rpctype=RPCREQ,
             code=None, udp=False, prekey=PREKEY, autocrypt=True):
    var = bytearray()
    var += encode_varint(cmdseq)
    var += encode_varint(cmdid)
    var.append((enctype << 2) | rpctype)
    if rpctype == RPCRESP and code is not None:
        var += encode_varint(code)
    body = bytes(payload)
    if body and autocrypt and enctype != AESNONE:
        k = _cmd_enkey(cmdid, cmdseq, rpctype, prekey)
        body = aes_cbc_encrypt(k, k, body)
    length = len(var) + len(body)
    return pack_fixheader(TYPE_PBBIN, length, udp) + bytes(var) + body


# ---- reading one packet off a socket ----------------------------------------
def _sock_reader(sock):
    buf = bytearray()

    def rd(k):
        while len(buf) < k:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf.extend(chunk)
        out = bytes(buf[:k])
        del buf[:k]
        return out
    return rd, buf


def read_packet(sock, udp=False):
    """Read exactly one pprpc packet from a TCP socket. Returns dict."""
    rd, _ = _sock_reader(sock)
    if udp:
        magic = rd(2)
        if magic[:2] != UDP_MAGIC:
            return {"error": "bad udp magic", "raw": magic}
    fb = rd(1)
    if not fb:
        return {"error": "eof"}
    mt = fb[0] >> 4
    flag = fb[0] & 0x0F
    length, _lb = read_varint(rd, 4)
    body = rd(length)
    pkt = {"type": mt, "type_name": TYPE_NAME.get(mt, "?"), "flag": flag,
           "length": length, "body": body}
    if mt in (TYPE_PBBIN, TYPE_PBJSON):
        import io
        b = io.BytesIO(body)
        rd2 = lambda k: b.read(k)
        pkt["cmdseq"], _ = read_varint(rd2, 4)
        pkt["cmdid"], _ = read_varint(rd2, 4)
        cf = b.read(1)[0]
        pkt["enctype"], pkt["rpctype"] = cf >> 2, cf & 3
        if pkt["rpctype"] == RPCRESP:
            pkt["code"], _ = read_varint(rd2, 4)
        pkt["rawpayload"] = b.read()
        if pkt["rawpayload"] and pkt["enctype"] != AESNONE:
            try:
                k = _cmd_enkey(pkt["cmdid"], pkt["cmdseq"], pkt["rpctype"])
                pkt["payload"] = aes_cbc_decrypt(k, k, pkt["rawpayload"])
            except Exception as e:
                pkt["decrypt_error"] = str(e)
    return pkt


if __name__ == "__main__":
    import sys
    print("pprpc self-test:")
    print("  HB (tcp):", pack_hb().hex())
    print("  HB (udp):", pack_hb(udp=True).hex())
    print("  cmd GetServers(601) empty:", pack_cmd(601).hex())
    k = _cmd_enkey(601, 0, 0)
    print("  enkey(601,0,0):", k.decode(), "len", len(k))
