#!/usr/bin/env python3
"""av.py - parse and reassemble pprpc type-6 (AV) video frames from the BK7252
camera, and decrypt the encrypted I-frame header slice.

Everything here except the AV *prekey* is reverse-engineered and verified against
a live capture (dumps: $CLAUDE_JOB_DIR/tmp/raw.bin, 2 MJPEG frames).

WIRE FORMAT (one pprpc packet == one slice; a full JPEG = several slices):
  FixHeader : byte(type<<4|8) varint(bodylen)          type==6 for AV
  AV header : byte(IFrame<<7|Format) byte(EncType)
              varint(Chan) varint(Seq) varint(TS) varint(EncLen)
  payload   : byte(0x01) byte(sliceIndex) byte(flag)   <- 3-byte slice prefix
              <slice data>                              (0xff sliceIndex = last)
  Format 4 == MJPEG. EncType 3 == AES-256-CBC. Only the first slice of an
  I-frame is encrypted, and only its first EncLen (~1040) bytes -- the JPEG
  SOI/DQT/DHT/SOF/SOS headers; the trailing entropy-coded scan data and all
  later slices are plaintext.

CRYPTO (verified from firmware FUN_0005d790 / FUN_0005e028 / FUN_0005daa0, and
proven end-to-end against a live capture 2026-08-31 -- yields a valid 640x480
JPEG):
  key = md5hex( prekey + ",AVSeq:%d-TT:%d-AVChannel:%d" % (seq, ts, chan) )
        -> 32 ASCII hex chars == an AES-256 key
  iv  = key[16:32]              (the video encrypt path formats key[16:32] as the
        IV via "%s"; decrypt_header_slice tries key[:16] too, just in case)
  seq/ts/chan == the AV wire-header fields (both the key builder and the wire
        serializer FUN_00060898 read the SAME struct offsets +0x40/+0x48/+0x38).
  region = payload[3 : 3+EncLen]     (skip the 3-byte slice prefix)

PREKEY == the LanAuth SESSION TOKEN (SOLVED 2026-08-31), NOT the "A2r0..."
control prekey. It is md5hex("+" + credential) where credential is the
"$<nonce>$<md5(did-secret-nonce)>" string sent in LanAuth_Req -- i.e. the same
value the device returns in LanAuth_Resp (protobuf field 1). So a client either
derives it (lanauth_token below) or just reads it off the LanAuth_Resp. This is
what the firmware copies into the pprpc session's conn+0x88 after auth; the
"A2r0..." default seen in pprpc_create is overwritten per-session with this.
"""
import hashlib
import sys

sys.path.insert(0, "tools")
import pprpc


def _rvarint(b, i):
    shift = 0
    val = 0
    while True:
        c = b[i]
        i += 1
        val |= (c & 0x7F) << shift
        if not (c & 0x80):
            break
        shift += 7
    return val, i


def iter_packets(raw):
    """Yield (type, flag, body) for each pprpc packet in a raw TCP byte stream.
    Stops cleanly on a truncated trailing packet."""
    i = 0
    while i < len(raw):
        b0 = raw[i]
        typ = b0 >> 4
        flag = b0 & 0xF
        length, j = _rvarint(raw, i + 1)
        body = raw[j:j + length]
        if len(body) < length:
            return
        yield typ, flag, body
        i = j + length


def parse_av_slice(body):
    """Decode one type-6 AV slice body into a dict."""
    p = 0
    bf = body[p]; p += 1
    iframe = bf >> 7
    fmt = bf & 0x7F
    enctype = body[p]; p += 1
    chan, p = _rvarint(body, p)
    seq, p = _rvarint(body, p)
    ts, p = _rvarint(body, p)
    enclen, p = _rvarint(body, p)
    payload = body[p:]
    slice_index = payload[1] if len(payload) > 1 else None  # payload = 01 idx flag ...
    return dict(iframe=iframe, fmt=fmt, enctype=enctype, chan=chan, seq=seq,
                ts=ts, enclen=enclen, slice_index=slice_index, payload=payload)


def credential(did, secret, nonce):
    """The LanAuth credential string "$<nonce>$<md5(did-secret-nonce)>"."""
    h = hashlib.md5(("%s-%s-%s" % (did, secret, nonce)).encode()).hexdigest()
    return "$%s$%s" % (nonce, h)


def lanauth_token(did, secret, nonce):
    """The LanAuth session token = the AV prekey. Equals md5hex("+" + credential)
    and is also what the device returns in LanAuth_Resp (protobuf field 1)."""
    return hashlib.md5(("+" + credential(did, secret, nonce)).encode()).hexdigest()


def av_key(prekey, seq, ts, chan):
    if isinstance(prekey, bytes):
        prekey = prekey.decode()
    ks = "%s,AVSeq:%d-TT:%d-AVChannel:%d" % (prekey, seq, ts, chan)
    return hashlib.md5(ks.encode()).hexdigest().encode()   # 32 ASCII hex bytes


def decrypt_header_slice(sl, prekey):
    """Return decrypted header bytes for an encrypted slice, or None on failure.
    prekey = the LanAuth session token (see lanauth_token). IV is key[16:32]
    (key[:16] tried as a fallback)."""
    key = av_key(prekey, sl["seq"], sl["ts"], sl["chan"])
    ct = sl["payload"][3:3 + sl["enclen"]]
    ct = ct[:(len(ct) // 16) * 16]
    if len(ct) < 16:
        return None
    for iv in (key[16:32], key[:16]):
        try:
            pt = pprpc.aes_cbc_decrypt(key, iv, ct)
        except Exception:
            continue
        if pt[:2] == b"\xff\xd8":            # JPEG SOI -> success
            return pt
    return None


def reassemble_frames(raw, prekey=None):
    """Group AV slices into frames by (chan, seq); return list of dicts with the
    concatenated slice data. If prekey is given and decrypts the header slice,
    'jpeg' holds a complete viewable JPEG; otherwise 'jpeg' is None and
    'plaintext_tail' holds the recoverable (headerless) scan data."""
    frames = {}
    order = []
    for typ, flag, body in iter_packets(raw):
        if typ != pprpc.TYPE_AV:
            continue
        sl = parse_av_slice(body)
        keyid = (sl["chan"], sl["seq"])
        if keyid not in frames:
            frames[keyid] = []
            order.append(keyid)
        frames[keyid].append(sl)

    out = []
    for keyid in order:
        slices = sorted(frames[keyid], key=lambda s: (s["slice_index"] or 0))
        chan, seq = keyid
        header = None
        parts = []
        for sl in slices:
            data = sl["payload"][3:]           # strip 01 idx flag
            if sl["enctype"] == 3:
                dec = decrypt_header_slice(sl, prekey) if prekey else None
                if dec is not None:
                    # decrypted header replaces the encrypted region; keep tail
                    header = dec
                    tail = sl["payload"][3 + sl["enclen"]:]
                    parts.append(header + tail)
                else:
                    # header still encrypted: keep only the plaintext tail
                    parts.append(sl["payload"][3 + sl["enclen"]:])
            else:
                parts.append(data)
        blob = b"".join(parts)
        jpeg = blob if (header is not None and blob[:2] == b"\xff\xd8") else None
        out.append(dict(chan=chan, seq=seq, ts=slices[0]["ts"],
                        n_slices=len(slices), jpeg=jpeg,
                        plaintext_tail=None if jpeg else blob, raw_slices=slices))
    return out


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "raw.bin"
    prekey = sys.argv[2] if len(sys.argv) > 2 else None
    raw = open(path, "rb").read()
    frames = reassemble_frames(raw, prekey=prekey)
    print("parsed %d frame(s) from %s (prekey=%r)" % (len(frames), path, prekey))
    for i, f in enumerate(frames):
        status = ("JPEG %d B" % len(f["jpeg"])) if f["jpeg"] else \
                 ("headerless %d B (header slice still encrypted)" %
                  len(f["plaintext_tail"]))
        print("  frame[%d] chan=%d seq=%d ts=%d slices=%d -> %s"
              % (i, f["chan"], f["seq"], f["ts"], f["n_slices"], status))
        if f["jpeg"]:
            fn = "frame_%d.jpg" % i
            open(fn, "wb").write(f["jpeg"])
            print("      wrote", fn)
