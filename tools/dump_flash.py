#!/usr/bin/env python3
"""Dump a FAL partition off the camera over the msh shell.

`fal read` tags every line with its absolute offset, so interleaved RTOS log
spam is survivable: lines are indexed by offset, and lines corrupted by a log
message landing mid-line are re-requested in repair passes.

The camera can reboot mid-dump (which silently drops the probed partition), so
a chunk that returns nothing triggers a re-probe and retry.
"""
import argparse
import re
import sys
import time

import serial

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

LINE = re.compile(rb"\[([0-9A-Fa-f]{8})\]((?: [0-9A-Fa-f]{2}){16})")
REBOOT_MARKERS = (b"RT-Thread", b"BK7252N", b"bk_reboot", b"Usage:", b"failed")


class Dumper:
    def __init__(self, port, baud):
        s = serial.Serial()
        s.port = port
        s.baudrate = baud
        s.timeout = 0.05
        s.dtr = False
        s.rts = False
        s.open()
        self.s = s
        self.seen = {}
        self.reprobes = 0

    def close(self):
        self.s.close()

    def probe(self, part):
        s = self.s
        s.reset_input_buffer()
        s.write(("fal probe %s\r\n" % part).encode())
        s.flush()
        buf = bytearray()
        t = time.time() + 6.0
        while time.time() < t:
            n = s.in_waiting
            c = s.read(n if n else 1)
            if c:
                buf += c
                m = re.search(rb"offset:\s*(\d+)\s*\|\s*len:\s*(\d+)", buf)
                if m:
                    return int(m.group(1)), int(m.group(2))
        return None

    def fetch(self, base, count, idle_gap=1.0, hard_cap=30.0):
        """Send one `fal read` and harvest every offset-tagged line it emits.

        Terminates on "no NEW hex line for idle_gap seconds" - byte-level idle
        never happens because the RTOS logs constantly.
        Returns (new_line_count, anomaly_marker_or_None).
        """
        s = self.s
        s.reset_input_buffer()
        s.write(("fal read %d %d\r\n" % (base, count)).encode())
        s.flush()
        buf = bytearray()
        deadline = time.time() + hard_cap
        last_new = time.time()
        n_new = 0
        while time.time() < deadline:
            n = s.in_waiting
            c = s.read(n if n else 1)
            if c:
                buf += c
                fresh = False
                for m in LINE.finditer(buf):
                    off = int(m.group(1), 16)
                    if off not in self.seen:
                        self.seen[off] = bytes.fromhex(
                            m.group(2).decode().replace(" ", ""))
                        n_new += 1
                        fresh = True
                if fresh:
                    last_new = time.time()
            if n_new and (time.time() - last_new) > idle_gap:
                break
            if len(buf) > (1 << 20):
                buf = buf[-8192:]
        anomaly = None
        for marker in REBOOT_MARKERS:
            if marker in buf:
                anomaly = marker.decode()
                break
        return n_new, anomaly


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default="COM5")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--part", default="app")
    ap.add_argument("--size", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--chunk", type=lambda x: int(x, 0), default=0x2000)
    ap.add_argument("--out", required=True)
    ap.add_argument("--passes", type=int, default=8)
    ap.add_argument("--merge-gap", dest="merge_gap", type=lambda x: int(x, 0),
                    default=0x800,
                    help="coalesce missing runs separated by less than this")
    ap.add_argument("--max-read", dest="max_read", type=lambda x: int(x, 0),
                    default=0x1000,
                    help="largest single fal read issued during repair")
    a = ap.parse_args()

    d = Dumper(a.port, a.baud)
    try:
        d.s.write(b"\r\n")
        d.s.flush()
        time.sleep(0.4)
        pr = d.probe(a.part)
        if not pr:
            print("Could not probe partition %r" % a.part)
            return 1
        part_off, part_len = pr
        total = a.size or part_len
        print("partition %s @ flash 0x%X, len 0x%X -> dumping %d bytes"
              % (a.part, part_off, part_len, total), flush=True)

        wanted = set(range(0, total, 16))
        t0 = time.time()

        for base in range(0, total, a.chunk):
            n = min(a.chunk, total - base)
            got, anomaly = d.fetch(base, n)
            tries = 0
            while got == 0 and tries < 3:
                tries += 1
                d.reprobes += 1
                print(" | chunk 0x%X empty (saw %s), re-probing" % (base, anomaly),
                      flush=True)
                time.sleep(1.0)
                d.probe(a.part)
                got, anomaly = d.fetch(base, n)
            done = base + n
            rate = done / max(time.time() - t0, 0.001)
            print("\r  sweep %6.2f%%  %7d/%d B  %5.0f B/s  ETA %4.0fs  lines=%d  "
                  % (100.0 * done / total, done, total, rate,
                     (total - done) / max(rate, 1), len(d.seen)),
                  end="", flush=True)
        print(flush=True)

        for p_i in range(a.passes):
            missing = sorted(wanted - set(d.seen))
            if not missing:
                break
            # Coalesce gaps that are close together: re-reading a little good
            # data is far cheaper than issuing one command per missing line.
            runs = []
            start = prev = missing[0]
            for off in missing[1:]:
                if off <= prev + a.merge_gap:
                    prev = off
                else:
                    runs.append((start, prev + 16))
                    start = prev = off
            runs.append((start, prev + 16))
            print("  repair pass %d: %d missing lines in %d runs"
                  % (p_i + 1, len(missing), len(runs)), flush=True)
            # A merged run can span most of the partition; split it into windows
            # small enough to actually transfer, and scale the cap with the size.
            windows = []
            for lo, hi in runs:
                lo2 = max(0, lo - 16)
                hi2 = min(total, hi + 16)
                for w in range(lo2, hi2, a.max_read):
                    windows.append((w, min(w + a.max_read, hi2)))
            for lo2, hi2 in windows:
                span = hi2 - lo2
                cap = max(8.0, span / 1800.0 + 5.0)
                got, _ = d.fetch(lo2, span, idle_gap=0.7, hard_cap=cap)
                if got == 0:
                    d.probe(a.part)

        missing = sorted(wanted - set(d.seen))
        out = bytearray(b"\xff" * total)
        for off, data in d.seen.items():
            if off < total:
                out[off:off + len(data)] = data
        with open(a.out, "wb") as fh:
            fh.write(out)
        print("wrote %s (%d bytes); %d/%d lines missing (%.4f%%); %d re-probes; %.0fs"
              % (a.out, len(out), len(missing), total // 16,
                 100.0 * len(missing) / max(total // 16, 1), d.reprobes,
                 time.time() - t0), flush=True)
        if missing:
            print("  first missing: %s"
                  % ", ".join("0x%X" % m for m in missing[:12]), flush=True)
    finally:
        d.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
