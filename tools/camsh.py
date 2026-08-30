#!/usr/bin/env python3
"""camsh.py - serial driver for the BK7252 camera's RT-Thread (finsh/msh) shell.

Read-only by default: it sends only the commands you pass on the command line.
Every session is teed to logs/ so captures are never lost to scrollback.

Usage:
    python tools/camsh.py probe                  # find the working baud rate
    python tools/camsh.py listen --secs 10       # passive capture (e.g. during boot)
    python tools/camsh.py run "help" "ps"        # send commands, capture replies
"""
import argparse
import datetime
import os
import sys
import time

import serial

# Windows consoles default to cp1252 and choke on replacement chars from noisy lines.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

DEFAULT_PORT = "COM5"
BAUD_CANDIDATES = [115200, 921600, 460800, 230400, 57600, 38400, 9600]
LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")


def open_port(port, baud, timeout=0.05):
    """Open without asserting DTR/RTS - those lines are wired to reset/boot on
    many USB-UART boards and we do not want to bounce the bridge."""
    s = serial.Serial()
    s.port = port
    s.baudrate = baud
    s.bytesize = serial.EIGHTBITS
    s.parity = serial.PARITY_NONE
    s.stopbits = serial.STOPBITS_ONE
    s.timeout = timeout
    s.dtr = False
    s.rts = False
    s.open()
    return s


def drain(s, seconds, quiet_stop=None):
    """Read for `seconds`. If `quiet_stop` is set, return early once the line has
    been silent that long and we already have data."""
    buf = bytearray()
    t_end = time.time() + seconds
    last = time.time()
    while time.time() < t_end:
        n = s.in_waiting
        chunk = s.read(n if n else 1)
        if chunk:
            buf += chunk
            last = time.time()
        elif quiet_stop is not None and buf and (time.time() - last) >= quiet_stop:
            break
    return bytes(buf)


def printable_ratio(data):
    if not data:
        return 0.0
    ok = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return ok / len(data)


def show(data, label=None):
    if label:
        print("=" * 8 + " " + label + " " + "=" * 8)
    if not data:
        print("(no data)")
        return
    ratio = printable_ratio(data)
    print(data.decode("utf-8", errors="replace"))
    if ratio < 0.85:
        print("--- looks like garbage (printable=%.2f), first 64 bytes hex ---" % ratio)
        print(data[:64].hex(" "))


def logfile(tag):
    os.makedirs(LOG_DIR, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    return os.path.join(LOG_DIR, "%s-%s.log" % (ts, tag))


def tee(path, text):
    with open(path, "a", encoding="utf-8", errors="replace") as fh:
        fh.write(text)


def cmd_probe(args):
    """Try each candidate baud, nudge the shell, and score the reply."""
    results = []
    for baud in BAUD_CANDIDATES:
        try:
            s = open_port(args.port, baud)
        except Exception as exc:
            print("%7d : cannot open (%s)" % (baud, exc))
            continue
        try:
            time.sleep(0.2)
            s.reset_input_buffer()
            s.write(b"\r\n")
            s.flush()
            data = drain(s, 1.5, quiet_stop=0.5)
            if not data:
                # Nothing echoed back; the shell may only be emitting logs.
                data = drain(s, 1.0, quiet_stop=0.5)
            ratio = printable_ratio(data)
            results.append((baud, len(data), ratio, data))
            print("%7d : %4d bytes, printable=%.2f  %r" % (baud, len(data), ratio, data[:48]))
        finally:
            s.close()
    good = [r for r in results if r[1] > 0 and r[2] >= 0.9]
    print()
    if good:
        best = max(good, key=lambda r: r[1])
        print("Best candidate: %d baud" % best[0])
    else:
        print("No baud produced clean ASCII. The camera may be idle (no unsolicited")
        print("log output) - try `listen` while power-cycling it to catch the boot log.")


def cmd_listen(args):
    path = logfile("listen")
    s = open_port(args.port, args.baud)
    print("Listening on %s @ %d for %ds (logging to %s)" % (args.port, args.baud, args.secs, path))
    try:
        data = drain(s, args.secs)
    finally:
        s.close()
    tee(path, data.decode("utf-8", errors="replace"))
    show(data, "captured %d bytes" % len(data))


def cmd_run(args):
    path = logfile("run")
    eol = {"crlf": "\r\n", "cr": "\r", "lf": "\n"}[args.eol]
    s = open_port(args.port, args.baud)
    print("Connected %s @ %d (logging to %s)\n" % (args.port, args.baud, path))
    try:
        # Wake the prompt and discard whatever was already buffered.
        s.reset_input_buffer()
        s.write(eol.encode())
        s.flush()
        banner = drain(s, 1.0, quiet_stop=0.4)
        if banner:
            show(banner, "prompt")
            tee(path, banner.decode("utf-8", errors="replace"))

        for c in args.commands:
            s.reset_input_buffer()
            s.write((c + eol).encode())
            s.flush()
            data = drain(s, args.timeout, quiet_stop=args.quiet)
            header = "\n===== $ %s =====\n" % c
            print(header, end="")
            show(data)
            tee(path, header + data.decode("utf-8", errors="replace"))
    finally:
        s.close()


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--port", default=DEFAULT_PORT)
    p.add_argument("--baud", type=int, default=115200)
    sub = p.add_subparsers(dest="mode", required=True)

    sp = sub.add_parser("probe", help="try candidate baud rates")
    sp.set_defaults(func=cmd_probe)

    sl = sub.add_parser("listen", help="passive capture")
    sl.add_argument("--secs", type=float, default=10.0)
    sl.set_defaults(func=cmd_listen)

    sr = sub.add_parser("run", help="send commands and capture replies")
    sr.add_argument("commands", nargs="+")
    sr.add_argument("--timeout", type=float, default=3.0, help="max seconds to wait per command")
    sr.add_argument("--quiet", type=float, default=0.5, help="silence gap that ends a reply")
    sr.add_argument("--eol", choices=["crlf", "cr", "lf"], default="crlf")
    sr.set_defaults(func=cmd_run)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
