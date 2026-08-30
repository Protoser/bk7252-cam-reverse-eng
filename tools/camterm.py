#!/usr/bin/env python3
"""camterm.py - a persistent, de-noised terminal for the camera's msh shell.

Unlike camsh.py (one command per invocation), this stays connected: type a
command, get the reply, keep typing.

The RTOS emits ~460 B/s of log spam that cannot be switched off (`set_log off`
does nothing; `xm_printf_bit_cmd`'s mask is already zero), and it is injected
*mid-line* - a real reply gets a `[xm]led off` record stapled into the middle of
it. So the filter removes each noise record INCLUDING its trailing newlines from
the raw stream, which stitches the interrupted line back together. Filtering
whole lines instead would leave the reply in shredded fragments.

    python tools/camterm.py                     # connect and go
    python tools/camterm.py --raw               # start unfiltered
    python tools/camterm.py --replay logs/x.log # test the filter on a saved log

Meta-commands (typed at the prompt, not sent to the camera):
    /raw /filter    toggle noise filtering
    /noise          show what has been filtered and how often
    /echo           toggle suppression of the device's command echo
    /log <file>     start teeing the clean output to a file
    /quit           exit
"""
import argparse
import os
import re
import sys
import threading
import time
from collections import Counter

import serial

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")

# Each pattern eats its own trailing newlines so a record injected into the
# middle of a real line rejoins that line instead of splitting it in two.
# The firmware emits \r\r\n on some lines and often leaves a blank line after a
# record, so eat runs of CRs and any number of following newlines - matching just
# one would leave the newline behind and the real line would stay split.
NL = r"[ \t]*(?:\r*\n)*"
NOISE = [
    ("rtt-log",   r"\[[IEWDA]/\d{4}-\d{2}-\d{2}[^\]]*\]\s*\[[^\]]*\]\s*:[^\r\n]*" + NL),
    ("iot-log",   r"\[(?:INFO|ERROR|WARN|ALWAY|DEBUG)\s*\]\s*\[[^\]]*\]\s*\[[^\]]*\][^\r\n]*" + NL),
    ("led",       r"\[xm\]led (?:on|off)" + NL),
    ("jpeg-fps",  r"jpeg fps:\[[^\]]*\][^\r\n]*" + NL),
    ("date",      r"date:\s*\d{4}-\d+-\d+,\s*time:[^\r\n]*" + NL),
    ("motion",    r"-{2,}MotionDetection[^\r\n]*" + NL),
    ("sdcard",    r"W \(\d+\)\s+\w+:[^\r\n]*" + NL),
    ("adc",       r"(?:temp_code|init_xtal|set adc channel)[^\r\n]*" + NL),
    ("statusreg", r"--write status reg:[^\r\n]*" + NL),
    ("memtable",  r"[ \t]*pool size\s+max used size\s+available size" + NL),
    ("memtable",  r"-{3,}\s+-{3,}\s+-{3,}\s+-{3,}" + NL),
    ("memtable",  r"(?:ITCM|TCM|heap)\s+\d+\s+\d+\s+\d+" + NL),
]
NOISE_RE = [(name, re.compile(pat)) for name, pat in NOISE]

NULRUN = re.compile("\x00+")

# Some noise categories are also legitimate command output: `free` prints the
# very memory table we suppress, and `date` prints the very line we suppress.
# When you ask for one, stop filtering that category briefly.
UNMUTE_ON = {
    "free": {"memtable"},
    "list_memheap": {"memtable"},
    "list_mempool": {"memtable"},
    "date": {"date"},
    "adc_check": {"adc"},
}
# Long enough for the reply to arrive at 115200, short enough that only a couple
# of periodic records slip through alongside it.
UNMUTE_SECONDS = 3.0


class Filter:
    def __init__(self, enabled=True):
        self.enabled = enabled
        self.counts = Counter()
        self.pending = ""
        self.unmuted = set()
        self.unmute_until = 0.0

    def note_command(self, cmd):
        """Called when the user sends a command, so its own output survives."""
        cats = UNMUTE_ON.get(cmd.split()[0] if cmd.split() else "", set())
        if cats:
            self.unmuted = cats
            self.unmute_until = time.time() + UNMUTE_SECONDS

    def _active(self, name):
        if name in self.unmuted and time.time() < self.unmute_until:
            return False
        return True

    def feed(self, text):
        """Return cleaned, complete lines; hold any partial tail."""
        # A run of NULs means the UART actually dropped bytes. Turn it into a
        # line break rather than closing the gap: joining across real data loss
        # would fuse two records into one plausible-looking but wrong line.
        text = NULRUN.sub("\n", text)
        self.pending += text

        # Split FIRST, filter second. The trailing partial line must never be
        # filtered: a record still arriving byte by byte would match (the
        # trailing-newline part of each pattern can match empty) and be deleted
        # early, and its remainder would then land as an orphan fragment like
        # "oltage:4207---". Only complete lines are safe to filter.
        cut = self.pending.rfind("\n")
        if cut < 0:
            return ""
        out, self.pending = self.pending[:cut + 1], self.pending[cut + 1:]

        if self.enabled:
            # Removing a record joins the fragments either side of it, which can
            # form a *new* noise record the pass has already walked past. So
            # iterate to a fixed point rather than filtering once.
            for _ in range(6):
                changed = False
                for name, rx in NOISE_RE:
                    if not self._active(name):
                        continue
                    out, n = rx.subn("", out)
                    if n:
                        self.counts[name] += n
                        changed = True
                if not changed:
                    break
        return out


def clean_lines(out, suppress_echo=False, last_cmd=None):
    """Drop blanks, bare prompts, and the device's echo of the command sent."""
    kept = []
    for line in out.split("\n"):
        s = line.rstrip("\r")
        if not s.strip():
            continue
        # The prompt carries no trailing newline, so it glues itself onto
        # whatever is printed next; strip it off rather than losing the line.
        while s.startswith("msh />"):
            s = s[len("msh />"):]
        if not s.strip():
            continue
        if suppress_echo and last_cmd:
            probe = s.strip()
            # the shell echoes the command back, often with its first char doubled
            if probe == last_cmd or (len(probe) > 1 and probe[0] == probe[1]
                                     and probe[1:] == last_cmd):
                continue
        kept.append(s)
    return kept


def replay(path, enabled=True, limit=80):
    f = Filter(enabled)
    raw = open(path, encoding="utf-8", errors="replace").read()
    # feed() only filters complete lines, so make sure the file ends with one
    out = f.feed(raw if raw.endswith(chr(10)) else raw + chr(10))
    lines = clean_lines(out)
    print("--- %s ---" % path)
    print("raw lines: %d -> kept: %d" % (len(raw.split("\n")), len(lines)))
    print("filtered: %s" % (dict(f.counts) or "nothing"))
    print("-" * 60)
    for l in lines[:limit]:
        print(l)
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", default="COM5")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--raw", action="store_true", help="start with filtering off")
    ap.add_argument("--no-echo-suppress", dest="echo", action="store_false",
                    help="show the device's echo of your command")
    ap.add_argument("--eol", choices=["crlf", "cr", "lf"], default="crlf")
    ap.add_argument("--replay", metavar="FILE",
                    help="run the filter over a saved log and exit")
    a = ap.parse_args()

    if a.replay:
        return replay(a.replay, not a.raw)

    eol = {"crlf": "\r\n", "cr": "\r", "lf": "\n"}[a.eol]
    filt = Filter(enabled=not a.raw)
    state = {"last_cmd": None, "echo": a.echo, "logfh": None, "stop": False}

    s = serial.Serial()
    s.port = a.port
    s.baudrate = a.baud
    s.timeout = 0.05
    s.dtr = False
    s.rts = False
    s.open()

    def reader():
        while not state["stop"]:
            try:
                n = s.in_waiting
                chunk = s.read(n if n else 1)
            except Exception:
                break
            if not chunk:
                continue
            out = filt.feed(chunk.decode("latin-1"))
            if not out:
                continue
            for line in clean_lines(out, state["echo"], state["last_cmd"]):
                sys.stdout.write(line + "\n")
                if state["logfh"]:
                    state["logfh"].write(line + "\n")
                    state["logfh"].flush()
            sys.stdout.flush()

    threading.Thread(target=reader, daemon=True).start()

    print("connected to %s @ %d  |  filter %s  |  /help for meta-commands"
          % (a.port, a.baud, "ON" if filt.enabled else "OFF"))
    s.write(eol.encode())
    s.flush()

    try:
        while True:
            try:
                line = input()
            except EOFError:
                break
            cmd = line.strip()

            if cmd in ("/quit", "/exit", "/q"):
                break
            if cmd == "/help":
                print("  /raw /filter  toggle noise filtering (now: %s)"
                      % ("ON" if filt.enabled else "OFF"))
                print("  /noise        what has been filtered so far")
                print("  /echo         toggle echo suppression (now: %s)"
                      % ("ON" if state["echo"] else "OFF"))
                print("  /log <file>   tee clean output to a file")
                print("  /quit         exit")
                continue
            if cmd in ("/raw", "/filter"):
                filt.enabled = (cmd == "/filter")
                print("  filter %s" % ("ON" if filt.enabled else "OFF"))
                continue
            if cmd == "/noise":
                total = sum(filt.counts.values())
                print("  %d records filtered: %s" % (total, dict(filt.counts) or "none"))
                continue
            if cmd == "/echo":
                state["echo"] = not state["echo"]
                print("  echo suppression %s" % ("ON" if state["echo"] else "OFF"))
                continue
            if cmd.startswith("/log"):
                parts = cmd.split(None, 1)
                if state["logfh"]:
                    state["logfh"].close()
                    state["logfh"] = None
                if len(parts) > 1:
                    os.makedirs(LOG_DIR, exist_ok=True)
                    p = parts[1] if os.path.isabs(parts[1]) else os.path.join(LOG_DIR, parts[1])
                    state["logfh"] = open(p, "a", encoding="utf-8", errors="replace")
                    print("  logging to %s" % p)
                else:
                    print("  logging stopped")
                continue
            if cmd.startswith("/"):
                print("  unknown meta-command %r - /help for the list" % cmd)
                continue

            state["last_cmd"] = cmd
            filt.note_command(cmd)
            s.write((cmd + eol).encode())
            s.flush()
    except KeyboardInterrupt:
        pass
    finally:
        state["stop"] = True
        time.sleep(0.2)
        if state["logfh"]:
            state["logfh"].close()
        s.close()
        print("\ndisconnected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
