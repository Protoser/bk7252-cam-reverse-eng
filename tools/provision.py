#!/usr/bin/env python3
"""Join the camera's station interface (w0) to a WLAN via the msh shell.

Reads the WLAN passphrase from the Windows profile store so it never has to be
typed, and redacts it from every printed line and from the session log.
"""
import argparse
import re
import subprocess
import sys
import time

import serial

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# netsh is localised; accept the common field labels.
SSID_KEYS = ("SSID", "SSID-Name")
KEY_KEYS = ("Key Content", "Schlusselinhalt", "Schluesselinhalt", "Contenu de la cle")


def netsh(args):
    out = subprocess.run(["netsh"] + args, capture_output=True, text=True,
                         errors="replace", encoding="utf-8")
    return out.stdout


def current_ssid():
    txt = netsh(["wlan", "show", "interfaces"])
    for line in txt.splitlines():
        m = re.match(r"\s*SSID\s*:\s*(.+?)\s*$", line)
        if m and "BSSID" not in line:
            return m.group(1)
    return None


def profile_key(ssid):
    txt = netsh(["wlan", "show", "profile", "name=" + ssid, "key=clear"])
    for line in txt.splitlines():
        if ":" not in line:
            continue
        label, _, value = line.partition(":")
        label = label.strip().replace("ü", "u").replace("é", "e")
        if any(label.startswith(k) for k in KEY_KEYS):
            v = value.strip()
            if v:
                return v
    return None


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--port", default="COM5")
    p.add_argument("--baud", type=int, default=115200)
    p.add_argument("--ssid", help="default: the WLAN this PC is on")
    p.add_argument("--psk", help="default: read from the Windows profile store")
    p.add_argument("--wait", type=float, default=45.0, help="seconds to wait for DHCP")
    a = p.parse_args()

    ssid = a.ssid or current_ssid()
    if not ssid:
        sys.exit("Could not determine the SSID - pass --ssid.")
    psk = a.psk or profile_key(ssid)
    if not psk:
        sys.exit("Could not read the passphrase for %r from Windows - pass --psk." % ssid)

    def redact(text):
        return text.replace(psk, "<REDACTED>")

    print("SSID: %s   passphrase: %d chars, read from Windows profile store" % (ssid, len(psk)))

    s = serial.Serial()
    s.port = a.port; s.baudrate = a.baud; s.timeout = 0.05
    s.dtr = False; s.rts = False
    s.open()

    def send(cmd, wait=3.0):
        s.reset_input_buffer()
        s.write((cmd + "\r\n").encode()); s.flush()
        buf = bytearray(); t = time.time() + wait
        while time.time() < t:
            n = s.in_waiting
            c = s.read(n if n else 1)
            if c: buf += c
        return redact(bytes(buf).decode("latin-1"))

    def interesting(text):
        noise = ("[xm]led", "xdev_", "xvideo.c", "date:", "jpeg fps", "pprpc",
                 "iot.dev", "osal.", "MotionDetection", "tf_record", "sd_card",
                 "avsdk", "pool size", "-------", "ITCM", "TCM ", "heap ")
        return [l for l in text.splitlines()
                if l.strip() and not any(k in l for k in noise)]

    try:
        send("")
        print("\n--- wifi cfg ---")
        out = send("wifi cfg %s %s" % (ssid, psk), 6.0)
        for l in interesting(out):
            print("  " + l)

        print("\n--- waiting for DHCP on w0 ---")
        deadline = time.time() + a.wait
        ip = None
        while time.time() < deadline:
            out = send("ifconfig", 3.0)
            block = None
            for line in out.splitlines():
                if "network interface" in line:
                    block = line
                if block and "w0" in block and "ip address" in line:
                    cand = line.split(":", 1)[1].strip()
                    if cand and cand != "0.0.0.0":
                        ip = cand
                    break
            if ip:
                break
            print("  ...still 0.0.0.0")
            time.sleep(4)

        print()
        if ip:
            print("w0 has an address: %s" % ip)
        else:
            print("w0 still has no address after %.0fs. Full ifconfig:" % a.wait)
            for l in interesting(send("ifconfig", 3.0)):
                print("  " + l)
            for l in interesting(send("wifi wlan_dev status", 3.0)):
                print("  " + l)
    finally:
        s.close()


if __name__ == "__main__":
    main()
