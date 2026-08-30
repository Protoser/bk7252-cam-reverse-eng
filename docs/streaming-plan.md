# Getting video off the camera locally - ranked plan

Goal: camera outputs its video feed over the LAN, no app, no cloud.

## Correction to earlier finding
The earlier conclusion ("no local stream exists, live view needs an afternoon of
protocol RE, not recommended") was wrong on both halves. Two routes need **no
firmware modification at all**. Also: the original hotspot port scan was TCP-only,
so it could not have seen a UDP trigger listener.

---

## Path 1 - wake the stock video_transfer demo  (try first, cheapest)
Beken's BK7252 SDK ships an image-transmission demo that the vendor firmware is
built on top of. Two documented ways in:

- **UDP trigger.** Send payload `Bv` to UDP **8080**, or `0f` to UDP **8070**,
  while the camera is in hotspot mode. This starts the MJPEG stream.
- **Shell command.** The finsh/msh shell may expose `video_transfer -a|s <ssid> <key>`.

Probe order once the serial shell is back:
    help                      # full command list - the ground truth
    video_transfer            # does the command exist?
    tvideo / vt / camera / cam
    list_device
    ifconfig

Zero risk, reversible, and if it works we are done.

## Path 2 - cam-reverse (finished PPPP client)   (fallback, also no firmware change)
https://github.com/DavidVentura/cam-reverse - a re-implementation of the
iLnk / iLnkP2P / PPPP protocol used by exactly these X5/A9-class cameras.
Handles LanSearch -> PunchPkt -> P2PRdy -> ConnectUser and the 400-500ms
P2PAlive heartbeat; reassembles 1028-byte payloads into JPEG frames plus
8 kHz A-law PCM audio.

    node dist/bin.cjs http_server     # MJPEG at http://localhost:5000/, ~350ms latency

This is the protocol behind the gated 20190/20023 ports. It speaks the app's
handshake, so it should work against the camera on the isolated VLAN with no
internet - the P2P layer falls back to LAN discovery.

## Path 3 - firmware analysis  (ACTIVE - chosen 2026-08-30)
Order of operations, do not skip step 1:
1. **Dump flash first**, over the Beken UART bootloader (bk_writer / hid_download
   style tools). No patching until a full known-good image is on disk.
2. RE the image to find the video pipeline entry points and the avsdk gate.
3. Patch to start an unconditional MJPEG push, reflash over UART.

Real brick risk, and it is unnecessary work if Path 1 lands. Deferred.

---

## Blocker
Camera is not reachable by either serial or network right now - see link-status.md.
Host is on 192.168.178.0/24; the camera's isolated VLAN is not visible from here,
and ARP shows no camera on this subnet.

Note: cam-reverse reports these cameras' UART test points run at **921600 8N1**.
If the ESP32-S3 bridge sketch is set to 115200 on the *camera-facing* side, that
is a candidate cause of the silence.

---

# Status update 2026-08-30

- **Path 1 (Beken UDP trigger): RULED OUT.** `netstat` shows the only listeners
  are TCP 20190, TCP 20023 and UDP 20190. Nothing on 8080/8070. The vendor
  replaced Beken's demo with their own avsdk/iLnk stack.
- **Path 2 (cam-reverse): built, blocked, and uncertain.** `third_party/cam-reverse`
  compiles to `dist/bin.cjs`. Two problems: it broadcasts LanSearch to UDP **32108**
  while this camera listens on **20190**, and it targets TXW817 devices whereas
  this is a BK7252 running `avsdk`/`pprpc`/`iot.dev.glbs`. The port is a one-line
  change; whether the wire protocol matches underneath is unknown.
- **Reachability is the gate.** The camera will not leave softAP mode
  (`wifi cfg` does not stick), so any IP test needs a client on its own hotspot
  at 192.168.9.x - this PC would have to leave its WLAN to do it.
- **Path 3 is now active** by choice: dump `app` with `fal read` and find out what
  the protocol on 20190/20023 actually is, rather than guessing at ports.

What to look for in the dump:
- strings around `iot_dev_localsrv_udp`, `pprpc`, `avsdk`, `LanSearch`/`PunchPkt`
  equivalents, and the 20190/20023 constants;
- whether `start web camerar` (xdev_video.c) implies an HTTP/MJPEG handler that
  is compiled in but never bound;
- the gate that rejects non-app handshakes on 20190/20023.
