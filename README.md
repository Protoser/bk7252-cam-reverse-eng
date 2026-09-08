# bk7252-cam-reverse-eng

Reverse engineering notes and tools for a cheap BK7252-based WiFi camera, with
the goal of running it fully app-free and cloud-free on an isolated VLAN
(local video/control only, no vendor cloud in the loop).

## Hardware / access

- SoC: Beken BK7252. The camera never leaves softAP mode; it's reached at
  `192.168.9.252`, not on the LAN.
- Full root shell via UART pads (RT-Thread, 115200) bridged through an
  ESP32-S3, and separately via telnet on TCP 20023 (`root` / `123`).
- Local video/control uses a proprietary protocol, `avsdk` / `pprpc`, running
  over KCP (not iLnk/PPPP, so tools like `cam-reverse` don't apply directly).
  `pprpc` itself is open source (github.com/pprpc); only the device's own
  `ipc_*` messages needed reversing from the firmware.

## Repo layout

- `docs/` — write-ups, one per topic (start with `docs/protocol.md` and
  `docs/ghidra.md` for the core LAN auth/video chain).
- `tools/` — Python scripts used to talk to the camera (serial shell,
  telnet, LAN protocol client, BLE provisioning, flash dump).
- `dumps/` — flash dumps (bootloader, app, combined image).
- `logs/` — raw session logs from serial/telnet/LAN capture runs.
- `frames/`, `cap.mjpeg/` — sample frames pulled from the local video stream.
- `todo.md` — open threads.

Two things are intentionally **not** in this repo:
- `ghidra-rev/` (a 219MB local Ghidra project) — the actual findings from it
  are written up in `docs/ghidra.md`.
- `third_party/` (local clones of other projects referenced during research,
  e.g. `pprpc-core`) — see the docs for links instead of vendoring copies.

The web viewer built on top of this is a separate project:
[cam-web-viewer](https://github.com/Protoser/cam-web-viewer).

## Key findings

- [`docs/flash-dump.md`](docs/flash-dump.md) — dumping flash over the serial
  bootloader.
- [`docs/findings-shell.md`](docs/findings-shell.md) /
  [`docs/device-intel.md`](docs/device-intel.md) — root shell access (UART +
  telnet), full command list, what's on the filesystem.
- [`docs/protocol.md`](docs/protocol.md) — the LAN `pprpc`/`avsdk` wire
  protocol: framing, auth handshake, video streaming.
- [`docs/protocol-commands.md`](docs/protocol-commands.md) — the ~135-command
  surface (WiFi reconfig, reboot, PTZ, storage format, etc.) with confirmed
  CmdIDs.
- [`docs/ghidra.md`](docs/ghidra.md) — static analysis of the firmware:
  the auth/video send call chain, where the identity struct
  (`did`/`signkey`/`lslat`/`scode`) is loaded from, and how the per-device
  auth credential is derived.
- [`docs/ble-protocol.md`](docs/ble-protocol.md) — BLE WiFi provisioning:
  the camera runs a BLE stack at boot that accepts SSID/password and hands
  back `did` + a scode-derived auth token.

## Tools

Scripts under `tools/` (each has more detail at the top of the file):

- `dump_flash.py`, `camsh.py`, `camterm.py`, `probe_telnet.py` — serial /
  bootloader / telnet access.
- `pprpc.py`, `av.py`, `lan_client.py`, `cam_probe.py`, `lan_auth_sweep.py` —
  the LAN protocol: framing, auth, video capture.
- `glbs_sinkhole.py` — intercepting the camera's cloud "GetServers" call to
  capture its identity in cleartext at boot, without serial/telnet access.
- `wifi.py` — WiFi reconfiguration over the LAN protocol.
- `ble_provision.py` — BLE provisioning client.
- `provision.py` — general provisioning helper.

## A note on the secrets in this repo

Some docs and logs here contain **real, captured credentials** for the
specific physical camera unit used in this research (`did`, `signkey`,
`lslat`, `scode`). These are left in deliberately, unredacted, so the write-
ups stay concrete and other people working on the same hardware have
something real to compare against. These units are not in active use. If
you're re-using code or docs from here against a camera you actually rely
on, treat any values you find as compromised and don't reuse them as-is.

## Status

See [`todo.md`](todo.md) for open items.
