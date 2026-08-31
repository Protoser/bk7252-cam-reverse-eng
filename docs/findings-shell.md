# Shell enumeration results (2026-08-30)

Link: PC -> CH343 (COM5) -> ESP32-S3 bridge -> camera. **115200 8N1**, both sides.
Prompt is `msh />` (RT-Thread finsh). Logs stream continuously and interleave with
command output; filter client-side (`set_log off` did not silence them).

## Device identity
    romVer      = 3.00.21.01_250918
    IOTSDK Ver  = 3.00.42.01_241230
    hardwareVer = INNO-IPC-48N-V2.2
    ap  MAC c8:47:8c:6c:2d:76
    w0  MAC c8:47:8c:6c:2d:77

## Network state
    ap : 192.168.9.252/24  UP LINK_UP     <- camera hotspot is LIVE
    w0 : 0.0.0.0           UP LINK_DOWN   <- NOT joined to any network
    lo : 127.0.0.1
Cloud is unreachable, as intended: repeated `tcp://8.209.77.49:8000` and
`tcp://39.108.59.60:465` (Alibaba Cloud) attempts all end in
`Failed to connect timeout` / `No conn Platfrom!`.

## Interesting commands (from `help`)
    video_buffer  - "vbuf open/read len/close/"   <- JPEG frame buffer API
    netio_init    - "NetIO server start successfully"  <- starts a TCP server
    fal           - Flash Abstraction Layer  <- firmware dump path, no bootloader needed
    wifi          - wifi command (used previously for `wifi cfg`)
    wifi_demo     - Beken app demo
    xc            - vendor CLI, bare invocation prints nothing (needs a subcommand)
    audio_dump, adc_check, netstat, dns, ping, ifconfig
    ls/cat/cp/mv/rm/df/mkfs  - filesystem
    xm_enter_deep_sleep, sleep_mode, pm_level, wdg_start/stop/refresh

## video_buffer behaviour
    video_buffer open        -> ok, silent
    video_buffer read 512    -> "get frame ret: -5, len:0"
    video_buffer read 2048   -> "vbuf full! / read frame full /
                                 get frame ret: -2, len:0 / full or data err, retry?"
The encoder runs at ~20 fps / ~300 KB/s (`jpeg fps:[20] bitrate:[300 KB]`); a
115200 shell drains ~11 KB/s, so the buffer overruns immediately. Serial is not a
viable transport - this only confirms the buffer opens and is being fed.

## PROBLEM: microSD is not working
    W sd_card: CMD8 SEND_IF_COND err:-3902
    W sd_card: CMD55 APP_CMD err:-3902
    [E] tf_record.c: SD File System initialzation failed!
    [E] tf_record.c: statfs failed for path->[/sd]
Repeats on a loop. Local recording - the previously recommended everyday mode -
is currently broken. Card absent, unseated, or not accepted by the controller.

## Also seen
Motion detection is active and firing: `---MotionDetection :23095,1  framelen = 15288 ---`
Battery healthy: vbat ~4.15-4.20 V, `battery=100`, `usb level is 1`.

## Listening sockets (netstat, 2026-08-30)
    Listen PCB:  #0 local port 20190 LISTEN
                 #1 local port 20023 LISTEN
    UDP PCB:     #0 0.0.0.0:20190
                 #1 0.0.0.0:67        (DHCP server for the camera's own AP)

**Path 1 (Beken stock video_transfer UDP trigger) is ruled out.** Nothing listens
on UDP 8080 or 8070. The vendor replaced Beken's demo with their avsdk/iLnk stack.
20190 + 20023 are the only video services. UDP 20190 is the LAN-discovery socket
that cam-reverse speaks to -> Path 2 is the live route.

## Services started at boot (from boot log)
    xdev_video.c /00207 : start web camerar
    [iot.dev.localsrv] : ====== iot_dev_localsrv_udp_start ======
    [iot.dev.upnpc]    : iot_dev_upnpc_start
    dev_ble /00379     : start ble
    iot.dev.glbs state: IDLE -> INIT -> RUN_TCP -> RUN_UDP

## Provisioning to a router is NOT taking
`wifi cfg SSID PASSWORD` is accepted silently but has no effect; bare `wifi` still
reports `ssid is null or bssid is invalid/disabled`, and after a reboot the SDK
reads back its own AP credentials:
    [get_wifi_con] ssid = LLM_HA10_06C095, password = 12345678
The device boots into softAP/pairing mode every time: `uap_ip_start`, static
192.168.9.252, DHCP pool 192.168.9.100-254. `wifi wlan_dev *` is unavailable
("no wlan:wlan_dev device") - the vendor bypasses RT-Thread's wlan framework.
Normal provisioning is BLE -> app -> credentials, which is what we are avoiding.
### to join a network: wifi w0 join [SSID] [PASS]

Consequence: reaching the camera over IP means joining ITS access point
(LLM_HA10_06C095 / 12345678, gateway 192.168.9.252), not putting it on the LAN.

## Interactive shell: tools/camterm.py
`camsh.py` sends one batch of commands per invocation. `camterm.py` is a
persistent terminal - connect once, type commands, keep typing:

    python tools/camterm.py            # connect (COM5 @ 115200)
    python tools/camterm.py --raw      # unfiltered
    python tools/camterm.py --replay logs/<file>.log   # test the filter offline

Meta-commands: /raw /filter /noise /echo /log <file> /quit

Measured effect: an `ifconfig` session that produced 820 raw lines yields the 5
that matter; a `help` capture drops from 375 lines to 65. Typically ~200 noise
records removed per short session.

### How the filter works, and why it is not just a line grep
The spam is injected *mid-line*, so whole-line filtering leaves replies shredded.
Instead each noise pattern eats its own trailing newlines, which stitches the
interrupted line back together. Four things that had to be right:

- **Split before filtering.** Only complete lines may be filtered. The trailing
  partial line must be left alone - a record still arriving byte by byte would
  match (each pattern's trailing-newline part can match empty), get deleted
  early, and its remainder would land as an orphan like `oltage:4207---`.
  This only shows up live; a `--replay` of a whole file will not reveal it.
- **Iterate to a fixed point.** Removing a record joins the fragments either
  side, which can form a *new* record the pass already walked past.
- **NUL runs mean dropped bytes**, not noise. They become a line break rather
  than being closed up - fusing across real data loss would invent a
  plausible-looking but wrong line.
- **Context-aware unmuting.** `free` prints the same memory table the filter
  suppresses, and `date` prints the same date line. Sending one of those
  un-suppresses that category for 3 s (see `UNMUTE_ON`).

The firmware emits `\r\r\n` on some lines and often a blank line after a record,
so the newline-eating pattern allows runs of CRs and multiple newlines.
