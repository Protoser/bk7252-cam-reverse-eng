# Device intel gathered from Ghidra (for the next hands-on session)

Everything here is actionable at the serial shell / on the camera's AP. Sourced
from static analysis of `dumps/firmware_combined.bin` (Ghidra project, base
0x10000 - see ghidra.md). Renamed functions + plate comments are in the Ghidra
DB. Gathered 2026-08-30.

## 1. Full shell command inventory (59 commands)
Enumerated from the FinSH command table (`__cmd_*` symbols; table at 0x149ac8+,
12-byte entries {name, desc, func}). `help` on the device only prints a subset;
this is the ground-truth complete list.

Network / system:
    ifconfig  netstat  dns  ping  netio_init  ntp_sync  date
    ps  free  stack  list_thread  list_fd  list_device  list_timer
    list_mempool  list_memheap  list_msgqueue  list_mailbox  list_mutex
    list_event  list_sem  reboot  set_log  help
Filesystem:
    ls  cat  cp  rm  mkdir  cd  pwd  df
Power / watchdog:
    wdg_start  wdg_stop  wdg_refresh  sleep_mode  pm_level
    xm_enter_deep_sleep
Flash / RF / radio:
    fal                (flash - dump path, NEVER `fal erase`)
    mac  rxsens  linkkey                         (RF/PHY test)
    rfcali_show_data  rfcali_cfg_tssi_g  rfcali_cfg_tssi_b
    rfcali_cfg_rate_dist  rfcali_cfg_mode        (RF calibration)
Camera / media / vendor:
    video_buffer       (encoder JPEG buffer open/read/close - see #5)
    audio_dump  mic_dac_loop  adc_check
    wifi  wifi_demo                              (see #4)
    cli_xwifi_reset                              (wifi reset - untested)
    xm_set_bit_cmd  xm_printf_bit_cmd            (log mask; already 0, can't
                                                  silence the log spam)

Notes:
- **No `telnet` command and no `xc` command in this table.** The telnet server
  (see #2) is started by a boot thread, not a shell command. `xc` (the vendor
  CLI noted in protocol.md as a dead end that bounces the AP) is dispatched by
  a separate mechanism, not FinSH.
- `list_device` / `list_fd` are new (not tried yet) and useful for enumerating
  hardware + open sockets from the shell.

## 2. Telnet server on TCP 20023 (network root shell candidate)
There IS a full telnet server compiled in (`xtelnet.c`, thread `telnet_task`),
and 20023 is one of the two always-listening TCP ports (the other, 20190, is
the pprpc/video port). It negotiates Telnet IAC then shows a banner
("Wellcome use telnet") and a `password>> ` prompt; wrong input ->
`>> Wrong password! ! !` and re-prompts. If the password is found, this is a
**root shell over the network** (same finsh shell as serial) - a big
convenience vs. the ESP32-S3 UART bridge.

### Password = `123`  (CONFIRMED)
Recovered by hand-decoding the Thumb of the login function (it's un-analyzed:
a boot thread, not a finsh command, and MCP Thumb-forcing is unavailable - so
disassemble_bytes rendered it as ARM garbage and I decoded the halfwords
manually). The relevant sequence, right after the password-input loop, at
0x000c8466:

    ldr r3,[pc,#0x220]   ; r3 = 0x00333231 = "123\0"   (pool @ 0xc8688)
    ldr r7,[pc,#0x220]   ; r7 = 0x0040b0dc              (pool @ 0xc868c)
    str r3,[r5]          ; store expected password "123" into a buffer
    ldr r3,[r7]          ; r3 = *(0x0040b0dc) = "configured password" pointer
    add r4,sp,#0xe8      ; r4 = the entered-password buffer
    cmp r3,#0
    beq <use default "123">     ; taken when no password is configured
    b   <compare against *(0x40b0dc)>

`"123"` is the default password, used when the global `0x0040b0dc` is null.
That global is a `.bss` value referenced ONLY at three telnet-local literal-
pool slots (0xc8340 / 0xc868c / 0xc8720); every use is a read, nothing in the
firmware writes a password to it (there is no telnet-password shell command,
and it is not a setting.json key). So it is always 0 -> the default branch
always runs -> **the telnet password is unconditionally `123`.**

**Action at the device:** `tools/probe_telnet.py --host 192.168.9.252 --send 123`
(override the stale default host 10.97.112.171). Port 20023. Expect the finsh
`msh />` root shell after it accepts. This is the same shell as serial, over
the network - no ESP32-S3 UART bridge needed once you're on the camera's AP.

## 3. netio_init - not useful (ruled out)
`netio_init` (FUN_000a41ec) is the stock RT-Thread/lwIP **netio throughput
benchmark** server. It only starts when you run the command (that's why the
earlier netstat, taken before running it, didn't show its port), guards against
double-start ("netio: server already running"), and just echoes data for
bandwidth measurement. Not a video path, not an auth bypass, nothing to exploit
for our goals. Don't chase it.

## 4. Why `wifi cfg` doesn't stick - and where creds actually go
Reversed the `wifi` command (`cmd_wifi` @ 0xbf5f4). `wifi cfg SSID PASSWORD`:
- copies SSID -> RAM global 0x407c4c, PASSWORD -> 0x407c6c, sets a Mode flag
  (0x4005a8) = 1;
- calls `wifi_write_setting_json` (0xbf350) which writes them into the JSON
  file **`/appfs/setting.json`** under keys `wifi.SSID`, `wifi.Key`,
  `wifi.Mode`.

**The catch:** `/appfs/setting.json` is referenced *only* by the `wifi cfg`
command (the string's address appears at exactly two code sites, both inside
`cmd_wifi`). Nothing in the boot / wifi bring-up / `get_wifi_con` path reads
station creds back from that file. So `wifi cfg` persists creds into a file the
connect path never consumes -> it's effectively a vendor stub. That is the
root cause of the observed "accepted silently but no effect, reboots back to
its own AP creds" behaviour. The real station provisioning uses the vendor
iot/BLE store (a different location), which is the thing the project is trying
to avoid.

The RT-Thread `wifi wlan_dev join|bjoin|ap ...` subcommands also exist in the
handler but fail on this device ("no wlan:wlan_dev device") because the vendor
bypasses RT-Thread's wlan framework.

**Actions at the device:**
- `cat /appfs/setting.json` - see what's actually stored (and whether an
  earlier `wifi cfg` left creds there); check if it survives a reboot (cat,
  `reboot`, cat) to learn whether /appfs is persistent. -> appfs is empty
- Editing `/appfs/setting.json` by hand won't help join a LAN unless we also
  find/patch the consumer; the productive next step for LAN mode is to locate
  the vendor iot provisioning store's read path (the `get_wifi_con` /
  `read wifi: SSID[%s] , PWD[%s]` code) and see what file/NVS key IT reads.

## 5. video_buffer command
`video_buffer` FinSH handler is at 0x920d8 (Thumb; Ghidra hadn't auto-created
the function, low priority to force). Behaviour is already characterised from
live device testing (see findings-shell.md): `open`/`read len`/`close` on the
encoder's JPEG ring buffer; the encoder runs ~20fps/~300KB and a 115200 shell
drains ~11KB/s so `read` overruns instantly (`vbuf full!`). It's a local
frame-buffer API but serial is far too slow to be a real transport - the pprpc
network path (VideoPlay, see protocol.md) remains the only viable video exit.

## 6. Cloud-retry thrashing = the frozen/bursty telnet + the reboots
Observed on-device: the telnet shell freezes for ~30s at a time then flushes in
a burst; login is slow. Root cause found in `iot_dev_handle` (0x00035230, the
iot.dev state machine). While the camera is cloud-disconnected it logs
`Failed to iot.dev.glbs, will sleep(off:8s~15s)or(on:60s~300s), retry.(N)` and
retries GetServers every 8-15s. Each retry does blocking DNS+connect attempts
to the unreachable Alibaba cloud IPs, which monopolise the single lwIP network
thread for seconds at a time - so the telnet TCP socket can't be serviced and
the shell freezes until the connect times out, then everything flushes. Same
thrashing eventually trips the `reboot reason: DEV net abnormal` reboot that
drops shell state mid-session.

Can we turn it off from the device? **No clean way.** The state machine's loop
exits only when one of two RAM flags is set (`ctx[0]==1` or
`*(ctx+0x3630)+0x9d==1`); neither is reachable from finsh - there is no
memory-write command in the 59-command shell, and flash is read-only (`fal`
has no write). Disabling the cloud retries would need firmware patching (UART
bootloader) or feeding the camera a reachable cloud. On its own softAP the
camera is the gateway with no upstream, so we also can't MITM/blackhole its
outbound connects to make them fail fast.

**Practical handling (now):** `tools/telnet_shell.py` was updated to WAIT
through the freezes (patient first-byte timeout, idle-based end) instead of
giving up after 8s - so recon/video capture works, just slowly (recon may take
a few minutes; that's expected). Prefer few-round-trip tasks (the video_buffer
probe, `cat /appfs/setting.json`) and don't be surprised by a mid-session
reboot - just re-run.

## 7. The reboots: xdev_abnormal_check watchdog (bk_reboot)
`bk_reboot(%d)` (str 0x16cf5f; wrapper @ 0x983dc) is the Beken SoC reset
primitive. The camera's constant reboots come from `xdev_abnormal_check`
(xdev_video.c, un-analyzed Thumb @ ~0x86196) - a periodic self-check thread
that deliberately reboots when any of THREE conditions persists past a time
threshold (abs(now - last_good) > threshold; pool constants include 0x7530=
30000 and 0x36ee80=3600000, i.e. millisecond timers):

  - **net abnormal**  - cloud unreachable too long (chronic on the isolated VLAN)
  - **fps abnormal**  - the encoder/sensor stopped producing frames at the
                        expected rate
  - **test abnormal** - an internal self-test

It PRINTS the reason in plaintext ("reboot reason: DEV <net|fps|test> abnormal")
to serial and the flash reboot log at 0x1F8000 - so the live device tells you
exactly which check fired. Read that first.

**It cannot be stopped from the shell.** It's a *software* reboot (bk_reboot),
not a hardware-watchdog timeout, so `wdg_stop` does nothing. The timers are RAM
state with no shell-reachable setter, and flash is read-only (`fal` has no
write). Disabling it needs a firmware patch, or satisfying the check (real
frames for fps / a reachable cloud for net).

### UPDATE: the actual reboot seen on-device is `bk_reboot(1)` / "pswdt reboot"
Serial showed `bk_reboot(1)` + `wdt reboot` (= the firmware's "pswdt reboot").
That is NOT the net/fps/test abnormal path above - it's a **software task
watchdog**:
  - `task_watchdog_check` (0x90820) monitors registered threads (list @
    0x00404910); if any thread hasn't checked in for **> 30 s** (0x7530 ms) it
    logs `task watchdog tiggered,current_thread:<NAME>` (0x16ab75) naming the
    stuck thread.
  - `pswdt_reboot` (0x94766) prints "pswdt reboot" then does bk_reboot(1)
    (reason 1) and spins. This is a software reboot independent of the HW WDT.
  - `wdg_stop` (cmd_wdg_stop, 0xa1d50) stops only the HARDWARE watchdog
    (rt_device_control cmd 6 = WDT_STOP). It helps ONLY if the reboot chain is
    the HW WDT interrupt-then-reset; against a pure software bk_reboot(1) it
    won't. Worth one try (low risk), but expect it may not stop these.
  - **Most useful next step: capture the `current_thread:<NAME>` from serial** -
    it names exactly which thread is hanging >30 s (prime suspect: a net/iot
    thread blocked in a cloud connect, i.e. the same cause as the freezes in
    section 6). That decides whether it's fixable.

**Working on a constantly-rebooting camera - practical guidance:**
- **Use SERIAL (the ESP32-S3 bridge), not telnet.** A reboot kills a telnet
  session (TCP + re-auth + fighting the frozen network); serial just re-streams
  the boot log immediately and is far more workable across reboots.
- If the reason is **fps abnormal**, the sensor/encoder is wedged (no frames) -
  do a FULL power-cycle (battery pull / unplug, not a soft reboot) to reset the
  sensor into a clean state. The fps watchdog only trips when frames genuinely
  stop, so a wedged sensor -> fast repeating reboots.
- If **net abnormal**, that's the chronic cloud-isolation cadence (see section
  6); nothing to fix on-device, just work in the window.
- Either way you get only ~tens of seconds per boot: script commands to fire
  immediately on connect (camsh.py batch / a prepared command list), don't type
  interactively.

## 8. Offline video: the routes, and which are dead (2026-08-30)
Goal is app-free/cloud-free video. Status of every route found:

- **`video_buffer` over the shell (serial OR telnet/WiFi): DEAD.** Not a
  bandwidth problem - the shell is request/response (REPL), so issuing
  `video_buffer read` commands one at a time can never keep up with the
  ~300 KB/s encoder; the ring buffer overflows -> `vbuf full!` regardless of
  link speed. Confirmed on-device over WiFi.
- **Local SD recording (`tf_record`, tf_record.c): works but is NOT armed by
  default.** Writes `.avi` files to the SD mount (path formats `%s/%02d.avi`,
  `%s/%d/%02d/%02d.avi`). With a working card, `/sd` stays empty because
  recording is armed by the app via pprpc datapoints RecordStart / RecordStop /
  EventRecordSet (0x15a880/0x15a88c/0x15ab90) - i.e. the same app/handshake
  path. No finsh command arms it.
- **`/sd/config_json.txt`: DEAD lever.** The reader (0x87bd8, Thumb) is a
  debug/test hook (adjacent string "--------->testing...<-----------"), not the
  record-enable config. Writing it won't enable recording.
- **Live streaming (pprpc VideoPlay 0x0a32): needs the app handshake** (LanAuth
  + SyncConn + state 3), or our own pprpc/KCP client (multi-day build - see
  protocol.md).

**Net: every offline-video route goes through the app's pprpc datapoints
(RecordStart to arm SD recording, or VideoPlay to stream).** There is no
finsh/shell trigger and no writable config file that arms it. So the realistic
options are:
  (A) Pair with the app ONCE (locally, over BLE) to set a record-to-SD mode,
      then park it offline and read the .avi files off the card. Caveat: record
      mode is a cloud datapoint (ConfigGet-driven); it MAY reset to default when
      the camera can't reach cloud - untested, could make this non-persistent.
  (B) Build the pprpc/LanAuth client and send RecordStart (arm) or VideoPlay
      (live) ourselves - the robust "no app ever" path, multi-day. Protocol +
      auth already reversed (see protocol.md, bk7252-ghidra-video-auth-reversed).

## Cross-references
- Shell access, log-spam filtering: findings-shell.md, tools/camterm.py
- Video feed / how to make it stream: protocol.md "HOW TO ACTUALLY MAKE IT
  STREAM", ghidra.md Session 3
- Cloud contact: protocol.md "What it phones home to", ghidra.md Session 2
- Ghidra base-address trap + function index: ghidra.md
