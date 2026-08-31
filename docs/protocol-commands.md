# pprpc LAN command surface (BK7252 / XC Things cam)

What the LAN pprpc protocol can drive beyond video, reverse-engineered from
firmware_combined.bin (Ghidra, base 0x10000). Source of truth:

- **Command enum / names**: `pprpc_cmd_id_to_name` @ 0x68e94 — a compiled binary
  search over ~135 CmdIDs. The name table is a `char*[]` at 0x69494 (strings at
  0x15a6c8+); the ID constants are at 0x69360. Verified by matching known anchors
  (SyncConn=0x6A, LanAuth=0x0A5A, VideoPlay=0x0A32 all resolve correctly).
- **Device handlers**: `dev_on_ipc_*` functions in ut_dev_ipc_cmd.c. Each logs a
  banner like `conn[%d]ipc_WifiSet_Req:` (strings at 0x164c00+). These are the
  server-side implementations the device actually runs for each command.

## Confirmed CmdIDs (control channel, TYPE_PBBIN, prekey "A2r0i1m1a2M0a1x6toriQue")

| CmdID   | Dec  | Name              | What it does |
|---------|------|-------------------|--------------|
| 0x6A    | 106  | SyncConn          | opens the streaming gate (already used) |
| 0x0A28  | 2600 | Discovery         | ipc_Discovery_Req — device/model/caps |
| 0x0A29  | 2601 | WifiAPGet         | "get AP list" — runs a WiFi **scan** (see below) |
| **0x0A2A** | **2602** | **WifiSet**   | **set STA wifi SSID+PWD, applies live (see below)** |
| 0x0A2B  | 2603 | WifiGet           | log-only **stub** — returns code=0 empty (see below) |
| 0x0A32  | 2610 | VideoPlay         | start AV stream (already used) |
| 0x0A33  | 2611 | VideoPause        | stop AV stream |
| 0x0A34  | 2612 | VideoQosSet       | set stream bitrate/qos |
| 0x0A35  | 2613 | FlipSet           | set image flip/mirror |
| 0x0A36  | 2614 | FlipGet           | read flip state |
| 0x0A57  | 2647 | Reboot            | reboot the device (channel arg) |
| 0x0A58  | 2648 | Reset             | factory reset (channel arg) |
| 0x0A5A  | 2650 | LanAuth           | session auth (already used) |
| 0x0A5E  | 2654 | StorageFormat     | format the SD card |
| 0x0A5F  | 2655 | StorageFormatRate | poll format progress |

Other named commands present in the enum (IDs derivable the same way, not all
traced): RecordStart, RecordStop, EventFile, AudioPlay/AudioPause, PtzCtrl
(~0x0A68), Screenshot, TimeSet, ConfigGet, MotionzoneSet, PirSet/PirGet,
LedModeSet/Get, PowerFreqSet/Get, AlarmGet, HistoryDayList/Play/Pause,
DirCreate/List/Del/Edit, StorageInfo, GetNetworkInfo, SetAutoTrack/GetAutoTrack,
VideoChanChange, LogSet, FileStart/FileStop, TimedcruiseSet/Get, FirmwareCheck/
FirmwareChanCheck/FirmwareNotify/FirmwareRate (OTA), IotAlertList/SetRead,
FTRECORD push. VideoCall(561) and PauseAllAv(563) exist in the enum but the
device replies "Device unsupport ...!!!" — not implemented on this model.

## WifiSet (0x0A2A) — live wifi reconfiguration over the LAN — WORKING

Handler: `dev_on_ipc_WifiSet` = FUN_00082ba8. **Verified end-to-end 2026-09-01:**
WifiSet -> `code=0` -> device rebooted -> rejoined the target network.

### Request schema (this was the whole battle — get the field numbers right)

The pprpc rx path (`pprpc_rx_dispatch` = FUN_00054128 -> parser FUN_00062304 ->
`FUN_0006b248`) nanopb-`pb_decode`s the payload against a **per-CmdID descriptor
table @ 0x159608** (134 entries × 0x20; entry for 0x0A2A is at 0x159ae8, its
request descriptor at **0x160058**, struct size 152). A decode failure returns
NULL and makes the dispatcher log **`ErrorPacket`** and DROP the packet *before*
the handler runs — no reply, no apply. So the wire fields must match exactly:

| field | type            | struct off | meaning |
|-------|-----------------|-----------|---------|
| 1     | variable string | +0x00     | like LanAuth's `did`; unused here |
| **2** | `char[65]`      | +0x04     | **SSID** |
| **3** | `char[65]`      | +0x45     | **PWD**  |
| 5     | `char[16]`      | +0x86     | optional |

An earlier guess of SSID=field1/PWD=field2 mis-decoded → `ErrorPacket` → silently
no-op (the "read wifi SSID/PWD" serial hexdump we first trusted was the raw
*pre-decode* packet dump, not proof of a good parse). **SSID=field 2, PWD=field 3**
is the confirmed layout, cross-checked against LanAuth_Req (descriptor @ 0x15e5e4:
field1=did, field3=cred, same two `char[65]` slots).

### What the handler does after a good decode

1. Logs `read wifi: SSID[%s] , PWD[%s]` (0x164e58).
2. `FUN_00081db0(ssid, pwd)` — stores into the global wifi-config struct
   (RAM 0x00403a60: ssid @ +0x04, pwd @ +0x44) and `FUN_00081c78` persists ~0x1a8
   bytes to flash partition 6 @ 0x2000.
3. `FUN_000c001c(2000,0)` — sleeps ~2s so the `code=0` reply flushes first.
4. `FUN_00087044()` — spawns the `xc_reboot` thread (entry FUN_00086dc4); the
   device reboots and joins the new credentials.

**So the camera can be re-pointed to a different WiFi network live over the LAN,
no app/cloud.** A wrong SSID persists across the reboot and the device comes up on
its softAP (192.168.9.252) instead — recover there or via serial.

Client: `python tools/lan_client.py --wifi-set --new-ssid <SSID> --new-pass <PWD>`
(sends field2=ssid, field3=pwd; confirmed byte-identical to the working probe).

## WifiGet (0x0A2B) and WifiAPGet (0x0A29) — what the backend actually does

Traced in Ghidra 2026-09-01. Handlers are identified by their own log banners
(`ipc_WifiGet_Req` @0x164e91, `ipc_WifiAPGet_Req` @0x164d76) — note the decompiler
mislabels these functions' string pointers by +0x10000 (shows 0x174xxx; the real
strings are at 0x164xxx, a base-analysis artifact), so read the raw literal pool.

- **WifiGet = `dev_on_ipc_WifiGet` (FUN_00082c78)** is a **pure log-only stub**. Its
  only callees are the two logger funcs (FUN_0008288c timestamp, FUN_00082864 line);
  it logs the banner, logs the request's first field, and `return 1`. It never reads
  the stored SSID/PWD, never scans, and builds no response body — so the framework
  sends `code=0` with an **empty payload**. This firmware simply does not hand the
  saved STA creds back over the LAN (they only ever appear in the device's serial).

- **WifiAPGet = `dev_on_ipc_WifiAPGet` (FUN_00082b44)** is really **"get the AP
  list" (a scan)**, not "read the camera's own softAP". It logs the banner +
  `channel:%d`, then tail-calls an `xwifi.c` routine at **0x8725c** that grabs the
  `"w0"` wlan device (logs `No wlan device` if absent) and runs a **WiFi scan**,
  logging every hit as `wifi scan:SSID[%s],qos[%d],rssi[%d]` (qos = security type,
  from the string table @0x1820e4: `OPEN` / `WPA2` / `WPA2-EAP-SUITE-B` / `OSEN` /
  `FT-…`). The scan is **asynchronous** — results arrive via the WLAN scan-done
  callback and go to serial, not into the RPC reply — so an empty WifiAPGet request
  gets **no useful body back** on the control socket (observed: no reply). This is
  the scan side-effect seen on serial in earlier testing (it was WifiAPGet, not
  WifiGet, that produced it).

**Net:** neither getter exposes data to the LAN client on this build. Config is
write-only from the network's perspective — you can `WifiSet` (and it reboots to
apply), but to *read* the current SSID/PWD or the scan results you need the serial
console. The scan list would require plumbing the async callback into a response,
which this firmware doesn't do.

## How to add any of these to the client

lan_client.py already does connect → LanAuth → SyncConn. Any command above is
just another `send_cmd(s, CMD_ID, <protobuf payload>)` after auth, read the
response with `pprpc.read_packet`. Reboot/Reset take a channel varint; WifiSet
takes ssid+pwd strings; the getters take an empty/channel payload and return the
value in the response protobuf. Control-channel crypto (enctype 3) uses the
"A2r0..." prekey per pprpc.py; most of these commands are also accepted plaintext
(enctype 0) on the LAN, same as LanAuth/SyncConn.
