# The camera's network protocol (from dumps/download_clean.bin)

## How to read the dump
`dumps/download.bin` is the raw physical `download` partition, so it still has
Beken's CRC bytes interleaved (2 bytes per 34). Strip them to get readable data:

    keep 32, drop 2, repeating   ->   dumps/download_clean.bin

The partition starts at physical 0x132000, and 0x132000 / 34 = 36864 exactly, so
block alignment falls out for free. Before stripping, strings show injected
garbage (`FailCCed to`, `iot_deoHv_localsrv`, `Cann:vot open`); after, they are
clean. `app.bin` is on the *CRC-decoded* device and needs no such treatment - but
it contains only code and essentially no strings.

## It is NOT iLnk / PPPP - cam-reverse cannot work
A vendor stack, confirmed by the leaked build path:

    /home/liangyuxuan/share/avsdk/src/xciot/pprpc/ikcp.c

`ikcp.c` is the **KCP** reliable-UDP library. `pprpc` is a protobuf-style RPC
(`pprpc.pb.stringfy`, `cmd_encode`, `ppiotcmd_encode`) carried over KCP/UDP.
Connection setup is entirely unlike PPPP's LanSearch/PunchPkt:

    ftconnp2p_P2PStepTwo, ftconnp2p_P2PHole, ftconnp2p_SyncConn,
    ftconnp2p_ConnHB, ftconnnat_NatTest1, ftconnnat_ReportNat,
    ftconnrelay_RelayStepOne, ftconnrelay_RelayStepTwo

Repointing cam-reverse's SEND_PORT at 20190 would have achieved nothing.

## There IS a local path, and it needs no cloud
Connection types: `local`, `local2`, `relay`, `relay_m`, `p2p`. The local one
(`iot.conn.local`) is what the app uses on the same LAN or on the camera's own AP:

    iot_dev_broadcast_discovery   broadcasts to 255.255.255.255
                                  "===iot.dev.broadcast_async try: %s://%s:%d===="
                                  update_lan_info, iot_dev_broadcast_discovery_did
    avsdk_localsrv_udp_start      binds udpsrv on 0.0.0.0   (this is UDP 20190)
    E_PPRPC_CMD_ID_ipc_LanAuth    LanAuth_Req -> LanAuth_Resp
    SyncConn_Req -> SyncConn_Resp
    avsdk_video_add_conn / avsdk_write_video_slice / avsdk_video_pause

Handshake, per the `iot.conn.local` log strings:

    conn[%d].local state connected, on packet LanAuth_Req
    local_check_auth1  ->  "local check auth1 OK!"
    local_check_auth2  ->  "local check auth2 OK!"
    (failure path: "check LanAuth NO PASS!")
    conn[%d].local state connected, on packet SyncConn_Req

Key-derivation format strings in that same block:

    %s-%s-%s      %s-%s-%d      $L%d$%s      %s+%s

Crypto primitives it has available:

    cal_aes256, cmd_raw_encode/decode, avsdk_local_encode,
    avsdk_EncodePayloadToMsg, avsdk_DecodePayloadToCmd,
    osal_mbedtls_md5, osal_mbedtls_base64_decode, tools_hexstr2arr

Two literals sit next to the base64/md5 calls in the broadcast-discovery block;
initially guessed as the shared secret but these are almost certainly just
format-string neighbors in rodata, not device credentials - superseded below:

    HL4viXBiGEz8mCBkuhkTQFaK      (24 chars)
    e7uJ6Q8uM7ikpUxf              (16 chars - AES-128 keylength)

## The real per-device credentials (captured 2026-08-30)
The camera prints its own cloud identity block unconditionally on every boot,
over UART, no command needed - just be logging serial across a reboot:

    [iot]
    did = PPHA1006C0955E8FD9
    signkey = OHkMAuCv/nOXRHwvW9TnSA==      (base64 -> 16 raw bytes)
    lslat = ivAygPb4VY5EyGAcYDuMAA==        (base64 -> 16 raw bytes)
    scode = 307953                          (6-digit numeric, untested as the
                                             telnet pwd>> password - candidate)
    gdomain = prod.glbs.xcthings.com
    gipaddr = 47.240.1.244,47.252.5.225,8.209.77.49,39.108.59.60

`signkey` and `lslat` are the real per-device secrets and are what
`local_check_auth1`/`local_check_auth2` almost certainly consume - use these
instead of the two generic guesses above. See [[bk7252-iot-identity]] in
project memory for full context.

Also observed in the same boot log: sensor chip is **GC0329C** (matched after
probing ~15 candidate sensor IDs), WiFi MAC `c8:47:8c:6c:2d:77`, BLE MAC
`c8:47:8c:6c:2d:78`, `iot_dev_localsrv_udp_start` (the UDP side of port 20190)
running at boot, and the `pprpc` context initializing at RAM `0x202d540`.

## What does NOT exist
No HTTP server, no MJPEG `multipart/x-mixed-replace`, no RTSP, no ONVIF. The only
`HTTP` string is a member of a server-type enum (`APIGW_MOB_HTTP`, alongside
`PPMQD_TCP`, `GLBS_UDP`, `FTCONN_RELAY`, ...) describing *cloud* endpoint kinds -
not a local listener. There is nothing to "switch on".

## The `xc` vendor CLI is a dead end, and it bites
`xc` accepts a subcommand but silently ignores unknown ones and prints no usage
(`xc help`, `xc ?`, `xc -h`, `xc list` all produce nothing). It is not a
dispatcher for the `cli_*` / `test_*` symbols in the image - those are not msh
commands either (`test_avsdk_user_Screenshot: command not found`).

Worse, it has side effects: `xc test_avsdk_user_Screenshot` bounced the WiFi AP
(`apm start with vif:0`, `beacon_int_set:100 TU`, `[msg]APM_STOP_CFM`), and
`xc test` dumped thread state and wrote status registers. Do not fuzz `xc`.

## Flash is read-only from the shell
`fal` offers `probe`, `read`, `erase`, `bench` - **there is no `fal write`**. So
firmware patching cannot be done from the shell. It would need the Beken UART
bootloader (bk_writer / hid_download class tooling) with the chip in download
mode, plus regenerating the CRC block layout. `fal erase` exists and must never
be run: it would brick the camera with no way to write an image back.

## Observed wire traffic (captured 2026-08-30 via ntopng, raw IP pcap)
A short capture of the camera's own outbound traffic while sitting on a real
LAN with internet (`stdin_192.168.178.147_live(3).pcap`, 6 packets) - decoded
by hand (no scapy/tshark available, wrote a 20-line pcap parser instead):

    cam 192.168.178.147:62518  <-->  cloud 8.209.73.117:80/UDP

(`8.209.73.117` is in the same Alibaba-Cloud range as the `gipaddr` list in
the `[iot]` block - a different specific address from current DNS resolution
of `gdomain = prod.glbs.xcthings.com`, not a new server family.)

Every payload, both directions, starts with the same 3-byte magic `51 70 48`.
Real ikcp frames have a 24-byte header starting with a 4-byte `conv`, so this
sits *outside* KCP - it's the `ftconn`-family wrapper (NAT punch/heartbeat)
from the handshake list above, with KCP/pprpc riding inside once a session is
established.

Two packet shapes seen:
  - **Heartbeat** (type byte `0x03` request / `0x04` reply, 7-8 bytes total):
    `51 70 48 03 11 13 00` / `51 70 48 04 11 13 01 00`. Byte 4 is a shared
    sequence counter that increments by 2 between heartbeat rounds (`0x11`->
    `0x13`, i.e. 17->19); the skipped value (18) turned up in the data
    exchange's own header below, confirming one shared counter.
  - **Data** (type byte `0xb3` request / `0x54` reply, 184B / 88B): header
    `51 70 48 b3 01 12 0d 0c ...` then high-entropy bytes with no visible
    structure - genuinely encrypted (`cal_aes256`/`avsdk_local_encode`),
    consistent with a periodic status/telemetry report (~15s cadence between
    cycles in this capture).

This is cloud-relay traffic only - nothing local was talking to the camera
during the capture, so there is nothing here yet to test `signkey`/`lslat`
against. **Next useful capture: the real vendor app talking to the camera
over the LAN**, to see `LanAuth_Req`/`Resp` and `SyncConn_Req`/`Resp` and
check whether the real per-device secrets decrypt/verify against them.

## LanAuth derivation, and the video gate - reversed 2026-08-30
Ghidra project was found loaded at the wrong base (0x0 instead of 0x10000 -
see docs/ghidra.md "Trap" section) which had been silently breaking every
xref lookup; fixed and re-analyzed (4906 -> 6620 functions found), then the
full local handshake + video-send chain was traced and labeled. Full function
index with addresses is in docs/ghidra.md; summary here.

**The handshake is one state machine**, `iot_conn_local_on_packet`
(0x0002f618), keyed off a per-connection state byte at `conn+0x178`:
- **state 1**: waiting for `LanAuth_Req` (pprpc cmd `0x0a5a`). Payload's
  credential string (at payload+0x45) goes through `local_check_auth`, which
  tries two formats:
  - `local_check_auth1`: input `"$<nonce>$<hash>"`, expects
    `hash == hash("<did>-<scode>-<nonce>")` using format string `"%s-%s-%s"`
    confirmed in rodata. `scode` is `iot_identity_get_scode_maybe()` normally
    (falls back to a second secret, `iot_identity_get_secret_fallback()`, only
    if that string is under 6 chars - scode is always exactly 6 digits when
    paired, e.g. the captured `307953`). `did` is
    `iot_identity_get_did_maybe()`. The hash function (`FUN_001496f4`) is an
    indirect dispatcher, not proven to be MD5 yet, but it's the same helper
    used everywhere osal_mbedtls_md5 was expected to live - treat as "very
    likely MD5" pending confirmation.
  - `local_check_auth2`: input `"$L<idx>$<hash>"`, a parallel derivation
    (index-selected identity?), not fully traced.
  - On pass: builds `LanAuth_Resp` (`lanauth_derive_resp_value`, same
    sprintf+hash shape) and sends it, transitions to **state 2**. On fail:
    logs exactly `"check LanAuth NO PASS!"`.
  - (Same state also answers `NatProbe_Req`, pprpc cmd `0x5d`, no state
    change.)
- **state 2**: waiting for `SyncConn_Req` (pprpc cmd `0x6a`). On receipt,
  sends `SyncConn_Resp`, transitions to **state 3**.
- **state 3**: fully connected - packets go to a generic per-conn callback
  (`conn+0x180`). **This is also the exact state `avsdk_video_conn_send_slice`
  requires before it will forward a video slice to this connection** - i.e.
  state 3 is both "handshake complete" and "eligible for video", same field.

**Working client recipe** (unverified against a live packet capture - the
next useful capture is still the real app talking LanAuth/SyncConn over the
LAN, per the section below):
1. Discover/connect, get a nonce (client-chosen or server-provided - not yet
   traced which).
2. Send `LanAuth_Req` (pprpc cmd `0x0a5a`) with credential
   `"$<nonce>$" + md5("<did>-<scode>-<nonce>")` using the real captured
   `did`/`scode` (see bk7252-iot-identity memory).
3. On `LanAuth_Resp`, send `SyncConn_Req` (pprpc cmd `0x6a`).
4. On `SyncConn_Resp`, the connection is in state 3 - subscribe/request video
   and `avsdk_write_video_slice` will start forwarding slices.

Video slices themselves flow through `avsdk_write_video_slice` ->
`avsdk_video_conn_send_slice` -> `pprpc_build_and_send_slice_msg` ->
`pprpc_enqueue_msg`, with sequence-continuity/backlog-ratio drop logic in
`pprpc_video_slice_check_packet_drop` (drops if a per-type outbound queue's
used/limit ratio exceeds ~0.5, or if the slice's seq byte isn't exactly
`last_seq+1`). See docs/ghidra.md for the full address list and per-function
notes, including what's still unconfirmed (auth2's format strings, whether
`FUN_001496f4` is really MD5, who calls the retry-wrapper
`pprpc_video_slice_wait_and_send`).

### Why `--video` sometimes captures 0 frames (Ghidra-traced 2026-09-01)

Confirmed the drop pipeline in full (`pprpc_video_slice_check_packet_drop` @
0x54c24, its retry wrapper `pprpc_video_slice_wait_and_send` @ 0x5523c) and
traced why it can silently eat every slice of a session, which is exactly
what makes `av.reassemble_frames()` come back with an empty list (raw capture
is empty or only partial slices) -> `lan_client.py`'s "captured 0 frame(s)".

**Nothing about a failed capture is visible to the client at all:**
- `dev_on_ipc_VideoPlay_Req` (0x82d04) calls `avsdk_video_add_conn` but
  **never checks its return value** - it unconditionally fills in a
  success-shaped response (`code=0`, the fixed `{1,10,4,0}` fields) even if
  add_conn failed (bad handle, bad channel, or the 10-slot connection-table
  cap already full -> return -6). So a `code=0` VideoPlay reply is *not*
  proof the subscription actually took.
- Even when the subscription bit *is* set, dropped slices generate no error
  packet - the client just receives fewer bytes than expected, or none.

**The drop gate itself** (`pprpc_video_slice_check_packet_drop`, run per
outbound slice against a per-connection msgqueue, queue-index 3):
1. **Out-of-order kill:** if a slice's seq byte isn't exactly
   `last_accepted_seq + 1` (and isn't a first/last-slice marker), the WHOLE
   frame is marked dropped for that connection+channel (a sticky per-channel
   bitmap at conn+0xc8/+200), and the terminating `0xff` slice of that same
   frame is dropped too if the bitmap bit is already set - so a frame is
   always all-or-nothing, never partially delivered.
2. **Health fast-path:** if any of 3 flag bits at conn+0xc4 are set, OR a
   lag/backlog metric at conn+0x748 (gated by a "not yet measured" flag at
   conn+0x74c) exceeds a fixed threshold (`0x157c` = 5500, units TBD - likely
   ms of estimated send backlog), EVERY slice is dropped unconditionally,
   logging the flag bits + metric. This is the "this connection is currently
   unhealthy, don't even try" path - the most likely explanation for a whole
   session coming back with 0 frames despite a clean handshake.
3. **Queue-congestion path** (only reached if #2 didn't already reject): compares
   `used`/`limit` of the per-conn video msgqueue (`pprpc_msgqueue_get_used`/
   `_get_limit` on conn+0x72c, queue 3). If `used < limit` there's room -
   accept. If the queue is full: drop (and if this was already a
   drop-streak, a *recovering* I-frame is only allowed to break out of the
   streak once the queue's fill ratio drops back under ~50% AND the queue's
   limit is > 8 - otherwise it keeps getting refused, so a congested queue
   can suppress every subsequent frame indefinitely, not just the one that
   overflowed it).
4. Mid-frame slices hitting a merely-full (not unhealthy) queue get a
   "retry" signal instead of an instant drop; `pprpc_video_slice_wait_and_send`
   polls every 10ms until the queue drains or a timeout budget expires, then
   gives up and marks the frame dropped. (Direct call site for this wrapper
   wasn't resolved via static xref - `pprpc_video_slice_check_packet_drop`'s
   only caller IS `pprpc_video_slice_wait_and_send`, but nothing calls that
   wrapper via a plain `bl` either; it's almost certainly invoked from the
   thread that drains the per-conn queue over the socket, registered as a
   function pointer/task entry rather than a direct call Ghidra can trace
   statically.)

**Practical read:** this is congestion/health-state-dependent, not a fixed
bug - a fresh TCP connect + LanAuth + SyncConn + VideoPlay generally starts
with a clean queue and a healthy connection, so a 0-frame run is most likely
hitting the device already in a bad state (e.g. a prior test's connection
slot/queue backlog not yet torn down - `lan_client.py --video` currently
just `s.close()`s without sending VideoPause first, so the server-side
teardown relies on detecting the TCP close rather than an explicit unsubscribe).
If `--video` returns 0 frames, retrying the whole handshake from a fresh
socket is more likely to help than just waiting longer in the same session.

## What it phones home to, and what it sends - reversed 2026-08-30
Traced `iot_dev_glbs` (Global load-balance Service - the cloud discovery/
bootstrap subsystem) in Ghidra. Full function/address list is in
docs/ghidra.md; summary here.

**Who it contacts.** `gdomain = prod.glbs.xcthings.com` plus a hardcoded
fallback IP list (`47.240.1.244, 47.252.5.225, 8.209.77.49, 39.108.59.60`,
all Alibaba Cloud) come from ONE printf-style template string baked into the
firmware (`"gdomain = prod.glbs.xcthings.com\ngipaddr = ..."`, rodata
`0x00164670`) - **these are firmware-wide defaults, the same for every
device**, not anything device-specific (did/signkey/lslat/scode in the same
`[iot]` block ARE device-specific, substituted via `%s` into that template).

**The bootstrap call - GetServers.** `iot_dev_glbs_run` does a fresh
connect -> call -> disconnect cycle every time (no persistent session for
this):
  1. Opens a transport to the target host:port, **UDP by default** (the
     function also supports "tcp", but the default/fallback path is UDP -
     matches the pcap capture below, which was UDP/80).
  2. `iot_dev_glbs_build_req` builds the request payload:
     `did` (25B) + `signkey` (65B, the device's permanent cloud-auth secret -
     confirmed by struct-offset arithmetic: same struct field
     `local_check_auth1` falls back to as a LAN secret) + a 16B field from an
     unrelated large buffer (purpose unclear, logged if non-empty) + a fixed
     7-int capability/version list (`1,2,6,8,15,18,19`) + a timestamp.
     **did and signkey go out inside the pprpc request payload in the clear
     at this layer** - `pprpc_call_and_wait` (the function that actually
     sends+waits) shows no AES/encode call at its level, so whether this gets
     wrapped by a lower KCP/transport-level cipher is NOT confirmed either
     way from this pass.
  3. `pprpc_call_and_wait` sends it as pprpc cmd `0x259` (resolves to
     "GetServers" via `pprpc_cmd_id_to_name`) and blocks up to 2000ms for a
     reply (matches the boot-log line
     `pprpc_xglbs call(GetServers), seq:0, run:2005ms, rc:-5` seen when the
     isolated VLAN blocks the request - rc:-5 = timeout).
  4. On success, `iot_dev_glbs_show_rsp` shows the response is a list of up
     to 10 candidate servers, each with a protocol/type byte + address + up
     to 3 sub-values (ports?) - i.e. GetServers is a **load-balancer
     redirect**: the camera doesn't just talk to `gdomain`, it asks that
     seed server "who should I actually talk to" and gets back a short list
     to pick from. This matches the pcap capture (below) showing traffic to
     `8.209.73.117`, a specific address NOT in the hardcoded `gipaddr` list -
     it must have come from a GetServers response on a prior successful
     connection.

### Does the camera ever hand out its own secret? (researched 2026-09-01)

Checked for a formula first: `iot_identity_get_scode_maybe`/`get_signkey`
are pure struct-field reads (offset math only, no hash/transform of `did`,
the MAC, or anything else public) - so there's no algorithm to invert. If
the vendor derives `scode`/`signkey` from anything, that math runs on a
factory/provisioning tool, not on the device - out of reach by firmware RE.

But **yes, the device broadcasts its own secret** every time it dials home:
`iot_dev_glbs_build_req` (see above) writes `did` (25B) then `signkey` (65B)
back-to-back into the GetServers request buffer, and that happens
automatically at boot - including on THIS isolated VLAN, where it just times
out and retries (matches the `reboot reason:DEV net abnormal` loop in
[[bk7252-flash-dumps]]). The packet still gets sent onto the local network
before it fails to get a reply - it doesn't need to actually reach the
internet. Whether an outer cipher wraps this specific payload before it hits
the UDP socket wasn't nailed down this pass (`pprpc_call_and_wait` shows no
AES call at its own level - see docs/ghidra.md); even if it does, the
wrapping key can't itself be `signkey` (that would be circular - the message
exists to deliver signkey to a server that doesn't have it yet), so it's
most likely either plaintext or the fixed public pprpc default prekey
(`P2p0r1p8c0622`), not something requiring the secret you're trying to get.

**Practical extraction path - no serial, no telnet, fully passive:** put a
capture point (promiscuous NIC / port mirror / a laptop acting as the
gateway) on the camera's own network segment and let it boot - it will emit
its GetServers UDP request (default target `prod.glbs.xcthings.com` or the
fallback IPs above) with `did`+`signkey` sitting at fixed offsets in the
payload. This is the most direct answer to "does the camera ever share the
secret" - not yet verified against a live capture on a *second* unit, but
the code path is unconditional and does not depend on the secret already
being known, unlike every other avenue explored (telnet/serial still work
too, but this one needs zero device access at all.

**Even better than passive capture - actively sinkhole it.** The firmware
tries exactly 4 ports for GetServers (read from its own literal pool @
0x153574): **465, 8000, 80, 53** (port 80 matches the earlier empirical UDP
pcap capture), over both TCP and a UDP-shaped transport, hitting `gdomain`
DNS first then the hardcoded IP list. Since you almost certainly already
control routing on the camera's own isolated network, you don't need to
sniff passing traffic at all - just become the destination: point DNS for
`prod.glbs.xcthings.com` at your own box and NAT-redirect the 4 fallback IPs
there too (or ARP-spoof if you're not the gateway), then run
**`tools/glbs_sinkhole.py`**, which listens on all 4 ports (TCP+UDP), parses
the pprpc frame, and prints/saves `did`+`signkey` the instant a hit arrives
- no reply needed, the camera just retries harmlessly if none comes. Built
and verified 2026-09-01 against a synthetic GetServers-shaped packet (both
UDP-framed and TCP parse correctly); not yet run against a real camera. Full
routing recipe is in the script's own module docstring.

**Observed live traffic** (from the existing capture, see the "Observed wire
traffic" section above) is consistent with this: an initial GetServers-style
exchange, then a steady-state cycle of small heartbeats (7-8B) and ~15s
periodic 184B-request/88B-reply exchanges that are genuinely high-entropy
(encrypted) - likely a status/telemetry report (`avsdk_dp_report_all`-style
datapoint push) or a lighter-weight heartbeat/keepalive on the *established*
session, as opposed to the one-shot GetServers bootstrap. **Not yet traced
this pass** - `avsdk_dp_report_all`/`avsdk_log_append` exist in the image
(confirmed via string search) but their call sites weren't resolvable via
simple xref search this time (packed name-string table, no direct pointer
per entry - same pattern that made `avsdk_write_video_slice` hard to find at
first). Next step for a full "what telemetry does it send" answer: either
grind through that packed table's base pointer, or - better - get a live
packet capture of the real device talking to the cloud on a network with
internet, now that the KCP/pprpc framing (`ikcp.c`, 24B header) and the
`ftconn` outer wrapper (3-byte magic `51 70 48`) are already known from the
existing capture.

## HOW TO ACTUALLY MAKE IT STREAM - the request side (reversed 2026-08-30)
Sessions 1-2 mapped the video *send* path and the auth handshake. This is the
missing piece: what a client sends to turn the feed ON. Full picture end to
end, all verified in Ghidra (function index in docs/ghidra.md):

**The one command that starts video: `VideoPlay`.**
- pprpc command id **0x0a32 (2610)** - directly confirmed: id at
  `DAT_00069394` maps, via `pprpc_cmd_id_to_name`, to the name pointer at
  `DAT_00069538` = `"VideoPlay"` @ 0x15a8cc. (The firmware ALSO logs
  `ipc_VideoCall(561)` / `iot_invoke_on_AppVideoPlay_561`; 561/0x231 is a
  higher app-invoke-layer id, NOT the pprpc wire id - use 0x0a32 on the wire.)
- Request payload field 0 = **channel index, 0..8** (rejected outside that
  range). Channel 0 = the main stream (the ~20fps/~300KB MJPEG the encoder is
  already producing). Fields 1 and 2 exist but aren't used for the
  subscription.
- Handler: `dev_on_ipc_VideoPlay_Req` (0x00082d04) -> calls
  `avsdk_video_add_conn(conn_handle, channel)` (0x0001f3d0).

**What add_conn does** (the mechanism): the firmware keeps ONE global
connection table at `0x004005cc` (10 slots x 0xc bytes). Per slot: `+0xcc` =
connection handle (-1 = free), `+0xd0+channel` = a per-channel "subscribed"
flag byte. `avsdk_video_add_conn` finds/claims this connection's slot and sets
`slot[+0xd0+channel] = 1`. **That same table+offset is exactly what
`avsdk_write_video_slice` reads** to decide who to forward each encoded slice
to (verified: both `avsdk_write_video_slice` and `avsdk_video_add_conn`
dereference the same global pointer - `DAT_0001dcf8` == `DAT_0001f774` ==
0x004005cc). So flipping that one bit is literally all it takes; frames start
flowing on the next encoder slice.

**Full sequence to get a live feed** (no app, no cloud, LAN only):
```
1. iot_dev_broadcast_discovery / connect to UDP 20190 on the camera's AP
   (192.168.9.252) - discovery/transport bring-up.
2. LanAuth_Req   (pprpc cmd 0x0a5a) with credential "$<nonce>$<md5-ish hash>"
                 where hash = H("<did>-<scode>-<nonce>")  [see the LanAuth
                 section above; did/scode from bk7252-iot-identity memory]
     -> camera verifies via local_check_auth, replies LanAuth_Resp,
        connection goes to state 2.
3. SyncConn_Req  (pprpc cmd 0x6a)
     -> SyncConn_Resp, connection goes to state 3 (now general pprpc commands
        are dispatched, incl. VideoPlay).
4. VideoPlay     (pprpc cmd 0x0a32) with channel=0
     -> avsdk_video_add_conn sets your slot's channel-0 subscribe bit.
5. Camera now pushes video-slice pprpc messages continuously
   (avsdk_write_video_slice -> avsdk_video_conn_send_slice ->
    pprpc_build_and_send_slice_msg -> pprpc). Reassemble slices into JPEG
   frames. Because the stream is MJPEG, every frame is a keyframe - no need
   to wait for an I-frame.
6. VideoPause    (pprpc cmd 0x0a33) to stop; VideoQosSet / VideoChanChange
   (same 0x0a2b-0x0a44 id family) tune bitrate / switch stream.
```

**Still not built, only mapped**: the exact pprpc/protobuf byte layout of the
VideoPlay request and of a video-slice message (field tags/wire types), and
confirmation that H() is MD5. Those need either more RE of the pprpc
encode/decode helpers or - faster - a single LAN packet capture of the real
app doing a VideoPlay, now that we know exactly which command to look for.

## BREAKTHROUGH: pprpc is open-source (github.com/pprpc) - 2026-08-30
The vendor's pprpc stack is a public Go project by XC Things (xcthings.com,
app package com.xcthings.fchan). Repos (now private, but SOURCE IS FROZEN in
the Go module proxy): github.com/pprpc/{core, ftconn, ppmq, util}. Confirmed
the same stack as our firmware (magic 0x5170 + type 0x48, CmdID 601=GetServers,
etc.). Cross-refs: FuseTim blog "The inSecurity Camera"
(fusetim.me/posts/20251005-the-insecurity-camera/) reversed the crypto/framing;
pkg.go.dev/github.com/pprpc/core + /core/packets have the API.

### Get the source (repo is private, proxy cache is not):
    curl -o pprpc-core.zip \
      https://proxy.golang.org/github.com/pprpc/core/@v/v0.0.0-20200908022406-5592f694d0e7.zip
    unzip pprpc-core.zip     # full Go source: packets/cmd_packet.go etc.
(Version string is the one pkg.go.dev pinned. Same URL pattern for ftconn/ppmq/
util once their versions are read off pkg.go.dev. No Go toolchain needed.)

### pprpc wire format (from core/packets, VERBATIM):
    FixHeader  { MessageType uint8; Flag uint8; Length uint64 }
    CmdPacket  { FixHeader; AutoCrypt bool; CmdSeq uint64; CmdID uint64;
                 CmdName string; EncType uint8; RPCType uint8;
                 Code uint64 /*present only when RPCType==1 (response)*/;
                 VarHeader []byte; Key/Md5Byte/EnKey []byte; Payload []byte }
  MessageType: HB=3, PBBIN=4 (protobuf control), PBJSON=5, AV=6 (media),
               CUSTOMER=7, FILE=8.   RPCType: REQ=0, RESP=1.
  So our video slices ride MessageType=6 (AV); control cmds (LanAuth/SyncConn/
  RecordStart/VideoPlay) ride MessageType=4 (PBBIN). The `0x48` type byte seen
  in the pcap = PBBIN(4) + flag bit. Pack()/Unpack() in cmd_packet.go are the
  exact serializer to port.

### Encryption (core/packets + blog):
  EncType AES256CBC=3. Per-packet key derivation:
    info = sprintf("%s,ID:%d-SEQ:%d-RPC:%d", PREKEY, CmdID, CmdSeq, RPCType)
    KEY  = hex(md5(info))        # 32 ASCII hex chars = 32 bytes -> AES-256
    IV   = KEY[:16]              # (weak: IV = first half of key)
    payload = AES-256-CBC(KEY, IV, plaintext)
  Default/hardcoded PREKEY seen in pprpc source: "P2p0r1p8c0622". For the LAN
  device path the PREKEY is likely the per-device secret (signkey/scode) or a
  post-LanAuth SessionKey - TO RECONCILE with local_check_auth1 (which uses
  MD5("<did>-<scode>-<nonce>") as the LanAuth *credential*, a SEPARATE thing
  from the packet AES key). ftconn model has a SessionKey field produced by the
  handshake.

### What is NOT in the public repos (still reverse from firmware):
  The device/app `ipc_*` command IDs + protobuf message bodies:
    LanAuth (0x0a5a=2650), SyncConn (0x6a=106), VideoPlay (0x0a32=2610),
    VideoPause (0x0a33), RecordStart, GetServers (0x259=601).
  These are XC Things' device layer, not the generic pprpc lib. Reverse the
  protobuf field tags from the firmware encode/decode + our cmd_id_to_name
  table. This is now the main remaining unknown (plus KCP params + discovery).

## LAN CLIENT - VALIDATED LIVE 2026-08-31 (one value from working video)
Camera was live on the user's LAN at 192.168.178.147. Built tools/pprpc.py
(Python port of core/packets) + tools/cam_probe.py (UDP/TCP send + COM5 serial
capture = a live send/observe RE loop). Everything below is EMPIRICALLY
confirmed against the real device + its serial log.

TRANSPORT (confirmed both work, NO KCP needed):
- **UDP 20190**: raw pprpc, 2-byte magic 51 70 then [type<<4|8][varint len]...
  Handled STATELESSLY by iot_invoke_on_cmd as conn[-2]. Good for fire-and-ack
  commands, but conn_id=-2 is NEGATIVE so avsdk_video_add_conn REJECTS it
  ("input conn_id=-2 < 0!!"). So UDP alone can't get video.
- **TCP 20190**: raw pprpc, NO magic, [type<<4|8][varint len]... A TCP connect
  creates a REAL connection conn[1] (positive id) and runs the connection
  state machine (iot_conn_local_on_packet / "iot.conn.local"). THIS is the
  path for video. Must complete the handshake within ~3s or it times out
  ("conn[1] open rc:-5") and closes.

pprpc framing (tools/pprpc.py, matches core/packets exactly + wire-verified):
  first byte = MessageType<<4|8 ; varint(Length) ; then per-type body.
  Control (PBBIN=4): varint(CmdSeq) varint(CmdID) byte(EncType<<2|RPCType)
                     [varint(Code) if RESP] payload.
  CmdID varint for e.g. 601 = `d9 04`, 0x0a5a = `da 14`, 0x0a32 = `b2 14`.
  Verified: VideoPlay reply decoded cleanly as VideoPlay.resp protobuf
  {field5=1, field6=10, field7=4} = the exact resp struct we reversed.

MESSAGES are nanopb (log names them, e.g. "LanAuth.req"). Field types matter:
  LanAuth.req field 1 is NOT a string (sending a string there -> log
  "Failed to pb_decode(invalid wire_type), LanAuth.req"). Working shape that
  reaches the auth check: field1=did (string), field2=credential (string).
  VideoPlay.req: field1(varint)=channel (0=main).

*** THE HANDSHAKE (over TCP), serial-log confirmed: ***
  1. TCP connect 20190            -> conn[1] created, state connected.
  2. send LanAuth (0x0a5a)        -> "conn[1].local ... on packet LanAuth_Req",
                                      then "local check auth1 OK!" (pass) or
                                      "check LanAuth NO PASS!" (fail).
  3. (on pass) send SyncConn(0x6a)-> advances to the streaming state.
  4. send VideoPlay(0x0a32, ch)   -> avsdk_video_add_conn(conn=1,ch) succeeds
                                      -> AV packets (MessageType=6) stream back.
  NOTE: SyncConn is "unsupported" on the stateless UDP path but IS part of the
  TCP connection state machine.

*** THE ONE REMAINING BLOCKER: local_check_auth1's "secret" value. ***
Auth algorithm 100% confirmed (local_check_auth1 @ 0x2f0a4, hash FUN_000c109c =
MD5, format "%02x" lowercase, parse fmt "%s", input fmt "%s-%s-%s"):
  credential = "$" + nonce + "$" + md5_lower("<did>-<secret>-<nonce>")
  did    = iot_identity_get_did_maybe()    (identity_struct+0x10)
  secret = iot_identity_get_scode_maybe()  (identity_struct+0x120) if len>=6,
           else iot_identity_get_signkey() (+0x29)
Rebooted (via serial `reboot`) and re-captured the [iot] block: did=
PPHA1006C0955E8FD9, signkey=OHkMAuCv/nOXRHwvW9TnSA==, lslat=ivAygPb4VY5EyGAcYDuMAA==,
scode=307953 - SAME as before. did is correct (the device's cloud auth, which
uses the same get_did_maybe(), succeeds - "platform connected is ok").

BUT every secret candidate gives "check LanAuth NO PASS!" on the LIVE device
(oracle via serial log): scode "307953", signkey (b64 text AND raw 16 bytes),
lslat (b64 AND raw), signkey+lslat, and the auth2 "$L<idx>$" variant for
idx 0-9. The field arrangement is right (f1=did string, f2=credential string ->
credential reaches auth1's '$' branch; verified it computes+compares).
=> iot_identity_get_scode_maybe() (identity_struct+0x120) returns a value that
is NOT the printed scode and NOT signkey/lslat. It is a distinct secret field
we don't yet have the VALUE of (can't read runtime RAM; no mem-read shell cmd).

NEXT STEP to crack it: reverse where the identity struct is POPULATED (find the
loader that writes +0x10/+0x29/+0x120 from the flash/cloud config) to learn
what +0x120 actually holds and where it comes from - then either read it from
flash via `fal` or reconstruct it. Everything else (transport, framing, crypto,
handshake sequencing, message shapes, the live send+serial oracle in
tools/cam_probe.py) is DONE and working. Once the secret is right:
LanAuth passes -> SyncConn(0x6a) -> VideoPlay(0x0a32,ch0) -> AV(type 6) video,
or RecordStart (find CmdID via cmd_id_to_name name ptr @ 0x6951c) to SD.

## LAN client (option B) - transport confirmed 2026-08-30
Target: a from-scratch client that talks to the camera on its own AP
(192.168.9.252) to arm SD recording (RecordStart) - no app, no cloud.

Transport stack, fully confirmed from firmware:
  UDP -> KCP (ikcp) -> pprpc RPC -> protobuf-ish messages
- The camera's LAN server is `iot_dev_localsrv_udp_start` (FUN_00046930):
  a pprpc server named "udpsrv" bound to UDP **0.0.0.0:20190**.
- `FUN_0005a0f8` = `pprpc_create`: allocates the 0x750-byte connection struct
  (same object used by the video/auth code - +0x72c msg queues, +0x740 mutex,
  +0x744 worker thread, +0x44 transport-type). transport-type arg = 1 for the
  LAN server (0 for the cloud glbs client).
- KCP is the standard open-source ikcp (build path
  /home/liangyuxuan/share/avsdk/src/xciot/pprpc/ikcp.c) - NOT custom, so a
  stock KCP lib can be reused as-is. ikcp params set via ikcp_nodelay /
  ikcp_wndsize / ikcp_setmtu (values TBD - read from pprpc_kcp setup).
- ftconn NAT wrapper (magic 51 70 48, seen on CLOUD traffic) is for P2P/relay;
  the LAN path is direct KCP to udpsrv, almost certainly WITHOUT the ftconn
  wrapper (to confirm).

Remaining unknowns to reverse (firmware-only - no app captures available):
  B1 discovery: iot_dev_broadcast_discovery - how the client finds the cam +
     gets the KCP conv id to open a session.
  B2 pprpc framing + protobuf field tags for LanAuth_Req/Resp, SyncConn_Req/
     Resp, RecordStart (the bulk of the work).
  B3 auth: confirm H()=MD5 and nonce source (see LanAuth section above).
Scope: KCP is off-the-shelf; the real work is B2 (message encoding) + B1.
Achievable but multi-session; validation is hard with no reference packets, so
the encoding must be reversed exactly. Worth checking first whether the vendor
"xciot"/"xcthings avsdk" SDK source leaked publicly - it would hand us B1/B2.

## What implementing local video would actually take
1. KCP (ikcp) transport over UDP 20190.
2. pprpc framing plus the protobuf message set (`LanAuth_Req/Resp`,
   `SyncConn_Req/Resp`, `ConnHB`, `ExecIOTCMD`).
3. The LanAuth derivation - recover `local_check_auth1` / `local_check_auth2`
   from the ARM code in `app.bin` (the code is there; only the strings live in
   `download`), then reproduce it with AES-256/MD5 and the device id.
4. Reassemble `avsdk_write_video_slice` output into JPEG frames.

That is a multi-day reverse-engineering project, not an afternoon. Everything
needed is now in hand: complete verified dumps, the message names, the auth
function names, the crypto primitives, and candidate secrets.

## The periodic telemetry payload - reversed 2026-09-01

Traced `avsdk_dp_report_all` (0x00152658/0x00152bcc are its log-tag strings;
real code is `FUN_0003f37c`) and the encode/enqueue chain underneath it, to
answer "what does the ~15s encrypted 'Data' packet actually contain".

**It's a generic Tuya-style "datapoint" (dp) system**, not camera-specific
telemetry hardcoded in one place - individual features report into a shared
queue whenever their own state changes, and a batcher flushes the queue.

**Wire format per datapoint** (`FUN_0003de10`, the TLV encoder):
```
[1 byte: length-field-size nibbles] [dp_id, 1-4B varint] [type byte] [ver byte]
[value_len, 1-4B varint] [value_len raw bytes]
```
Decoder side (`FUN_0003db10`) is the exact mirror - confirms the format, not
device-specific (it's a generic length-prefixed record parser with no
per-ID switch in this function; the ID *meanings* are external).

**Batching** (`FUN_0003f37c` = the real `dp_report_all`): walks a linked list
of pending dp entries (head @ `DAT_0003f7e0`), each entry gated by an
enabled-flag byte (`entry+0x20==1`) and a pending-flag byte (`entry+0x21==0`),
packs as many as fit into a **1200-byte (0x4b0) buffer**, sends that as one
batch via `FUN_0003eed0` (-> `FUN_0003ed60`, the actual pprpc send), then
loops for more if the list wasn't fully drained. This 1200B cap is well above
the 184B "Data" packet size seen in the one live pcap - so that capture was
either a single small dp or a partial/steady-state heartbeat-class report,
not a full batch.

**Concrete dp IDs traced to real call sites** (each via `FUN_00041d7c`, the
enqueue function that both validates the entry and immediately triggers
`FUN_0003f37c`/`FUN_0003ef1c` to flush it):
- **dp 0x22 (34) - `ttcmd_timestamp`** (`FUN_00040fec`,
  "avsdk_dp_update_ttcmd_timestamp"): reports a timestamp value back to the
  cloud. Reads as an ack/round-trip marker for a received cloud command
  ("TT cmd" = thing-template command), not a sensor reading.
- **dp 0x3b (59)** (`FUN_00040d38`, log string
  "avsdk_dp_query(dpid:59)"): reports a single byte, hardcoded to `0` at this
  call site - looks like a generic on-demand status/boolean flag whose real
  value is set by a caller we haven't traced; this occurrence just answers a
  query with a default.
- **dp 0x30 (48) - OTA progress** (`FUN_00042dc4`): loops `for pct = 5; pct
  <= 100; pct += 5`, enqueuing dp 0x30 with the percentage each iteration and
  sleeping 2000ms between - this is the **firmware-update progress bar**
  datapoint, confirmed by the sibling string `cli_dp_report_ota` in the same
  packed name table.
- **dp 0x89d (2205)** (`FUN_00042ca8`, a generic "report this one int as dp
  N" helper parameterized by a global at 0x00042db8 = `0x89d`): matches the
  `cli_dp_report_dp_2205` FinSH test-command string exactly - this is a
  manual/debug hook exposed on the serial shell, not something that fires on
  its own.

**Not resolved this pass**: which dp IDs are "enabled" by default at boot and
therefore make up the actual unprompted ~15s cycle (candidates: device
online/heartbeat status, WiFi RSSI, SD-card state, video-channel state - all
plausible given the surrounding code, none confirmed at a call site). The
callers that `FUN_00041d7c`'s xref list pointed at for the remaining
addresses (`0x00042b34/78/bf4/c70`) sit in a code region Ghidra hasn't
resolved into defined functions yet (same packed/indirect-call pattern noted
before) - next step there is `create_function` at those addresses to force
disassembly, or set TMode explicitly and re-run analysis over that range.

**Bottom line**: the mechanism (format, batching, send path) is now fully
nailed down, and several concrete datapoints are named (OTA progress, a
command-ack timestamp, one debug/manual dp) - but the *routine, unprompted*
15-second report's exact field(s) are still not pinned to a specific named
dp, only bounded (small int/byte-sized values, well under the 1200B batch
cap, AES-encrypted before it hits the wire so a capture alone won't reveal
it without the per-device key).
