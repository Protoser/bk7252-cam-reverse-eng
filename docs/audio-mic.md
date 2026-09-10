# The microphone: capture path and the LAN commands that drive it

Reversed from `firmware_combined.bin` in Ghidra (base 0x10000), 2026-09-10.

**Short answer: yes.** The camera has a working mic, an always-running capture
thread, and four pprpc commands on the same LAN control channel already used for
video. `AudioPlay` returns raw **8 kHz / 16-bit / mono PCM**, no codec to decode.

## 1. The four audio commands

They sit immediately after the video commands in the pprpc enum, at consecutive
CmdIDs. Derived from `pprpc_cmd_id_to_name` @0x68e94: ID constant array @0x69360,
name-pointer array @0x69494, strings @0x15a6c8+. Cross-checked against the
per-CmdID nanopb descriptor table @0x159608 (entry N = 0x159608 + N*0x20), whose
entries carry the same IDs in the same order.

| CmdID  | Dec  | Name          | Req desc / size | Rsp desc / size | Handler |
|--------|------|---------------|-----------------|-----------------|---------|
| 0x0A36 | 2614 | AudioPlay     | 0x15cc80 / 4    | 0x15ccb4 / 20   | 0x82f48 |
| 0x0A37 | 2615 | AudioPause    | 0x15cc30 / 4    | 0x15cc64 / 1    | 0x83064 |
| 0x0A38 | 2616 | TalkbackPlay  | 0x15f83c / 4    | 0x15f870 / 20   | none    |
| 0x0A39 | 2617 | TalkbackPause | 0x15f7ec / 4    | 0x15f820 / 1    | none    |

**Correction to `protocol-commands.md`:** that table listed 0x0A36 as `FlipGet`.
There is no `FlipGet` in this enum. The order is
`... VideoQosSet(0x0A34), FlipSet(0x0A35), AudioPlay(0x0A36), AudioPause(0x0A37),
TalkbackPlay(0x0A38), TalkbackPause(0x0A39), HistoryPlanSet(0x0A3A) ...`
verified byte-for-byte off the string blob at 0x15a8a4.

`AudioPlay_Req` is a 4-byte / single-int32 struct, byte-identical in shape to
`VideoPause_Req` — i.e. just the channel. `AudioPlay_Rsp` is 5 x int32, the same
shape as `VideoPlay_Rsp`.

## 2. What AudioPlay actually does

`dev_on_ipc_AudioPlay` @ **0x00082f48** — signature `(conn, req, rsp)`, banner
`conn[%d]ipc_AudioPlay_Req:` @0x1650b2. Body:

1. logs the banner and `req` field 1 (channel),
2. `bl 0x149828` (Thumb->ARM veneer) -> **`FUN_0001fa2c(conn)`**,
3. fills the response with **hardcoded constants** and logs each one
   (`rsp->bit`, `rsp->code`, `rsp->codec`, `rsp->track`, `rsp->rate`
   @0x1650e8 / 0x16510f / 0x165137 / 0x165160 / 0x165189),
4. returns 1.

Response, by nanopb field number (struct offset):

| field | off  | name  | value |
|-------|------|-------|-------|
| 1     | +0x0 | code  | **0** (success, unconditional) |
| 2     | +0x4 | codec | **21** |
| 3     | +0x8 | rate  | **8000** (`0xfa << 5`) |
| 4     | +0xc | bit   | **16** |
| 5     | +0x10| track | **1** |

`FUN_0001fa2c(conn)` is the whole subscription mechanism: a **10-slot table** at
`*DAT_0001fb5c + 0xA4` (`base + (i+0x28)*4 + 4`). It scans for `conn`, and if
absent drops it into the first `-1` slot. Exact mirror of the video subscriber
list. `dev_on_ipc_AudioPause` @0x83064 calls the matching remover,
`FUN_0001f958` (via `thunk_FUN_0001f958` @0x148de0).

So AudioPlay is *not* a codec negotiation — it is "add me to the audio fan-out
list", and the reply is a fixed capability advert.

## 3. The capture pipeline (`xdev_audio.c`)

- `xaudio_start` (banner @0x16713b) runs during device init. It mallocs the
  audio thread stack (`audio_thread_stack malloc failed !!!` @0x167461) and
  `rt_thread_init`/`rt_thread_startup`s a thread named **`audio_enc`**
  (@0x1674a1, entry **0x00085b34**, prio 10, stack 20 words of args at 0x85d76).
- The thread sets the ctx sample rate to 8000 (`[ctx+0xc] = 0xfa<<5`), mallocs a
  **320-byte** read buffer (`0xa0 << 1`), and then blocks on a **mailbox**
  (`rt_mb_recv` @0xa5a1c) — logging `---mb receive msg:%x----`. Message `1` =
  start (`----start---`, `record encoder start`), `2` = stop.
- While running it loops **5 times x 320 bytes** per pass, `memcpy`ing each read
  into a ring at `[ctx+0x10 + ctx->off]`, capping `ctx->off` at **1600**
  (compare against 1599 @0x85cec, clamp to `0xc8<<3`).

320 bytes = 160 samples = **20 ms** at 8 kHz/16-bit/mono; 5 of them = a
**1600-byte, 100 ms** frame. **There is no encoder call in the loop** — the
bytes go from the mic device straight into the frame buffer. "codec 21" is raw
PCM; the `bit:16` field is literal, not a decoded-width hint.

(For contrast, `streaming-plan.md` mentions 8 kHz **A-law** — that came from
cam-reverse's iLnk/PPPP cameras, which this device is not. Don't apply it here.)

## 4. Mic driver layer

Beken audio driver strings @0x171848-0x17198a:
`audio_device_opened` / `audio_device_mic_opened` / `audio_device_mic_set_rate:%d`
/ `..._set_channel:%d` / `..._set_volume:%d` / `..._mic_closed`, plus
`audio_codec_control`, `set_dac_sample_rate %d`, `unsupported sample rate:%d`
(@0x17172b) and the failure path `mic device not found` (@0x17189c).

There is also a **DAC**, so the hardware is capable of output: `aud_dac`,
`pcm_dac`, `-set dac vol:%d - indx:%d,dig:%d,ana:%02x`, `audio dac not found`.

Two shell commands exist on the serial/telnet console (see `device-intel.md`):

- **`mic_dac_loop`** (`__cmd_mic_dac_loop`, help text "mic dac loop") — mic ->
  DAC loopback. Logs `[micdac]:samplerate/n_channel/volume/channel`,
  `[micdac]:start loop back, tick %d`, `stop`, `exit`. Fails with
  `audio mic not found` / `audio dac not found` if the device is missing.
  **This is the cheapest way to prove the mic hardware works, no network needed.**
- **`audio_dump`** (`__cmd_audio_dump`) — dumps `audio->dma_irq_cnt = %d`.

## 5. Talkback (device -> speaker) is enumerated but not implemented

`TalkbackPlay`/`TalkbackPause` have CmdIDs *and* nanopb descriptors, but there is
**no `ipc_TalkbackPlay_Req` handler banner anywhere in the image** — unlike every
implemented command, which logs one. The explicit refusals
`Device unsupport ipc_VideoCall(561)!!!` and `..._PauseAllAv(563)!!!` (@0x14a548,
0x14a570) don't name Talkback, so it should fall through to the generic
`Device unsupport ipc cmd %s(%d)` (@0x14a848). Expect a rejection, not audio in.

The DAC hardware is present regardless, so two-way audio is a firmware gap, not a
hardware one.

## 6. Is it encrypted? No - audio ships in the clear

**The audio slices are sent with EncType = 0.** Verified at instruction level,
because the decompiler is actively misleading here (see the caveat below).

Both media types end up in the same wire-send, `pprpc_build_and_send_slice_msg`
@0x5c168, which takes the per-packet **EncType** in the stack slot at `[sp,#0x8]`
(0 = none, 3 = AES-256-CBC). The two callers fill that slot differently:

- **Video** - `avsdk_video_conn_send_slice` @0x1d868:
  ```
  0001d8fc  mov  r3,#0x0
  0001d900  strb r3,[r11,#-0x11]     ; enctype = 0
  0001d904  ldrb r3,[r11,#0x24]
  0001d908  cmp  r3,#0x1
  0001d90c  bhi  0x1d918             ; if that byte > 1, leave it at 0
  0001d910  mov  r3,#0x3
  0001d914  strb r3,[r11,#-0x11]     ; else enctype = 3 (AES-256-CBC)
  ...
  0001d9c4  ldrb r3,[r11,#-0x11]
  0001d9c8  str  r3,[sp,#0x8]        ; <- EncType arg
  ```
  i.e. conditional, which is why only the I-frame header slice comes out
  encrypted (see `av.py`'s header notes).

- **Audio** - `FUN_00044e24` (reached from `xsend_audio` @0xc8e38 ->
  `FUN_000c8a3c` -> `thunk_FUN_00025ed4`):
  ```
  00044eec  mov  r3,#0x0
  00044ef4  str  r3,[sp,#0x8]        ; <- EncType arg, hardcoded 0
  ```
  Unconditional, and identical in **both** branches of the function
  (@0x44eec and @0x44fcc). There is no path that sets it to 3.

So an audio slice is a plain pprpc type-6 packet whose payload is the raw PCM.
No key needed: capture the AV socket, keep the audio slices, write the bytes out,
play them. The LanAuth session token is only required for the *video* I-frame
header.

**Decompiler caveat:** Ghidra renders the audio call as
`pprpc_build_and_send_slice_msg(..., 0)` with 7 arguments, because it inherits the
7-parameter prototype guessed for that function. The real call passes ~20 args and
spills most of them to the stack, so argument positions in the pseudocode do not
line up with reality. Do not read the EncType off the decompiled call - diff the
two `bl 0x5c168` call frames in the disassembly instead.
Don't be misled by `mov r3,#0x3 ; str r3,[sp,#0x20]` in the audio path either:
that is a *different* parameter (video passes a caller byte from `[r11,#0x14]`
into the same slot), not the encryption type.

### The layers around it, for completeness

| Layer | Encrypted? |
|-------|-----------|
| TCP transport (20190) | **No.** No TLS. `av.py` parses pprpc frames straight off the raw socket bytes. |
| Control channel (type 4: LanAuth, AudioPlay, ...) | AES-256-CBC, key `md5hex(prekey + ",ID:%d-SEQ:%d-RPC:%d")`. The pre-auth prekey is the hardcoded `A2r0i1m1a2M0a1x6toriQue`, recoverable from any firmware image. |
| Video (type 6) | Only the I-frame header slice, first `EncLen` (~1040) bytes, key `md5hex(token + ",AVSeq:%d-TT:%d-AVChannel:%d")` where token is the per-session LanAuth secret. |
| **Audio (type 6)** | **Never. EncType is hardcoded 0.** |

The one thing that does gate audio is *authorisation*, not encryption: you still
need a valid LanAuth session before `AudioPlay` will put your connection in the
subscriber table. But once frames flow, the audio bytes themselves are plaintext
to anyone who can see the traffic - and per the boot-time `GetServers` leak, a
passive observer who catches a reboot gets the device secret anyway.

## 7. How to try it

`AudioPlay` takes the same one-field request as `VideoPause` and needs the same
session state as video: LanAuth, then `SyncConn`, then `AudioPlay(0x0A36)` on the
control channel. Audio frames then arrive on the AV channel alongside video, and
`ConnHB` flow control still applies (see `bk7252-connhb-flow-control`), so the
receiver must keep reporting its frame seq or the stream stalls.

Raw output is directly playable:

    ffplay -f s16le -ar 8000 -ac 1 audio.raw
    # or: sox -t raw -r 8000 -e signed -b 16 -c 1 audio.raw out.wav

`tools/lan_client.py` does not send `AudioPlay` yet — the command plumbing is the
same shape as `--video`, plus a demux for the audio frame type on the AV channel.
