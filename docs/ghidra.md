# Loading the firmware into Ghidra

## Language
    ARM:LE:32:v5t          (little-endian, 32-bit, ARMv5TE)

The BK7252's core is an ARM968E-S = ARMv5TE, ARM + Thumb. Compiler spec: `default`.
Do not pick a Cortex-M variant - this is a classic ARM9 with a full ARM32 vector
table, not an M-profile part.

Endianness is confirmed from the data: word 0 of the image is `0E 00 00 EA`, which
is only the branch `EA00000E` when read little-endian, and the port constants
appear as LE (`de 4e` = 20190).

## Load THE COMBINED IMAGE, not the individual partitions
`app` and `download` are **one contiguous firmware**, not two images. FAL's
partition names are misleading: the linked image simply runs past the end of the
`app` partition into what the table calls `download`. That is why `app.bin` has
code but no strings - `.rodata` lives past 0x120000.

    dumps/firmware_combined.bin   = app.bin + download_clean.bin   (1,784,864 bytes)

Proof: string addresses computed in the combined image appear verbatim as code
literals, e.g. `check LanAuth NO PASS!` sits at vaddr 0x0014F35C and the 4-byte
literal `5C F3 14 00` appears in the code. Same for `local check auth1 OK!`
(0x0014F2A4) and `avsdk_write_video_slice` (0x0014E288).

Note `download_clean.bin` is the **CRC-stripped** version (2 bytes dropped per 34).
Never concatenate the raw `download.bin` - it will be misaligned garbage.

## Base address: 0x00010000
Derived from the image itself, not guessed. The vector table is:

    +0x00  EA00000E   b +0x40
    +0x04..+0x1C      ldr pc,[pc,#0x14]   x7

and the literal pool immediately after holds the handler addresses:

    +0x20  0x000106C0     +0x24  0x00010740     +0x28  0x000106E0
    +0x2C  0x00010700     +0x30  0x00010720     +0x34  0x00010760
    +0x38  0x00010780     +0x3C  0xDEADBEEF   (sentinel)

Those land at file offsets 0x6C0-0x780, so base = 0x00010000 - which also matches
the `app` partition's logical flash offset exactly. File offset 0x6C0 decodes as
`push {r0,r1}` / `ldr r1,[pc,#0x27c]` / `bx r0`.

In Ghidra: File > Import File, set Language `ARM:LE:32:v5t`, then Options... and
set **Base Address = 10000** (Ghidra takes it as hex).

## ARM vs Thumb - this is the part that will waste your time if you miss it
The image is mixed-mode, with a hard boundary:

    vaddr 0x00010000 - 0x00080000   ARM    (74-91% of words carry cond 0xE)
    vaddr 0x00080000 - 0x00120000   THUMB  (cond 0xE collapses to 2-9%,
                                            14-73 Thumb `bx lr` per 32KB)
    vaddr 0x00120000 - 0x00140000   THUMB  (continues into "download")
    vaddr ~0x00140000 - 0x00180000  RODATA / strings (37-75% ASCII)
    vaddr ~0x00190000+              erased (all zero)

Ghidra's auto-analysis will disassemble the whole thing as ARM and produce
nonsense above 0x80000. For the Thumb region, select the range and set the
`TMode` register to 1 (Ctx-Register / "Set Register Values", TMode = 1) before
analysing, or disassemble Thumb explicitly with Ctrl-Alt-D on a known entry.

## Suggested memory blocks
    flash (rx)   0x00010000  len 0x1B3C20   <- the combined image
    ram  (rw)    0x00400000  len 0x00050000 <- no data; thread stacks observed at
                                              0x00426488, 0x00432520, 0x004331C0
                                              in crash and `ps` output

## Good starting points once loaded
Search the rodata for these, then follow the xrefs back into code:

    "check LanAuth NO PASS!"      0x0014F35C   -> LanAuth verification
    "local check auth1 OK!"       0x0014F2A4   -> local_check_auth1
    "avsdk_write_video_slice"     0x0014E288   -> video slice emitter
    "cal_aes256"                               -> the AES-256 helper
    "===iot.dev.broadcast_async try: %s://%s:%d===="

The auth derivation (`local_check_auth1` / `local_check_auth2`) is the target if
you want a local video client - see protocol.md.

## Trap: the saved project can silently be at base 0x0 instead of 0x10000
Found 2026-08-30. Even though this doc says to set Base Address = 0x10000 on
import, a saved `.gpr`/`.rep` project can end up loaded at base **0x00000000**
(confirmed via `get_metadata`/`get_current_program_info` showing
`image_base: 00000000`, `min_address: 00000000`). At base 0, every literal-pool
pointer in the firmware is wrong by exactly `0x10000` - `get_xrefs_to` on known
rodata strings returns nothing, `search_functions`/`search_strings` for known
symbol-ish names turn up empty, and auto-analysis undercounts functions
(4906 vs 6620 after the fix on this binary).

**How to detect it:** search_byte_patterns for a string's address plus
`0x10000` (LE bytes) and see if it turns up inside a function's literal pool;
if so, the project is at the wrong base. Concretely: the string `"LanAuth"`
lives at file-relative offset `0x0014aa70`; a reference to it only resolves
as the 4 bytes `70 aa 15 00` (== `0x0014aa70 + 0x10000`) found inside
`FUN_00068584`'s code.

**Fix:** call Ghidra's "Set Image Base" to `0x10000` (MCP: `set_image_base`
with `address: "0x10000"`) and let auto-analysis re-run (`analysis_status`
polls to `analyzing:false`; on this binary it took ~10-15 min and the run
looked stuck at times between polls - be patient, don't re-issue the rebase).
Verify afterward with `get_current_program_info` (`image_base` should read
`00010000`, `min_address`/`max_address` should read `00010000`/`001c3c1f`) -
don't trust `list_segments` alone, it showed the corrected range transiently
even before the metadata/actual memory contents had caught up once in this
session. Confirm content moved correctly by reading a couple of known
addresses (e.g. `0x10000` should be the ARM vector table
`0e0000ea14f09fe5...`, and the "LanAuth" string should read at `0x15aa70` -
old_file_offset + 0x10000 - not at its pre-rebase number).

## Session 2026-08-30: functions reversed and named
Starting from the base-address fix above, the following call chain was
identified, renamed, and plate-commented (full reasoning in each function's
plate comment - this is just an index):

**Video send path** (fires whenever the encoder produces a slice and pushes it
to subscribed/connected LAN clients):
```
avsdk_write_video_slice (0x0001daf0)      fan-out to up to 10 connections,
                                           gated by a per-conn/per-channel
                                           subscription bitmap
  -> avsdk_video_conn_send_slice (0x0001d868)   per-conn gate: only sends if
                                                 conn state == 3 (see below)
    -> pprpc_build_and_send_slice_msg (0x0005c168)   builds the wire message
                                                      (header/type/payload/
                                                      trailer sub-builders)
      -> pprpc_enqueue_msg (0x0005b0b0)     generic per-type outbound queue
                                             push; type 3 == video slice
```
Throttling/backlog-drop machinery for the same per-type queues (referenced by
the send path via conn+0x72c, an array of 4 queue-object pointers):
```
pprpc_video_slice_check_packet_drop (0x00054c24)  sequence-continuity +
                                                   used/limit ratio (>0.5)
                                                   drop test, sets a per-slot
                                                   bit in conn+200
pprpc_video_slice_wait_and_send (0x0005523c)      10ms-poll retry wrapper
                                                   around the above
                                                   (no resolved callers -
                                                   likely reached through an
                                                   indirect table)
pprpc_msgqueue_get_used/get_limit/push (0x00053420/0x000533e0/0x00053460)
```
Packet-field accessors on the slice object: `video_slice_pkt_get_flag/
get_qword40/get_seq` (0x0006200c/0x000620b4/0x000620e4).

**LanAuth/SyncConn handshake** (the gate that gets a connection to state==3,
i.e. eligible for video):
```
iot_conn_local_on_packet (0x0002f618)   *** the whole local handshake state
                                         machine *** - conn+0x178 is the
                                         state byte:
    state 1: verify LanAuth_Req (pprpc cmd 0x0a5a) via local_check_auth,
             on pass send LanAuth_Resp and set state=2; also answers
             NatProbe_Req (cmd 0x5d)
    state 2: verify SyncConn_Req (pprpc cmd 0x6a), on pass send
             SyncConn_Resp and set state=3
    state 3: hand off to a generic per-conn callback at conn+0x180

local_check_auth (0x0002f440)      tries local_check_auth1, falls back to
                                    local_check_auth2
local_check_auth1 (0x0002f0a4)     verifies "$<nonce>$<hash>" where
                                    hash == MD5-ish("<did>-<scode>-<nonce>")
                                    (did/scode from iot_identity_get_*
                                    accessors - unverified against a live
                                    capture, see protocol.md)
local_check_auth2 (0x0002f32c)     verifies "$L<idx>$<hash>" variant, calls
                                    FUN_0002f28c (CONFIRMED 2026-09-01, see below)
lanauth_derive_resp_value (0x0002f4a8)   builds the LanAuth_Resp value the
                                          same way (format string not yet
                                          read out - DAT_0002f510)
lanauth_parse_dollar_nonce_hash (0x0002ef70)   parses "$<digits>$<rest>"
iot_identity_get_did_maybe/get_scode_maybe/get_secret_fallback
  (0x0001c2f8/0x0001c2b8/0x0001c338)   property-store getters, name is a
                                        hypothesis from usage pattern only
pprpc_cmd_id_to_name (0x00068584)   ~150-entry pprpc command ID -> name
                                     binary search (confirms 0xa5a's row
                                     returns "LanAuth")
```
Plus recognized as libc `strcmp` (0x0007f544, standard word-at-a-time
`0xfefefeff`/`0x80808080` bit-trick implementation - Ghidra's normal
"recognize known function" analyzer hadn't tagged it, probably because it was
only reachable post-rebase).

**`FUN_0002f28c` decompiled and CONFIRMED 2026-09-01** (read via raw
`read_memory` on its two format-string pointers, not the decompiler's inline
names - see the +0x10000 mislabeling note in [[bk7252-protocol-commands]]):
    DAT_0002f324 @ 0x0014f2bc = "%s-%s-%d"     (input:  did, scode, idx)
    DAT_0002f328 @ 0x0014f2c8 = "$L%d$%s"      (output: idx, hash)
So `local_check_auth2`'s credential = `"$L" + str(idx) + "$" +
hash(sprintf("%s-%s-%d", did, scode, idx))`, idx a small int (0-9 per the
"$L<idx>$" sweep candidates in protocol.md) - a parallel derivation to
local_check_auth1 that ALSO consumes `did`+`scode`, not an independent
secret. Confirms scode (not some other value) is the one per-device secret
both auth paths need - see [[bk7252-per-device-secret]] for what that means
for a second physical unit.

**Loose ends for a future pass:** read out `DAT_0002f27c` ("%s-%s-%s" already
confirmed), `DAT_0002f510`; the generic senders `FUN_0005bab4`/
`pprpc_send_ctrl_resp`; find what calls `pprpc_video_slice_wait_and_send`
(currently zero resolved xrefs - likely an indirect/table call Ghidra hasn't
resolved); confirm `FUN_001496f4` really is MD5 (it's an indirect-call
dispatcher, `(*DAT_001496fc)()`, not proven); trace where the identity
struct (did/signkey/lslat/scode) is actually LOADED FROM at boot - not yet
found (no `fal` partition or `/appfs` file confirmed as the source yet, see
[[bk7252-per-device-secret]]).

## Session 2 (2026-08-30): cloud contact (iot_dev_glbs / GetServers)
Same technique as above (find a self-referencing log-tag string, byte-search
for its address+0 as a literal pool pointer, `get_function_by_address`
stepping backward/forward to find the real prologue when Ghidra hadn't
auto-detected the function boundary). All in the `0x00045700-0x00046600`
region, one source file:

```
iot_dev_glbs_run (0x00045c50)        the actual "phone home" call - opens a
                                      fresh transport (UDP by default),
                                      builds+sends GetServers (pprpc cmd
                                      0x259), waits up to 2000ms, closes.
  -> iot_dev_glbs_build_req (0x000458c4)   builds the request: did+signkey+
                                            a 16B unknown field+7-int
                                            capability list+timestamp
  -> pprpc_call_and_wait (0x0005c8f0)      generic sync pprpc call+wait,
                                            shared with other control calls
                                            (builds envelope via the same
                                            FUN_0006225c header builder as
                                            the video-slice path)
iot_dev_glbs_show_rsp (0x00045a24)   debug-dumps a GetServers response: up
                                      to 10 {type,address,port(s)} entries
iot_dev_glbs_state_change (0x00045830)   glbs state-machine transition log
FUN_00045734 / FUN_00045774          state-enum -> string helpers (6-way and
                                      generic switch, used by state_change)
```
Identity struct field accessors (the struct `iot_dev_glbs_build_req` and
`local_check_auth1` both read from - base pointer not yet named):
```
identity_struct_get_did_field     (0x0003baa8)  struct+0x10  (did, 25B)
identity_struct_get_signkey_field (0x0003bad8)  struct+0x29  (signkey, 65B) -
    CORRECTED from an earlier "secret_fallback" guess once this function
    turned up feeding the cloud GetServers request directly - confirmed by
    field-order arithmetic (0x10+0x19=0x29) matching the did/signkey/lslat/
    scode ordering in the [iot] boot-log block.
identity_struct_get_scode_field   (0x0003bb0c)  struct+0x120 (scode, 6 digits)
```
`iot_identity_get_did_maybe`/`get_scode_maybe`/`get_signkey` (0x0001c2f8/
0x0001c2b8/0x0001c338, named in session 1) are thin wrappers around these
three plus a dereference through a global config pointer - i.e. two layers of
indirection to the same struct.

## Session 3 (2026-08-30): the video REQUEST side - how to turn the feed on
Sessions 1-2 had the send path + auth; this session found what a client sends
to start video. All confirmed, named, and commented in the Ghidra DB:

```
dev_on_ipc_VideoPlay_Req (0x00082d04)   ipc_VideoPlay_Req handler (Thumb).
                                         request field 0 = channel (0-8).
                                         just calls ->
avsdk_video_add_conn (0x0001f3d0)        claims this conn's slot in the global
                                         conn table @ 0x004005cc and sets
                                         slot[+0xd0+channel]=1 (the subscribe
                                         bit). Returns -6 if the conn-count cap
                                         (table +0xa0) is hit.
```
Key proof this is THE gate: `avsdk_video_add_conn` and (session 1)
`avsdk_write_video_slice` dereference the SAME global table pointer -
`DAT_0001f774` == `DAT_0001dcf8` == 0x004005cc - and use the identical slot
layout (+0xcc handle, +0xd0+channel flag). add_conn sets the exact byte
write_video_slice tests. So VideoPlay -> one bit -> frames flow.

**Command ids** (via pprpc_cmd_id_to_name = the giant binary search at
0x00068584; ids are the compare-constants at 0x693xx, names the pointers at
0x695xx/0x696xx):
  VideoPlay      = 0x0a32 (2610)   id@0x69394 -> name@0x69538 -> 0x15a8cc
  VideoPause     = 0x0a33 (2611)   (consecutive; the stop/del_conn command)
  VideoQosSet, VideoChanChange     same 0x0a2b-0x0a44 family (exact ids not
                                   pinned this pass)
  (compare: LanAuth=0x0a5a, SyncConn=0x6a, GetServers=0x259 from earlier)
Reminder: the firmware's "ipc_VideoCall(561)" / "AppVideoPlay_561" strings use
561/0x231, a DIFFERENT higher app-invoke id, NOT the pprpc wire id.

Tooling note: `emulate_function` fails on this ARM target with "Undefined
register: ESP" even with sp/lr set (x86 assumption in the tool) - couldn't use
it to resolve the id; read the compare-constant out of memory directly
instead (id @ DAT_00069394 = 0x0a32), which is exact anyway.

## Session 4 (2026-08-30): device-side intel (shell / telnet / wifi)
Broad "what's useful at the device" sweep. Written up in docs/device-intel.md;
Ghidra-side notes:
- FinSH command table at 0x149ac8+ (12-byte entries {name_ptr, desc_ptr,
  func_ptr}). Enumerate all commands fast via `search_strings "__cmd_"` (59
  hits). Each __cmd_ name's finsh entry gives the handler func ptr (odd =
  Thumb).
- `cmd_wifi` (0xbf5f4), `wifi_write_setting_json` (0xbf350),
  `cmd_wifi_print_usage` (0xbf1f4) named + commented. `wifi cfg` writes
  /appfs/setting.json (wifi.SSID/Key/Mode) but nothing reads station creds
  back from it -> explains "doesn't stick".
- netio_init = FUN_000a41ec = stock lwIP netio benchmark (dismissed).
- Telnet login fn (~0xc8000-0xc86cc) is UN-ANALYZED THUMB - Ghidra never got a
  code ref (it's a boot thread, not a finsh cmd). Bytes are valid Thumb (bl/blx
  F-prefix encodings) but disassemble_bytes rendered them as ARM garbage.
  Couldn't force Thumb: `run_script_inline` is disabled
  (GHIDRA_MCP_ALLOW_SCRIPTS not set) and there's no TMode-register MCP tool.
  To finish: in the Ghidra GUI set TMode=1 over the range and re-disassemble,
  or enable scripts. Inline "123" constant in its literal pool @ ~0xc8694 is a
  candidate telnet password.

**Loose ends:** `iot_dev_glbs_append_srvres` and `iot_dev_glbs_update`
(string refs at 0x0004604c/0x00046564) not yet located/decompiled - presumably
where the GetServers response list actually gets stored and later picked
from. The periodic ~15s encrypted "Data" packet seen in the existing pcap
capture (184B req/88B reply) is NOT yet tied to a specific function -
`avsdk_dp_report_all`/`avsdk_log_append` exist in the image but their strings
sit in a packed, no-per-entry-pointer name table like `avsdk_write_video_slice`
originally did, so the direct byte-pattern-search trick didn't immediately
work; whether `pprpc_call_and_wait`'s payload gets encrypted by a lower layer
(KCP or inside `FUN_00149670`) is also unconfirmed.

## Session 5 (2026-09-10): the microphone / audio path

Answering "is there anything about a mic": yes, a complete one. Full write-up in
`audio-mic.md`; what was labelled in the project this session:

| Address    | Name | Notes |
|------------|------|-------|
| 0x0001fa2c | `av_audio_subscriber_add` | renamed function + plate comment |
| 0x0001f958 | `av_audio_subscriber_del` | renamed function |
| 0x00082f48 | `dev_on_ipc_AudioPlay` | label + plate comment (region is DATA, see below) |
| 0x00083064 | `dev_on_ipc_AudioPause` | label + plate comment (region is DATA) |
| 0x00085b34 | `audio_enc_thread_entry` | label + plate comment |

**Trap worth knowing:** the `ut_dev_ipc_cmd.c` handler block around
0x82f48-0x83100 is classified as **defined data**, not code. `create_function`
refuses there ("Function entryPoint may not be created on defined data") and
`decompile_function` has nothing to work with. Two consequences:

- Some handler banner strings have **no xrefs** even though they are referenced
  (`ipc_AudioPlay_Req` @0x1650b2 shows none, while `ipc_AudioPause_Req` @0x1651b1
  shows one). Absence of an xref is not evidence of absence of a handler.
- Read these with `disassemble_bytes` + `dry_run: true` and decode the literal
  pool by hand with `read_memory`. Starting mid-instruction gives convincing
  garbage, so anchor on a Thumb prologue (`f0b5`, `f7b5`) before trusting output.

**Deriving any CmdID -> name mapping** (generalises the WifiSet work):
`pprpc_cmd_id_to_name` @0x68e94 compiles to a binary search over two parallel-ish
arrays - ID constants at **0x69360** (`id[m]` at `0x69360 + 4m`) and name pointers
at **0x69494** (`name[n]` at `0x69494 + 4n`, strings from 0x15a6c8). Read both
with `read_memory` and match the `DAT_` addresses in the decompiled comparisons.
Cross-check against the nanopb descriptor table @**0x159608** (entry N at
`0x159608 + N*0x20`, first word = CmdID), whose entry index equals the name
index. Doing this found that the old `FlipGet @0x0A36` row in
`protocol-commands.md` was wrong - 0x0A36 is `AudioPlay`.
