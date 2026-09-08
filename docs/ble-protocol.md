# BLE protocol (client-facing surface)

Reverse-engineered from `dumps/firmware_combined.bin` (ARM:LE:32, base 0x10000)
in Ghidra. This documents what a phone/app can actually do by talking to the
camera over Bluetooth LE.

## TL;DR

The BLE interface is a **provisioning-only channel**. The one and only
functional operation exposed over BLE is **WiFi network config / device bind**
(`bdn_netcfg`, pprpc message type `0x2718`):

- The app sends the target **WiFi SSID + password** (plus an optional cloud
  host/region string) in a single AES-256-CBC-encrypted pprpc message.
- The camera replies with its **`did` (device id) + an scode-derived auth
  token**, then applies the credentials and joins the WiFi.

The rich command set (Reboot, PtzCtrl, WifiSet live-reconfig, StorageFormat,
Reset, the ~135 `ipc_*` commands in `pprpc_net_dispatch` / `FUN_0006a47c`) is
**NOT reachable over BLE**. That dispatch table is only wired to the LAN/cloud
KCP session. Over BLE the reassembled-message callback is hardcoded to
`ble_prov_handle_netcfg_msg`, which acts on type `0x2718` and ignores every
other message type (logs "recv msg type %d").

## Stack layers

```
BLE controller (Beken BLE 5.2, beken378/driver/ble/ble_5_2)
   |  GAP advertising, GATT server, ATT write/notify
   v
ble_thread_main            @ 0x00081530   "xdev_ble_thread" / "dev_ble"
   |  - starts BLE stack, sets adv data + device name (derived from did)
   |  - registers a pprpc provisioning session:
   |       ble_prov_session_create(&sess, tx_cb, wifi_set_cb=ble_prov_wifi_set_cb)
   v
ble_prov_rx_entry          @ 0x00039d68   (called via ptr FUN_0002b428/thunk)
   |  raw ATT-write bytes in
   v
ble_prov_reassemble_fragments @ 0x00038ffc
   |  de-fragments (see wire format), then when complete calls session+0x1a8
   v
ble_prov_handle_netcfg_msg @ 0x00039908   (== *(sess+0x1a8), hardcoded)
   |  AES decrypt + pprpc parse -> 0xce0 ctx; dispatch on msg type
   +-- type 0x2718 (bdn_netcfg): reply + apply wifi (below)
   +-- anything else: logged and dropped
```

Sender side (device -> phone), used for the netcfg response:

```
ble_prov_build_netcfg_rsp @ 0x00039704
   -> pprpc encode (AES-256-CBC) -> ble_prov_send_fragmented @ 0x000394e8
   -> *(sess+4) tx callback -> GATT notify
```

## Wire format (fragmentation)

BLE ATT payloads are small (default 23-byte MTU => 20 usable), so pprpc frames
are chunked. Every BLE packet is:

```
byte 0 : total_fragment_count      (1..11)
byte 1 : fragment_index            (1-based)
byte 2 : this_fragment_payload_len (<= 0x11 = 17)
byte 3.. : payload chunk (<= 17 bytes)
```

- Sender (`ble_prov_send_fragmented`): splits the pprpc frame into ceil(len/17)
  chunks of 17 bytes (last chunk = remainder).
- Reassembler (`ble_prov_reassemble_fragments`): slots are 21 (0x15) bytes;
  each accepted fragment must be >= 3 bytes; payload copied is `frag_len - 3`.
  Max message = 11 fragments => ~187 bytes reassembled. Enough for
  ssid(<=32) + pwd(<=64) + did + token.

Once all fragments arrive, the concatenated buffer is handed to
`ble_prov_handle_netcfg_msg`.

## pprpc envelope + crypto

The reassembled buffer is a standard **pprpc** frame (github.com/pprpc, XC
Things), the same protocol used on the LAN/KCP path. Parsing path:

```
FUN_0002b100 -> FUN_0002a98c -> FUN_00029768 -> FUN_00149598 (AES engine)
```

Payloads are **AES-256-CBC** with **PKCS#7** padding (`FUN_00029768`:
`0x10 - (len & 0xf)` padding; key size arg = 0x100 = 256 bits). The key + IV are
**hardcoded in firmware** (fixed, almost certainly product-line-wide), loaded
from `DAT_0002b20c` / `DAT_0002b210`:

```
AES-256 key : "UI3lQZ920C57E972YvuvvhRbIea3KXjj"   @ 0x0014cfbc (32 ASCII bytes)
AES IV      : "YvuvvhRbIea3KXjj"                   @ 0x0014cfe0 (16 ASCII bytes)
```

(The IV is the second half of the key string.) Because the key is static and in
the clear, provisioning frames can be encrypted/decrypted offline - the crypto
provides obfuscation and message integrity, not per-device secrecy.

## The netcfg request (0x2718) fields

After decrypt/parse into the 0xce0 context, `ble_prov_handle_netcfg_msg` reads:

| ctx offset | meaning                                   |
|-----------:|-------------------------------------------|
| `+0x40`    | pprpc message type; must equal `0x2718`   |
| `+0xc4`    | **SSID** (128-byte region)                |
| `+0x144`   | **WiFi password** (128-byte region)       |
| `+0x1c4`   | **cloud host / region** override string   |

The SSID + password are logged verbatim as `ssid:%s, pwd=%s`. The `+0x1c4`
string is fed to `FUN_0002ab04` -> `FUN_000380a8`, which compares it against the
stored server address (`server_ctx+0x2ff1`) and, if different, overwrites it and
reconnects (`FUN_00037fc0`). So field 3 = the cloud endpoint/region the device
should use after joining.

Handling sequence:
1. `ble_prov_build_netcfg_rsp(sess, 1)` builds and sends the response (below).
2. If a `wifi_set` callback is registered (`*(sess+8)`, guarded by
   `*(sess+0x1ac)==0` so it fires once): call it with
   `(ssid=+0xc4, pwd=+0x144, host=+0x1c4)`. On success `sess+0x1ac++`.
   In the BLE wiring this callback is `ble_prov_wifi_set_cb` @ 0x000814b0,
   which stores the two strings into a ring (`FUN_00081db0`, `DAT_00081ddc`)
   and sets a "creds ready" flag (`DAT_000814f8 = 1`) for the WiFi/join thread.
3. If no callback is registered: logs `no register wifi_set!` and returns -9.

## The netcfg response (device -> phone)

`ble_prov_build_netcfg_rsp` (module string `bdn_netcfg_rsp`, encoder
`bdn_ppiotcmd_encode`) builds a pprpc reply, type `0x2718`, carrying:

- `rsp+0xc4`  = the device **`did`** (from `iot_identity_get_did_maybe`).
- `rsp+0x144` = an **auth token** built by `ble_prov_build_auth_token`
  (`FUN_0003bc10`):

  ```
  n     = time() % 10
  inner = sprintf("%s-%s-%d", did, scode, n)     ; scode = per-device signkey
  token = sprintf("$L%d$%s", n, HASH(inner))     ; HASH via FUN_001496f4
  ```

  This is the same `did` + scode-derived credential the camera already leaks in
  its cloud `GetServers` boot traffic (see [[bk7252-per-device-secret]]); BLE is
  just another place it hands it out. `scode`/`signkey` is unique per physical
  unit with no known formula.

## Advertising / discovery

`ble_thread_main` builds standard GAP AD structures: a Complete Local Name
(AD type 0x09) and Shortened Local Name (0x08). The name is derived from the
device `did` (`FUN_00029484` -> `identity_struct_get_did_field` ->
`FUN_000293c8`), so the camera is discoverable by a did-based BLE name.
"ble stack ok" / "start ble stack success" mark a healthy bring-up.

## Security notes

- Static AES key/IV => the provisioning frame format is fully forgeable; the
  channel is not confidential against anyone with the firmware.
- The device volunteers `did` + scode token to whatever completes the netcfg
  handshake (no pairing / bonding gate observed on this path). Anyone in BLE
  range during setup can (a) harvest the per-device secret and (b) push their
  own SSID/password + cloud host. Provision only inside a trusted RF space.
- Upside for the app-free goal: you can drive WiFi onboarding yourself over BLE
  (SSID/pwd + point the "cloud host" field at nothing / your own sink) without
  the vendor app, and read back the did/token in the response.

## Exact wire format (for tools/ble_provision.py)

Full byte grammar, verified against the encoder `FUN_0002a090` (@0x2a090) and
decoder `FUN_0002998c` (@0x2998c). One reassembled BLE frame is:

```
[0x03] [varint(cipherlen)] [ AES-256-CBC(static key/iv) over the ppiot body ]
   ^ fixheader byte0 (FUN_00029598: high bit MUST be clear or RX rejects)
```

varint = standard protobuf base-128 LE (FUN_00012084 / FUN_00012264). The ppiot
body (plaintext, before AES) for a single-item message:

```
byte  flags               ; bit2 (0x04) mandatory; bit0/bit1 optional
byte  len_a ; a[len_a]     ; top string A (<=25) - empty on the device's frames
byte  len_b ; b[len_b]     ; top string B (<=25)
varint v1                  ; 0
varint v2                  ; 0
byte  item_count           ; 1
  -- per item --
  varint item_id           ; 0x2718 (10008) = bdn_netcfg
  byte  sub1_count ; sub1_count x varint     ; 1 x [0]
  byte  str_count  ; str_count x (byte len<=0x80 + bytes)
                           ; REQUEST: [ssid, pwd, host]
                           ; RESPONSE: [did, token]
  varint blob_len ; blob_len bytes           ; 0
  byte  cnt3                                 ; 0 (then cnt3*4 skipped bytes)
```

Crypto: AES-256-CBC + PKCS#7, static key/iv (see above). Same key both
directions, so the response is decrypted with the same key.

Worked example - `--ssid TestNet2G --psk hunter2secret --host ""` produces this
plaintext body (38 bytes) before encryption:

```
04 00 00 00 00 01           flags=4, a="", b="", v1=0, v2=0, item_count=1
98 4e                       item_id varint = 0x2718
01 00                       sub1_count=1, sub1[0]=0
03                          str_count=3
09 "TestNet2G"              ssid
0d "hunter2secret"          pwd
00                          host ""
00 00                       blob_len=0, cnt3=0
```

then `[0x03][varint(48)][AES256(padded body)]`, then fragmented into 3 BLE
packets of `[total][idx][len]+<=17B`.

## Provisioning tool

`tools/ble_provision.py` (needs `pip install -r tools/requirements-ble.txt`):

```
# inspect the exact frame without any hardware / without bleak:
python tools/ble_provision.py --dry-run --ssid MyNet --psk secret

# list nearby BLE devices:
python tools/ble_provision.py --scan

# provision (SSID from this PC's WLAN, psk from the Windows profile store):
python tools/ble_provision.py --ssid MyNet
python tools/ble_provision.py --address AA:BB:CC:DD:EE:FF --ssid MyNet --psk pw
```

It scans/connects, auto-discovers a write+notify characteristic pair (override
with `--write-uuid` / `--notify-uuid`), sends the netcfg request, and prints the
camera's `did` + auth token from the reply. The camera then joins the WLAN and
reboots. Status: the codec self-tests (TX+RX round-trip, in/out-of-order
reassembly) pass; the frame has NOT yet been confirmed against real hardware -
run `--dry-run` first, and keep a serial/softAP recovery path ready.

Note on the "secret": BLE returns `did` + `$L<n>$md5(did-scode-<n>)`, a one-way
token, NOT the raw `scode`. The LAN video path (`tools/lan_client.py` ->
`LanAuth`, cmd 0x0A5A) needs the raw scode (`credential = "$"+nonce+"$"+
md5("did-scode-nonce")`); for this unit that scode is already known to
lan_client. BLE cannot recover raw scode on its own.

## Ghidra labels applied

| Address    | Name                             | Role |
|-----------:|----------------------------------|------|
| 0x00081530 | `ble_thread_main`                | BLE task: stack + adv + session reg |
| 0x00039d68 | `ble_prov_rx_entry`              | RX entry (defrag front door) |
| 0x00038ffc | `ble_prov_reassemble_fragments`  | fragment reassembly |
| 0x000394e8 | `ble_prov_send_fragmented`       | TX fragmenter |
| 0x00039908 | `ble_prov_handle_netcfg_msg`     | 0x2718 handler (only real cmd) |
| 0x00039704 | `ble_prov_build_netcfg_rsp`      | did+token response |
| 0x0003bc10 | `ble_prov_build_auth_token`      | `$L<n>$<hash>` token |
| 0x00039bf4 | `ble_prov_session_create`        | 0x1b0 session alloc/init |
| 0x000814b0 | `ble_prov_wifi_set_cb`           | stores ssid/pwd, sets ready flag |
| 0x0003a3c0 | `pprpc_net_dispatch`             | LAN/cloud cmd router (NOT ble) |
| 0x0006a47c | (FUN_0006a47c)                   | ~135-cmd pprpc table (LAN/cloud) |
| 0x0014cfbc | `pprpc_aes256_key_UI3lQZ`        | static AES-256 key |
| 0x0014cfe0 | `pprpc_aes_iv_Yvuvvh`            | static AES IV |
