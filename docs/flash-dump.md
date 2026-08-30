# Flash access and dumping

The shell's `fal` (Flash Abstraction Layer) gives direct read access, so no
Beken UART bootloader tool and no disassembly of the OTA process is needed to
get an image. **Never run `fal erase`.**

## Partition table
    | name       | flash_dev        |   offset   |    length  |
    | download   | beken_onchip     | 0x00132000 | 0x000ae000 |   OTA staging, 696 KB
    | app        | beken_onchip_crc | 0x00010000 | 0x00110000 |   main firmware, 1.06 MB
    | bootloader | beken_onchip_crc | 0x00000000 | 0x00010000 |   64 KB

`beken_onchip_crc` is the CRC-checked view; `fal read` returns decoded payload
bytes, so dumps need no CRC stripping. Offsets passed to `fal read` are relative
to the probed partition, and reads succeed across the whole range (verified at
`app` offset 1114000).

## Commands
    fal probe <part>     - select a partition (required before read)
    fal read <off> <len> - hexdump, one offset-tagged line per 16 bytes
    fal bench <blk>      - throughput test
    fal erase            - DO NOT USE

First 16 bytes of `app` are `0E 00 00 EA 14 F0 9F E5 ...` - an ARM32 exception
vector table (`b`, then `ldr pc, [pc, #0x14]` x7), as expected for the ARM968
core in a BK7252.

## Why dumping is fiddly
The RTOS prints ~460 B/s of unsolicited log spam that cannot be silenced:
`set_log off` has no effect (measured 461 -> 468 B/s), and `xm_printf_bit_cmd`
reports its mask already at `0000 0000`. The spam lands *inside* hexdump lines
and corrupts roughly 15% of them per pass.

`tools/dump_flash.py` handles this:
- every line carries its own offset, so lines are indexed rather than streamed,
  and interleaved noise is simply skipped;
- termination is "no NEW hex line for ~1s" - byte-level idle never occurs,
  which is what made the first version crawl at 445 B/s;
- corrupted lines are re-requested in repair passes, with nearby gaps coalesced
  (`--merge-gap`) so a pass is a few hundred reads instead of thousands;
- a chunk that returns nothing triggers a re-probe and retry, because the camera
  can reboot mid-dump and silently lose the probed partition.

Usage:
    python tools/dump_flash.py --part app --out dumps/app.bin

---

# Dump results (2026-08-30)

## Flash layout, resolved
The device reports 4 MB but `fal read 0` and `fal read 2097152` on the raw
`beken_onchip` device return identical bytes - the address space **mirrors at
2 MB**, so physical flash is 2 MB.

The two devices use different addressing, which is the key to the map:
- `beken_onchip_crc` - logical, CRC bytes stripped (32 data bytes per 34 physical)
- `beken_onchip`     - raw physical

    logical 0x120000 (end of bootloader+app) x 34/32 = physical 0x132000
                                                     = exactly where `download` starts

So the flash is fully accounted for:

    physical 0x000000 - 0x132000   bootloader + app, CRC-protected (logical 0x0-0x120000)
    physical 0x132000 - 0x1E0000   download, raw
    physical 0x1E0000 - 0x200000   unmapped tail (128 KB)

## dumps/app.bin - 1,114,112 bytes, 0 lines missing
Byte-perfect (0/69632 lines missing, 2 re-probes, 1828 s). The content is
**genuine, correctly-aligned ARM/Thumb code**:
    88.7% of ARM words carry condition nibble 0xE ("always")
    1637x `bx lr` (ARM), 618x `ldm..pc`, 740x `bx lr` (Thumb), 2384x Thumb prologues

But it contains **almost no strings**: `%s` x2, `%d` x5, `err` x0, longest
readable run 37 chars, and run boundaries are uniform mod 32 (so this is not
block-boundary corruption - the ASCII is incidental bytes inside code).
None of `RT-Thread`, `msh`, `statfs`, `xvideo`, `avsdk`, `pprpc`, `LLM_HA10`
appear. Do not go looking for protocol strings in app.bin - they are not there.

## dumps/download.bin - where the strings actually live
The `download` partition holds a full image *with* rodata. Sampling at physical
0x160000 gave 89.8% ASCII:

    live_type=%d, live_name=%s, live.f_desc=%s, live_value=%s
    avsdk_get_user_list, rc=

This is the avsdk stack's string table and the real reverse-engineering target.

## Why the camera keeps rebooting
Physical 0x1F8000, in the unmapped tail, is a persistent reboot log:

    reboot reason:DEV net abnormal, reboot time:1788083382346

It reboots itself when it cannot reach its cloud. That is a direct consequence of
the isolation, and it is what forced the dumper's re-probe logic (a reboot
silently drops the `fal` probed partition). Expect it to keep happening.
