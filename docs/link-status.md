# Serial link status (2026-08-30)

Chain: PC -> CH343 (COM5) -> ESP32-S3 bridge -> camera UART pads

## Verified working
- COM5 enumerates as `USB-Enhanced-SERIAL CH343`, opens cleanly, not held by another process.
- COM5 *is the ESP32-S3*, not a direct tap. Pulsing RTS (EN) makes it print its ROM banner:
  `ESP-ROM:esp32s3-20210327 / rst:0x1 (POWERON) / boot:0x8 (SPI_FAST_FLASH_BOOT)`
  then it loads and runs the flashed app (`entry 0x403c88b8`).

## Not working
- No camera data at any baud: 115200, 921600, 460800, 230400, 115200, 74880, 57600, 38400, 9600.
- Tried with and without DTR/RTS asserted, and with CR / CRLF / LF and a `help` command.
- After the ROM banner the bridge app emits only `\r\n` and nothing further.
  (The garbage seen at 921600/460800/230400/74880/57600 is just the 115200 ROM
  banner misread at the wrong rate - not camera traffic.)

## Conclusion
The PC-to-bridge half is healthy. Silence is on the ESP32-S3 <-> camera side:
camera unpowered/asleep, far-side wiring loose or TX/RX swapped, or the flashed
sketch is not currently a transparent passthrough.

## Next check
Run this, then power-cycle the camera to catch its boot log:

    python tools/camsh.py listen --secs 25
