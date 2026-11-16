# US-16x08 Firmware — Reverse-Engineering Notes & Tools

Read-only reverse engineering of TASCAM's official **US-16x08 firmware updater** (`us-16x08_firmware_2.00.exe`), done to find out whether missing DSP features (a per-channel noise gate, real direct-outs/aux sends) could be added by patching the firmware.

**Bottom line: no.** The firmware-update image contains **no executable code** — it is DSP data only. The mixer program lives in the chip's on-chip ROM, so it can't be modified by patching the update file. See [Conclusion](#conclusion).

> Companion to the control-surface app: **[US16x08_Panel](https://github.com/Limbik-Systems/US16x08_Panel)**.
>
> **No proprietary binaries are in this repo.** TASCAM's firmware image, the firmware/driver updater executables, and the GPL binutils sources are all excluded (see [.gitignore](.gitignore)). You supply your own copies to reproduce the analysis. Nothing here was ever written to a device — all analysis is read-only.

---

## What was investigated

The goal was to evaluate modifying the Blackfin DSP firmware to add features the hardware lacks (confirmed absent: any gate/expander; per-channel direct-outs/aux sends). The investigation covered the updater, the image format, the processor/ISA, and the flashing protocol.

### The updater & image
- `us-16x08_firmware_2.00.exe` is a 7-Zip SFX, **Authenticode-signed by TEAC** (valid). Inside is a Qt 5 GUI app (`us-16x08_firmware.exe`, 32-bit i386, unsigned) plus Qt DLLs.
- The firmware image is a Qt resource `:/res/update.bin`, extracted **exactly** (not carved) by parsing the Qt resource tables (`qRegisterResourceData`) — file node at data offset 0, flags `0x0` (**uncompressed**), **178,208 bytes**. (An earlier 257,216-byte "carve" was a false positive.)
- **Container layout** (`update.bin`, a TASCAM wrapper — *not* a raw ADI `.ldr`):

  | Offset | Bytes | Meaning |
  |--------|-------|---------|
  | `0x00` | `US-16x08\0` | magic |
  | `0x09` | `C8 00` | `0x00C8` = 200 = v2.00 |
  | `0x0C` | `07 E0 08 16` | build date 2016-08-22 |
  | `0x10` | `00 F5 3A FD` | **header checksum** (the "Hardware checksum" the updater verifies; algorithm not recovered) |
  | `0x14` | `00 02 B8 20` | `178208` = total size |
  | `0x18`–`0x1F` | zero | — |
  | `0x20`+ | — | payload (entropy ~6.4, uncompressed, unencrypted) |
  | end | `00 4A A5 43` | trailer, likely an image CRC, distinct from the header checksum |

### Processor
- **Analog Devices Blackfin** (confirmed). Image is 32-bit-word-structured, `0x68`-heavy, with `0xFFC00000` L1/MMR address references (appears 8×). No ASCII strings anywhere. Not ARM Cortex-M (no valid vector table).

### Flashing protocol (from disassembling the updater's x86 with capstone)
- Flashing goes through **TASCAM's own driver via vendor IOCTL `0x222000`** — the *same* channel the mixer panel uses (`TascamHardwareService`), **not** standard USB DFU.
- The real `bRequest` is the byte at request-struct `+0xF`: **`0x1D` write / `0x1E` read** (same as the mixer); the `0x17` seen at `+8` is a fixed USB field, not a flash opcode.
- **No addressable/bulk flash read exists** in the updater: the single read wrapper always sends `wValue=0, wIndex=0` and returns a fixed ≤64-byte status/checksum block. So the protocol is **write + small fixed read-back only** — there is **no software route to dump the running firmware**.
- The device verifies a checksum (mismatch → "Hardware checksum is not equal to firmware" / "Please turn the device's power on again"), suggesting a bootloader that survives a bad main-image flash (recovery path, unconfirmed).

## Conclusion

Using an **authoritative Blackfin disassembler** (binutils `bfin-dis.c`, compiled standalone — see [`disassembler/`](disassembler/)):

- **Zero genuine `LINK` stack-frame instructions** in the whole 178 KB. Compiled Blackfin C emits `LINK`/`UNLINK` per function, so real code would show many.
- Every region examined (`0x20`, `0xA000`, `0x11000`, `0x16000`, `0x15000`) disassembles as incoherent garbage (scattered `ILLEGAL`, nonsensical ops like `RETS=R4`, `A0.X=P1`, `EXCPT`) — i.e. **data mis-decoded as instructions**.
- Not compressed (entropy ~6.4), not byte-swapped (swapping *raises* the illegal-instruction rate).

So `update.bin` is **DSP data** — coefficient / preset / lookup tables (consistent with the ratio/pan/attack tables mirrored in the panel's `MixerModels.cs`), config, possibly USB descriptors — **not** the mixer program.

**Therefore a gate (or any DSP change) cannot be added by patching this firmware update.** The mixer algorithm is in on-chip ROM (or loaded at runtime from somewhere other than this file). The only theoretical route left is a **JTAG / boundary-scan dump of the live device** to study RAM/ROM-resident code — hardware access, uncertain payoff (ROM isn't persistently modifiable; RAM patches don't survive reboot). That route is **parked**.

## Repository contents

```
scripts/        Our read-only analysis tools (Python + PowerShell):
                  qt_extract.py   extract :/res/update.bin from the updater via Qt resource tables
                  boot.py         analyze the container/boot header & address-like words
                  entropy.py      windowed entropy (compression/encryption check)
                  findcode.py     scan for Blackfin code markers (LINK/CALL/RTS)
                  carve.py / extract_qrc.py / qrctree.py   Qt resource carving/inspection
                  disasm_range.py / disasm_ioctl.py / bfdis.py   disassembly helpers
                  ldr.py / ldrscan.py   ADI .ldr block-stream probing
                  find_reg.py / xref.py / strref.py / strings.ps1 / peinfo.ps1 / period.py / analyze.py
disassembler/   main.c + sysdep.h + disassemble.h — a tiny standalone wrapper around
                binutils' bfin-dis.c (the GPL source itself is NOT included; fetch + build below)
```

## Reproducing

All inputs are things you must supply yourself (none are redistributed here):

1. **Extract the image.** Put your own `us-16x08_firmware_2.00.exe` somewhere and run `scripts/qt_extract.py` to produce `update.bin` (178,208 bytes).
2. **Build the disassembler.** Fetch the two authoritative GPL sources from sourceware and compile with the wrapper in `disassembler/`:
   - `binutils-gdb/opcodes/bfin-dis.c` → place as `bfin-dis.c`
   - `binutils-gdb/include/opcode/bfin.h` → place as `opcode/bfin.h`
   - With MSVC (from a `vcvars64` shell), in the `disassembler/` dir:
     ```
     cl /TC /I. main.c bfin-dis.c /Fe:bfdis.exe
     ```
   - Usage: `bfdis.exe <binfile> <start_off_hex> <count> <base_va_hex>` (start = file offset, base = the VA that offset maps to).
3. **Analyze.** Run the `scripts/` tools against your extracted `update.bin`.

> `bfin-dis.c` / `bfin.h` are GPL (part of GNU binutils) and `bfdis.exe` is a GPL-derived binary, so they are intentionally **not** committed here — the build step above reproduces them. Run any script that reads the downloaded updater/image in Python isolated mode caveats aside; the capstone-based updater scripts need the user site, so run those from the scripts dir without `-I`.

## Status

Closed/parked. The firmware-update-file route is a dead end for adding DSP features; reopen only with a JTAG/boundary-scan dump of a live device. All analysis was read-only — nothing was ever flashed or sent to hardware.
