# Minimal Analog Devices Blackfin (ADSP-BF5xx) disassembler — iterative, for firmware RE.
# Length rule is exact (4 bytes if first halfword >= 0xC000 else 2), so alignment is always correct;
# opcodes we don't decode yet print as raw .hword/.word. Little-endian.
# Usage: python bfdis.py <binfile> <start_off_hex> <count> [base_va_hex]
import sys

data = open(sys.argv[1], "rb").read()
start = int(sys.argv[2], 16)
count = int(sys.argv[3])
base = int(sys.argv[4], 16) if len(sys.argv) > 4 else 0   # VA of file offset 0 of the slice's region
# We treat the payload as loaded at address = (file_off - payload_start0) ; caller passes base to map.

def u16(o): return data[o] | (data[o+1] << 8)
def sext(v, bits): return v - (1 << bits) if v & (1 << (bits-1)) else v

DREG = [f"R{i}" for i in range(8)]
PREG = ["P0","P1","P2","P3","P4","P5","SP","FP"]

def decode(off, addr):
    iw0 = u16(off)
    length = 4 if (iw0 & 0xC000) == 0xC000 else 2
    iw1 = u16(off+2) if length == 4 and off+3 < len(data) else 0
    txt = None; tgt = None

    if length == 2:
        hi = iw0 >> 8
        if hi == 0x00:  # ProgCtrl
            f = (iw0 >> 4) & 0xF; r = iw0 & 0xF
            if iw0 == 0x0000: txt = "NOP"
            elif f == 1: txt = ["RTS","RTI","RTX","RTN","RTE"][r] if r < 5 else f"RT? {r}"
            elif f == 2: txt = {0:"IDLE",3:"CSYNC",4:"SSYNC",5:"EMUEXCPT"}.get(r, f"sync? {r}")
            elif f == 3: txt = f"CLI R{r}"
            elif f == 4: txt = f"STI R{r}"
            elif f == 5: txt = f"JUMP ({PREG[r]})"
            elif f == 6: txt = f"CALL ({PREG[r]})"
            elif f == 7: txt = f"JUMP (PC + {PREG[r]})"
            elif f == 8: txt = f"RAISE {r}"
            elif f == 9: txt = f"EXCPT {r}"
            elif f == 0xA: txt = f"TESTSET ({PREG[r]})"
        elif (iw0 & 0xF800) == 0x1800:  # BRCC: IF [!]CC JUMP pcrel
            T = (iw0 >> 10) & 1
            off10 = sext(iw0 & 0x3FF, 10) * 2
            tgt = addr + off10
            txt = f"IF {'' if T else '!'}CC JUMP 0x{tgt:X}"
        elif (iw0 & 0xF000) == 0x2000:  # UJUMP: JUMP.S pcrel
            off12 = sext(iw0 & 0xFFF, 12) * 2
            tgt = addr + off12
            txt = f"JUMP.S 0x{tgt:X}"
        elif (iw0 & 0xFC00) == 0x3000:  # REGMV (guess): 0011 00 ss sdd ddd  reg move
            # low 3 bits dst, next 3 src, group bits — tentative; label loosely
            pass
    else:  # 32-bit
        hi = iw0 >> 8
        if hi in (0xE2, 0xE3):  # CALLa (E3) / JUMP.L (E2) pcrel25 (to validate)
            raw = ((iw0 & 0xFF) << 16) | iw1
            tgt = addr + sext(raw, 24) * 2
            txt = f"{'CALL' if hi==0xE3 else 'JUMP.L'} 0x{tgt:X}"
        elif hi == 0xE1:  # LDImmHalf: reg.(L|H) = imm16
            grp = (iw0 >> 3) & 7; H = (iw0 >> 6) & 1; reg = iw0 & 7
            rn = (DREG[reg] if grp==0 else PREG[reg] if grp==1 else f"g{grp}r{reg}")
            txt = f"{rn}.{'H' if H else 'L'} = 0x{iw1:04X}"
        elif hi == 0xE0:  # LDImm (full) / LoopSetup region — tentative
            pass

    raw = data[off:off+length]
    rawhex = raw.hex(' ')
    return length, txt, tgt, rawhex

off = start; addr = base + 0  # address mapping: caller sets base to addr of 'start'
# Actually map: addr at 'off' = base; increments by length.
addr = base
o = start
end = start + 1
# We iterate 'count' instructions
known = 0; tgts_in = 0; tgts_tot = 0
for _ in range(count):
    if o + 1 >= len(data): break
    length, txt, tgt, rawhex = decode(o, addr)
    mark = "   " if txt else " ??"
    disp = txt if txt else (f".word 0x{u16(o)|(u16(o+2)<<16):08X}" if length==4 else f".hword 0x{u16(o):04X}")
    if txt: known += 1
    if tgt is not None:
        tgts_tot += 1
        if base <= tgt < base + (len(data)-start): tgts_in += 1
    print(f"{addr:06X}: {rawhex:<12}{mark} {disp}")
    o += length; addr += length
print(f"\n-- decoded {known}/{count} known; branch/call targets in-range {tgts_in}/{tgts_tot}")
