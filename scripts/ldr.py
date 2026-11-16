# Parse an Analog Devices Blackfin .ldr boot stream. Supports the new 16-byte block header
# (BF52x/BF54x: block code dword with HDRSGN=0xAD in MSB, target addr, byte count, argument).
# Searches the given file for the first valid header, then walks the block chain. Read-only.
# Usage: python -I ldr.py <file> [search_limit]
import sys, struct

data = open(sys.argv[1], "rb").read()
n = len(data)

BFLAG = {0x0001:"ZEROFILL",0x0002:"RESVECT",0x0008:"INIT",0x0010:"IGNORE",
         0x0020:"FIRST",0x0040:"FINAL",0x0080:"AUX",0x0100:"SAVE",0x8000:"FILL"}

def flags(f):
    return "|".join(v for k,v in BFLAG.items() if f & k) or "-"

def valid_header(p):
    if p+16 > n: return None
    code, addr, count, arg = struct.unpack_from("<IIII", data, p)
    if (code >> 24) != 0xAD: return None           # HDRSGN
    if count > 0x200000: return None               # sane block size
    # target addr: Blackfin L1 (0xFFxxxxxx), SDRAM (0x0000_0000..0x07FF_FFFF), async (0x2000_0000..)
    hi = addr >> 24
    if not (hi==0xFF or addr < 0x08000000 or 0x20000000 <= addr <= 0x2FFFFFFF): return None
    return code, addr, count, arg

# find first header
start=None
for p in range(0, min(n, int(sys.argv[2]) if len(sys.argv)>2 else n)):
    h=valid_header(p)
    if h and (h[0] & 0x20):   # BFLAG_FIRST set on the first block
        start=p; break
if start is None:
    # fall back: first valid header at all
    for p in range(0, n):
        if valid_header(p): start=p; break

if start is None:
    print("no Blackfin LDR block header found"); sys.exit()

print(f"first block header at file offset 0x{start:X}")
p=start; idx=0; regions={}
while p+16<=n:
    h=valid_header(p)
    if h is None:
        print(f"  [stop: non-header at 0x{p:X}: {data[p:p+16].hex(' ')}]"); break
    code,addr,count,arg=h
    f=(code>>0)&0xFFFF
    fill = f & 0x8000
    payload = 0 if fill else count
    reg = "L1" if (addr>>24)==0xFF else ("SDRAM" if addr<0x08000000 else "ASYNC")
    regions[reg]=regions.get(reg,0)+count
    if idx<24:
        print(f"  #{idx:3d} @0x{p:06X} addr=0x{addr:08X} count={count:7d} arg=0x{arg:08X} flags={flags(f)} [{reg}]")
    p += 16 + payload
    idx+=1
    if f & 0x0040:  # FINAL
        print(f"  #{idx-1}: FINAL block — image ends at 0x{p:X}")
        break
print(f"blocks={idx} image_end=0x{p:X} (carved size 0x{n:X})")
print("bytes per region:", {k:f'{v} ({v/1024:.1f}KB)' for k,v in regions.items()})
