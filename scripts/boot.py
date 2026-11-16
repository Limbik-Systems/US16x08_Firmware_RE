# Analyze the firmware boot/block structure. Read-only.
import sys, struct
b = open(sys.argv[1], "rb").read()
P = 0x20  # payload start (after 32-byte TASCAM header)
def w(o): return struct.unpack_from("<I", b, o)[0]

print(f"file size 0x{len(b):X}; payload 0x{P:X}..0x{len(b):X}")
print("\n=== first 0x80 bytes as LE32 words ===")
for o in range(P, P+0x80, 16):
    print(f"{o:05X}: " + "  ".join(f"{w(o+i):08X}" for i in range(0,16,4)))

def is_addr(v):
    return (0xFF800000 <= v <= 0xFFFFFFFF) or (0 < v < 0x08000000)

print("\n=== all 4-byte-aligned address-like values in payload ===")
hits=[]
o=P
while o < len(b)-4:
    v=w(o)
    if is_addr(v): hits.append((o,v))
    o+=4
# show the ones in the first 0x400 (likely the table) and overall count
print(f"total address-like aligned values: {len(hits)}")
print("first 24 (offset -> value):")
for o,v in hits[:24]:
    print(f"  {o:05X} -> {v:08X}")

print("\n=== positions of 0xFFC00000 ===")
for o,v in hits:
    if v==0xFFC00000: print(f"  {o:05X}")

# Try tiling as [flags(4)][addr(4)][count(4)][arg(4)] + count bytes (pad to 4)
print("\n=== try LDR-ish tiling from 0x20: [flags][addr][count][arg] + count data ===")
o=P; n=0
while o+16 <= len(b) and n < 20:
    flags,addr,count,arg = w(o),w(o+4),w(o+8),w(o+12)
    ok = is_addr(addr) and count <= len(b)
    print(f"  @{o:05X} flags={flags:08X} addr={addr:08X} count={count:8d}(0x{count:X}) arg={arg:08X} {'OK' if ok else 'BAD-ADDR'}")
    if not ok: break
    o = o + 16 + ((count + 3) & ~3)
    n += 1
print(f"  ended at 0x{o:X} (image end 0x{len(b):X})")
