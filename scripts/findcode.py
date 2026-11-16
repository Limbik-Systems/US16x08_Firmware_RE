# Scan raw image for genuine Blackfin code markers. Read-only.
import sys, struct
b = open(sys.argv[1], "rb").read()
def h16(o): return b[o] | (b[o+1]<<8)

links=[]; callp=[]; rts=[]; unlink=[]
for i in range(0x20, len(b)-4, 2):
    iw0 = h16(i)
    # LINK: iw0 == 0xE800, iw1 = framesize (small in real code)
    if iw0 == 0xE800:
        iw1 = h16(i+2)
        if iw1 <= 0x400: links.append((i, iw1))
    elif iw0 == 0xE801:
        unlink.append(i)
    # CALL (Preg): 0x0060..0x0067
    elif 0x0060 <= iw0 <= 0x0067:
        callp.append((i, iw0 & 7))
    # RTS
    elif iw0 == 0x0010:
        rts.append(i)

print(f"real LINK (framesize<=0x400): {len(links)}")
for o,fs in links[:20]: print(f"   {o:05X}  LINK 0x{fs:X}")
print(f"UNLINK (0xE801): {len(unlink)} -> {[f'{o:05X}' for o in unlink[:20]]}")
print(f"CALL(Preg): {len(callp)}")
print(f"RTS (0x0010): {len(rts)}")
# cluster RTS positions into 0x1000 buckets to see code regions
from collections import Counter
c = Counter((o>>12) for o in rts)
print("RTS by 0x1000 bucket:", {f'{k:X}000':v for k,v in sorted(c.items()) if v>=2})
c2 = Counter((o>>12) for o,_ in callp)
print("CALL(P) by 0x1000 bucket:", {f'{k:X}000':v for k,v in sorted(c2.items()) if v>=2})
