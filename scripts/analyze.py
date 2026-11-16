# Characterize a firmware blob: overall + windowed entropy, printable strings, repeated structure,
# and a guess at ARM Cortex-M vector table (initial SP + reset vector plausibility). Read-only.
# Usage: python -I analyze.py <blob>
import sys, math, struct, collections

b = open(sys.argv[1], "rb").read()
n = len(b)
def ent(d):
    if not d: return 0
    c = collections.Counter(d); m=len(d)
    return -sum((v/m)*math.log2(v/m) for v in c.values())
print(f"size={n} ({n/1024:.1f} KB)  overall_entropy={ent(b):.2f}")

# windowed entropy, show min/max to see if uniformly high (encrypted) or mixed (code)
ents=[ent(b[i:i+4096]) for i in range(0,n,4096)]
print(f"win4k entropy: min={min(ents):.2f} max={max(ents):.2f} avg={sum(ents)/len(ents):.2f}")
print(f"low-entropy windows (<5.0): {sum(1 for e in ents if e<5.0)}/{len(ents)}")

# byte histogram top
hist=collections.Counter(b).most_common(6)
print("top bytes:", [(f'{k:02X}',v) for k,v in hist])

# printable ASCII strings >=5
import re
strings=re.findall(rb"[\x20-\x7e]{5,}", b)
print(f"ascii strings >=5: {len(strings)}")
for s in strings[:40]:
    print("   ", s.decode('latin1'))

# ARM Cortex-M vector table check: word0=initial SP (points to RAM, often 0x2000xxxx or 0x1000xxxx),
# word1=reset handler (odd = thumb). Check at offset 0 and a few.
for base in (0,):
    if n>=8:
        sp,reset=struct.unpack_from("<II",b,base)
        print(f"@{base}: SP=0x{sp:08X} reset=0x{reset:08X} thumb={'Y' if reset&1 else 'N'}")
# also big-endian interpretation
sp,reset=struct.unpack_from(">II",b,0)
print(f"BE@0: w0=0x{sp:08X} w1=0x{reset:08X}")
