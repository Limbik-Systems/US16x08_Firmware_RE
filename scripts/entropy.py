# Entropy map of a file in windows, plus locate the Qt ":/res/update.bin" resource name
# and any 4-byte-BE-length-prefixed blobs near big high-entropy regions. Read-only.
# Usage: python -I entropy.py <file>
import sys, math, struct

data = open(sys.argv[1], "rb").read()
win = 4096
print(f"file size={len(data)} ({len(data)/1024:.0f} KB)")

# Entropy per 8KB, print only transitions to keep output short
def ent(b):
    if not b: return 0
    from collections import Counter
    c = Counter(b); n = len(b)
    return -sum((v/n) * math.log2(v/n) for v in c.values())

prev = None
runs = []
step = 8192
for off in range(0, len(data), step):
    e = ent(data[off:off+step])
    band = round(e)
    if band != prev:
        runs.append((off, e))
        prev = band
for off, e in runs:
    print(f"  off={off:7X} entropy={e:.2f}")

# Find "update.bin" as ASCII and as UTF-16BE (Qt names are UTF-16BE)
for label, needle in [("ascii update.bin", b"update.bin"),
                      ("utf16be update.bin", "update.bin".encode("utf-16-be")),
                      ("ascii res", b"res"),
                      ("utf16be res", "res".encode("utf-16-be"))]:
    idx = data.find(needle)
    print(f"{label}: {'%X'%idx if idx>=0 else 'not found'}")
