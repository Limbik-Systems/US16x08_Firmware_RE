# Carve Qt resource payloads: scan .rdata for [BE uint32 length][data] records whose length
# is a plausible firmware size, dump each. Read-only on input.
# Usage: python -I carve.py <exe> <out_dir>
import sys, os, struct

data = open(sys.argv[1], "rb").read()
outdir = sys.argv[2]
os.makedirs(outdir, exist_ok=True)

# .rdata from peinfo: rawptr=0xFA00 rawsize=0x34C00
lo, hi = 0xFA00, 0xFA00 + 0x34C00
hits = []
i = lo
while i < hi - 4:
    L = struct.unpack(">I", data[i:i+4])[0]
    if 0x4000 <= L <= 0x60000 and i + 4 + L <= len(data):
        payload = data[i+4:i+4+L]
        # score: fraction of bytes that are not printable-ASCII and not 0x00 (firmware-ish)
        nz = sum(1 for b in payload[:4096] if b not in (0,))
        hits.append((i, L, payload))
    i += 4  # resource data table is 4-byte aligned

# keep the few largest, de-duplicated by overlap
hits.sort(key=lambda t: -t[1])
kept = []
for off, L, payload in hits:
    if any(abs(off - k[0]) < 0x1000 for k in kept):
        continue
    kept.append((off, L, payload))
    if len(kept) >= 6:
        break

print(f"candidate records: {len(hits)}, kept {len(kept)}")
for off, L, payload in kept:
    path = os.path.join(outdir, f"res_off{off:X}_{L}.bin")
    open(path, "wb").write(payload)
    print(f"off={off:X} len={L} head={payload[:24].hex(' ')}  -> {os.path.basename(path)}")
    print(f"        tail={payload[-16:].hex(' ')}")
