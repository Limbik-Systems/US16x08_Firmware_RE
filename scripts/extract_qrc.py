# Scans a PE for zlib streams (Qt stores qrc data as big-endian uint32 uncompressed-size + zlib),
# decompresses each, and writes the largest few to an output dir. Read-only on the input.
# Usage: python -I extract_qrc.py <input_exe> <out_dir>
import sys, zlib, os, struct

inp, outdir = sys.argv[1], sys.argv[2]
os.makedirs(outdir, exist_ok=True)
with open(inp, "rb") as fh:
    data = fh.read()

found = []
i = 0
while True:
    i = data.find(b"\x78", i)
    if i < 0:
        break
    if i + 1 < len(data) and data[i + 1] in (0x01, 0x9C, 0xDA):
        try:
            d = zlib.decompressobj()
            out = d.decompress(data[i:i + 4_000_000])
            if len(out) >= 4096:
                # Qt prefixes the compressed blob with a 4-byte big-endian uncompressed size
                hdr = struct.unpack(">I", data[i - 4:i])[0] if i >= 4 else -1
                found.append((i, len(out), hdr, out))
        except Exception:
            pass
    i += 1

found.sort(key=lambda t: -t[1])
print(f"zlib streams >=4KB: {len(found)}")
for rank, (off, n, hdr, out) in enumerate(found[:8]):
    match = "OK" if hdr == n else f"hdr={hdr}"
    path = os.path.join(outdir, f"blob_{rank}_off{off:X}_{n}.bin")
    with open(path, "wb") as f:
        f.write(out)
    head = out[:16].hex(" ")
    print(f"#{rank} off={off:X} size={n} qtlen={match} head={head} -> {os.path.basename(path)}")
