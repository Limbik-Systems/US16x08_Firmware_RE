# Parse Qt resource name + struct tables to resolve :/res/update.bin to its data offset/length.
# Read-only. Usage: python -I qrctree.py <exe> <out_dir>
import sys, os, struct

data = open(sys.argv[1], "rb").read()
outdir = sys.argv[2]; os.makedirs(outdir, exist_ok=True)

# Name table: records are [u16 BE namelen][u32 BE hash][name UTF-16BE]. Find all names.
names = {}  # file-offset of record start -> (name, namelen)
i = 0
targets = {}
for word in (b"res", b"update.bin"):
    u = word.decode().encode("utf-16-be")
    off = data.find(u)
    if off >= 0:
        rec = off - 6
        nl = struct.unpack(">H", data[rec:rec+2])[0]
        targets[word.decode()] = (rec, off, nl)
        print(f"name '{word.decode()}' text@{off:X} rec@{rec:X} namelen={nl}")

# qt_resource_name base: the record offsets are stored in struct as (nameoffset) relative to name base.
# Heuristic: name base = offset of the FIRST name record. Find earliest name record among known Qt names.
name_base = min(rec for rec,_,_ in targets.values())
print(f"assumed name_base ~ {name_base:X}")

# Walk the data table: it's packed [BE u32 len][bytes]. Find its start by trying the region after
# the struct/names. We instead brute force: for each known plausible data-table start, walk and see if
# records tile until we hit the update.bin-sized one. Simpler: scan for a record whose len is 100KB-400KB
# AND whose (start-? ) ... just dump the single best by walking from several starts.

# Pragmatic: the data table usually sits lower in .rdata than names. Walk from a set of starts and
# collect any record of size >= 0x8000; report the largest contiguous-valid chain.
def walk(start, limit=0x45000):
    recs = []
    p = start
    while p < limit - 4:
        L = struct.unpack(">I", data[p:p+4])[0]
        if L == 0 or p + 4 + L > len(data) or L > 0x60000:
            break
        recs.append((p, L))
        p += 4 + L
        if len(recs) > 12: break
    return recs, p

best = None
for start in range(0xFA00, 0x16000, 4):
    recs, end = walk(start)
    total = sum(L for _, L in recs)
    big = [r for r in recs if r[1] >= 0x8000]
    if big and total > (best[0] if best else 0) and len(recs) >= 1:
        # require the chain to tile at least 3 records or cover a big blob cleanly
        if len(recs) >= 2 or big[0][1] > 0x20000:
            best = (total, start, recs)

if best:
    total, start, recs = best
    print(f"best data-table start={start:X} records={len(recs)} total={total}")
    for p, L in recs:
        tag = "update.bin?" if L >= 0x20000 else ""
        print(f"  rec@{p:X} len={L} head={data[p+4:p+4+12].hex(' ')} {tag}")
    # dump the largest
    p, L = max(recs, key=lambda r: r[1])
    path = os.path.join(outdir, "update.bin")
    open(path, "wb").write(data[p+4:p+4+L])
    print(f"wrote {path} ({L} bytes)")
else:
    print("no clean data-table chain found")
