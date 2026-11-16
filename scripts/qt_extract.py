# Parse Qt resource arrays (struct/name/data) at known VAs and extract (decompress) update.bin.
# Read-only. Usage: python qt_extract.py <exe> <struct_va> <name_va> <data_va> <out_dir>
import sys, struct, zlib, os
b = open(sys.argv[1], "rb").read()
sv, nv, dv = int(sys.argv[2],16), int(sys.argv[3],16), int(sys.argv[4],16)
outdir = sys.argv[5]; os.makedirs(outdir, exist_ok=True)
pe = struct.unpack_from("<I", b, 0x3C)[0]; nsec = struct.unpack_from("<H", b, pe+6)[0]
optsz = struct.unpack_from("<H", b, pe+20)[0]; imagebase = struct.unpack_from("<I", b, pe+24+28)[0]
sectab = pe+24+optsz; secs=[]
for i in range(nsec):
    h=sectab+i*40; vsize,va,rsize,raw=struct.unpack_from("<IIII",b,h+8); secs.append((va,vsize,raw,rsize))
def off(va):
    rva=va-imagebase
    for va0,vs,raw,rs in secs:
        if va0<=rva<va0+max(vs,rs): return raw+(rva-va0)
    return None
so, no, do = off(sv), off(nv), off(dv)
print(f"file offsets: struct={so:X} name={no:X} data={do:X}")
print("struct bytes:", b[so:so+64].hex(' '))
print("name   bytes:", b[no:no+40].hex(' '))
print("data   head :", b[do:do+24].hex(' '))

# Name table: [u16 BE len][u32 BE hash][utf16-be name]. Map name-offset -> string.
def read_name(rel):
    p=no+rel; ln=struct.unpack_from(">H",b,p)[0]
    s=b[p+6:p+6+ln*2].decode("utf-16-be")
    return s
# Find update.bin's name-rel by scanning
names={}
p=no
while p < no+(dv-nv):
    ln=struct.unpack_from(">H",b,p)[0]
    if ln==0 or ln>64: break
    s=b[p+6:p+6+ln*2].decode("utf-16-be","replace")
    names[p-no]=s; p+=6+ln*2
print("names:", names)

# Try both struct node formats; find a file node whose name-offset maps to 'update.bin'.
upd_off = [k for k,v in names.items() if v=="update.bin"]
upd_off = upd_off[0] if upd_off else None
print("update.bin name-offset:", upd_off)

def extract(data_off, flags):
    p=do+data_off; ln=struct.unpack_from(">I",b,p)[0]; payload=b[p+4:p+4+ln]
    print(f"  data record @data+{data_off:X}: stored_len={ln} flags=0x{flags:X}")
    if flags & 0x01:  # zlib-compressed: [BE u32 uncompressed_len][zlib]
        ulen=struct.unpack_from(">I",payload,0)[0]
        out=zlib.decompress(payload[4:])
        print(f"  zlib: declared_ulen={ulen} got={len(out)}")
        return out
    if flags & 0x04:  # zstd
        import zstandard; out=zstandard.ZstdDecompressor().decompress(payload[4:]); return out
    return payload

# Walk struct as 14-byte nodes (v1) scanning for a node whose nameoffset==upd_off and not a dir
found=False
for nodesz in (14,):
    for base in range(so, so+64-10, 2):
        nameoff,flags = struct.unpack_from(">IH", b, base)
        if nameoff==upd_off and not (flags & 0x02):
            # file node: ... country(2) lang(2) dataoffset(4)
            dataoff = struct.unpack_from(">I", b, base+10)[0]
            print(f"file node @struct+{base-so:X}: nameoff={nameoff:X} flags=0x{flags:X} dataoff={dataoff:X}")
            out=extract(dataoff, flags)
            open(os.path.join(outdir,"update.bin"),"wb").write(out)
            print(f"WROTE update.bin: {len(out)} bytes, head={out[:16].hex(' ')}")
            found=True; break
    if found: break
if not found: print("file node not found with 14-byte format; dump above for manual parse")
