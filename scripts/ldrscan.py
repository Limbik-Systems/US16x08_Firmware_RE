# Find a Blackfin .ldr boot stream inside a file by locating a block-header chain that tiles
# correctly for many consecutive blocks. Tries new (16-byte, HDRSGN=0xAD) and old (10-byte) formats.
# Read-only. Usage: python -I ldrscan.py <file> [dump_out]
import sys, struct
data = open(sys.argv[1], "rb").read(); n=len(data)

def addr_ok(a):
    return (a>>24)==0xFF or a < 0x08000000 or 0x20000000 <= a <= 0x2FFFFFFF

def chain_new(start):
    p=start; blocks=0
    while p+16<=n:
        code,addr,count,arg=struct.unpack_from("<IIII",data,p)
        if (code>>24)!=0xAD: break
        if not addr_ok(addr) or count>0x200000: break
        fill = (code & 0x8000) != 0
        p += 16 + (0 if fill else count); blocks+=1
        if code & 0x0040: return blocks,p,True   # FINAL
        if blocks>4000: break
    return blocks,p,False

def chain_old(start):
    p=start; blocks=0
    while p+10<=n:
        addr,count,flags=struct.unpack_from("<IIH",data,p)
        if not addr_ok(addr) or count==0 or count>0x200000: break
        fill = (flags & 0x0001) != 0
        p += 10 + (0 if fill else count); blocks+=1
        if flags & 0x8000: return blocks,p,True
        if blocks>4000: break
    return blocks,p,False

best=None
for fmt,fn,step in (("new16",chain_new,4),("old10",chain_old,2)):
    for s in range(0, n-16, step):
        b,end,final=fn(s)
        if b>=8:
            score=(b, final)
            if best is None or b>best[1]:
                best=(fmt,b,s,end,final)
    if best:
        pass

if not best:
    print("no tiling Blackfin LDR chain (>=8 blocks) found in either format"); sys.exit()

fmt,b,s,end,final=best
print(f"BEST: format={fmt} blocks={b} start=0x{s:X} end=0x{end:X} final={final} size={end-s}")
# re-walk and summarize regions + first blocks
p=s; idx=0; regions={}
while idx<b and p+16<=n:
    if fmt=="new16":
        code,addr,count,arg=struct.unpack_from("<IIII",data,p); fill=(code&0x8000)!=0; hdr=16; fin=code&0x40
    else:
        addr,count,flags=struct.unpack_from("<IIH",data,p); fill=(flags&0x0001)!=0; arg=flags; hdr=10; fin=flags&0x8000
    reg="L1" if (addr>>24)==0xFF else ("SDRAM" if addr<0x08000000 else "ASYNC")
    regions[reg]=regions.get(reg,0)+count
    if idx<16: print(f"  #{idx:3d} @0x{p:06X} addr=0x{addr:08X} count={count:7d} {'FILL' if fill else ''} [{reg}]")
    p+=hdr+(0 if fill else count); idx+=1
    if fin: break
print("regions:", {k:f'{v/1024:.1f}KB' for k,v in regions.items()})
if len(sys.argv)>2:
    open(sys.argv[2],"wb").write(data[s:end]); print(f"dumped image to {sys.argv[2]} ({end-s} bytes)")
