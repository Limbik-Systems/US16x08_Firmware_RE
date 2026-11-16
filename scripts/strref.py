# Find instructions in .text that reference a target VA (or VA range) as an imm32, and disassemble
# a window around each. Read-only. Usage: python strref.py <exe> <lo_va> <hi_va> [ctx_before] [ctx_after]
import sys, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
b=open(sys.argv[1],"rb").read(); lo=int(sys.argv[2],16); hi=int(sys.argv[3],16)
cb=int(sys.argv[4]) if len(sys.argv)>4 else 6; ca=int(sys.argv[5]) if len(sys.argv)>5 else 22
pe=struct.unpack_from("<I",b,0x3C)[0]; nsec=struct.unpack_from("<H",b,pe+6)[0]
optsz=struct.unpack_from("<H",b,pe+20)[0]; imagebase=struct.unpack_from("<I",b,pe+24+28)[0]; sectab=pe+24+optsz
for i in range(nsec):
    h=sectab+i*40; name=b[h:h+8].split(b"\0")[0].decode("latin1")
    vsize,va,rsize,raw=struct.unpack_from("<IIII",b,h+8)
    if name==".text": tva,traw,trsz=va,raw,rsize
code=b[traw:traw+trsz]; base=imagebase+tva
md=Cs(CS_ARCH_X86,CS_MODE_32); md.detail=True
insns=list(md.disasm(code,base))
hits=[]
for i,ins in enumerate(insns):
    # look for imm32 operands in range (in op_str as 0x...)
    for tok in ins.op_str.replace(',',' ').split():
        if tok.startswith("0x"):
            try: v=int(tok,16)
            except: continue
            if lo<=v<=hi: hits.append(i); break
print(f"refs in [{lo:X},{hi:X}]: {len(hits)}")
seen=set()
for i in hits:
    fstart=max(0,i-cb)
    if fstart in seen: continue
    seen.add(fstart)
    print(f"\n--- @0x{insns[i].address:X} ---")
    for j in range(fstart, min(len(insns), i+ca)):
        print(f"   {insns[j].address:08X}  {insns[j].mnemonic:8s} {insns[j].op_str}")
