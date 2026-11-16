# Find direct CALL sites to a target VA in a PE32 .text and disassemble the N instructions before
# each (to see the arguments pushed). Read-only. Usage: python xref.py <exe> <targetVA hex> [ctx]
import sys, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
b=open(sys.argv[1],"rb").read(); target=int(sys.argv[2],16); ctx=int(sys.argv[3]) if len(sys.argv)>3 else 18
pe=struct.unpack_from("<I",b,0x3C)[0]; nsec=struct.unpack_from("<H",b,pe+6)[0]
optsz=struct.unpack_from("<H",b,pe+20)[0]; imagebase=struct.unpack_from("<I",b,pe+24+28)[0]
sectab=pe+24+optsz
for i in range(nsec):
    h=sectab+i*40; name=b[h:h+8].split(b"\0")[0].decode("latin1")
    vsize,va,rsize,raw=struct.unpack_from("<IIII",b,h+8)
    if name==".text": tva,traw,trsz=va,raw,rsize
code=b[traw:traw+trsz]; base=imagebase+tva
md=Cs(CS_ARCH_X86,CS_MODE_32)
insns=list(md.disasm(code, base))
addr_idx={ins.address:i for i,ins in enumerate(insns)}
sites=[]
for i,ins in enumerate(insns):
    if ins.mnemonic=="call" and ins.op_str.startswith("0x"):
        try:
            if int(ins.op_str,16)==target: sites.append(i)
        except: pass
print(f"call sites to 0x{target:X}: {len(sites)}")
for i in sites:
    print(f"\n--- caller @0x{insns[i].address:X} ---")
    for j in range(max(0,i-ctx), i+1):
        print(f"   {insns[j].address:08X}  {insns[j].mnemonic:7s} {insns[j].op_str}")
