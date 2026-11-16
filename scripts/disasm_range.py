# Disassemble a VA range of a PE32 .text, highlighting immediate stores (candidate command/bRequest
# bytes and USB setup fields). Read-only. Usage: python disasm_range.py <exe> <startVA hex> <endVA hex>
import sys, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
b=open(sys.argv[1],"rb").read()
start=int(sys.argv[2],16); end=int(sys.argv[3],16)
pe=struct.unpack_from("<I",b,0x3C)[0]; nsec=struct.unpack_from("<H",b,pe+6)[0]
optsz=struct.unpack_from("<H",b,pe+20)[0]; imagebase=struct.unpack_from("<I",b,pe+24+28)[0]
sectab=pe+24+optsz
for i in range(nsec):
    h=sectab+i*40; name=b[h:h+8].split(b"\0")[0].decode("latin1")
    vsize,va,rsize,raw=struct.unpack_from("<IIII",b,h+8)
    if name==".text":
        tva,traw,trsz=va,raw,rsize
code=b[traw:traw+trsz]; base=imagebase+tva
soff=start-base
md=Cs(CS_ARCH_X86,CS_MODE_32)
for ins in md.disasm(code[soff:soff+(end-start)], start):
    mark=""
    if ins.mnemonic in ("mov","push") and any(x in ins.op_str for x in ("byte ptr","0x")):
        mark=" <<" if ins.mnemonic=="mov" and "byte ptr" in ins.op_str else ""
    print(f"{ins.address:08X}  {ins.mnemonic:7s} {ins.op_str}{mark}")
