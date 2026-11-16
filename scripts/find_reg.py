# Find the qRegisterResourceData call in a PE32 and print its 4 pushed args (version, tree, name, data
# pointers). Those give the Qt resource arrays. Read-only. Usage: python find_reg.py <exe>
import sys, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
b = open(sys.argv[1], "rb").read()
pe = struct.unpack_from("<I", b, 0x3C)[0]
nsec = struct.unpack_from("<H", b, pe+6)[0]; optsz = struct.unpack_from("<H", b, pe+20)[0]
magic = struct.unpack_from("<H", b, pe+24)[0]; imagebase = struct.unpack_from("<I", b, pe+24+28)[0]
sectab = pe+24+optsz
secs=[]
for i in range(nsec):
    h=sectab+i*40; name=b[h:h+8].split(b"\0")[0].decode("latin1")
    vsize,va,rsize,raw=struct.unpack_from("<IIII",b,h+8); secs.append((name,va,vsize,raw,rsize))
def rva2off(rva):
    for n,va,vs,raw,rs in secs:
        if va<=rva<va+max(vs,rs): return raw+(rva-va)
    return None
# imports
dd=pe+24+(96 if magic==0x10b else 112)
imp_rva=struct.unpack_from("<I",b,dd+1*8)[0]; off=rva2off(imp_rva); iat={}
while True:
    oft,tds,fc,nrva,ft=struct.unpack_from("<IIIII",b,off)
    if oft==0 and nrva==0 and ft==0: break
    thunks=oft if oft else ft; t=rva2off(thunks); i=0
    while True:
        val=struct.unpack_from("<I",b,t+i*4)[0]
        if val==0: break
        if not(val&0x80000000):
            fn=b[rva2off(val)+2:].split(b"\0")[0].decode("latin1")
            iat[imagebase+ft+i*4]=fn
        i+=1
    off+=20
reg=[va for va,nm in iat.items() if "RegisterResourceData" in nm]
print("qRegisterResourceData IAT:", [hex(x) for x in reg], [iat[x] for x in reg])
reg=set(reg)
text=[s for s in secs if s[0]==".text"][0]; code=b[text[3]:text[3]+text[4]]; base=imagebase+text[1]
md=Cs(CS_ARCH_X86,CS_MODE_32); insns=list(md.disasm(code,base))
for i,ins in enumerate(insns):
    if ins.mnemonic=="call" and ins.op_str.startswith("dword ptr ["):
        try: tgt=int(ins.op_str.split("[")[1].rstrip("]"),16)
        except: continue
        if tgt in reg:
            print(f"\ncall @0x{ins.address:X}")
            for j in range(max(0,i-10),i+1):
                print(f"   {insns[j].address:08X}  {insns[j].mnemonic:7s} {insns[j].op_str}")
