# Disassemble a PE32 and dump the instructions around every call to DeviceIoControl, so we can read
# the IOCTL code and in/out buffer sizes (reveals any device memory/firmware read command).
# Read-only; the input exe is treated as data, never executed. Usage: python disasm_ioctl.py <exe>
import sys, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

b = open(sys.argv[1], "rb").read()
pe = struct.unpack_from("<I", b, 0x3C)[0]
nsec = struct.unpack_from("<H", b, pe+6)[0]
optsz = struct.unpack_from("<H", b, pe+20)[0]
magic = struct.unpack_from("<H", b, pe+24)[0]
imagebase = struct.unpack_from("<I", b, pe+24+28)[0]
sectab = pe+24+optsz
secs=[]
for i in range(nsec):
    h=sectab+i*40
    name=b[h:h+8].split(b"\0")[0].decode("latin1")
    vsize,va,rsize,raw=struct.unpack_from("<IIII", b, h+8)
    secs.append((name,va,vsize,raw,rsize))

def rva2off(rva):
    for name,va,vsize,raw,rsize in secs:
        if va<=rva<va+max(vsize,rsize): return raw+(rva-va)
    return None

# Import table (data dir entry 1)
dd = pe+24+(96 if magic==0x10b else 112)
imp_rva, imp_size = struct.unpack_from("<II", b, dd+1*8)
iat_names={}  # IAT slot VA -> name
off=rva2off(imp_rva)
while True:
    oft,tds,fc,name_rva,ft = struct.unpack_from("<IIIII", b, off)
    if oft==0 and name_rva==0 and ft==0: break
    dllname=b[rva2off(name_rva):].split(b"\0")[0].decode("latin1")
    thunks = oft if oft else ft
    t=rva2off(thunks); slot=ft
    i=0
    while True:
        val=struct.unpack_from("<I", b, t+i*4)[0]
        if val==0: break
        if not (val & 0x80000000):
            fname=b[rva2off(val)+2:].split(b"\0")[0].decode("latin1")
            iat_names[imagebase+ft+i*4]=fname
        i+=1
    off+=20

dioc = [va for va,nm in iat_names.items() if nm=="DeviceIoControl"]
print("DeviceIoControl IAT slot(s):", [hex(x) for x in dioc])
if not dioc: sys.exit()
dioc=set(dioc)

# Disassemble .text
text=[s for s in secs if s[0]==".text"][0]
code=b[text[3]:text[3]+text[4]]
base=imagebase+text[1]
md=Cs(CS_ARCH_X86, CS_MODE_32); md.detail=True
insns=list(md.disasm(code, base))
# index by address for backward window
for i,ins in enumerate(insns):
    if ins.mnemonic=="call" and ins.op_str.startswith("dword ptr ["):
        try: tgt=int(ins.op_str.split("[")[1].rstrip("]"),16)
        except: continue
        if tgt in dioc:
            print(f"\n=== DeviceIoControl call @0x{ins.address:X} ===")
            for j in range(max(0,i-14), i+1):
                print(f"   {insns[j].address:08X}  {insns[j].mnemonic:7s} {insns[j].op_str}")
