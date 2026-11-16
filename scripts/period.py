# Detect repeating-key obfuscation and inspect block structure. Read-only.
# Usage: python -I period.py <blob>
import sys, collections
b = open(sys.argv[1],"rb").read(); n=len(b)

# Autocorrelation: for small lags, count byte equality b[i]==b[i+lag]. A spike => repeating period.
print("lag : match%  (spikes = repeating structure/key)")
best=[]
for lag in range(1,65):
    m=sum(1 for i in range(0,min(n-lag,60000)) if b[i]==b[i+lag])
    pct=100*m/min(n-lag,60000)
    best.append((pct,lag))
    if pct>8: print(f"  {lag:3d}: {pct:5.1f}%")
best.sort(reverse=True)
print("top lags:", [(l,f'{p:.1f}%') for p,l in best[:6]])

# Look at first 64 bytes and a middle chunk as hex
print("head 64:", b[:64].hex(' '))
print("mid  48:", b[n//2:n//2+48].hex(' '))

# Count 4-byte aligned words that are 0 (padding) to see structure
import struct
zeros=sum(1 for i in range(0,n-4,4) if b[i:i+4]==b'\x00\x00\x00\x00')
print(f"zero dwords: {zeros} of {n//4}")
