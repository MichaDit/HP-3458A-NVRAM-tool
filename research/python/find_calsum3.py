"""Keresés seed=3-mal, start+end 16 byte eltolásig; és raw hex dump a határok körül."""
import struct
from pathlib import Path

data = (Path('dumps') / 'calram_20260614_171609.bin').read_bytes()

stored = {
    'Cal_Sum0': struct.unpack('>H', data[0x1BC:0x1BE])[0],
    'Cal_Sum1': struct.unpack('>H', data[0x59C:0x59E])[0],
    'Cal_Sum2': struct.unpack('>H', data[0x5C8:0x5CA])[0],
}

# Kumulatív összeg
cum = [0] * (len(data)+1)
for i, b in enumerate(data): cum[i+1] = cum[i] + b
def rsum(s, e): return (cum[e] - cum[s]) & 0xFFFF

nominal = [
    ('Cal_Sum0', 0x1BC, 0x000, 0x1BC),
    ('Cal_Sum1', 0x59C, 0x1BE, 0x59C),
    ('Cal_Sum2', 0x5C8, 0x59E, 0x5C8),
]

print('=== Kereses seed=3, ±16 byte hatarok korul ===')
for name, cs_off, nom_s, nom_e in nominal:
    sv = stored[name]
    print('%s stored=0x%04X:' % (name, sv))
    found = []
    for ds in range(-16, 17, 2):
        for de in range(-16, 17, 2):
            s = nom_s + ds
            e = nom_e + de
            if s < 0 or e > len(data) or s >= e: continue
            if (3 + rsum(s, e)) & 0xFFFF == sv:
                found.append((s, e))
    if found:
        for s, e in found:
            ds = s - nom_s; de = e - nom_e
            print('  TALALT: [0x%04X:0x%04X]  ds=%+d de=%+d' % (s, e, ds, de))
    else:
        print('  Nincs seed=3-mal ±16 bájton belül')
    print()

print('=== Implied seed az eredeti tartomanyokhoz ===')
for name, cs_off, s, e in nominal:
    sv = stored[name]
    bsum = rsum(s, e)
    iseed = (sv - bsum) & 0xFFFF
    print('%s: stored=0x%04X sum=0x%04X implied_seed=%d (0x%04X)' % (name, sv, bsum, iseed, iseed))

print()
print('=== Hex dump hatarok korul ===')
for label, off in [('Cal_Sum0 elott 8B', 0x1B4), ('Cal_Sum2 utan 8B', 0x5C8)]:
    hexline = ' '.join('%02X' % data[off+i] for i in range(16))
    print('  %s @ 0x%04X: %s' % (label, off, hexline))
