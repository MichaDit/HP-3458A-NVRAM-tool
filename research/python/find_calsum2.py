"""Atfogo Cal_Sum keresés: byte-sum és word-sum, start+end mindkettő változhat."""
import struct
from pathlib import Path

data = (Path('dumps') / 'calram_20260614_171609.bin').read_bytes()
N = len(data)  # 2048

stored = {
    'Cal_Sum0': struct.unpack('>H', data[0x1BC:0x1BE])[0],
    'Cal_Sum1': struct.unpack('>H', data[0x59C:0x59E])[0],
    'Cal_Sum2': struct.unpack('>H', data[0x5C8:0x5CA])[0],
}

# Kumulatív összegek (byte és word)
cum_b = [0] * (N+1)
for i, b in enumerate(data):
    cum_b[i+1] = cum_b[i] + b

# u16 word összeg (big-endian, csak páros indexre)
cum_w = [0] * (N//2+1)
for i in range(N//2):
    w = (data[i*2] << 8) | data[i*2+1]
    cum_w[i+1] = cum_w[i] + w

def byte_rsum(s, e): return (cum_b[e] - cum_b[s]) & 0xFFFF
def word_rsum(s, e):
    """s, e byte offset (meg kell lennie parosnak)."""
    assert s % 2 == 0 and e % 2 == 0
    return (cum_w[e//2] - cum_w[s//2]) & 0xFFFF

for name, cs_off in [('Cal_Sum0', 0x1BC), ('Cal_Sum1', 0x59C), ('Cal_Sum2', 0x5C8)]:
    sv = stored[name]
    print('%s stored=0x%04X  (cs_at=0x%04X):' % (name, sv, cs_off))

    # Kereses korlatok: a tartomany nem tartalmazhatja a checksum helyet
    # Tipikusan end <= cs_off
    # start a megfelelo elojzo checksum utan van:
    # Cal_Sum0: start ∈ [0x000, 0x1BC]
    # Cal_Sum1: start ∈ [0x1BC, 0x59C]
    # Cal_Sum2: start ∈ [0x59C, 0x5C8]
    if name == 'Cal_Sum0':
        s_range = range(0, cs_off+1, 2)
        e_range = range(0, cs_off+3, 2)
    elif name == 'Cal_Sum1':
        s_range = range(0x1BC, cs_off+1, 2)
        e_range = range(0x1BC, cs_off+3, 2)
    else:  # Cal_Sum2
        s_range = range(0x59C, cs_off+1, 2)
        e_range = range(0x59C, cs_off+3, 2)

    found = []
    for seed in range(256):
        for s in s_range:
            for e in e_range:
                if e <= s: continue
                # Byte sum
                if (seed + byte_rsum(s, e)) & 0xFFFF == sv:
                    found.append(('byte', seed, s, e))
                # Word sum (csak paros hatarok)
                if s % 2 == 0 and e % 2 == 0:
                    if (seed + word_rsum(s, e)) & 0xFFFF == sv:
                        found.append(('word', seed, s, e))

    # Szurjuk: inkabb a kis seedeket es "logikus" hatarrokat preferaljuk
    clean = [(t,sd,s,e) for t,sd,s,e in found if sd <= 16]
    print('  Eredmenyek (seed<=16): %d db' % len(clean))
    for t, sd, s, e in sorted(clean)[:20]:
        print('    %-4s seed=%3d  [0x%04X : 0x%04X]  (%d byte)' % (t, sd, s, e, e-s))
    if not clean and found:
        print('  Seed>16 talalt:')
        for t, sd, s, e in sorted(found, key=lambda x: x[1])[:5]:
            print('    %-4s seed=%3d  [0x%04X : 0x%04X]' % (t, sd, s, e))
    print()
