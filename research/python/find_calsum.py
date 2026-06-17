import struct
from pathlib import Path

data = (Path('dumps') / 'calram_20260614_171609.bin').read_bytes()
assert len(data) == 2048

stored_vals = {
    'Cal_Sum0': struct.unpack('>H', data[0x1BC:0x1BE])[0],
    'Cal_Sum1': struct.unpack('>H', data[0x59C:0x59E])[0],
    'Cal_Sum2': struct.unpack('>H', data[0x5C8:0x5CA])[0],
    'Cal_Sum3': struct.unpack('>H', data[0x624:0x626])[0],
}

cum = [0] * (len(data) + 1)
for i, b in enumerate(data):
    cum[i+1] = cum[i] + b

def rsum(s, e):
    return (cum[e] - cum[s]) & 0xFFFF

for name, cs_off in [('Cal_Sum0', 0x1BC), ('Cal_Sum1', 0x59C), ('Cal_Sum2', 0x5C8)]:
    stored = stored_vals[name]
    print('%s stored=0x%04X:' % (name, stored))
    found_any = False
    for seed in range(16):
        target = (stored - seed) & 0xFFFF
        full   = rsum(0, cs_off)
        need_p = (full - target) & 0xFFFF
        for s in range(0, cs_off + 1):
            if cum[s] & 0xFFFF == need_p:
                print('  seed=%d  start=0x%04X  end=0x%04X  (%d byte)' % (seed, s, cs_off, cs_off - s))
                found_any = True
    if not found_any:
        # Prob: end is not cs_off — try cs_off+2 (including the checksum bytes?)
        for seed in range(16):
            target = (stored - seed) & 0xFFFF
            for end in (cs_off + 2, cs_off - 2):
                full = rsum(0, end)
                need_p = (full - target) & 0xFFFF
                for s in range(0, min(cs_off, end) + 1):
                    if cum[s] & 0xFFFF == need_p:
                        print('  [alt_end=0x%04X] seed=%d  start=0x%04X  end=0x%04X  (%d byte)' % (end, seed, s, end, end - s))
    print()

s3 = (3 + rsum(0x5CA, 0x624)) & 0xFFFF
v3 = stored_vals['Cal_Sum3']
print('Cal_Sum3 check: computed=0x%04X stored=0x%04X  %s' % (s3, v3, 'OK' if s3 == v3 else 'HIBA'))
