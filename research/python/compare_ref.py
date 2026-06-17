"""Cal RAM dump vs referencia fájl összehasonlítás.

Beolvassa a dump_01.json-t, kiszedi a Cal RAM régió HIGH byte-jait,
és összehasonlítja a referencia fájl mindkét felével.
"""

import json
from pathlib import Path

DUMP_JSON = Path(r'C:\Users\Mate\Desktop\teszt\FW\dump_20260611_224909\dump_01.json')
REF_BIN   = Path(r'C:\Users\Mate\Desktop\teszt\FRAM\image_gpib olvasott.bin')
CAL_START = 0x060000
CAL_END   = 0x061000  # 2KB régió: 0x060000–0x060FFF

# --- betöltés ---
dump = json.loads(DUMP_JSON.read_text())['data']
ref  = REF_BIN.read_bytes()

print(f'Referencia fájl mérete: {len(ref)} bájt')
print(f'Dump bejegyzések száma: {len(dump)}')

# Cal RAM HIGH byte-ok kinyerése (cím szerint rendezve)
cal_entries = sorted(
    (int(addr, 16), val)
    for addr, val in dump.items()
    if CAL_START <= int(addr, 16) < CAL_END
)

print(f'Cal RAM WORD-ök a dumpban: {len(cal_entries)}')

if not cal_entries:
    print('HIBA: Nincs Cal RAM bejegyzés a dumpban!')
    raise SystemExit(1)

# HIGH byte kinyerés (& 0xFFFF maszk a negatív signed értékekhez)
high_bytes = bytes((val & 0xFFFF) >> 8 for _, val in cal_entries)

print(f'HIGH byte-ok száma: {len(high_bytes)}')
print()

# --- összehasonlítás ---
def compare_range(label: str, dump_slice: bytes, ref_slice: bytes) -> bool:
    if len(dump_slice) != len(ref_slice):
        print(f'[{label}] Hossz eltér: dump={len(dump_slice)}, ref={len(ref_slice)}')
        return False
    if dump_slice == ref_slice:
        print(f'[{label}] EGYEZIK ({len(dump_slice)} bájt)')
        return True
    diffs = [(i, dump_slice[i], ref_slice[i])
             for i in range(len(dump_slice)) if dump_slice[i] != ref_slice[i]]
    print(f'[{label}] ELTÉR — {len(diffs)} különbség:')
    for i, d, r in diffs[:20]:
        print(f'  [{i:4d}] dump=0x{d:02X}  ref=0x{r:02X}')
    if len(diffs) > 20:
        print(f'  ... és még {len(diffs)-20} eltérés')
    return False

n = len(ref) // 2  # ref felének mérete

ok1 = compare_range('ref[0:1024]    vs dump HIGH[0:1024]',    high_bytes[:n],  ref[:n])
ok2 = compare_range('ref[1024:2048] vs dump HIGH[1024:2048]', high_bytes[n:],  ref[n:])

print()
if ok1 and ok2:
    print('ÖSSZESÍTÉS: A dump HIGH byte-ok TELJES EGYEZÉS a referenciával.')
    print('A dump teljes Cal RAM tartalmát tartalmazza.')
elif ok1:
    print('ÖSSZESÍTÉS: Csak az első fél egyezik. Második fél eltér — vizsgálni kell.')
else:
    print('ÖSSZESÍTÉS: Sem az első, sem a második fél nem egyezik. Ellenőrizd a régiót.')
