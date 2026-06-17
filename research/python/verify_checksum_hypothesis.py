"""A cs.txt-ben felvetett checksum-hipotézis ellenőrzése több, független
cal_ram dumpon (saját + régi/külső műszerek dumpjai).

Két képletet hasonlítunk össze minden elérhető 2048-byte cal_ram dumpon:
  1. RÉGI: egy összefüggő tartomány + fix seed (CAL_SUM_DEFS).
  2. ÚJ (cs.txt hipotézis): több tartomány összege + "flag_count" maradék,
     amit minden dumpból visszafejtünk (stored - rangesum).

Ha a hipotézis helyes, a flag_count-nak STABILNAK kellene lennie (vagy
kevés diszkrét érték közül kerülne ki) FÜGGETLEN dumpok között is — nem
csak a saját, egymással rokon dumpjainkon.
"""
import struct
import sys
from pathlib import Path

DUMPS_DIR = Path(__file__).parent.parent / 'dumps'

# ── Régi képlet (jelenleg a programban: hp3458a_calram.py / hp3458a_instr.py) ──
OLD_DEFS = [
    ('CS0', 0x1BC, 0x000, 0x1BC, 0xEF62),
    ('CS1', 0x59C, 0x1BE, 0x59C, 0x1087),
    ('CS2', 0x5C8, 0x59E, 0x5C8, 0xFF13),
    ('CS3', 0x624, 0x5CA, 0x624, 0x0003),
]

# ── Új, cs.txt-ben javasolt "firmware-szerű" képlet ──────────────────────────
NEW_DEFS = [
    ('CS0', 0x1BC, [(0x000, 0x040), (0x060, 0x1BC)]),
    ('CS1', 0x59C, [(0x040, 0x060), (0x1C0, 0x59C)]),
    ('CS2', 0x5C8, [(0x5A0, 0x5C8)]),
    ('CS3', 0x624, [(0x5CA, 0x624)]),
]

# cs.txt szerint "tipikus" flag_count értékek
CS_TXT_CLAIMED_FLAGCOUNT = {'CS0': 56, 'CS1': 187, 'CS2': 11, 'CS3': 3}


def stored_u16(data: bytes, off: int) -> int:
    return struct.unpack('>H', data[off:off + 2])[0]


def old_seed_check(data: bytes):
    out = {}
    for name, off, start, end, seed in OLD_DEFS:
        stored = stored_u16(data, off)
        rsum = sum(data[start:end]) & 0xFFFF
        implied_seed = (stored - rsum) & 0xFFFF
        out[name] = (stored, rsum, implied_seed, implied_seed == seed)
    return out


def new_flagcount_check(data: bytes):
    out = {}
    for name, off, ranges in NEW_DEFS:
        stored = stored_u16(data, off)
        rsum = 0
        for s, e in ranges:
            rsum += sum(data[s:e])
        rsum &= 0xFFFF
        flag_count = (stored - rsum) & 0xFFFF
        out[name] = (stored, rsum, flag_count)
    return out


def main():
    files = sorted(DUMPS_DIR.glob('*.bin')) + sorted(DUMPS_DIR.glob('*.BIN'))
    files = [f for f in files if f.stat().st_size == 2048]
    if not files:
        print(f'Nincs 2048-byte dump a {DUMPS_DIR} mappában.')
        return

    print(f'{len(files)} cal_ram dump (2048 byte) található:\n')
    for f in files:
        print(f'  {f.name}')
    print()

    print('=' * 100)
    print('1) RÉGI KÉPLET — implied_seed minden dumpon (egyezik-e a fix seeddel?)')
    print('=' * 100)
    header = f'{"dump":48s}' + ''.join(f'{n:>16s}' for n, *_ in OLD_DEFS)
    print(header)
    for f in files:
        data = f.read_bytes()
        res = old_seed_check(data)
        row = f'{f.name:48s}'
        for name, *_ in OLD_DEFS:
            stored, rsum, implied, ok = res[name]
            mark = 'OK' if ok else 'ELTÉR'
            row += f'{("0x%04X[%s]" % (implied, mark)):>16s}'
        print(row)

    print()
    print('=' * 100)
    print('2) ÚJ (cs.txt) KÉPLET — implied flag_count minden dumpon')
    print('   (cs.txt állítása szerint stabilnak kellene lennie: CS0=56 CS1=187 CS2=11 CS3=3)')
    print('=' * 100)
    header = f'{"dump":48s}' + ''.join(f'{n:>14s}' for n, *_ in NEW_DEFS)
    print(header)
    all_flagcounts = {name: set() for name, *_ in NEW_DEFS}
    for f in files:
        data = f.read_bytes()
        res = new_flagcount_check(data)
        row = f'{f.name:48s}'
        for name, *_ in NEW_DEFS:
            stored, rsum, fc = res[name]
            all_flagcounts[name].add(fc)
            row += f'{fc:>14d}'
        print(row)

    print()
    print('Összesítés — hány DISZTINKT flag_count érték fordul elő dump-onként/CS-enként:')
    for name in all_flagcounts:
        vals = sorted(all_flagcounts[name])
        claimed = CS_TXT_CLAIMED_FLAGCOUNT.get(name)
        print(f'  {name}: {len(vals)} különböző érték: {vals}   (cs.txt állítása: {claimed})')


if __name__ == '__main__':
    main()
