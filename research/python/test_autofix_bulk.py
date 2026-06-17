"""
Teszt: write_calram_bin auto-fix ellenőrzése.

Feltölti a legutóbbi dump-ot a műszerre a javított write_calram_bin()-nel,
majd teljes verify-t futtat. A progress logban látszik:
  - mikor fut az auto-fix spot-verify
  - melyik pair-t javítja és milyen értékre
  - végeredmény: OK / ELTÉRÉS lista

Futtatás:
    python test_autofix_bulk.py [dump_file.bin]
"""
import sys
import time
from pathlib import Path

# Windows CP1250 konzolon is mukodjek
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.stderr.reconfigure(encoding='utf-8', errors='replace')

BRIDGE_HOST = '192.168.2.88'
BRIDGE_PORT = 1234
GPIB_ADDR   = 22

DUMPS_DIR = Path(__file__).parent / 'dumps'


def pick_dump(argv):
    if len(argv) > 1:
        p = Path(argv[1])
        if not p.exists():
            p = DUMPS_DIR / argv[1]
        return p
    bins = sorted(DUMPS_DIR.glob('calram_*.bin'))
    if not bins:
        raise FileNotFoundError('Nincs calram_*.bin a dumps/ mappában')
    return bins[-1]   # legutóbbi


def progress(cur, total, msg):
    bar = ''
    if total > 1:
        pct = int(cur * 40 / total)
        bar = f'[{"#" * pct}{"-" * (40 - pct)}] {cur}/{total}  '
    print(f'  {bar}{msg}')


def main():
    dump_path = pick_dump(sys.argv)
    data = dump_path.read_bytes()
    print(f'Dump: {dump_path.name}  ({len(data)} byte)')
    assert len(data) == 2048, f'Érvénytelen méret: {len(data)}'

    # Előre kiírjuk a 3 ismert bugos byte várt értékét
    buggy = [(946, 947), (1018, 1019), (1022, 1023)]
    print()
    print('Ismert bugos pair-ok a dump-ban:')
    for hi_i, lo_i in buggy:
        print(f'  pair {hi_i // 2}: cal_RAM[{hi_i}]={data[hi_i]:02X}  cal_RAM[{lo_i}]={data[lo_i]:02X}')
    print()

    from hp3458a_conn import TCPConn
    from hp3458a_instr import HP3458A

    print(f'Kapcsolódás {BRIDGE_HOST}:{BRIDGE_PORT} (GPIB {GPIB_ADDR})...')
    conn = TCPConn(BRIDGE_HOST, BRIDGE_PORT, GPIB_ADDR)
    meter = HP3458A(conn)

    try:
        print('Init (PRESET NORM, BEEP 1)...')
        meter.init()
        idn = meter.test_id()
        print(f'ID? -> {idn!r}')
        if 'HP3458A' not in idn:
            print('HIBA: műszer nem válaszol!')
            return

        print()
        print('=' * 60)
        print('FELTÖLTÉS + AUTO-FIX TESZT')
        print('=' * 60)
        t0 = time.time()

        # Ha ERR jön a JSR-re, flush + retry egyszer
        ok = meter.write_calram_bin_safe(data, progress_cb=progress)
        if not ok:
            print()
            print('Hiba - flush + ujra init, 5s var...')
            meter.flush_errors()
            time.sleep(5.0)
            idn2 = meter.test_id()
            print(f'  ID? -> {idn2!r}')

        elapsed = time.time() - t0
        print()
        print(f'write_calram_bin eredmeny: {"OK" if ok else "HIBA"}  ({elapsed:.1f}s)')

        print()
        print('=' * 60)
        print('TELJES VERIFY')
        print('=' * 60)
        t1 = time.time()

        ok_v, diffs = meter.verify_calram(data, progress_cb=progress)

        elapsed_v = time.time() - t1
        print()
        if ok_v:
            print(f'Verify: MINDEN BYTE HELYES OK  ({elapsed_v:.1f}s)')
        else:
            print(f'Verify: {len(diffs)} ELTERES  ({elapsed_v:.1f}s)')
            print()
            print('Eltérések:')
            for offset, exp, got in diffs[:30]:
                pair_i = offset // 2
                hi_lo = 'HI' if offset % 2 == 0 else 'LO'
                phys = 0x60000 + pair_i * 4 + (0 if offset % 2 == 0 else 2)
                print(f'  cal_RAM[{offset:4d}] ({hi_lo}, phys=0x{phys:06X}): '
                      f'várt=0x{exp:02X}  kapott=0x{got:02X}')
            if len(diffs) > 30:
                print(f'  ... ({len(diffs) - 30} további)')

    finally:
        conn.close()
        print()
        print('Kapcsolat lezárva.')


if __name__ == '__main__':
    main()
