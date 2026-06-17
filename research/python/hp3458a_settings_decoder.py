"""
HP 3458A settings_ram decoder
Bemenet: dump_XXXXX/dump_01_settings_ram.bin  (65536 byte, DS1235 NVRAM, base 0x120000)

Figyelmeztetés: a settings_ram tartalma dinamikus (futás közben változik).
Ez a decoder egy adott pillanatban készült dump pillanatképét értelmezi.
"""

import struct
import sys
import os
import argparse

SETTINGS_RAM_SIZE = 65536
SETTINGS_RAM_BASE = 0x120000

# JMP abs.l opcode a 68000-en
M68K_JMP_ABSLONG = b'\x4E\xF9'

# DEFKEY slot mérete byte-ban (10 kulcs × 41 byte = F0–F9)
DEFKEY_BASE  = 0x1B10   # relatív offset a settings_ram-ban
DEFKEY_SLOT  = 41
DEFKEY_COUNT = 10

# Mentett state string (pSOS command history ring buffer) kezdete
STATE_CMDS_OFF = 0x1CB0

# STATE0 blokkok (műszer konfiguráció snapshot)
STATE0_OFFSETS = [0x711C, 0xB018]

# ---------------------------------------------------------------------------

def read_cstr(data, offset, maxlen=256):
    """Null-lezárt ASCII string olvasása."""
    end = data.find(b'\x00', offset, offset + maxlen)
    if end == -1:
        end = offset + maxlen
    return data[offset:end].decode('ascii', errors='replace')


def hex_row(data, offset, n=16):
    chunk = data[offset:offset + n]
    hex_s = ' '.join(f'{b:02X}' for b in chunk)
    asc_s = ''.join(chr(b) if 0x20 <= b <= 0x7E else '.' for b in chunk)
    return f'{hex_s:<48}  {asc_s}'


def hexdump(data, offset, length, base=SETTINGS_RAM_BASE, indent='  '):
    for row in range(0, length, 16):
        off = offset + row
        if off >= len(data):
            break
        n = min(16, length - row)
        print(f'{indent}0x{base + off:06X}: {hex_row(data, off, n)}')


def section(title):
    print()
    print(f'{"=" * 70}')
    print(f'  {title}')
    print(f'{"=" * 70}')


# ---------------------------------------------------------------------------
# Dekódolók szekciónként
# ---------------------------------------------------------------------------

def decode_header(data):
    section('1. HEADER — Magic bytes + crash log')
    magic = data[0:4]
    print(f'  Magic bytes (0x120000): {" ".join(f"{b:02X}" for b in magic)}', end='  ')
    if magic == b'\x55\x55\xAA\xAA':
        print('[OK — érvényes HP 3458A boot szignál]')
    else:
        print('[ISMERETLEN]')

    # Crash log: 0x12000C-től null-lezárt ASCII
    crash = read_cstr(data, 0x000C, 64).strip()
    if crash:
        print(f'  Crash log (0x12000C): "{crash}"')
        # Értelmezés
        if 'Bus Error' in crash:
            print( '    -> 68000 Bus Error kivétel — unmapped memóriacím hozzáférés')
            print( '       (MREAD scan mellékterméke: az érintetlen 68000 buszra küldött')
            print( '       olvasási kísérlet Bus Error-t vált ki, amit a pSOS RTOS loggol)')
        if 'PC=' in crash:
            # "PC=017BEA,072000" formátum
            parts = crash.split(',')
            for p in parts:
                if p.startswith('#PC=') or p.startswith('PC='):
                    pc_str = p.split('=')[-1]
                    try:
                        pc_val = int(pc_str, 16)
                        print(f'    -> Program Counter a crash pillanatában: 0x{pc_val:06X}')
                    except ValueError:
                        pass
    else:
        print('  Crash log: nincs (0x00 a 0x12000C-n)')

    print()
    hexdump(data, 0x0000, 0x30)


def decode_jump_vectors(data):
    section('2. JUMP VEKTORTÁBLA — 68000 JMP abs.l utasítások')
    print('  A settings_ram 0x12004C-tól tartalmaz JMP utasításokat,')
    print('  amelyek a pSOS RTOS interrupt/tasklist vektorait tárolják.')
    print()
    count = 0
    off = 0x004C
    while off + 6 <= 0x0120:
        if data[off:off+2] == M68K_JMP_ABSLONG:
            target = struct.unpack('>I', data[off+2:off+6])[0]
            print(f'  0x{SETTINGS_RAM_BASE + off:06X}: JMP  0x{target:06X}')
            count += 1
        off += 6
    print(f'  ({count} vektor)')


def decode_display(data):
    section('3. DISPLAY BUFFER — VFD kijelző tartalma')
    print('  0x120A4C: 256 byte-os display buffer (HP 3458A frontpanel kijelző)')
    print()
    raw = data[0x0A4C:0x0A4C + 256]
    # A HP 3458A VFD kijelzője 12 karakteres fősor + annunciátorok
    # A buffer 0x20 (space) karakterekkel van kitöltve
    display_str = ''.join(chr(b) if 0x20 <= b <= 0x7E else ' ' for b in raw)
    # Első értékes tartalom kiemelése
    stripped = display_str.strip()
    if stripped:
        print(f'  Tartalom: "{stripped[:80]}"')
    else:
        print('  Tartalom: (üres / space padding)')
    print()
    hexdump(data, 0x0A4C, 48)


def decode_last_measurement(data):
    section('4. UTOLSÓ MÉRÉSI EREDMÉNY')

    # ADC buffer: ASCII float string 0x120DAE-től
    result_str = read_cstr(data, 0x0DAE, 32).strip()
    print(f'  ADC buffer (0x120DAE)  : "{result_str}"')
    if result_str:
        try:
            val = float(result_str)
            print(f'                           = {val:.6E}')
        except ValueError:
            pass

    # Display copy: a mérési egység is (mV DC, Ohm stb.)
    disp_copy = data[0x0DC4:0x0DC4 + 16]
    disp_str = ''.join(chr(b) if 0x20 <= b <= 0x7E else ' ' for b in disp_copy).strip()
    print(f'  Display másolat (0x120DC4): "{disp_str}"')

    # RMEM 1 terület
    rmem_raw = read_cstr(data, 0x0E38, 40).strip()
    print(f'  Math memória (0x120E38): "{rmem_raw}"')


def decode_error_strings(data):
    section('5. FIRMWARE HIBAÜZENET STRINGEK')
    print('  A settings_ram tartalmazza a firmware ROM hibaüzeneteinek')
    print('  null-lezárt másolatait (a pSOS RTOS a RAM-ba másolja őket).')
    print()

    candidates = [
        (0x0F0A, 'NO ERROR'),
        (0x0F14, 'Nonvolatile ram checksum'),
        (0x0F55, 'HOLD/LINE trigger opciók'),
        (0x10FD, 'Expected command header'),
    ]
    for off, hint in candidates:
        s = read_cstr(data, off, 64).strip()
        if s:
            print(f'  0x{SETTINGS_RAM_BASE + off:06X}: "{s}"  [{hint}]')


def decode_defkeys(data):
    section('6. DEFKEY F0–F9 — frontpanel makróbillentyűk')
    print('  Minden DEFKEY slot 41 byte: "DEFKEY Fn,\\"<macro>\\""')
    print()
    any_defined = False
    for i in range(DEFKEY_COUNT):
        off = DEFKEY_BASE + i * DEFKEY_SLOT
        s = read_cstr(data, off, DEFKEY_SLOT).strip()
        if s and s != f'DEFKEY F{i},"':
            print(f'  F{i}: {s}')
            any_defined = True
        else:
            # Ellenőrizzük, van-e tartalma a "" után
            prefix = f'DEFKEY F{i},"'
            if s.startswith(prefix):
                macro = s[len(prefix):].rstrip('"')
                if macro:
                    print(f'  F{i}: [{macro}]')
                    any_defined = True
                else:
                    print(f'  F{i}: (üres — nincs hozzárendelve)')
            else:
                print(f'  F{i}: (üres — nincs hozzárendelve)')
    if not any_defined:
        print('  Minden billentyű üres (gyári alapértelmezés).')


def decode_saved_state(data):
    section('7. MENTETT PARANCSOK / STATE HISTORY')
    print('  A 0x121CB0-tól tárolt tömörített parancssor-lista.')
    print('  A nem-ASCII byte-ok (< 0x20 vagy > 0x7E) linked-list mutatók.')
    print()

    off = STATE_CMDS_OFF
    raw = data[off:off + 0x100]

    # Kinyerjük az ASCII blokkokat (printable runs) a linked-list byte-ok között
    cmds = []
    run_start = None
    for i, b in enumerate(raw):
        if 0x20 <= b <= 0x7E:
            if run_start is None:
                run_start = i
        else:
            if run_start is not None and i - run_start >= 3:
                cmds.append(raw[run_start:i].decode('ascii', errors='replace'))
            run_start = None
    if run_start is not None:
        cmds.append(raw[run_start:].decode('ascii', errors='replace'))

    if cmds:
        print('  Azonosított parancsok / beállítások:')
        seen = set()
        for c in cmds:
            c = c.strip()
            if c and c not in seen:
                print(f'    {c}')
                seen.add(c)
    else:
        print('  (nem található ASCII tartalom)')

    print()
    print('  Nyers dump:')
    hexdump(data, STATE_CMDS_OFF, 0x100)


def decode_state0(data):
    section('8. STATE0 BLOKKOK — műszer konfigurációs snapshots')
    print('  A pSOS RTOS STATE0 nevű struktúrái a műszer aktuális')
    print('  üzemmódját (NPLC, TARM, TRIG, mértékegység) tárolják.')
    print()
    for off in STATE0_OFFSETS:
        tag = read_cstr(data, off, 8)
        print(f'  0x{SETTINGS_RAM_BASE + off:06X}: "{tag}"')
        hexdump(data, off, 32)
        print()


def decode_ascii_strings(data):
    section('9. EGYÉB ASCII STRINGEK (>= 8 karakter)')
    run_start = None
    strings = []
    for i, b in enumerate(data):
        if 0x20 <= b <= 0x7E:
            if run_start is None:
                run_start = i
        else:
            if run_start is not None:
                length = i - run_start
                if length >= 8:
                    s = data[run_start:i].decode('ascii', errors='replace').strip()
                    strings.append((run_start, s))
            run_start = None

    # Kizárjuk az előző szekciókban már megmutatottakat
    skip_ranges = [
        (0x000C, 0x0040),   # crash log
        (0x0A4C, 0x0B4C),   # display buffer
        (0x0DAE, 0x0DC0),   # ADC result
        (0x0DC4, 0x0DD0),   # display copy
        (0x0E38, 0x0E60),   # RMEM
        (0x0EF0, 0x0F80),   # error strings
        (0x1B10, 0x1CB0),   # DEFKEY
        (0x1CB0, 0x1DB0),   # saved state
        (0x711C, 0x712C),   # STATE0
        (0xB018, 0xB028),   # STATE0
    ]

    def in_skip(off):
        return any(lo <= off < hi for lo, hi in skip_ranges)

    for off, s in strings:
        if not in_skip(off):
            print(f'  0x{SETTINGS_RAM_BASE + off:06X}: "{s}"')


# ---------------------------------------------------------------------------

def decode(path):
    with open(path, 'rb') as f:
        data = f.read()

    if len(data) != SETTINGS_RAM_SIZE:
        print(f'HIBA: {len(data)} byte, elvárt {SETTINGS_RAM_SIZE}', file=sys.stderr)
        sys.exit(1)

    print('HP 3458A settings_ram decoder')
    print(f'Fájl  : {path}')
    print(f'Méret : {len(data)} byte')
    print(f'Base  : 0x{SETTINGS_RAM_BASE:06X}')
    print()
    print('FIGYELMEZTETÉS: A settings_ram dinamikus tartalom — a dump pillanatképe.')
    print('Minden futás között más lehet (mérési eredmények, RTOS állapot).')

    decode_header(data)
    decode_jump_vectors(data)
    decode_display(data)
    decode_last_measurement(data)
    decode_error_strings(data)
    decode_defkeys(data)
    decode_saved_state(data)
    decode_state0(data)
    decode_ascii_strings(data)

    section('KÉSZ')
    print(f'  settings_ram dekódolva: {path}')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description='HP 3458A settings_ram decoder')
    p.add_argument('bin', nargs='?', default=None,
                   help='settings_ram .bin fájl (alapértelmezett: legfrissebb dump könyvtárból)')
    args = p.parse_args()

    path = args.bin
    if path is None:
        fw_dir = os.path.dirname(os.path.abspath(__file__))
        candidates = sorted(
            [d for d in os.listdir(fw_dir) if d.startswith('dump_')],
            reverse=True
        )
        if not candidates:
            print('Nem található dump_* könyvtár. Add meg a fájlt argumentumként.', file=sys.stderr)
            sys.exit(1)
        path = os.path.join(fw_dir, candidates[0], 'dump_01_settings_ram.bin')
        print(f'[auto] {path}')

    decode(path)
