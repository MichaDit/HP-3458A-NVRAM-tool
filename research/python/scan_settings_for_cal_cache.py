"""Settings_RAM dump szkennelése: van-e benne CAL_RAM-mal kapcsolatos cache?

Két módszer:
  1. Egzakt byte-egyezés keresése: minden cal_ram mező (dbl/i32/u16/u8/str)
     nyers byte-sorozata megtalálható-e valahol a settings_RAM dumpban.
  2. "Plauzibilis double" pásztázás: minden 2-byte-aligned pozíción 8 byte-ot
     IEEE754 big-endian double-ként dekódolva, megnézzük hány találat esik
     egy tipikus kalibrációs érték tartományba (0.00001 .. 1e7, nem NaN/Inf).
     Ez segít megtalálni azokat a cache-eket is, ahol az érték NEM egyezik
     pontosan az aktuális cal_ram tartalommal (pl. egy korábbi/eltérő mérési
     körből), csak a *formátuma* kalibrációs jellegű.
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from hp3458a_calram_decoder import FIELDS, CAL_RAM_SIZE

SETTINGS_BASE = 0x120000
CAL_RAM_BASE  = 0x60000

# Ismert, korábban már feltérképezett zónák (ne lepjen meg, ha ezek dobnak találatot)
KNOWN_CACHE_ZONES = [
    (0x12D000, 0x12E000, 'régi DATA_BASE — ismert kalibrációs cache (IEEE754 doublek)'),
    (0x12E000, 0x12E200, 'régi CODE_BASE/CB_BASE — ismert kalibrációs cache'),
]
KNOWN_FREE_ZONE = (0x127196, 0x12A885, 'megerősített szabad/nulla zóna')


def load(path):
    return Path(path).read_bytes()


def field_bytes(cal_data: bytes, off: int, typ: str, name: str):
    if typ == 'dbl':
        return cal_data[off:off + 8]
    if typ == 'i32':
        return cal_data[off:off + 4]
    if typ == 'u16':
        return cal_data[off:off + 2]
    if typ == 'u8':
        return cal_data[off:off + 1]
    if typ == 'str':
        # str mezőknél a hossz nem mindig egyértelmű FIELDS-ből; kihagyjuk
        return None
    return None


def find_all(haystack: bytes, needle: bytes):
    if not needle or len(needle) < 2:
        return []
    out = []
    start = 0
    while True:
        idx = haystack.find(needle, start)
        if idx == -1:
            break
        out.append(idx)
        start = idx + 1
    return out


def in_zone(addr, zones):
    for a, b, label in zones:
        if a <= addr < b:
            return label
    return None


def scan_exact(cal_data: bytes, settings_data: bytes):
    print(f'\n=== 1. Egzakt mező-egyezés keresése ({len(FIELDS)} mező) ===')
    any_hit = False
    for off, typ, name in FIELDS:
        nb = field_bytes(cal_data, off, typ, name)
        if nb is None or len(nb) < 2:
            continue
        # csupa-nulla / csupa-FF mezőket kihagyjuk (túl gyakori, zaj)
        if nb == bytes(len(nb)) or nb == b'\xff' * len(nb):
            continue
        hits = find_all(settings_data, nb)
        if hits:
            any_hit = True
            cal_abs = CAL_RAM_BASE + off * 2  # EVEN bank phys cím (info)
            for h in hits:
                abs_addr = SETTINGS_BASE + h
                zone = in_zone(abs_addr, KNOWN_CACHE_ZONES)
                tag = f'  [{zone}]' if zone else '  [ÚJ / eddig nem ismert zóna]'
                print(f'  {name:30s} cal_ram+0x{off:04X} ({typ}) '
                      f'-> settings 0x{abs_addr:06X} (settings_off=0x{h:04X}){tag}')
    if not any_hit:
        print('  (nincs egzakt egyezés)')


def scan_plausible_doubles(settings_data: bytes):
    print('\n=== 2. Plauzibilis IEEE754 double pásztázás (kalibrációs jellegű értékek) ===')
    hits = []
    n = len(settings_data)
    for off in range(0, n - 8, 2):  # word-aligned
        chunk = settings_data[off:off + 8]
        try:
            val = struct.unpack('>d', chunk)[0]
        except struct.error:
            continue
        if val != val:  # NaN
            continue
        av = abs(val)
        if av == 0.0:
            continue
        if 1e-6 < av < 1e7:
            hits.append((off, val))

    print(f'  {len(hits)} plauzibilis double-szerű pozíció (word-aligned, |érték| 1e-6..1e7 tartományban)')
    # Csoportosítás zóna szerint, hogy lássuk hol koncentrálódnak
    zone_counts = {}
    listed = 0
    for off, val in hits:
        abs_addr = SETTINGS_BASE + off
        zone = in_zone(abs_addr, KNOWN_CACHE_ZONES) or 'ÚJ/ismeretlen zóna'
        zone_counts[zone] = zone_counts.get(zone, 0) + 1
        if listed < 40:
            print(f'    0x{abs_addr:06X}  = {val!r}   [{zone}]')
            listed += 1
    if len(hits) > 40:
        print(f'    ... (+{len(hits) - 40} további, lásd zóna-összesítés alább)')
    print('  Zóna-összesítés:')
    for zone, cnt in sorted(zone_counts.items(), key=lambda kv: -kv[1]):
        print(f'    {cnt:5d} db  — {zone}')


def main():
    if len(sys.argv) < 3:
        print('Usage: python scan_settings_for_cal_cache.py <calram.bin> <settings.bin>')
        sys.exit(1)
    cal_path, settings_path = sys.argv[1], sys.argv[2]
    cal_data = load(cal_path)
    settings_data = load(settings_path)
    print(f'cal_ram: {cal_path} ({len(cal_data)} byte)')
    print(f'settings: {settings_path} ({len(settings_data)} byte, '
          f'0x{SETTINGS_BASE:06X}-0x{SETTINGS_BASE + len(settings_data):06X})')

    scan_exact(cal_data, settings_data)
    scan_plausible_doubles(settings_data)


if __name__ == '__main__':
    main()
