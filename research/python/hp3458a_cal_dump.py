#!/usr/bin/env python3
"""HP 3458A CAL RAM dump via GPIB (MREAD). Read-only — no MWRITE."""

import argparse
import hashlib
import json
import socket
import struct
import time
from datetime import datetime
from pathlib import Path

try:
    import pyvisa
except ImportError:
    pyvisa = None

GPIB_RESOURCE     = 'GPIB0::22::INSTR'
CAL_RAM_START     = 0x060000   # DS1220Y chip, 2KB
CAL_RAM_WORDS     = 0x1000 // 2
SETTINGS_RAM_START = 0x120000  # DS1235 chip, 32KB
SETTINGS_RAM_WORDS = 0x10000 // 2

SCAN_MAX_ADDR  = 0x200000   # 2MB address space (HP 3458A 68000 bus)
COARSE_STEP    = 0x2000     # 8KB coarse probe (~256 probes, ~85s)
FINE_STEP      = 0x200      # 512B fine probe for region boundary refinement

_KNOWN_NAMES = {
    0x000000: 'vectors',
    0x060000: 'cal_ram',
    0x120000: 'settings_ram',
}

_KNOWN_WIDTHS = {
    0x000000: 16,  # ROM vektorok (16-bit busz)
    0x060000: 8,   # DS1220Y Cal RAM (8-bit, EVEN bank)
    0x120000: 16,  # DS1235 Settings RAM (16-bit)
}


def _width_for_addr(start: int) -> int:
    """Visszaadja a régió busz-szélességét (8 vagy 16 bit) cím alapján."""
    for known, width in _KNOWN_WIDTHS.items():
        if abs(start - known) < 0x4000:
            return width
    return 16  # ismeretlen régiók: konzervatív 16-bit alapértelmezés


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description='HP 3458A CAL RAM dump via GPIB')
    p.add_argument('--fixed-regions', action='store_true', default=False,
                   help='Fix hardcoded tartományok (szkennelés kihagyása)')
    p.add_argument('--no-diff', dest='diff', action='store_false', default=True,
                   help='Differenciális elemzés kihagyása')
    p.add_argument('--bridge', metavar='HOST[:PORT]', default=None,
                   help='Prologix bridge IP, pl. 192.168.2.88 vagy 192.168.2.88:1234')
    return p.parse_args()


class GpibSession:
    def __init__(self, resource: str = GPIB_RESOURCE, timeout_ms: int = 30000,
                 bridge_host: str | None = None, bridge_port: int = 1234):
        self._resource    = resource
        self._timeout_ms  = timeout_ms
        self._bridge_host = bridge_host
        self._bridge_port = bridge_port
        self._rm   = None
        self._inst = None
        self._sock = None
        self._buf  = b''

    # ── Socket (Prologix bridge) transport ───────────────
    def _sw(self, cmd: str) -> None:
        if not cmd.endswith('\n'):
            cmd += '\n'
        self._sock.sendall(cmd.encode('ascii'))

    def _sr(self) -> str:
        while b'\n' not in self._buf:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise RuntimeError('Bridge kapcsolat megszakadt')
            self._buf += chunk
        line, self._buf = self._buf.split(b'\n', 1)
        return line.decode('ascii', errors='replace').strip()

    def _sq(self, cmd: str) -> str:
        self._sw(cmd)
        self._sw('++read')
        return self._sr()

    # ── Unified write / query ─────────────────────────────
    def _write(self, cmd: str) -> None:
        if self._bridge_host:
            self._sw(cmd)
        else:
            self._inst.write(cmd)

    def _query(self, cmd: str) -> str:
        if self._bridge_host:
            return self._sq(cmd)
        return self._inst.query(cmd)

    def __enter__(self) -> 'GpibSession':
        if self._bridge_host:
            self._sock = socket.create_connection(
                (self._bridge_host, self._bridge_port),
                timeout=self._timeout_ms / 1000)
            self._sock.settimeout(self._timeout_ms / 1000)
            addr = int(self._resource.split('::')[1])
            self._sw(f'++addr {addr}')
            # NPLC 0 + TRIG HOLD esetén MREAD válasz ~10-50ms — T300ms (300ms) 6x margó.
            # Unmapped 68000 cím timeout esetén 300ms << 1s, így retry sokkal gyorsabb.
            self._sw('++read_tmo_ms 300')
            # ibclr (Device Clear): HP 3458A GPIB output buffer törlése az init előtt.
            # A régi bridge ++addr auto-init-je ezt elvégezte; az új bridge nem csinálja.
            self._sw('++clr')
            time.sleep(1.0)  # HP 3458A SDC feldolgozási ideje ~800ms
        else:
            self._rm   = pyvisa.ResourceManager()
            self._inst = self._rm.open_resource(self._resource)
            self._inst.timeout          = self._timeout_ms
            self._inst.read_termination = ''
        self._init()
        return self

    def __exit__(self, *_) -> None:
        try:
            for cmd in ('BEEP 0', 'TRIG AUTO', 'DISP 1'):
                self._write(cmd)
        except Exception:
            pass
        if self._sock:
            self._sock.close()
            self._sock = None
        if self._inst:
            self._inst.close()
        if self._rm:
            self._rm.close()

    def _init(self) -> None:
        for cmd in ('END ALWAYS', 'NPLC 0', 'NRDGS 1', 'TRIG HOLD', 'QFORMAT NUM'):
            self._write(cmd)
        if self._bridge_host:
            time.sleep(0.3)

    def beep(self, mode: int) -> None:
        self._write(f'BEEP {mode}')

    def mread_word(self, addr: int) -> int:
        raw = ''
        for attempt in range(5):
            if attempt:
                time.sleep(0.1)
            try:
                raw = self._query(f'MREAD {addr}').strip()
            except (TimeoutError, OSError):
                continue  # socket timeout vagy hálózati hiba → újra
            # "ERR" = bridge ibrd timeout (pl. műszer nem válaszolt)
            if not raw or '\x00' in raw or raw.upper() == 'ERR':
                continue
            try:
                return int(raw)
            except ValueError:
                raise RuntimeError(f'MREAD invalid response @ {addr:#010x}: {raw!r}')
        raise RuntimeError(f'MREAD no valid response @ {addr:#010x}: {raw!r}')


def _fast_hypothesis_check(session: 'GpibSession') -> 'int | None':
    candidate = A5_HYPOTHESIS + BEEP_FLAG_OFFSET   # 0x1213A6

    session.beep(1)
    val_b1 = session.mread_word(candidate)

    session.beep(2)
    val_b2 = session.mread_word(candidate)

    session.beep(1)

    if val_b2 - val_b1 == 256:
        return A5_HYPOTHESIS
    return None


def _coarse_fine_scan(session: 'GpibSession', start: int, end: int) -> int:
    """Offset-alapú kétlépéses scan: minden A5-kandidátushoz a BEEP_FLAG_OFFSET
    -on lévő szót olvassa, így a 0x100-as lépés is pontosan lefedi a flag-et."""
    COARSE = 0x100

    # Koarse fázis: 0x100-as A5-kandidátusokhoz a flag-cím olvasása
    a5_cands = list(range(start & ~1, (end - BEEP_FLAG_OFFSET) & ~1, COARSE))

    session.beep(1)
    baseline = {a: session.mread_word(a + BEEP_FLAG_OFFSET) for a in a5_cands}
    session.beep(2)
    after    = {a: session.mread_word(a + BEEP_FLAG_OFFSET) for a in a5_cands}
    session.beep(1)

    hits = [a for a in a5_cands if after[a] - baseline[a] == 256]
    if not hits:
        raise RuntimeError(
            f'A5 nem azonosítható {start:#x}–{end:#x} tartományban. '
            'Próbáld --mode c opciót.')

    a5_rough = hits[0]

    # Fine fázis: ±COARSE körüli 2-bájtos scan (nem 0x100-aligned A5 esetére)
    fine_start = max(start & ~1, a5_rough - COARSE)
    fine_end   = min((end - BEEP_FLAG_OFFSET) & ~1, a5_rough + COARSE)
    fine_cands = list(range(fine_start, fine_end, 2))

    session.beep(1)
    fine_base  = {a: session.mread_word(a + BEEP_FLAG_OFFSET) for a in fine_cands}
    session.beep(2)
    fine_after = {a: session.mread_word(a + BEEP_FLAG_OFFSET) for a in fine_cands}
    session.beep(1)

    exact = [a for a in fine_base if fine_after[a] - fine_base[a] == 256]
    if not exact:
        raise RuntimeError('A5 fine-scan sikertelen.')

    return exact[0]


def detect_a5(session: 'GpibSession', mode: str) -> int:
    fast = _fast_hypothesis_check(session)
    if fast is not None:
        print(f'[A5] Hipotézis megerősítve: A5 = {fast:#010x}')
        return fast

    print('[A5] Hipotézis eltér, scan indul...')
    ranges = {'b': (0x11C000, 0x126000), 'c': (0x100000, 0x140000)}
    a5 = _coarse_fine_scan(session, *ranges[mode])
    print(f'[A5] Megtalálva: A5 = {a5:#010x}')
    return a5


def compute_regions() -> list[tuple[str, int, int, int]]:
    """Fix (hardcoded) tartományok fallback-ként. [(név, start_addr, word_count, bus_width)]"""
    return [
        ('cal_ram',      CAL_RAM_START,      CAL_RAM_WORDS,      8),
        ('settings_ram', SETTINGS_RAM_START, SETTINGS_RAM_WORDS, 16),
        ('vectors',      0x000000,           0x0400 // 2,        16),
    ]


def scan_is_active(val: int) -> bool:
    """True ha a MREAD érték valódi adatnak tűnik (nem lebegő busz)."""
    hi = (val >> 8) & 0xFF
    lo = val & 0xFF
    # Azonos byte mindkét helyen + ismert lebegő busz érték = inaktív
    return not (hi == lo and lo in (0x00, 0xFF, 0xB9))


def _name_for_addr(start: int) -> str:
    for known, name in _KNOWN_NAMES.items():
        if abs(start - known) < 0x4000:
            return name
    return f'region_{start:06x}'


def auto_detect_regions(session: 'GpibSession',
                        max_addr: int = SCAN_MAX_ADDR,
                        coarse_step: int = COARSE_STEP,
                        fine_step: int = FINE_STEP) -> list[tuple[str, int, int, int]]:
    """Kétfázisú memória-szkenn: coarse → aktív blokkok → fine határok.
    Visszatér: [(név, start_addr, word_count)]"""
    # 1. fázis: durva szkenn
    total = max_addr // coarse_step
    print(f'[SCAN] 1. fázis: 0x000000–0x{max_addr:06X}, lépés 0x{coarse_step:X} ({total} próba)')
    coarse_active: list[int] = []
    for i, addr in enumerate(range(0, max_addr, coarse_step)):
        if i % 32 == 0:
            print(f'\r  [{100*i//total:3d}%] {i}/{total}', end='', flush=True)
        try:
            val = session.mread_word(addr)
            if scan_is_active(val):
                coarse_active.append(addr)
        except (RuntimeError, OSError):
            pass  # nincs válasz / unmapped cím = kihagyjuk
    print(f'\r  [100%] {total}/{total} — {len(coarse_active)} aktív blokk')

    if not coarse_active:
        print('[SCAN] Figyelmeztetés: nincs aktív terület, visszaesés fix régiókra')
        return compute_regions()

    # Szomszédos coarse találatok összevonása régiókba (max 2×coarse_step rés engedélyezett)
    cands: list[tuple[int, int]] = []
    seg_s = coarse_active[0]
    seg_e = coarse_active[0]
    for a in coarse_active[1:]:
        if a - seg_e <= coarse_step * 2:
            seg_e = a
        else:
            cands.append((seg_s, seg_e))
            seg_s = seg_e = a
    cands.append((seg_s, seg_e))
    print(f'[SCAN] Régió-jelöltek: {len(cands)}')

    # 2. fázis: finomítás minden jelöltre
    regions: list[tuple[str, int, int]] = []
    for ci, (cs, ce) in enumerate(cands):
        scan_from = max(0,        cs - coarse_step) & ~1
        scan_to   = min(max_addr, ce + coarse_step)
        fine_hits: list[int] = []
        for addr in range(scan_from, scan_to, fine_step):
            try:
                val = session.mread_word(addr)
                if scan_is_active(val):
                    fine_hits.append(addr)
            except (RuntimeError, OSError):
                pass

        if not fine_hits:
            continue

        r_start    = fine_hits[0]
        r_end      = fine_hits[-1] + fine_step   # konzervatív felső határ
        word_count = (r_end - r_start) // 2
        name       = _name_for_addr(r_start)
        width      = _width_for_addr(r_start)
        regions.append((name, r_start, word_count, width))
        print(f'  [{ci+1}/{len(cands)}] {name}: {r_start:#010x}–{r_end:#010x} ({word_count} word, {width}-bit)')

    return regions if regions else compute_regions()


def dump_regions(session: 'GpibSession',
                 regions: list[tuple[str, int, int, int]]) -> dict[int, int]:
    """Végigolvassa az összes régiót MREAD-del. Visszatér: {addr: signed_word}."""
    result: dict[int, int] = {}
    total = sum(cnt for _, _, cnt, *_ in regions)
    done  = 0

    for name, start, count, *_ in regions:
        for i in range(count):
            addr = start + i * 2
            result[addr] = session.mread_word(addr)
            done += 1
            if done % 200 == 0:
                pct = 100 * done // total
                print(f'\r  [{pct:3d}%] {done}/{total} words', end='', flush=True)

    print(f'\r  [100%] {total}/{total} words')
    return result


def compute_hash(dump: dict[int, int]) -> str:
    """SHA-256 a rendezett (addr, word) párokból, big-endian kódolással."""
    h = hashlib.sha256()
    for addr in sorted(dump):
        h.update(struct.pack('>Ih', addr, dump[addr]))
    return h.hexdigest()


def verify_dumps(dumps: list[dict[int, int]]) -> tuple[bool, list[str]]:
    """Visszatér: (mind_egyezik, [hash1, hash2, hash3])."""
    hashes = [compute_hash(d) for d in dumps]
    return len(set(hashes)) == 1, hashes


def save_json(dump: dict[int, int], metadata: dict, path: Path) -> None:
    data = {
        'metadata': metadata,
        'data': {f'0x{addr:08X}': val for addr, val in sorted(dump.items())},
    }
    path.write_text(json.dumps(data, indent=2))


def save_binary(dump: dict[int, int],
                regions: list[tuple[str, int, int, int]],
                base: Path) -> None:
    """Régiónként ír bináris fájlt (base_<name>.bin).
    8-bit régió (pl. Cal RAM EVEN bank): csak HIGH byte — 1 bájt/cím.
    16-bit régió: teljes WORD big-endian unsigned short — 2 bájt/cím."""
    for name, start, count, width in regions:
        path = base.parent / f'{base.name}_{name}.bin'
        addrs = [start + i * 2 for i in range(count) if (start + i * 2) in dump]
        if width == 8:
            buf = bytes((dump[a] & 0xFF00) >> 8 for a in addrs)
        else:
            buf = b''.join(struct.pack('>H', dump[a] & 0xFFFF) for a in addrs)
        path.write_bytes(buf)


def save_hexdump(dump: dict[int, int], path: Path) -> None:
    WORDS_PER_LINE = 8
    addrs = sorted(dump)
    lines = []
    for i in range(0, len(addrs), WORDS_PER_LINE):
        row = addrs[i:i + WORDS_PER_LINE]
        hex_parts, ascii_chars = [], []
        for a in row:
            w = dump[a] & 0xFFFF
            hex_parts.append(f'{w:04X}')
            for b in ((w >> 8) & 0xFF, w & 0xFF):
                ascii_chars.append(chr(b) if 0x20 <= b < 0x7F else '.')
        padding = '     ' * (WORDS_PER_LINE - len(row))
        lines.append(
            f'0x{row[0]:08X}: {" ".join(hex_parts)}{padding}  {"".join(ascii_chars)}'
        )
    path.write_text('\n'.join(lines) + '\n')


def save_outputs(dump: dict[int, int], metadata: dict,
                 outdir: Path, index: int,
                 regions: list[tuple[str, int, int, int]]) -> None:
    base = outdir / f'dump_{index:02d}'
    save_json(dump, metadata, base.with_suffix('.json'))
    save_binary(dump, regions, base)
    save_hexdump(dump, base.with_suffix('.hex'))


def save_summary(hashes: list[str], consistent: bool, outdir: Path,
                 regions: list[tuple[str, int, int, int]]) -> None:
    summary = {
        'timestamp':  datetime.now().isoformat(),
        'regions':    [{'name': n, 'start': f'{s:#010x}', 'words': c, 'width': w}
                       for n, s, c, w in regions],
        'gpib':       GPIB_RESOURCE,
        'consistent': consistent,
        'hashes':     hashes,
    }
    (outdir / 'summary.json').write_text(json.dumps(summary, indent=2))


def format_diff(baseline: dict[int, int], modified: dict[int, int]) -> str:
    header = ['# Differenciális elemzés',
              '# Cím           Előtte   Utána   Delta',
              '# ' + '─' * 40]
    body, changed = [], 0
    for addr in sorted(baseline):
        before = baseline[addr]
        after  = modified.get(addr, 0)  # missing addr in modified → treated as 0
        if before != after:
            body.append(f'  0x{addr:08X}   {before:+7d}  {after:+7d}  {after-before:+7d}')
            changed += 1
    footer = [f'\n# Összesen: {changed} word változott']
    return '\n'.join(header + body + footer) + '\n'


def run_differential(session: 'GpibSession', baseline: dict[int, int],
                     outdir: Path, regions: list[tuple[str, int, int]]) -> None:
    input('\n[Diff] Változtass egy front-panel értéket (pl. NPLC), '
          'majd nyomj ENTER-t...')
    print('[Diff] Módosított dump folyamatban...')
    modified  = dump_regions(session, regions)
    diff_text = format_diff(baseline, modified)
    (outdir / 'diff.txt').write_text(diff_text, encoding='utf-8')
    print(diff_text)


def main() -> None:
    args   = parse_args()
    outdir = Path(f'dump_{datetime.now().strftime("%Y%m%d_%H%M%S")}')
    outdir.mkdir()
    print(f'[*] Kimenet könyvtár: {outdir}')

    bridge_host, bridge_port = None, 1234
    if args.bridge:
        if ':' in args.bridge:
            h, p_str = args.bridge.rsplit(':', 1)
            bridge_host, bridge_port = h, int(p_str)
        else:
            bridge_host = args.bridge
        print(f'[*] Bridge: {bridge_host}:{bridge_port}')

    with GpibSession(bridge_host=bridge_host, bridge_port=bridge_port) as session:
        if args.fixed_regions:
            regions = compute_regions()
            print(f'[1/4] Fix tartományok: {len(regions)} régió')
        else:
            print('[1/4] Automatikus memória-detekció...')
            regions = auto_detect_regions(session)
            if not regions:
                print('[!] Nincs detektált régió, kilépés.')
                return

        total = sum(c for _, _, c, *_ in regions)
        print(f'      Összesen: {len(regions)} régió, {total} word ({total*2} bájt)')
        for name, start, count, width in regions:
            print(f'      {name}: {start:#010x}–{start+count*2-1:#010x} ({count} word, {width}-bit)')

        dumps = []
        for i in range(1, 4):
            print(f'\n[2/4] Dump {i}/3 ({total} word)...')
            d = dump_regions(session, regions)
            meta = {
                'timestamp':  datetime.now().isoformat(),
                'gpib':       GPIB_RESOURCE,
                'dump_index': i,
            }
            save_outputs(d, meta, outdir, i, regions)
            dumps.append(d)

        print('\n[3/4] Hash-ellenőrzés...')
        consistent, hashes = verify_dumps(dumps)
        if consistent:
            print(f'      OK Mind 3 dump egyezik: {hashes[0][:24]}...')
        else:
            print('      FIGYELMEZTETÉS: Dump-ok eltérnek!')
            for i, h in enumerate(hashes, 1):
                print(f'        Dump {i}: {h[:32]}...')

        save_summary(hashes, consistent, outdir, regions)

        if args.diff:
            print('\n[4/4] Differenciális elemzés...')
            run_differential(session, dumps[0], outdir, regions)
        else:
            print('\n[4/4] Diff kihagyva (--no-diff).')

    print(f'\n[OK] Kész. Fájlok mentve: {outdir}/')


if __name__ == '__main__':
    main()
