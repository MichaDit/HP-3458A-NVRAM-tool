"""
Parancs mechanika elemzese - minden handler pontosan mit csinal?
Fokusz: mem-teruletek, IO-portok, mellekhatások felderítese.
NMR, SWEEP, RATIO, BUSOUT_, CAT, DIAGNOST, TONE, WAIT, TERM, ACBAND
"""
import struct, re, sys

try:
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_M68K, capstone.CS_MODE_M68K_000)
    md.detail = False
except ImportError:
    print('pip install capstone'); sys.exit(1)

ROM = r'C:\Users\Mate\Desktop\teszt\FW\HP3458A_REV9_assembled_and_analysis\HP3458A_REV9_cpu_order_384K_for_Ghidra.bin'
with open(ROM, 'rb') as f:
    rom = f.read()

def disasm(addr, max_bytes=500, follow_jsr=False):
    """Disassemblalja az adott cimtol max_bytes bajtot, RTS-ig all meg."""
    if addr <= 0 or addr >= len(rom):
        return []
    data = rom[addr:addr + max_bytes]
    return list(md.disasm(data, addr))

def explain_addr(addr):
    """Ismert cim-tartomanyok magyarazata."""
    if addr == 0xC0001:
        return 'IO /WE + SECURE flag'
    if addr == 0xC0000:
        return 'IO port (par)'
    if 0x60000 <= addr <= 0x60FFF:
        cal_off = (addr - 0x60000) // 2
        return f'cal_ram[0x{cal_off:03X}]'
    if 0x120000 <= addr <= 0x12FFFF:
        off = addr - 0x120000
        return f'settings_ram[0x{off:04X}]'
    if 0x70000 <= addr <= 0x7FFFF:
        return f'ADC_IO[0x{addr:05X}]'
    if 0x80000 <= addr <= 0x8FFFF:
        return f'ROM[0x{addr:05X}]'
    if addr < 0x20000:
        return f'RAM/IO[0x{addr:05X}]'
    return ''

def analyze_handler(name, addr, max_bytes=600):
    """Reszletes elemzes: milyen tartomanyokat erint a handler."""
    insns = disasm(addr, max_bytes)
    lines = []
    lines.append(f'Handler: {name} @ 0x{addr:05X}')
    lines.append('-' * 60)

    reads  = set()
    writes = set()
    jsrs   = []
    io_ops = []

    for ins in insns:
        mn  = ins.mnemonic.lower()
        ops = ins.op_str

        # Abszolut cim-referenciák keresése
        for m in re.finditer(r'\$([0-9a-fA-F]{4,6})\.l', ops):
            t = int(m.group(1), 16)
            expl = explain_addr(t)
            if expl:
                if 'move' in mn or 'clr' in mn or 'bset' in mn or 'bclr' in mn or 'movep' in mn:
                    if ops.startswith(f'${m.group(1)}'):
                        # cim a cel (write)
                        writes.add((t, expl))
                    else:
                        # cim a forras (read)
                        reads.add((t, expl))
                elif 'tst' in mn or 'cmp' in mn or 'btst' in mn:
                    reads.add((t, expl))

        # A5+offset hivatkozasok (settings_ram via frame pointer)
        for m in re.finditer(r'\$([0-9a-fA-F]+)\(a5\)', ops):
            off = int(m.group(1), 16)
            if 'move' in mn or 'clr' in mn:
                note = f'A5+0x{off:X}'
                if ops.find(f'${m.group(1)}(a5)') == 0:
                    writes.add((0x120000 + off, f'settings_ram via A5+0x{off:X}'))
                else:
                    reads.add((0x120000 + off, f'settings_ram via A5+0x{off:X}'))

        # JSR hívások
        if mn == 'jsr':
            m = re.search(r'\$([0-9a-fA-F]+)\.l', ops)
            if m:
                jsrs.append(int(m.group(1), 16))

        # Sor kiiratas
        expl_line = ''
        for m in re.finditer(r'\$([0-9a-fA-F]{4,6})\.l', ops):
            t = int(m.group(1), 16)
            e = explain_addr(t)
            if e:
                expl_line = f'   ; {e}'

        lines.append(f'  {ins.address:05X}: {ins.mnemonic:<8} {ops}{expl_line}')
        if mn == 'rts':
            break

    lines.append('')
    lines.append('  == Memoria hozzaferesek ==')
    if reads:
        lines.append('  OLVAS:')
        for a, e in sorted(reads):
            lines.append(f'    0x{a:06X}  {e}')
    if writes:
        lines.append('  IR:')
        for a, e in sorted(writes):
            lines.append(f'    0x{a:06X}  {e}')
    if jsrs:
        lines.append('  JSR hivasok:')
        for j in jsrs:
            lines.append(f'    -> 0x{j:05X}')
    lines.append('')
    return '\n'.join(lines)

# Elemzendo parancsok handler cimekkel (list_all_commands.py-bol)
targets = [
    ('NMR',      0x03FB78),
    ('NMR?',     0x03FAFE),
    ('SWEEP',    0x030DA8),
    ('RATIO',    0x031C46),
    ('BUSOUT_',  0x02B36C),
    ('CAT',      0x017EC0),
    ('DIAGNOST', 0x04E58A),
    ('TONE',     0x007CB4),
    ('WAIT',     0x017B06),
    ('TERM',     0x02F0A2),
    ('ACBAND',   0x031094),
    ('ACBAND?',  0x031174),
    ('RES',      0x031790),
    ('ECHO',     0x01DB86),
    ('ECHO2',    0x01DBAA),
    ('GREG_',    0x01A600),
    ('TEMP?',    0x02FB8C),
    ('ADDRESS',  0x05B7E4),
    ('ADDRESS?', 0x05B89E),
    ('LIST',     0x018756),
    ('CAL_NUM',  0x02FDF2),
    ('DEFEAT',   0x02FCAA),
]

for name, addr in targets:
    print(analyze_handler(name, addr))

print('=== KESZ ===')
