"""
HP 3458A CAL handler trace — megkeresi a /WE nyitó IO port write-ot.

1. Parancstáblából kiolvas minden CAL* handler cím-et
2. Capstone M68K disassembly-val trace-eli a hívásláncot
3. Kiemeli az IO port write utasításokat (MOVE.B/BSET/BCLR abs.l cím-ekre)
"""

import struct, sys
try:
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_M68K, capstone.CS_MODE_M68K_000)
    md.detail = True
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False
    print('HIBA: capstone nem telepítve. pip install capstone')
    sys.exit(1)

ROM_FILE = r'C:\Users\Mate\Desktop\teszt\FW\HP3458A_REV9_assembled_and_analysis\HP3458A_REV9_cpu_order_384K_for_Ghidra.bin'
ROM_BASE = 0x000000
CMD_TABLE_START = 0x08B20
CMD_ENTRY_SIZE  = 24

with open(ROM_FILE, 'rb') as f:
    rom = f.read()

ROM_SIZE = len(rom)

def rom_read(addr, n):
    off = addr - ROM_BASE
    if off < 0 or off + n > ROM_SIZE:
        return None
    return rom[off:off+n]

def rom_word(addr):
    b = rom_read(addr, 2)
    return struct.unpack('>H', b)[0] if b else None

def rom_long(addr):
    b = rom_read(addr, 4)
    return struct.unpack('>I', b)[0] if b else None


# ── 1. Parancstábla beolvasása ────────────────────────────────────────────────

def parse_cmd_table():
    entries = []
    off = CMD_TABLE_START
    while off + CMD_ENTRY_SIZE <= ROM_SIZE:
        chunk = rom[off:off + CMD_ENTRY_SIZE]
        name_len = struct.unpack('>H', chunk[0:2])[0]
        if name_len == 0 or name_len > 10:
            break
        name = chunk[2:2+name_len].decode('ascii', errors='replace')
        cmd_id    = struct.unpack('>H', chunk[12:14])[0]
        flags     = struct.unpack('>H', chunk[14:16])[0]
        marker    = struct.unpack('>H', chunk[16:18])[0]   # 0x89EA
        handler_hi = struct.unpack('>H', chunk[18:20])[0]
        handler_lo = struct.unpack('>H', chunk[20:22])[0]
        priv      = struct.unpack('>H', chunk[22:24])[0]
        handler   = (handler_hi << 16) | handler_lo
        entries.append({'name': name, 'cmd_id': cmd_id, 'flags': flags,
                        'handler': handler, 'priv': priv, 'off': off})
        off += CMD_ENTRY_SIZE
    return entries

cmds = parse_cmd_table()
print(f'Parancstábla: {len(cmds)} bejegyzés')
print()

# CAL* parancsok kilistázása
print('=== CAL* parancsok ===')
cal_cmds = [c for c in cmds if c['name'].startswith('CAL') or c['name'] in ('SECURE', 'ACAL', 'SCAL')]
for c in cal_cmds:
    h = c['handler']
    hstr = f'0x{h:06X}' if h else '(token)'
    print(f"  {c['name']:<12} cmd_id=0x{c['cmd_id']:04X}  handler={hstr}  priv={c['priv']}")
print()


# ── 2. Disassembly helper ─────────────────────────────────────────────────────

def disasm_at(addr, max_insns=80, max_bytes=256, label=None, indent='  '):
    """Disassembly egy cím-től, visszaadja az utasítások listáját."""
    off = addr - ROM_BASE
    if off < 0 or off >= ROM_SIZE:
        return []
    chunk = rom[off:off + max_bytes]
    insns = list(md.disasm(chunk, addr))
    return insns[:max_insns]

def is_io_write(ins):
    """IO port write: MOVE.B / BSET / BCLR abs.l célra (addr < 0x20000)."""
    mn = ins.mnemonic.lower()
    ops = ins.op_str
    if mn in ('move.b', 'bset', 'bclr', 'bchg'):
        # abs.l target cím keresése az operandusban
        import re
        m = re.search(r'\$([0-9a-fA-F]+)\.l', ops)
        if m:
            target = int(m.group(1), 16)
            if target < 0x20000:   # IO port (nem RAM, nem ROM terület)
                return target
    return None

def is_jsr(ins):
    mn = ins.mnemonic.lower()
    if mn == 'jsr':
        import re
        m = re.search(r'\$([0-9a-fA-F]+)', ins.op_str)
        if m:
            return int(m.group(1), 16)
    return None

def is_rts(ins):
    return ins.mnemonic.lower() in ('rts', 'rte', 'unlk')


# ── 3. Handler trace (2 szint mélység) ───────────────────────────────────────

def trace_handler(start_addr, name, depth=0, visited=None):
    if visited is None:
        visited = set()
    if start_addr in visited or depth > 3:
        return
    visited.add(start_addr)

    indent = '  ' * depth
    print(f'{indent}>>> {name} @ 0x{start_addr:06X}')

    off = start_addr - ROM_BASE
    if off < 0 or off >= ROM_SIZE:
        print(f'{indent}    (ROM-on kívül)')
        return

    insns = disasm_at(start_addr, max_insns=120, max_bytes=400)
    if not insns:
        print(f'{indent}    (nem disassembly-zható)')
        return

    io_found = []
    jsr_targets = []

    for ins in insns:
        io_target = is_io_write(ins)
        if io_target is not None:
            line = f'{indent}  {ins.address:06X}: {ins.mnemonic:<8} {ins.op_str}'
            print(f'{line}   <== IO PORT WRITE target=0x{io_target:06X}')
            io_found.append((ins.address, io_target))

        jsr_t = is_jsr(ins)
        if jsr_t and jsr_t != start_addr:
            jsr_targets.append((ins.address, jsr_t))
            if depth < 2:
                print(f'{indent}  {ins.address:06X}: JSR  0x{jsr_t:06X}')

        if is_rts(ins) and ins.mnemonic.lower() == 'rts':
            print(f'{indent}  {ins.address:06X}: RTS  (vége)')
            break

    # Rekurzív JSR követés (csak ha nem volt IO write itt)
    if not io_found and depth < 2:
        for call_addr, jsr_t in jsr_targets[:6]:   # max 6 JSR/függvény
            off2 = jsr_t - ROM_BASE
            if 0 <= off2 < ROM_SIZE:
                trace_handler(jsr_t, f'sub_{jsr_t:06X}', depth + 1, visited)

    return io_found


# ── 4. Fő trace: CAL handler ─────────────────────────────────────────────────

print('=' * 70)
print('CAL handler teljes trace (IO port write keresés)')
print('=' * 70)

# CAL parancs (nem CAL?, nem CALSTR, nem CALNUM?)
cal_main = [c for c in cal_cmds if c['name'] == 'CAL' and c['handler'] != 0]
if not cal_main:
    print('Nem találtam CAL handler-t!')
else:
    for c in cal_main:
        print(f"\n--- CAL handler: 0x{c['handler']:06X}  (priv={c['priv']}) ---\n")
        trace_handler(c['handler'], 'CAL_handler')

# ACAL és CALSTR is érdekes (szintén ír cal_ram-ba)
print()
print('=' * 70)
print('CALSTR handler trace')
print('=' * 70)
calstr = [c for c in cal_cmds if c['name'] == 'CALSTR' and c['handler'] != 0]
for c in calstr:
    print(f"\n--- CALSTR handler: 0x{c['handler']:06X} ---\n")
    trace_handler(c['handler'], 'CALSTR_handler')
