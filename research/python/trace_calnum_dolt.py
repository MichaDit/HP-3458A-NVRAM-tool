"""
1. CALNUM es tovabbi CAL* parancs handlerek megkeresese
2. CAL handler (0x04A9FA) teljes disassembly
3. sub_05D3A0 (CALSTR handler vegen hivodik) - mi csinal utana?
4. CAL handler '0x04A3A: move.b #$1c, $c0001' kontextusa
"""
import struct, re

try:
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_M68K, capstone.CS_MODE_M68K_000)
    md.detail = False
except ImportError:
    print('pip install capstone'); exit(1)

ROM = r'C:\Users\Mate\Desktop\teszt\FW\HP3458A_REV9_assembled_and_analysis\HP3458A_REV9_cpu_order_384K_for_Ghidra.bin'
with open(ROM, 'rb') as f:
    rom = f.read()

CMD_TABLE_START = 0x08B20
CMD_ENTRY_SIZE  = 24

def parse_cmd_table():
    entries = []
    off = CMD_TABLE_START
    while off + CMD_ENTRY_SIZE <= len(rom):
        chunk = rom[off:off + CMD_ENTRY_SIZE]
        name_len = struct.unpack('>H', chunk[0:2])[0]
        if name_len == 0 or name_len > 10:
            break
        name = chunk[2:2+name_len].decode('ascii', errors='replace')
        cmd_id    = struct.unpack('>H', chunk[12:14])[0]
        handler_hi = struct.unpack('>H', chunk[18:20])[0]
        handler_lo = struct.unpack('>H', chunk[20:22])[0]
        priv      = struct.unpack('>H', chunk[22:24])[0]
        handler   = (handler_hi << 16) | handler_lo
        entries.append({'name': name, 'cmd_id': cmd_id,
                        'handler': handler, 'priv': priv})
        off += CMD_ENTRY_SIZE
    return entries

cmds = parse_cmd_table()
cal_cmds = [c for c in cmds if 'CAL' in c['name'] or c['name'] in ('SECURE', 'ACAL', 'SCAL')]

print('=== Osszes CAL* parancs handler cim ===')
for c in cal_cmds:
    h = c['handler']
    print(f"  {c['name']:<12} handler=0x{h:06X}  priv={c['priv']}")

def print_func(addr, label, max_b=400, stop_rts=True):
    off = addr
    if off < 0 or off + max_b > len(rom):
        print(f'  (ROM-on kivul @ 0x{addr:05X})')
        return
    insns = list(md.disasm(rom[off:off+max_b], addr))
    if not insns:
        print(f'  (nem disassembly-zathato @ 0x{addr:05X})')
        return
    print(f'\n{"="*60}')
    print(f'  {label} @ 0x{addr:05X}')
    print(f'{"="*60}')
    for ins in insns:
        ops = ins.op_str
        mn  = ins.mnemonic.lower()
        flag = ''
        m = re.search(r'\$([0-9a-fA-F]+)\.l', ops)
        if m:
            t = int(m.group(1), 16)
            if t < 0x20000 and mn not in ('jsr', 'lea', 'movea.l', 'pea', 'bra', 'bne', 'beq', 'bcc', 'bcs', 'bge', 'bgt', 'ble', 'blt'):
                flag = f'   <<< IO PORT 0x{t:05X}'
            elif 0x60000 <= t <= 0x60FFF and mn not in ('jsr', 'lea', 'pea'):
                flag = f'   <<< CAL RAM 0x{t:06X}'
        m2 = re.search(r'\$([0-9a-fA-F]{5,6})\.l', ops)
        if m2:
            t2 = int(m2.group(1), 16)
            if 0x60000 <= t2 <= 0x60FFF and mn not in ('jsr', 'lea', 'pea'):
                flag = f'   <<< CAL RAM 0x{t2:06X}'
            elif 0xC0000 <= t2 <= 0xCFFFF and mn not in ('jsr', 'lea', 'pea'):
                flag = f'   <<< /WE IO 0x{t2:06X}'
        print(f'  {ins.address:05X}:  {ins.bytes.hex():<14}  {ins.mnemonic:<8} {ops}{flag}')
        if stop_rts and ins.mnemonic.lower() == 'rts':
            break

# ── 1. Minden CAL* handler disassembly ───────────────────────────────────────
for c in cal_cmds:
    h = c['handler']
    if h and h < len(rom):
        print()
        print_func(h, f"{c['name']}_handler", max_b=300)

# ── 2. sub_05D3A0 (CALSTR vegen hivodik) ─────────────────────────────────────
print()
print('=== sub_05D3A0 (CALSTR utan hivodik - checksum frissites?) ===')
print_func(0x5D3A0, 'sub_05D3A0', max_b=300)

# ── 3. 0x04A3A kontextus (move.b #$1c, $c0001) ───────────────────────────────
print()
print('=== 0x04A00 kontextus (ahol a #$1c /WE write van) ===')
print_func(0x04A00, 'context_before_04A3A', max_b=300, stop_rts=False)

# ── 4. CAL handler (0x04A9FA) teljes disassembly ──────────────────────────────
print()
print('=== CAL handler @ 0x04A9FA TELJES ===')
print_func(0x04A9FA, 'CAL_handler_full', max_b=600)

# ── 5. sub_05A3FC (CALSTR hivja eloszor) ─────────────────────────────────────
print()
print('=== sub_05A3FC (CALSTR elso hivasa) ===')
print_func(0x5A3FC, 'sub_05A3FC', max_b=200)
