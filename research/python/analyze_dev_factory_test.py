"""
Fejleszto parancsok, gyari parancsok es selftest rutinok elemzese.
- GREG_, CRASH_, BOMB?, XYZZY, JUNK_
- LOADREAL_, TRIGGER_, DCBD_, ACBD_, ADMEM_, ADCAL_, INGRD_
- TEST, IST, DIAGNOST startup selftest
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

def note(ops):
    for m in re.finditer(r'\$([0-9a-fA-F]{4,6})(?:\.l)?', ops):
        t = int(m.group(1), 16)
        if t == 0xC0001:   return '  ; IO /WE+ADC+SEC'
        if t == 0x70000:   return '  ; ADC DATA'
        if t == 0x70003:   return '  ; ADC STATUS'
        if t == 0x8001E:   return '  ; SAR DAC'
        if t == 0x80000:   return '  ; ADC CTRL[0]'
        if t == 0x80002:   return '  ; ADC CTRL[2]'
        if 0x60000 <= t <= 0x60FFF:
            return f'  ; cal_ram[0x{(t-0x60000)//2:03X}]'
        if 0x120000 <= t <= 0x12FFFF:
            return f'  ; sram[0x{t-0x120000:04X}]'
    return ''

def disasm_func(addr, max_bytes=400, label=''):
    if addr <= 0 or addr >= len(rom):
        print(f'  [ROM-on kivul: 0x{addr:05X}]')
        return
    insns = list(md.disasm(rom[addr:addr+max_bytes], addr))
    print(f'\n{"="*60}')
    print(f'  {label}  @ 0x{addr:05X}')
    print('='*60)
    jsrs = []
    for ins in insns:
        mn  = ins.mnemonic.lower()
        ops = ins.op_str
        n   = note(ops)
        print(f'  {ins.address:05X}: {ins.mnemonic:<10} {ops}{n}')
        if mn == 'jsr':
            m = re.search(r'\$([0-9a-fA-F]+)\.l', ops)
            if m:
                jsrs.append(int(m.group(1), 16))
        if mn == 'rts':
            break
    if jsrs:
        print(f'  >> JSR hivasok: {[f"0x{j:05X}" for j in jsrs]}')

def ascii_at(addr, max_len=80):
    """ASCII szoveg olvasasa ROM-bol adott cimrol."""
    s = ''
    for i in range(max_len):
        b = rom[addr + i]
        if b == 0:
            break
        if 0x20 <= b <= 0x7E:
            s += chr(b)
        else:
            s += f'\\x{b:02X}'
    return s

# ─────────────────────────────────────────────────────────────
# 1. FEJLESZTOI PARANCSOK
# ─────────────────────────────────────────────────────────────
print('=== 1. FEJLESZTOI PARANCSOK ===')

# GREG_ @ 0x01A600
disasm_func(0x01A600, 300, 'GREG_ (Greg fejleszto debug rutinja)')

# CRASH_ @ 0x00053C
disasm_func(0x00053C, 200, 'CRASH_ (szandekos crash + build datum)')
# CRASH_ utan ASCII build datum keresese
crash_area = rom[0x0053C:0x005A0]
print('  CRASH_ kornyekeben ASCII szovegek:')
for off in range(0, len(crash_area)):
    if all(0x20 <= crash_area[off+i] <= 0x7E for i in range(8) if off+i < len(crash_area)):
        s = ''
        for i in range(40):
            if off+i >= len(crash_area) or crash_area[off+i] == 0:
                break
            s += chr(crash_area[off+i])
        if len(s) >= 8:
            print(f'    0x{0x053C+off:05X}: "{s}"')
            break

# BOMB? @ 0x0176A6
disasm_func(0x0176A6, 300, 'BOMB? (settings_ram dump)')

# JUNK_ @ 0x003AB2 (priv=2)
disasm_func(0x003AB2, 200, 'JUNK_ (junk/garbage test, priv=2)')

# XYZZY @ 0x017BA0
disasm_func(0x017BA0, 150, 'XYZZY (Colossal Cave easter egg)')
# Megnezzuk, van-e ASCII szoveg a XYZZY utan
print('  XYZZY kornyekeben ASCII szoveg:')
for off in range(0, 200):
    addr = 0x017BA0 + off
    if addr >= len(rom): break
    s = ''
    while addr + len(s) < len(rom):
        b = rom[addr + len(s)]
        if b == 0 or not (0x20 <= b <= 0x7E):
            break
        s += chr(b)
    if len(s) >= 10:
        print(f'    0x{addr:05X}: "{s}"')

# ─────────────────────────────────────────────────────────────
# 2. GYARI PARANCSOK (factory calibration block 0x04B5xx)
# ─────────────────────────────────────────────────────────────
print()
print('=== 2. GYARI PARANCSOK (0x04B5xx factory cal block) ===')

factory_cmds = [
    ('LOADREAL_', 0x04B58A),
    ('TRIGGER_',  0x04B592),
    ('DCBD_',     0x04B5CC),
    ('ACBD_',     0x04B616),
    ('ADMEM_',    0x04B650),
    ('ADCAL_',    0x04B68A),
    ('INGRD_',    0x04B6D4),
    ('ENTER',     0x04B6E8),
    ('OUTPUT',    0x04B75E),
]

for name, addr in factory_cmds:
    disasm_func(addr, 300, name)

# Az ENTER handler utan keressuk a parameterformatumot
print()
print('  ENTER parameterformat: A5 offset-ek')
for name, addr in factory_cmds[1:]:  # LOADREAL_ utan
    insns = list(md.disasm(rom[addr:addr+300], addr))
    offsets = []
    for ins in insns:
        m = re.search(r'\$([0-9a-fA-F]{3,4})\(a5\)', ins.op_str)
        if m:
            off = int(m.group(1), 16)
            if off not in offsets:
                offsets.append(off)
        if ins.mnemonic.lower() == 'rts':
            break
    if offsets:
        print(f'  {name:<12}: A5+[{", ".join(f"0x{o:04X}" for o in offsets)}]')

# ─────────────────────────────────────────────────────────────
# 3. SELFTEST / TEST / IST
# ─────────────────────────────────────────────────────────────
print()
print('=== 3. SELFTEST / TEST / IST parancsok ===')

# A parancstablabol kell kiolvasni a TEST handler cimet
# list_all_commands.py eredmenye alapjan (kor. elemzesbol):
# TEST handler keresese

CMD_TABLE_START = 0x08B20
CMD_ENTRY_SIZE  = 24

def find_cmd(name):
    off = CMD_TABLE_START
    while off + CMD_ENTRY_SIZE <= len(rom):
        chunk = rom[off:off + CMD_ENTRY_SIZE]
        nlen = struct.unpack('>H', chunk[0:2])[0]
        if nlen == 0 or nlen > 10:
            break
        n = chunk[2:2+nlen].decode('ascii', errors='?')
        if n == name:
            h_hi = struct.unpack('>H', chunk[18:20])[0]
            h_lo = struct.unpack('>H', chunk[20:22])[0]
            handler = (h_hi << 16) | h_lo
            priv = struct.unpack('>H', chunk[22:24])[0]
            return handler, priv
        off += CMD_ENTRY_SIZE
    return None, None

for cmd in ['TEST', 'IST', 'DIAGNOST', 'RESET', 'PRESET']:
    h, p = find_cmd(cmd)
    if h:
        disasm_func(h, 400, f'{cmd} (priv={p})')
    else:
        print(f'  {cmd}: nem talalhato a parancstablabol')

# ─────────────────────────────────────────────────────────────
# 4. STARTUP SELFTEST keresese
# ─────────────────────────────────────────────────────────────
print()
print('=== 4. STARTUP / INIT szekvencia ===')

# A 68000 vektor tabla (0x0000): reset vector = [4] (SSP), [8] (PC)
ssp = struct.unpack('>I', rom[4:8])[0]
pc  = struct.unpack('>I', rom[8:12])[0]
print(f'  Reset SSP: 0x{ssp:08X}')
print(f'  Reset PC:  0x{pc:08X}  (startup entry point)')
print()
disasm_func(pc & 0x3FFFF if pc > 0x80000 else pc, 300, 'Startup entry point')

# 0x00730 (startup /WE init - kor. elemzesbol ismert)
disasm_func(0x00730, 150, 'Startup /WE init @ 0x730')
