"""
Két párhuzamos keresés:
A) sub_003124 és más jelöltek mélyebb disassembly-ja
B) ROM-ban MOVE.W utasítások a 0x60000-0x60FFF cal_ram tartományra
C) IO port cím-ekre (0x0000-0x00FF) mutató MOVE.B/BSET/BCLR az egész ROM-ban
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

def disasm_func(addr, max_b=512):
    off = addr
    if off < 0 or off + max_b > len(rom):
        return []
    return list(md.disasm(rom[off:off+max_b], addr))

def print_func(addr, label, max_b=512):
    insns = disasm_func(addr, max_b)
    if not insns:
        print(f'  (nem disassembly-zható @ 0x{addr:05X})')
        return
    print(f'\n{"="*60}')
    print(f'  {label} @ 0x{addr:05X}')
    print(f'{"="*60}')
    for ins in insns:
        line = f'  {ins.address:05X}:  {ins.bytes.hex():<14}  {ins.mnemonic:<8} {ins.op_str}'
        # Kiemelés
        ops = ins.op_str
        mn  = ins.mnemonic.lower()
        flag = ''
        # IO port write (cél < 0x200)
        m = re.search(r'\$([0-9a-fA-F]{1,4})\.l', ops)
        if m:
            t = int(m.group(1), 16)
            if t < 0x200 and mn not in ('jsr', 'lea', 'movea.l', 'move.l'):
                flag = f'   <<< IO PORT 0x{t:04X}'
            elif 0x60000 <= t <= 0x60FFF:
                flag = f'   <<< CAL RAM WRITE 0x{t:05X}'
        # cal_ram tartomány (0x60000)
        m2 = re.search(r'\$([0-9a-fA-F]{5,6})\.l', ops)
        if m2:
            t2 = int(m2.group(1), 16)
            if 0x60000 <= t2 <= 0x60FFF and mn not in ('jsr', 'lea', 'pea'):
                flag = f'   <<< CAL RAM WRITE 0x{t2:06X}'
        print(line + flag)
        if ins.mnemonic.lower() == 'rts':
            break

# ── A) Jelölt rutinok részletes disassembly-ja ────────────────────────────────
print('=== A) JELÖLT RUTINOK ===')
candidates = [
    (0x003124, 'sub_003124 (CAL+CALSTR közös)'),
    (0x05BB22, 'sub_05BB22 (CALSTR belső)'),
    (0x05BC2C, 'sub_05BC2C (CAL belső)'),
    (0x05B96A, 'sub_05B96A'),
    (0x05BA46, 'sub_05BA46'),
    (0x05A158, 'sub_05A158'),
    (0x05A4EA, 'sub_05A4EA'),
    (0x05D07C, 'sub_05D07C'),
    (0x05CE4C, 'sub_05CE4C'),
]
for addr, label in candidates:
    print_func(addr, label, max_b=300)

# ── B) MOVE.W a cal_ram tartományra (0x60000-0x60FFF) ─────────────────────────
print()
print()
print('=== B) ROM-ban cal_ram tartományra (0x60000-0x60FFF) irányuló MOVE.W ===')
# MOVE.W (Dn),(abs.l): 33 Cx 00 06 xx xx
# MOVE.W (An),(abs.l): 33 Dx 00 06 xx xx  (D0=33D0, D1=33D2, A0=33D0 ...)
# Keressük a 0x0006 prefixet az abs.l cím-ben
i = 0
found = []
while i < len(rom) - 5:
    # abs.l cím high word = 0x0006
    if rom[i] == 0x00 and rom[i+1] == 0x06:
        # Valószínűleg egy abs.l cím közepén járunk, de ellenőrzés:
        # Vagy keressük az opcode-ot 2 byte-tal előbb
        for back in (2, 4):
            if i - back >= 0:
                op = struct.unpack('>H', rom[i-back:i-back+2])[0]
                # MOVE.W src,(abs.l): opcode magas nibble = 0x33
                if (op & 0xFF00) == 0x3300 and op != 0x3300:
                    addr_val = struct.unpack('>I', rom[i:i+4])[0]
                    if 0x60000 <= addr_val <= 0x60FFF:
                        insn_addr = i - back
                        found.append(insn_addr)
                        insns = list(md.disasm(rom[insn_addr:insn_addr+8], insn_addr))
                        if insns:
                            print(f'  {insn_addr:05X}: {insns[0].mnemonic} {insns[0].op_str}')
    i += 2

if not found:
    print('  Nem található direkt cal_ram abs.l write.')
    print('  (Valószínűleg közvetett: A0-ba betöltve a cím, majd MOVE.W Dn,(A0))')

# ── C) MOVE.W Dn,(A0) mintakeresés a cal_ram közelében ───────────────────────
print()
print('=== C) Indirect cal_ram write: LEA 0x6xxxx,A0 + MOVE.W Dn,(A0) minta ===')
# LEA abs.l, A0 = 0x41F9 0x0006xxxx
i = 0
while i < len(rom) - 10:
    if rom[i:i+2] == b'\x41\xF9':   # LEA abs.l, A0
        target = struct.unpack('>I', rom[i+2:i+6])[0]
        if 0x60000 <= target <= 0x60FFF:
            # Megnézzük mi következik
            insns = list(md.disasm(rom[i:i+30], i))
            print(f'  {i:05X}: LEA 0x{target:06X},A0  -> következő utasítások:')
            for ins in insns[:6]:
                flag = ' <<< WRITE' if ins.mnemonic.lower().startswith('move') and '(a0)' in ins.op_str else ''
                print(f'    {ins.address:05X}: {ins.mnemonic} {ins.op_str}{flag}')
    i += 2
