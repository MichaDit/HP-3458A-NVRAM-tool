"""
sub_05A158 ISR callback (0x5A1D0) és rokon rutinok disassembly-ja.
Cél: megérteni pontosan hogyan nyílik a DS1220Y /WE latch a cal_ram íráshoz.
"""
import struct

try:
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_M68K, capstone.CS_MODE_M68K_000)
    md.detail = False
except ImportError:
    print('pip install capstone'); exit(1)

ROM = r'C:\Users\Mate\Desktop\teszt\FW\HP3458A_REV9_assembled_and_analysis\HP3458A_REV9_cpu_order_384K_for_Ghidra.bin'
with open(ROM, 'rb') as f:
    rom = f.read()

IO_PORTS   = {0xC0001, 0x11800, 0x12800, 0x11, 0xE, 0x1BC, 0x1C0, 0x40, 0x60}
CALRAM_LO  = 0x60000
CALRAM_HI  = 0x60FFF

def print_func(addr, label, max_b=512):
    off = addr
    if off < 0 or off + max_b > len(rom):
        print(f'  (ROM-on kívül @ 0x{addr:05X})')
        return
    insns = list(md.disasm(rom[off:off+max_b], addr))
    if not insns:
        print(f'  (nem disassembly-zható @ 0x{addr:05X})')
        return
    print(f'\n{"="*60}')
    print(f'  {label} @ 0x{addr:05X}')
    print(f'{"="*60}')
    for ins in insns:
        ops = ins.op_str
        mn  = ins.mnemonic.lower()
        flag = ''
        import re
        # IO port (cél < 0x20000 vagy ismert cím)
        m = re.search(r'\$([0-9a-fA-F]+)\.l', ops)
        if m:
            t = int(m.group(1), 16)
            if t < 0x20000 and mn not in ('jsr', 'lea', 'movea.l', 'pea', 'bra', 'bne', 'beq'):
                flag = f'   <<< IO PORT 0x{t:05X}'
            elif CALRAM_LO <= t <= CALRAM_HI and mn not in ('jsr', 'lea', 'pea'):
                flag = f'   <<< CAL RAM 0x{t:06X}'
        m2 = re.search(r'\$([0-9a-fA-F]{5,6})\.l', ops)
        if m2:
            t2 = int(m2.group(1), 16)
            if CALRAM_LO <= t2 <= CALRAM_HI and mn not in ('jsr', 'lea', 'pea'):
                flag = f'   <<< CAL RAM 0x{t2:06X}'
        print(f'  {ins.address:05X}:  {ins.bytes.hex():<14}  {ins.mnemonic:<8} {ops}{flag}')
        if ins.mnemonic.lower() == 'rts':
            break

# ── 1. sub_05A158 ISR callback @ 0x5A1D0 ────────────────────────────────────
print('=== sub_05A158 ISR callback @ 0x5A1D0 (a TRAP #5 lefutásakor hívódik) ===')
print_func(0x5A1D0, 'ISR_callback_5A1D0', max_b=256)

# ── 2. sub_05A0E4 (a cal_ram olvasó párja?) ──────────────────────────────────
print()
print('=== sub_05A0E4 (hasonló cal_ram rutin, 0x5A0E4) ===')
print_func(0x5A0E4, 'sub_05A0E4', max_b=300)

# ── 3. sub_05A0BE (ahova sub_05A158 ugrik beq.w esetén) ─────────────────────
print()
print('=== 0x5A0BE (beq.w cél sub_05A158-ban) ===')
print_func(0x5A0BE, 'sub_05A0BE_err_handler', max_b=128)

# ── 4. 0x58620 és 0x58608 (sub_05B96A hívásai) ──────────────────────────────
print()
print('=== sub_058620 (sub_05B96A -> JSR $58620) ===')
print_func(0x58620, 'sub_058620', max_b=300)

print()
print('=== sub_058608 (sub_05B96A -> JSR $58608) ===')
print_func(0x58608, 'sub_058608', max_b=200)

# ── 5. sub_05B96A teljes kód (CAL belső write loop hívója) ───────────────────
print()
print('=== sub_05B96A TELJES (CAL belső loop) ===')
print_func(0x5B96A, 'sub_05B96A_full', max_b=400)

# ── 6. sub_05A444 és sub_05A50C ──────────────────────────────────────────────
print()
print('=== sub_05A444 ===')
print_func(0x5A444, 'sub_05A444', max_b=200)

print()
print('=== sub_05A50C (sub_05CE4C hívja többször) ===')
print_func(0x5A50C, 'sub_05A50C', max_b=200)

print()
print('=== sub_05A342 (sub_05CE4C checksum loop) ===')
print_func(0x5A342, 'sub_05A342', max_b=200)

# ── 7. BSET/BCLR keresése az ismert IO portokra (0x0C0001 környéke) ──────────
print()
print('=== ROM-ban minden write 0x0C0001 IO portra ===')
import re
for i in range(0, len(rom)-8, 2):
    chunk = rom[i:i+8]
    insns = list(md.disasm(chunk, i))
    if not insns:
        continue
    ins = insns[0]
    if '0c0001' in ins.op_str.lower() or 'c0001' in ins.op_str.lower():
        print(f'  {ins.address:05X}: {ins.mnemonic} {ins.op_str}')

# ── 8. Teljes ROM scan: minden IO write 0x0B0000-0x0FFFFF tartományba ─────────
print()
print('=== ROM-ban write-ok 0xC0000-0xCFFFF IO terület ===')
pattern = b'\x13\xC6'  # MOVE.B D6,(abs.l) — ez volt sub_05A158-ban
idx = 0
while True:
    pos = rom.find(pattern, idx)
    if pos == -1 or pos > 0x60000:
        break
    if pos + 6 <= len(rom):
        target = struct.unpack('>I', rom[pos+2:pos+6])[0]
        if 0xC0000 <= target <= 0xCFFFF:
            insns = list(md.disasm(rom[pos:pos+8], pos))
            if insns:
                print(f'  {pos:05X}: {insns[0].mnemonic} {insns[0].op_str}')
    idx = pos + 2
