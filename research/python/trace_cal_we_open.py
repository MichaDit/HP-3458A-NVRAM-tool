"""
CAL handler /WE nyito/zaro IO port write disassembly.
0x04A3A: move.b #$1c, $c0001.l (CAL handler kozeleben)
0x04AF8: move.b #$18, $c0001.l (CAL handler-en belul?)
+ tobb cal_ram write rutin (0x5A22C, 0x5A2A0, 0x5A2F2)
+ 0x5A150 ISR callback (sub_05A0E4 parj)
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

def print_func(addr, label, max_b=400):
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
            if t < 0x20000 and mn not in ('jsr', 'lea', 'movea.l', 'pea', 'bra', 'bne', 'beq'):
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
        if ins.mnemonic.lower() == 'rts':
            break

# ── 1. CAL handler teruleten levo IO port write-ok kornyezete ────────────────
print('=== CAL handler / /WE context @ 0x04A3A -64 byte (0x04A00) ===')
print_func(0x04A00, 'CAL_context_before_4A3A', max_b=512)

print()
print('=== CAL handler / /WE @ 0x04AF0 (+context) ===')
print_func(0x04AF0, 'CAL_context_4AF8', max_b=300)

# ── 2. CALSTR handler kozeleben is megnezzuk ──────────────────────────────────
print()
print('=== CALSTR handler @ 0x04B162 (CAL WE nyitas koezeleben?) ===')
print_func(0x04B162, 'CALSTR_handler', max_b=400)

# ── 3. Tovabbi cal_ram write rutinok (5A22C, 5A2A0, 5A2F2) ───────────────────
print()
print('=== sub_05A22C (tovabbi cal_ram writer) ===')
print_func(0x5A22C, 'sub_05A22C', max_b=300)

print()
print('=== sub_05A2A0 ===')
print_func(0x5A2A0, 'sub_05A2A0', max_b=300)

print()
print('=== sub_05A2F2 ===')
print_func(0x5A2F2, 'sub_05A2F2', max_b=300)

# ── 4. 0x5A150 ISR callback (sub_05A0E4 parj) ────────────────────────────────
print()
print('=== ISR callback 0x5A150 (sub_05A0E4 par) ===')
print_func(0x5A150, 'ISR_callback_5A150', max_b=128)

# ── 5. sub_005BC ISR context (00734 / 0074E) ─────────────────────────────────
print()
print('=== Startup /WE init @ 0x00730 ===')
print_func(0x00730, 'startup_we_init_730', max_b=128)

# ── 6. sub_05B5FC (szinten /WE write-ot tartalmaz) ────────────────────────────
print()
print('=== sub_05B5FC ===')
print_func(0x5B5FC, 'sub_05B5FC', max_b=200)

# ── 7. 0x5A070 kornyezete (c0001 olvasas) ─────────────────────────────────────
print()
print('=== sub_05A070 (c0001 olvasas kontextus) ===')
print_func(0x5A070, 'sub_05A070_read_c0001', max_b=200)

# ── 8. Osszes 0xC0001 write-ra MILYEN ertek kerul? ────────────────────────────
print()
print('=== 0xC0001-re irt ertekek osszefoglaloja ===')
writes = {
    0x04A3A: '#$1c', 0x04AF8: '#$18',
    0x5A130: 'd6|0x80', 0x5A1B0: 'd6|0x80',
    0x5A22C: '?', 0x5A2A0: '?', 0x5A2F2: '?',
    0x5B5FC: 'd0',
    0x50486: 'd3', 0x504A2: 'd3', 0x50584: 'd3', 0x506CA: 'd0',
}
print(f'  Cim     Ertek           Magyarazat')
print(f'  {"─"*50}')
# 0x1c = 0001 1100, 0x18 = 0001 1000, 0x80 = 1000 0000
for addr, val in sorted(writes.items()):
    print(f'  0x{addr:05X}: {val:<15}  ({hex(addr)})')
