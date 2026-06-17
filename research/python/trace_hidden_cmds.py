"""
Rejtett GPIB parancsok disassembly-ja.
Fokuszban: LOADREAL_, DEFEAT, ADCAL_, ADMEM_, DCBD_, ACBD_, INGRD_,
XYZZY, CIIL, CAL_NUM, GREG_, CRASH_
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
            if t < 0x20000 and mn not in ('jsr','lea','movea.l','pea','bra','bne','beq','bcc','bcs','bge','bgt','ble','blt'):
                flag = f'   <<< IO PORT 0x{t:05X}'
            elif 0x60000 <= t <= 0x60FFF and mn not in ('jsr','lea','pea'):
                flag = f'   <<< CAL RAM 0x{t:06X}'
        m2 = re.search(r'\$([0-9a-fA-F]{5,6})\.l', ops)
        if m2:
            t2 = int(m2.group(1), 16)
            if 0x60000 <= t2 <= 0x60FFF and mn not in ('jsr','lea','pea'):
                flag = f'   <<< CAL RAM 0x{t2:06X}'
            elif 0xC0000 <= t2 <= 0xCFFFF and mn not in ('jsr','lea','pea'):
                flag = f'   <<< /WE IO 0x{t2:06X}'
        print(f'  {ins.address:05X}:  {ins.bytes.hex():<14}  {ins.mnemonic:<8} {ops}{flag}')
        if ins.mnemonic.lower() == 'rts':
            break

# ── 1. LOADREAL_ — kalibracios ertek betoltese cal_ram-ba? ──────────────────
print('=== LOADREAL_ @ 0x04B58A ===')
print_func(0x04B58A, 'LOADREAL_', max_b=300)

# ── 2. DEFEAT — Defeats mezo irasa? ─────────────────────────────────────────
print()
print('=== DEFEAT @ 0x02FCAA ===')
print_func(0x02FCAA, 'DEFEAT', max_b=300)

# ── 3. DEFEAT? @ 0x01E032 ───────────────────────────────────────────────────
print()
print('=== DEFEAT? @ 0x01E032 ===')
print_func(0x01E032, 'DEFEAT?', max_b=200)

# ── 4. Factory cal blokk (0x04B5xx) ─────────────────────────────────────────
print()
print('=== TRIGGER_ @ 0x04B592 ===')
print_func(0x04B592, 'TRIGGER_', max_b=200)

print()
print('=== DCBD_ @ 0x04B5CC ===')
print_func(0x04B5CC, 'DCBD_', max_b=200)

print()
print('=== ACBD_ @ 0x04B616 ===')
print_func(0x04B616, 'ACBD_', max_b=200)

print()
print('=== ADMEM_ @ 0x04B650 ===')
print_func(0x04B650, 'ADMEM_', max_b=200)

print()
print('=== ADCAL_ @ 0x04B68A ===')
print_func(0x04B68A, 'ADCAL_', max_b=200)

print()
print('=== INGRD_ @ 0x04B6D4 ===')
print_func(0x04B6D4, 'INGRD_', max_b=200)

# ── 5. XYZZY easter egg ──────────────────────────────────────────────────────
print()
print('=== XYZZY @ 0x017BA0 ===')
print_func(0x017BA0, 'XYZZY', max_b=128)

# ── 6. CIIL es IST/CNF/STA (priv=3, legmagasabb privilege!) ─────────────────
print()
print('=== CIIL @ 0x04E91E (priv=2) ===')
print_func(0x04E91E, 'CIIL', max_b=200)

print()
print('=== IST @ 0x04E9F2 (priv=3 - legmagasabb!) ===')
print_func(0x04E9F2, 'IST', max_b=200)

print()
print('=== OPN @ 0x04E7B0 (priv=3) ===')
print_func(0x04E7B0, 'OPN', max_b=200)

# ── 7. CAL_NUM @ 0x02FDF2 ───────────────────────────────────────────────────
print()
print('=== CAL_NUM @ 0x02FDF2 ===')
print_func(0x02FDF2, 'CAL_NUM', max_b=200)

# ── 8. Fejlesztoi parancsok ──────────────────────────────────────────────────
print()
print('=== GREG_ @ 0x01A600 ===')
print_func(0x01A600, 'GREG_', max_b=128)

print()
print('=== CRASH_ @ 0x00053C ===')
print_func(0x00053C, 'CRASH_', max_b=128)

print()
print('=== BOMB? @ 0x0176A6 ===')
print_func(0x0176A6, 'BOMB?', max_b=128)

# ── 9. BUSOUT_ — cal adat kiment? ────────────────────────────────────────────
print()
print('=== BUSOUT_ @ 0x02B36C ===')
print_func(0x02B36C, 'BUSOUT_', max_b=300)

# ── 10. NMR / NMR? ──────────────────────────────────────────────────────────
print()
print('=== NMR @ 0x03FB78 ===')
print_func(0x03FB78, 'NMR', max_b=200)

# ── 11. ENTER/OUTPUT/OUTDISP (CIIL IO) ──────────────────────────────────────
print()
print('=== ENTER @ 0x04B6E8 (CIIL) ===')
print_func(0x04B6E8, 'ENTER_CIIL', max_b=200)

print()
print('=== OUTPUT @ 0x04B75E (CIIL) ===')
print_func(0x04B75E, 'OUTPUT_CIIL', max_b=200)
