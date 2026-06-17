"""
BUSOUT_ handler teljes mechanika elemzese.
Cim: 0x02B36C
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

def disasm_func(addr, max_bytes=800, label=''):
    if addr <= 0 or addr >= len(rom):
        print(f'  [ROM-on kivul: 0x{addr:05X}]')
        return []
    insns = list(md.disasm(rom[addr:addr+max_bytes], addr))
    print(f'\n{"="*65}')
    if label:
        print(f'  {label}')
    print(f'  @ 0x{addr:05X}')
    print('='*65)
    result = []
    for ins in insns:
        mn  = ins.mnemonic.lower()
        ops = ins.op_str
        note = ''

        # IO/memory notation
        for m in re.finditer(r'\$([0-9a-fA-F]{4,6})(?:\.l)?', ops):
            t = int(m.group(1), 16)
            if t == 0xC0001:
                note = '  ; <<< IO: /WE + SECURE reg'
            elif t == 0x70000:
                note = '  ; <<< ADC IO data port'
            elif t == 0x70003:
                note = '  ; <<< ADC IO status/ready port'
            elif t == 0x8001E:
                note = '  ; <<< 0x8001E (DAC control? mystery reg)'
            elif 0x60000 <= t <= 0x60FFF:
                note = f'  ; <<< cal_ram[0x{(t-0x60000)//2:03X}]'
            elif 0x120000 <= t <= 0x12FFFF:
                note = f'  ; <<< settings_ram[0x{t-0x120000:04X}]'
            elif t < 0x20000 and mn not in ('jsr','bra','bne','beq','bcc','bcs','bge','blt','bgt','ble','lea','movea.l','pea'):
                note = f'  ; <<< RAM/IO 0x{t:05X}'

        print(f'  {ins.address:05X}: {ins.mnemonic:<10} {ops}{note}')
        result.append(ins)
        if mn == 'rts':
            break
    return result

# --- 1. BUSOUT_ fő handler ---
print('BUSOUT_ parameter szintaxis es mechanika elemzes')
print()
print('Fontos regiszterek:')
print('  a0 = 0x8001E  -> ismeretlen reg (DAC?)')
print('  a1 = 0xC0001  -> IO port (/WE + SECURE)')
print('  a2 = 0x70000  -> ADC IO data')
print('  a3 = 0x70003  -> ADC IO status/ready')
print('  d1 = N param  -> loop counter (BUSOUT_ N)')
print('  d2 = 0x01     -> bit mask (0xC0001 bit 1 teszteleshez)')
print('  d3 = 0x00     -> bit mask (0x70003 bit 0 teszteleshez)')

insns = disasm_func(0x02B36C, 500, 'BUSOUT_ handler')

# --- 2. sub_0277C8 meghivott szubrutinok ---
print()
print('--- Sub-rutinok amelyeket BUSOUT_ hiv ---')

# sub_02778C: interrupt / callback helper
disasm_func(0x02778C, 200, 'sub_02778C (BUSOUT_ callback / interrupt handler)')

# sub_05B606: ?
disasm_func(0x05B606, 200, 'sub_05B606 (BUSOUT_ cleanup?)')

# sub_0087CC: ?
disasm_func(0x0087CC, 200, 'sub_0087CC (BUSOUT_ finalize?)')

# --- 3. A 0x8001E memoriateruleten olvassuk ki a kornyezetet ---
print()
print('='*65)
print('  0x8001E kornyezet: mi van ott a ROM-ban?')
print('='*65)
# Az 0x8001E egy IO port (nem ROM). De van-e mas hivatkozas ra?
import re as _re
hits = []
for i in range(0, len(rom)-4):
    word = struct.unpack('>I', rom[i:i+4])[0]
    if word == 0x0008001E:  # LEA.L / MOVEA.L #$8001E
        hits.append(i)
    elif word == 0x8001E000:
        hits.append(i)

print(f'  0x8001E abszolut cimhivatkozas a ROM-ban ({len(hits)} hely):')
for h in hits[:20]:
    ctx = rom[max(0,h-2):h+6]
    insns2 = list(md.disasm(rom[max(0,h-4):h+8], max(0,h-4)))
    for ins in insns2:
        if ins.address >= h-2 and ins.address <= h+2:
            print(f'    0x{ins.address:05X}: {ins.mnemonic} {ins.op_str}')

# --- 4. 0x70000 es 0x70003 ADC IO port kornyezet ---
print()
print('='*65)
print('  0x70000 ADC IO port hivatkozasok a ROM-ban')
print('='*65)
adc_hits = []
for i in range(0, len(rom)-4):
    word = struct.unpack('>I', rom[i:i+4])[0]
    if word == 0x00070000 or word == 0x00070003:
        adc_hits.append((i, word))

print(f'  Osszes 0x70000/70003 hivatkozas: {len(adc_hits)}')
for h, w in adc_hits[:30]:
    insns3 = list(md.disasm(rom[max(0,h-4):h+8], max(0,h-4)))
    for ins in insns3:
        if abs(ins.address - h) <= 4:
            print(f'    0x{ins.address:05X}: {ins.mnemonic:<10} {ins.op_str}')
            break

# --- 5. 0xC0001 bit 1 ertelmezese ---
print()
print('='*65)
print('  0xC0001 IO port bit-terkep:')
print('='*65)
print('  bit 7 = DS1220Y /WE (Write Enable, 1=iras engedett)')
print('  bit 0 = SECURE flag (1=secured, 0=unsecured)')
print('  bit 1 = ??? (BUSOUT_ ellenorzi: btst.l #1, 0xC0001)')
print()
print('  BUSOUT_ loop feltetel:')
print('  btst.l d2, (a1)   ahol d2=1, a1=0xC0001')
print('  -> ha bit 1 SET: exit loop (meres veget jelzi?)')
print('  -> ha bit 1 CLEAR: folytatas')
print()
print('  A 0xC0001 bit 1 megvizsgalasa mas helyeken...')

# Keressuk a btst ... 0xC0001 mintazatot
c0001_refs = []
for i in range(0, len(rom)-6):
    chunk = rom[i:i+20]
    insns4 = list(md.disasm(chunk, i))
    for ins in insns4:
        if '0xc0001' in ins.op_str.lower() or 'c0001' in ins.op_str.lower():
            c0001_refs.append((ins.address, ins.mnemonic, ins.op_str))
            break

print(f'  Osszes 0xC0001 hivatkozas: {len(c0001_refs)}')
for addr, mn, ops in c0001_refs[:40]:
    print(f'    0x{addr:05X}: {mn:<10} {ops}')
