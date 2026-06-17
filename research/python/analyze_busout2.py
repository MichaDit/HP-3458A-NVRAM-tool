"""
BUSOUT_ ADC mechanika merlyebb elemzese:
- 0x70000 / 0x70003 ADC IO funkcioja
- 0x8001E 'mystery' reg funkcioja
- 0x80000 / 0x80002 ADC control regiszterek
- sub_05B606 cleanup mechanika
- A teljes SAR ADC algoritmus rekonstrukcioja
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

def disasm_range(addr, max_bytes=300, label=''):
    if addr <= 0 or addr >= len(rom):
        return
    insns = list(md.disasm(rom[addr:addr+max_bytes], addr))
    if label:
        print(f'\n{"="*60}')
        print(f'  {label} @ 0x{addr:05X}')
        print('='*60)
    for ins in insns:
        mn  = ins.mnemonic.lower()
        ops = ins.op_str
        note = ''
        for m in re.finditer(r'\$([0-9a-fA-F]{4,6})(?:\.l)?', ops):
            t = int(m.group(1), 16)
            if t == 0xC0001:   note = '  ; IO /WE+SEC'
            elif t == 0x70000: note = '  ; ADC DATA'
            elif t == 0x70001: note = '  ; ADC D+1'
            elif t == 0x70002: note = '  ; ADC D+2'
            elif t == 0x70003: note = '  ; ADC STATUS/READY'
            elif t == 0x8001E: note = '  ; DAC/SAR feedback'
            elif t == 0x80000: note = '  ; ADC CTRL[0]'
            elif t == 0x80002: note = '  ; ADC CTRL[2]'
            elif 0x60000 <= t <= 0x60FFF:
                note = f'  ; cal_ram[0x{(t-0x60000)//2:03X}]'
            elif 0x120000 <= t <= 0x12FFFF:
                note = f'  ; sram[0x{t-0x120000:04X}]'
        print(f'  {ins.address:05X}: {ins.mnemonic:<10} {ops}{note}')
        if mn == 'rts':
            break

# --- 1. 0x70000 terulet hivatkozasok elso 10 helyen kontextusban ---
print('=== 0x70000 ADC IO port kontextusa a ROM-ban ===')
print()

hits_70000 = []
i = 0
while i < len(rom) - 4:
    word = struct.unpack('>I', rom[i:i+4])[0]
    if word == 0x00070000 or word == 0x00070003:
        hits_70000.append(i)
    i += 1

print(f'70000/70003 hivatkozasok szama: {len(hits_70000)}')
print()

# Megmutatjuk az elso 15 unikalis fuggvenycim korulibeli kodot
seen = set()
count = 0
for h in hits_70000:
    func_region = (h // 0x100) * 0x100
    if func_region in seen or count >= 10:
        continue
    seen.add(func_region)
    count += 1
    insns = list(md.disasm(rom[h-4:h+20], h-4))
    for ins in insns:
        if h-4 <= ins.address <= h+16:
            ops = ins.op_str
            note = ''
            if '70000' in ops: note = '  ; ADC DATA'
            if '70003' in ops: note = '  ; ADC STATUS'
            if '8001e' in ops.lower(): note = '  ; DAC feedback'
            if '80000' in ops.lower(): note = '  ; ADC CTRL'
            print(f'  0x{ins.address:05X}: {ins.mnemonic:<10} {ops}{note}')
    print()

# --- 2. 0x80000 / 0x80002 ADC control regiszterek ---
print()
print('=== 0x80000 es 0x80002 ADC control regiszterek ===')
print()

hits_80000 = []
i = 0
while i < len(rom) - 4:
    word = struct.unpack('>I', rom[i:i+4])[0]
    if word in (0x00080000, 0x00080002, 0x00080001, 0x00080003):
        hits_80000.append(i)
    i += 1

print(f'0x80000/80002 hivatkozasok: {len(hits_80000)}')
seen2 = set()
for h in hits_80000[:20]:
    fr = (h // 0x100) * 0x100
    if fr in seen2:
        continue
    seen2.add(fr)
    insns = list(md.disasm(rom[max(0,h-4):h+16], max(0,h-4)))
    for ins in insns:
        if h-6 <= ins.address <= h+12:
            ops = ins.op_str
            note = ''
            if '80000' in ops.lower(): note = '  ; ADC CTRL[0]'
            if '80002' in ops.lower(): note = '  ; ADC CTRL[2]'
            if '8001e' in ops.lower(): note = '  ; SAR feedback'
            if 'c0001' in ops.lower(): note = '  ; /WE IO'
            print(f'  0x{ins.address:05X}: {ins.mnemonic:<10} {ops}{note}')
    print()

# --- 3. sub_05B606 elott/utan levo kod (ADC reset szekvencia) ---
disasm_range(0x05B5F0, 200, 'ADC reset blokk (sub_05B606 kornyezete)')

# --- 4. A 0x8001E hivatkozasok teljes listaja ---
print()
print('=== 0x8001E SAR/DAC hivatkozasok osszes helye ===')
hits_8001e = []
i = 0
while i < len(rom) - 4:
    word = struct.unpack('>I', rom[i:i+4])[0]
    if word == 0x0008001E:
        hits_8001e.append(i)
    i += 1
print(f'Osszes 0x8001E hivatkozas: {len(hits_8001e)}')
for h in hits_8001e:
    insns = list(md.disasm(rom[max(0,h-4):h+12], max(0,h-4)))
    for ins in insns:
        if h-4 <= ins.address <= h+4:
            print(f'  0x{ins.address:05X}: {ins.mnemonic:<10} {ins.op_str}  ; SAR/DAC feedback reg')
    print()

# --- 5. A SAR ADC algoritmus rekonstrukcioja ---
print()
print('=== BUSOUT_ SAR ADC algoritmus rekonstrukcioja ===')
print()
print('  BUSOUT_ N  parametere: N = loop iteraciok szama (szamlalo)')
print()
print('  Pszeudonyelv:')
print('  -----------------------------------------------')
print('  d0 = 0  (SAR regiszter: aktualis becslés)')
print('  d5 = 0x7FFF  (max pozitiv)')
print('  d6 = 0x8000  (max negativ / legkisebb)')
print()
print('  Loop (N-szer):')
print('    if 0xC0001.bit1 == 1: goto next_iter  ; stop bit = ADC abort/interrupt')
print('    write d0 -> 0x8001E  ; DAC: feedback ertek kuldese')
print('    while 0x70003.bit0 == 0: wait  ; var ADC konverzio keszen')
print('    d4 = read(0x70000)  ; ADC eredmeny olvasasa')
print('    if d4 > 0:   d0 = 0x7FFF; next_iter  ; ADC > 0: full pos')
print('    if d4 < 0xFFFF: d0 = 0x8000; next_iter  ; ADC neg: full neg')
print('    d0 = read(0x70000)  ; masodszori olvasas (pontositas)')
print('    if d0 XOR d4 < 0: bisect(d0/d5/d6)  ; SAR bisekció')
print('  next_iter: N--; if N>0 goto Loop')
print()
print('  Vegeredmeny: d0 az utolso SAR becsles (raw 16-bit ADC ertek)')
print()
print('  Fuggveny:')
print('  sub_05B606 = cleanup: ADC reset (0x80000=0x37, 0x80002=0x88),')
print('               IO port visszaallitas (0xC0001 = sram[0x185A])')
print('  sub_02778C = abort check (visszater 1 ha abort kell, 0 ha nem)')
print('  sub_0087CC = finalize (DCV mod visszaallitas?)')
