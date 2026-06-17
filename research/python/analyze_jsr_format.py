"""
JSR parancs parameterformatum visszafejtese:
- sub_585A0 disassembly (a JSR parameter-to-address konverter)
- sub_585C8 osszehasonlitas (standard int parser - ismert referencia)
- Privilege szint ellenorzese: priv=1 vs GPIB hozzaferheto parancsok
- Biztonságos tesztelési célcímek azonosítása
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

def ascii_at(addr, maxl=60):
    s = ''
    for i in range(maxl):
        if addr+i >= len(rom): break
        b = rom[addr+i]
        if b == 0: break
        s += chr(b) if 0x20 <= b <= 0x7E else f'[{b:02X}]'
    return s

def dis(addr, label='', maxb=400):
    if addr <= 0 or addr >= len(rom):
        print(f'  [ROM-on kivul: 0x{addr:05X}]'); return
    print(f'\n{"="*60}')
    print(f'  {label}  @ 0x{addr:05X}')
    print('='*60)
    jsrs = []
    for ins in md.disasm(rom[addr:addr+maxb], addr):
        mn, ops = ins.mnemonic.lower(), ins.op_str
        note = ''
        if '(pc)' in ops and 'lea' in mn:
            m = re.search(r'\$([0-9a-fA-F]+)\(pc\)', ops)
            if m:
                t = ins.address + ins.size + int(m.group(1), 16)
                s = ascii_at(t, 40)
                if s: note = f'  ; "{s}"'
        for m in re.finditer(r'\$([0-9a-fA-F]{4,6})', ops):
            t = int(m.group(1), 16)
            if 0x120000 <= t <= 0x12FFFF: note = f'  ; sram[0x{t-0x120000:04X}]'
        if mn in ('jsr','bsr'):
            m = re.search(r'\$([0-9a-fA-F]+)', ops)
            if m: jsrs.append(int(m.group(1), 16))
        print(f'  {ins.address:05X}: {ins.mnemonic:<10} {ops}{note}')
        if mn == 'rts': break
    if jsrs:
        print(f'  >> Hivasok: {[hex(j) for j in jsrs]}')
    return jsrs

# === 1. JSR handler ===
dis(0x017C28, 'JSR parancs handler')

# === 2. sub_585A0 - a JSR parameter parseroloja ===
dis(0x0585A0, 'sub_585A0 (JSR parameter -> address konverter)')

# === 3. sub_585C8 - standard integer parser (referencia) ===
dis(0x0585C8, 'sub_585C8 (standard integer parser - ismert referencia)')

# === 4. sub_58608 / sub_58620 - token matchers (ACBAND-bol ismert) ===
dis(0x058608, 'sub_58608 (token matcher 1 - ACBAND-bol ismert)')
dis(0x058620, 'sub_58620 (token matcher 2)')

# === 5. Privilege szint vizsgalat ===
# Megvizsgaljuk, melyik priv=1 parancs mukodik GPIB-en (mar teszteltek)
print('\n' + '='*60)
print('  PRIVILEGE SZINT ELEMZES')
print('='*60)
print()
print('  Tesztelt priv=1 parancsok (GPIB-en mukodok):')
print('    TEMP?   (priv=1, 0x02FB8C) -> "35.6" [CONFIRMED]')
print('    DEFEAT? (priv=1, 0x01E032) -> "0"    [CONFIRMED]')
print('    ADDRESS?(priv=1, 0x05B89E) -> "22"   [CONFIRMED]')
print()
print('  Tesztelt priv=0 parancsok:')
print('    CAL_NUM (priv=0, 0x02FDF2) -> NO ERROR [CONFIRMED]')
print('    ECHO    (priv=0, 0x01DB86) -> string   [CONFIRMED]')
print()
print('  Konkluzio: priv=1 = standard GPIB user szint')
print('  JSR (priv=1) ELÉRHETŐ GPIB-ROL!')

# === 6. Biztonsagos teszt celcimek ===
print('\n' + '='*60)
print('  BIZTONSAGOS TESZT CELCIMEK')
print('='*60)

safe_targets = [
    (0x017C56, 'JSR handler RTS - azonnal visszater (NOP teszt)'),
    (0x02FDF2, 'CAL_NUM - DOLT/Defeats=0 (mar tesztelve!)'),
    (0x001CE4, 'sub_1CE4 - CIIL/CANCIIL reset rutin'),
    (0x017BB8, 'XYZZY RTS - azonnal visszater (NOP+1 teszt)'),
    (0x04562,  'PRESET(arg) - de stack-et var, direkt nem biztonságos'),
]

print()
for addr, desc in safe_targets:
    # Mi van ott pontosan?
    insns = list(md.disasm(rom[addr:addr+6], addr))
    first = insns[0] if insns else None
    first_str = f'{first.mnemonic} {first.op_str}' if first else '???'
    print(f'  0x{addr:05X}: {first_str:<25} -> {desc}')

# === 7. A JSR utan: mi van a celcimen? Ellenorizzuk a legbiztonságosabbat ===
print()
print('  Legbiztonsagosabb: RTS-re mutat')
rts_targets = []
for off in range(0, len(rom)-2, 2):
    word = struct.unpack('>H', rom[off:off+2])[0]
    if word == 0x4E75:  # RTS opcode
        rts_targets.append(off)

print(f'  RTS utasitasok szama a ROM-ban: {len(rts_targets)}')
print(f'  Elso nehany RTS cim:')
for t in rts_targets[:5]:
    print(f'    0x{t:05X}')

# === 8. Decimalis konverzio a JSR-hez ===
print()
print('='*60)
print('  JSR DECIMAL PARAMETEREK (tesztelendo celcimek)')
print('='*60)
test_addrs = [
    (0x02FDF2, 'CAL_NUM - DOLT/Defeats nullazas (biztonságos!)'),
    (0x017BA0, 'XYZZY - easter egg (biztonságos, priv=0)'),
    (rts_targets[0], 'Elso ROM RTS (azonnal visszater - lehetseges NOP)'),
    (rts_targets[1], 'Masodik ROM RTS'),
]
for addr, desc in test_addrs:
    print(f'  JSR {addr}  (0x{addr:05X} = {addr})  -> {desc}')

print()
print('  FONTOS: ha a firmware decimalist var, akkor:')
print('    JSR 196082    -> CAL_NUM (0x02FDF2)')
print()
print('  SZINTAXIS VALTOZATOK (tesztelendo):')
print('    JSR 196082')
print('    JSR 131072    (0x20000 - ROM kezdete, nem hasznos de arf)')
print('    Valoszinuleg: GPIB-en JSR<szokoz><decimalis_szam>')

# === 9. Parameter struktura vizsgalat - mas parancsok alapjan ===
print()
print('='*60)
print('  PARAMETER STRUKTURA VIZSGALAT')
print('='*60)
print()
print('  A WAIT parancs (priv=1) hasonlo egyszamu parameter fogadas:')
dis(0x017B06, 'WAIT parancs handler (referencia - 1 numerikus param)')

print()
print('  Az NMR parancs (priv=1) hasonlo:')
dis(0x03FB78, 'NMR parancs handler (referencia - 1 numerikus param)')
