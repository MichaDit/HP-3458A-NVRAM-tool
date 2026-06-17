"""
sub_58340 vs sub_5845A - parameter konverter osszehasonlitas
Cel: megerteni milyen szamformatot varhat a JSR parancs
"""
import struct, re, sys
try:
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_M68K, capstone.CS_MODE_M68K_000)
    md.detail = False
except ImportError:
    print('pip install capstone'); sys.exit(1)

ROM = r'C:\Users\Mate\Desktop\teszt\FW\HP3458A_REV9_assembled_and_analysis\HP3458A_REV9_cpu_order_384K_for_Ghidra.bin'
rom = open(ROM, 'rb').read()

def ascii_at(addr, maxl=50):
    s = ''
    for i in range(maxl):
        if addr+i >= len(rom): break
        b = rom[addr+i]
        if b == 0: break
        s += chr(b) if 0x20 <= b <= 0x7E else f'[{b:02X}]'
    return s

def dis(addr, label='', maxb=500):
    if addr <= 0 or addr >= len(rom):
        print(f'  [ROM-on kivul: 0x{addr:05X}]'); return []
    print(f'\n{"="*60}')
    print(f'  {label}  @ 0x{addr:05X}')
    print('='*60)
    jsrs = []
    for ins in md.disasm(rom[addr:addr+maxb], addr):
        mn, ops = ins.mnemonic.lower(), ins.op_str
        note = ''
        if 'lea' in mn and '(pc)' in ops:
            m = re.search(r'\$([0-9a-fA-F]+)\(pc\)', ops)
            if m:
                t = ins.address + ins.size + int(m.group(1), 16)
                s = ascii_at(t)
                if s: note = f'  ; "{s}"'
        if mn in ('jsr','bsr'):
            m = re.search(r'\$([0-9a-fA-F]+)', ops)
            if m: jsrs.append(int(m.group(1), 16))
        print(f'  {ins.address:05X}: {ins.mnemonic:<10} {ops}{note}')
        if mn == 'rts': break
    if jsrs: print(f'  >> Hivasok: {[hex(j) for j in jsrs]}')
    return jsrs

# === 1. sub_58340 - a JSR address konverzio ===
dis(0x058340, 'sub_58340 (JSR address konverter - f[8 byte descriptor -> 32bit])')

# === 2. sub_5845A - a standard int konverzio (referencia) ===
dis(0x05845A, 'sub_5845A (standard int konverter - referencia)')

# === 3. Kozos subrutin(ok) ha van ===
# Ha mindketto ugyanazt a kozos float->int rutint hivja, akkor ugyanazt a formaatumot varjak
print()
print('=== OSSZEHASONLITAS ===')
print()

# 3a. Mi van 0x58340-nel - az elso nehany utasitas
insns_340 = list(md.disasm(rom[0x58340:0x58340+80], 0x58340))
insns_45a = list(md.disasm(rom[0x5845A:0x5845A+80], 0x5845A))

print('  sub_58340 elso utasitasok:')
for ins in insns_340[:8]:
    print(f'    {ins.address:05X}: {ins.mnemonic:<10} {ins.op_str}')

print()
print('  sub_5845A elso utasitasok:')
for ins in insns_45a[:8]:
    print(f'    {ins.address:05X}: {ins.mnemonic:<10} {ins.op_str}')

# === 4. HP 3458A parameter descriptor format azonositasa ===
# A 8 byte-os parameter descriptor formatum visszafejtese
# A HP BASIC/internal number format: 8-byte BCD vagy IEEE 754 double?
print()
print('=== HP 3458A PARAMETER DESCRIPTOR FORMATUM ===')
print()
print('  8-byte parameter descriptor:')
print('  [0-3]: d0 = mantissa high / flag / type')
print('  [4-7]: d1 = mantissa low / exponent')
print()
print('  Az NMR handler peldaja:')
print('    NMR 5 GPIB parancs eseten a 8 byte-os descriptor:')

# Keressuk meg, milyen konstanst hasonlit a firmware
# pl. 0x8A00 = numerikus literal token
for off in range(0, len(rom)-4, 2):
    word = struct.unpack('>H', rom[off:off+2])[0]
    if word == 0x8A00:
        # mi van ezt megnezve kontextusban
        insns = list(md.disasm(rom[max(0,off-4):off+10], max(0,off-4)))
        for ins in insns:
            if '8a00' in ins.op_str.lower() and 'cmp' in ins.mnemonic.lower():
                # Ez egy parameter type check
                print(f'    0x{ins.address:05X}: {ins.mnemonic} {ins.op_str}  <- 0x8A00 = numeric literal type')
                break
        break

# === 5. A LEGFONTOSABB: szimulaljuk a parameter formatumot ===
print()
print('=== SZINTAXIS ELLENORZES MAS NUMERIKUS PARANCSOKBOL ===')
print()

# WAIT handler - legegyszerubb: direkten word-ot kap
# Ha JSR 196082 mukodik ugy ahogy NMR 5 is mukodik, akkor ugyanaz a formatum
# Ez szinte biztosan igaz mert mindketto a standard command dispatcher-en megy at

print('  Bizonytalan kerdes: a firmware BCD vagy binary integer-t varhat?')
print()

# Keressuk a BCD konverzio jeleit
bcd_hints = []
for off in range(0, len(rom)-2, 2):
    word = struct.unpack('>H', rom[off:off+2])[0]
    # ABCD = BCD add, NBCD = negate BCD
    if word in (0xC100, 0x4800):  # ABCD / NBCD opcodes (approximation)
        bcd_hints.append(off)

print(f'  BCD utasitasok a ROM-ban (korigens): {len(bcd_hints)} db')
print('  (Ha sok van, BCD-t hasznal; ha keves, binary int)')

# === 6. Konkret tesztelendo szintaxisok es ajanlott sorrend ===
print()
print('='*60)
print('  AJANLOTT TESZTELESI SORREND (biztonsag szerint)')
print('='*60)
print()

test_plan = [
    ('1. LEGBIZTONSAGOSABB - csak ellenorzas',
     'ERRSTR?',
     'baseline, nincs hatas'),
    ('2. JSR SYNTAX TESZT - hiba varható ha rossz szintaxis',
     'JSR',
     'parameter nelkul -> syntax error kellene'),
    ('3. HOZZAFERHETOSEG TESZT',
     'JSR 0',
     'ha priv OK: crash (0x0000 = 0x0000 cim) - NEM AJANLOTT'),
    ('4. BIZTONSAGOS CELCIM - XYZZY (no GPIB output)',
     'JSR 97184',
     '0x17BA0 = XYZZY handler, priv=0 - easter egg'),
    ('5. BIZTONSAGOS CELCIM - CAL_NUM (mar tesztelve direkten)',
     'JSR 196082',
     '0x2FDF2 = CAL_NUM, DOLT/Defeats=0, ERRSTR? utan is ellenorizheto'),
    ('6. BIZTONSAGOS CELCIM - ECHO "TESZT"',
     'ECHO "JSR_TEST"\nJSR ??? \nERRSTR?',
     'A JSR RTS-re ugras esetere: semmi sem tortenik'),
    ('7. RTS-re ugras (NOP equivalens)',
     'JSR 1044',
     '0x0414 = ROM RTS utasitas = azonnali visszater, semmi sem tortenik'),
]

for step, cmd, reason in test_plan:
    print(f'  {step}')
    print(f'    Parancs: {cmd}')
    print(f'    Varantas: {reason}')
    print()

# === 7. Ellenorzes: 0x0414 valszinuleg RTS-e? ===
print('=== 0x0414 ellenorzes (elso RTS cim) ===')
insns = list(md.disasm(rom[0x0410:0x041A], 0x0410))
for ins in insns:
    print(f'  {ins.address:05X}: {ins.mnemonic} {ins.op_str}')

print()
print('=== 0x007B0 ellenorzes (masodik RTS cim) ===')
insns = list(md.disasm(rom[0x07AC:0x07B6], 0x07AC))
for ins in insns:
    print(f'  {ins.address:05X}: {ins.mnemonic} {ins.op_str}')

# === 8. A LEGJOBB teszt celcim: XYZZY vs RTS ===
print()
print('=== XYZZY mint teszt celcim ===')
print('  XYZZY (0x17BA0) elonye:')
print('  - priv=0 parancs -> biztosan vegrehajthat')
print('  - GPIB-en nem ad visszavalaszt (silent)')
print('  - Nem valtoztat semmin (nem ir cal_ram-ba)')
print('  - Ha mukodik: BEEP hallhato es/vagy LCD valtozik')
print()
print('  JSR 97184  <- ez a javasolt ELSO teszt')
print()
print('  Ha XYZZY GPIB-bol direkten igazolva lett (ERRSTR? = NO ERROR),')
print('  akkor a JSR 97184 ERRSTR?-je ugyanigy NO ERROR kell legyen')
print('  ES a muszeren beep/LCD valtozas latszik.')
