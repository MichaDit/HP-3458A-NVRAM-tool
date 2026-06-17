"""
Mély elemzés: fejlesztői parancsok, CIIL protokoll, és ismeretlen parancsok
- GREG_, CRASH_, BOMB?, JUNK_, XYZZY, AUXERR?, CSB
- CIIL state machine (OPN/CLS/INX/FTH/STA/IST/FNC/RST)
- JSR, MADDR, ANNUN_, SSTATE, RSTATE, STB?, RQS, SCROLL
- R, T, R?, T?, U_RANGE, D_RANGE
- SYNCPARM_, FILLBIN, RMEM?_, TBUFF, SSAC/SSDC
- DSP, DSP?, MCOUNT?, MSIZE, MSIZE?, PAUSED?, SIZE?
- SMATH, MMATH, RMATHV, OCOMP, FSOURCE, EXTOUT
- Math: SIN/COS/ATN/EXP/LOG/LGT/SQR/ABS, BINCMP/BINAND/BINIOR...
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
    n = ''
    for m in re.finditer(r'\$([0-9a-fA-F]{4,6})(?:\.l)?', ops):
        t = int(m.group(1), 16)
        if t == 0xC0001:   n = '  ; IO_PORT(/WE+SEC)'
        elif t == 0x70000: n = '  ; ADC_DATA'
        elif t == 0x70003: n = '  ; ADC_READY'
        elif t == 0x8001E: n = '  ; SAR_DAC'
        elif t == 0x80000: n = '  ; ADC_CTRL[0]'
        elif t == 0x80002: n = '  ; ADC_CTRL[2]'
        elif t == 0x80006: n = '  ; GPIB_CTRL[6] (SPOLL/IRQ)'
        elif t == 0x8000A: n = '  ; GPIB_CTRL[A]'
        elif t == 0x8000C: n = '  ; GPIB_CTRL[C]'
        elif t == 0xD0001: n = '  ; IO_D0001'
        elif 0x60000 <= t <= 0x60FFF:
            n = f'  ; cal_ram[0x{(t-0x60000)//2:03X}]'
        elif 0x120000 <= t <= 0x12FFFF:
            n = f'  ; sram[0x{t-0x120000:04X}]'
    return n

def pcrel_str(pc_at_end, offset_hex):
    """PC-relativ cim kiszamitasa."""
    return pc_at_end + int(offset_hex, 16)

def ascii_at(addr, max_len=80):
    s = ''
    for i in range(max_len):
        if addr + i >= len(rom): break
        b = rom[addr + i]
        if b == 0: break
        if 0x20 <= b <= 0x7E: s += chr(b)
        else: s += f'\\x{b:02X}'
    return s

def dis(addr, label='', maxb=600, stop_rts=True):
    if addr <= 0 or addr >= len(rom):
        print(f'  [{label}] ROM-on kivul: 0x{addr:05X}')
        return []
    insns = list(md.disasm(rom[addr:addr+maxb], addr))
    print(f'\n{"="*64}')
    print(f'  {label}  @ 0x{addr:05X}')
    print('='*64)
    jsrs = []
    for ins in insns:
        mn  = ins.mnemonic.lower()
        ops = ins.op_str
        n   = note(ops)
        # PC-relativ string keresese (lea $xxxx(pc),a0)
        pcs = ''
        if mn == 'lea' and '(pc)' in ops:
            m = re.search(r'\$([0-9a-fA-F]+)\(pc\)', ops)
            if m:
                target = ins.address + ins.size + int(m.group(1), 16)
                s = ascii_at(target, 40)
                if s: pcs = f'  ; "{s}"'
        print(f'  {ins.address:05X}: {ins.mnemonic:<10} {ops}{n}{pcs}')
        if mn == 'jsr':
            m = re.search(r'\$([0-9a-fA-F]+)\.l', ops)
            if m: jsrs.append(int(m.group(1), 16))
        elif mn == 'bsr':
            m = re.search(r'\$([0-9a-fA-F]+)', ops)
            if m: jsrs.append(int(m.group(1), 16))
        if stop_rts and mn == 'rts':
            break
    if jsrs:
        print(f'  >> Hivasok: {[hex(j) for j in jsrs]}')
    return jsrs

# ============================================================
# 1. FEJLESZTOI PARANCSOK - reszletes
# ============================================================
print('\n' + '#'*64)
print('# 1. FEJLESZTOI PARANCSOK')
print('#'*64)

# GREG_ es a 0x19FE2 subroutine
dis(0x01A600, 'GREG_ (Greg debug parancsa)')
dis(0x019FE2, 'sub_19FE2 (GREG_ target - mi ez?)')

# CRASH_ - build datum string
dis(0x00053C, 'CRASH_ (szandekos crash)')
print()
print('  CRASH_ utan kozott ASCII szovegek a ROM-ban:')
for off in range(0, 200):
    addr = 0x0053C + off
    s = ascii_at(addr, 40)
    if len(s) >= 8:
        print(f'    0x{addr:05X}: "{s}"')
        break

# BOMB? - settings_ram dump mechanika
dis(0x0176A6, 'BOMB? (settings_ram dump)')
dis(0x05337A, 'sub_5337A (BOMB? - memcpy rutinja?)')
dis(0x01F530, 'sub_1F530 (BOMB? / tobbi - GPIB send?)')

# JUNK_ - mi a parameter? mi a logika?
dis(0x003AB2, 'JUNK_ (factory junk test, priv=2)', 800)
# JUNK_ string keresese
print()
print('  JUNK_ PC-relativ string cimai:')
junk_strings = []
for ins in md.disasm(rom[0x003AB2:0x003AB2+800], 0x003AB2):
    if ins.mnemonic.lower() == 'lea' and '(pc)' in ins.op_str:
        m = re.search(r'\$([0-9a-fA-F]+)\(pc\)', ins.op_str)
        if m:
            target = ins.address + ins.size + int(m.group(1), 16)
            s = ascii_at(target, 50)
            if s and target not in junk_strings:
                junk_strings.append(target)
                print(f'    0x{target:05X}: "{s}"')
    if ins.mnemonic.lower() == 'rts':
        break

# AUXERR?
dis(0x0037CC, 'AUXERR? (auxiliary error lekerdezes)')

# CSB - GPIB Status Byte clear (GPIB chip IO)
dis(0x004270, 'CSB (Clear Status Byte - GPIB chip)')

# XYZZY
dis(0x017BA0, 'XYZZY (easter egg)')
print()
target_xyzzy = 0x017BA8 + 4 + 0x185C0  # korigens szamitas
# Pontosan: 0x017BAC: lea $185c0(pc),a0 -> PC=0x017BAE, offset=0x185C0 -> ???
# Inkabb direkt olvasas
for ins in md.disasm(rom[0x017BA0:0x017BA0+30], 0x017BA0):
    if ins.mnemonic.lower() == 'lea' and '(pc)' in ins.op_str:
        m = re.search(r'\$([0-9a-fA-F]+)\(pc\)', ins.op_str)
        if m:
            t = ins.address + ins.size + int(m.group(1), 16)
            s = ascii_at(t, 60)
            print(f'  XYZZY string @ 0x{t:05X}: "{s}"')
dis(0x01D8B8, 'sub_1D8B8 (XYZZY LCD display rutin?)')

# ============================================================
# 2. CIIL PROTOKOLL - state machine rekonstrukcio
# ============================================================
print('\n' + '#'*64)
print('# 2. CIIL PROTOKOLL - teljes state machine')
print('#'*64)

ciil_cmds = [
    ('CIIL',      0x04E91E, 'Aktivalas, PRESET, TRIG HOLD'),
    ('CIIL?',     0x04E814, 'Allapot lekerdezes'),
    ('CIILMODE?', 0x04E89A, 'Mod lekerdezes'),
    ('GAL',       0x04E9AA, 'Generic Array Language'),
    ('CANCIIL',   0x04E9E4, 'Megszakitas'),
    ('GETCIIL',   0x04E996, 'Adat fogadasa'),
    ('IST',       0x04E9F2, 'Instrument Self Test (priv=3)'),
    ('CNF',       0x04EA1C, 'Config (=> IST)'),
    ('OPN',       0x04E7B0, 'Csatorna megnyitasa (priv=3)'),
    ('CLS',       0x04E7E2, 'Csatorna zarasa (priv=3)'),
    ('INX',       0x04EA26, 'Index/felvesz adat (priv=3)'),
    ('FTH',       0x04EB2E, 'Fetch adat (priv=3)'),
    ('STA',       0x04EBD2, 'Status lekerdezes (priv=3)'),
    ('RST',       0x04EBC4, 'Reset (priv=3)'),
    ('FNC',       0x04FD46, 'Function (priv=3)'),
]
for name, addr, desc in ciil_cmds:
    dis(addr, f'{name} - {desc}')

# CIIL alap-subroutine (0x4E596 - minden CIIL ellenorzi)
dis(0x04E596, 'sub_4E596 (CIIL elofeltetelek ellenorzese)')

# ============================================================
# 3. UJ ISMERETLEN PARANCSOK - elso kor elemzes
# ============================================================
print('\n' + '#'*64)
print('# 3. ISMERETLEN PARANCSOK - elso elemzesi kor')
print('#'*64)

unknown_cmds = [
    ('JSR',       0x017C28, 'GPIB szubrutin-ugras parancs! priv=1'),
    ('MADDR',     0x017C8C, 'Memory address beallitas'),
    ('ANNUN_',    0x008124, 'Annunciator (LED/szegmens) vezerlese'),
    ('SSTATE',    0x00433A, 'Save State -> settings_ram'),
    ('RSTATE',    0x004412, 'Restore State <- settings_ram'),
    ('STB?',      0x004176, 'Status Byte lekerdezes'),
    ('RQS',       0x004138, 'Request Service (SRQ)'),
    ('RQS?',      0x0041EE, 'RQS allapot lekerdezes'),
    ('CSB',       0x004270, 'Clear Status Byte (GPIB chip)'),
    ('SCROLL',    0x007B2A, 'Display scroll'),
    ('DSP',       0x01DB0A, 'Display string GPIB-rol'),
    ('DSP?',      0x007FB2, 'Display olvasas'),
    ('MENU',      0x0053D2, 'Menu aktivalas'),
    ('MENU?',     0x005430, 'Menu allapot'),
    ('PURGE',     0x0047F0, 'Program/memoria torlese'),
    ('FILLBIN',   0x0183EE, 'Binarisan tolt memoria'),
    ('RMEM?_',    0x01BE08, 'Read Memory (factory)'),
    ('SIZE?',     0x017EA0, 'Program merete'),
    ('MCOUNT?',   0x01DEFA, 'Memory meres szamlalo'),
    ('MSIZE',     0x027AAA, 'Memory merete beallitas'),
    ('MSIZE?',    0x027AB2, 'Memory merete lekerdezes'),
    ('PAUSED?',   0x010462, 'Program paused allapot'),
    ('SUB',       0x018818, 'Subroutine definicio'),
    ('R',         0x0315DE, 'R parancs (?)'),
    ('T',         0x0331B6, 'T parancs (?)'),
    ('R?',        0x01F2E0, 'R lekerdezes'),
    ('T?',        0x01EC68, 'T lekerdezes'),
    ('U_RANGE',   0x0316D4, 'Up range leptet'),
    ('D_RANGE',   0x031732, 'Down range leptet'),
    ('SYNCPARM_', 0x0397DE, 'Sync parametere (factory)'),
    ('TBUFF',     0x033D86, 'Trigger buffer'),
    ('TBUFF?',    0x01E0AE, 'Trigger buffer lekerdezes'),
    ('SSAC',      0x030C02, 'Scale/Sens AC'),
    ('SSPARM?',   0x01E70E, 'Sweep/sens parameterek lekerdezes'),
    ('OCOMP',     0x031494, 'Offset Compensation'),
    ('OCOMP?',    0x0204CE, 'Offset Compensation lekerdezes'),
    ('FSOURCE',   0x0314FA, 'Frequency Source beallitas'),
    ('FSOURCE?',  0x020B02, 'Frequency Source lekerdezes'),
    ('EXTOUT',    0x032CF8, 'External Output beallitas'),
    ('EXTOUT?',   0x01E1AE, 'External Output lekerdezes'),
    ('SMATH',     0x054284, 'Set Math fuggveny'),
    ('MMATH',     0x0536DA, 'Memory Math'),
    ('MMATH?',    0x01E336, 'Memory Math lekerdezes'),
    ('RMATHV',    0x053E88, 'Reset Math Value'),
    ('OPT?',      0x0175DA, 'Options lekerdezes (priv=2)'),
    ('HELP',      0x017544, 'Help (priv=1)'),
    ('ACDCI',     0x030A28, 'AC/DC input beallitas (?)'),
]

for name, addr, desc in unknown_cmds:
    dis(addr, f'{name} ({desc})', 500)

# ============================================================
# 4. MATH ES BIT PARANCSOK - beepitett programnyelv
# ============================================================
print('\n' + '#'*64)
print('# 4. BEEPITETT PROGRAMNYELV - MATH es BIT ops')
print('#'*64)

math_cmds = [
    ('SIN',    0x05694E),
    ('COS',    0x056956),
    ('ATN',    0x05695E),
    ('EXP',    0x056966),
    ('LOG',    0x05696E),
    ('LGT',    0x056976),
    ('SQR',    0x05697E),
    ('ABS',    0x056986),
    ('BINCMP', 0x056618),
    ('BINAND', 0x056600),
    ('BINIOR', 0x056608),
    ('BINEOR', 0x056610),
    ('BIT',    0x05662C),
    ('SHIFT',  0x056654),
    ('ROTATE', 0x05666C),
]
for name, addr in math_cmds:
    dis(addr, f'{name}', 150)

print('\n=== KESZ ===')
