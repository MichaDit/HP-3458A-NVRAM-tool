"""Reszletes ellenorzesek - T, CIIL string-ek, GREG_ offsets"""
import capstone, re
md = capstone.Cs(capstone.CS_ARCH_M68K, capstone.CS_MODE_M68K_000)
md.detail = False
rom = open(r'C:\Users\Mate\Desktop\teszt\FW\HP3458A_REV9_assembled_and_analysis\HP3458A_REV9_cpu_order_384K_for_Ghidra.bin','rb').read()

A5_BASE = 0x120000  # settings_ram báziscíme (közelítés)

def ascii_at(addr, maxl=60):
    s = ''
    for i in range(maxl):
        if addr+i >= len(rom): break
        b = rom[addr+i]
        if b == 0: break
        s += chr(b) if 0x20 <= b <= 0x7E else f'.{b:02X}.'
    return s

def get_strings_and_offsets(start, maxb=400):
    strs = []
    offs = []
    for ins in md.disasm(rom[start:start+maxb], start):
        ops = ins.op_str
        mn  = ins.mnemonic.lower()
        # PC-relativ string
        if 'lea' in mn and '(pc)' in ops:
            m = re.search(r'\$([0-9a-fA-F]+)\(pc\)', ops)
            if m:
                t = ins.address + ins.size + int(m.group(1), 16)
                s = ascii_at(t)
                if s: strs.append((t, s))
        # A5 offsetek
        if '(a5)' in ops:
            m = re.search(r'\$([0-9a-fA-F]+)\(a5\)', ops)
            if m:
                off = int(m.group(1), 16)
                offs.append((ins.address, mn, ops, off))
        if mn == 'rts':
            break
    return strs, offs

# === T parancs ===
print('=== T parancs (0x331B6) - TRIG mode ===')
strs, offs = get_strings_and_offsets(0x331B6, 500)
print('  String-ek:')
for t,s in strs: print(f'    0x{t:05X}: "{s}"')
print('  A5 offsetek:')
for addr,mn,ops,off in offs: print(f'    {addr:05X}: {mn:<8} {ops}  -> A5+0x{off:04X}')

# === R parancs ===
print()
print('=== R parancs (0x315DE) - RANGE set ===')
strs, offs = get_strings_and_offsets(0x315DE, 500)
print('  String-ek:')
for t,s in strs: print(f'    0x{t:05X}: "{s}"')
print('  A5 offsetek (elso 15):')
for addr,mn,ops,off in offs[:15]: print(f'    {addr:05X}: {mn:<8} {ops}  -> A5+0x{off:04X}')

# === CIIL aktivaciokor megjelenített string-ek ===
print()
print('=== CIIL handler string-ek (0x4E91E) ===')
strs, offs = get_strings_and_offsets(0x4E91E, 200)
print('  String-ek:')
for t,s in strs: print(f'    0x{t:05X}: "{s}"')

print()
print('=== CIIL? string-ek (0x4E814) ===')
strs, offs = get_strings_and_offsets(0x4E814, 200)
for t,s in strs: print(f'    0x{t:05X}: "{s}"')

print()
print('=== CIILMODE? string-ek (0x4E89A) ===')
strs, offs = get_strings_and_offsets(0x4E89A, 200)
for t,s in strs: print(f'    0x{t:05X}: "{s}"')

print()
print('=== IST belső string-ek / selftest rutin 0x1780E ===')
strs, offs = get_strings_and_offsets(0x1780E, 600)
print('  String-ek:')
for t,s in strs: print(f'    0x{t:05X}: "{s}"')
print('  A5 offsetek:')
for addr,mn,ops,off in offs[:20]: print(f'    {addr:05X}: {mn:<8} {ops}  -> A5+0x{off:04X}')

# === GREG_ - 0x19FE2 offsets ===
print()
print('=== GREG_ sub_19FE2 - A5 offsetek ===')
strs, offs = get_strings_and_offsets(0x19FE2, 400)
print('  String-ek:')
for t,s in strs: print(f'    0x{t:05X}: "{s}"')
print('  A5 offsetek:')
for addr,mn,ops,off in offs: print(f'    {addr:05X}: {mn:<8} {ops}  -> A5+0x{off:04X}')

# === JUNK_ string-ek (korrigalva) ===
print()
print('=== JUNK_ (0x3AB2) - string-ek ===')
strs, offs = get_strings_and_offsets(0x3AB2, 800)
print('  String-ek:')
for t,s in strs: print(f'    0x{t:05X}: "{s}"')

# === JSR parancs - mi a 0x585A0 ===
print()
print('=== JSR parancs sub_585A0 (parameter parse) ===')
strs, offs = get_strings_and_offsets(0x585A0, 200)
print('  String-ek (format?):', strs)

# === RQS - Service Request ===
print()
print('=== RQS (0x4138) - GPIB SRQ ===')
strs, offs = get_strings_and_offsets(0x4138, 200)
print('  String-ek:')
for t,s in strs: print(f'    0x{t:05X}: "{s}"')
print('  A5 offsetek:')
for addr,mn,ops,off in offs: print(f'    {addr:05X}: {mn:<8} {ops}  -> A5+0x{off:04X}')

# === STB? ===
print()
print('=== STB? (0x4176) ===')
strs, offs = get_strings_and_offsets(0x4176, 200)
print('  String-ek:')
for t,s in strs: print(f'    0x{t:05X}: "{s}"')
print('  A5 offsetek:')
for addr,mn,ops,off in offs: print(f'    {addr:05X}: {mn:<8} {ops}  -> A5+0x{off:04X}')

# === SCROLL (0x7B2A) ===
print()
print('=== SCROLL (0x7B2A) - display scroll ===')
strs, offs = get_strings_and_offsets(0x7B2A, 200)
print('  A5 offsetek:')
for addr,mn,ops,off in offs: print(f'    {addr:05X}: {mn:<8} {ops}  -> A5+0x{off:04X}')

# === T? és R? lekérdezők ===
print()
print('=== T? (0x1EC68) - TRIG lekerdezes ===')
strs, offs = get_strings_and_offsets(0x1EC68, 300)
for t,s in strs: print(f'  "{s}"')

print()
print('=== R? (0x1F2E0) - RANGE lekerdezes ===')
strs, offs = get_strings_and_offsets(0x1F2E0, 300)
for t,s in strs: print(f'  "{s}"')

# === SYNCPARM_ - factory sync ===
print()
print('=== SYNCPARM_ (0x397DE) ===')
strs, offs = get_strings_and_offsets(0x397DE, 400)
print('  String-ek:')
for t,s in strs: print(f'    0x{t:05X}: "{s}"')
print('  A5 offsetek:')
for addr,mn,ops,off in offs[:15]: print(f'    {addr:05X}: {mn:<8} {ops}  -> A5+0x{off:04X}')

# === OPT? (priv=2) - mi az options string ===
print()
print('=== OPT? (0x175DA, priv=2) ===')
strs, offs = get_strings_and_offsets(0x175DA, 300)
print('  String-ek:')
for t,s in strs: print(f'    0x{t:05X}: "{s}"')

# === HELP ===
print()
print('=== HELP (0x17544) ===')
strs, offs = get_strings_and_offsets(0x17544, 400)
print('  String-ek:')
for t,s in strs: print(f'    0x{t:05X}: "{s}"')
