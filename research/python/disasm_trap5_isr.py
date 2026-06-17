"""
sub_05A070 (TRAP #5 ISR) es a cal_ram write mechanizmus teljes elemzese.
Cele: megerteni hogyan hivja a callback-ot, es hogyan zarjuk be /WE-t utana.
"""
import struct, sys

ROM_PATH = r'HP3458A_REV9_assembled_and_analysis\HP3458A_REV9_cpu_order_384K_for_Ghidra.bin'
ROM_BASE = 0x000000
ROM_SIZE = 0x60000  # 384KB

try:
    with open(ROM_PATH, 'rb') as f:
        ROM = f.read()
except FileNotFoundError:
    print(f'HIBA: {ROM_PATH} nem talalhato')
    sys.exit(1)

def rom_word(addr):
    off = addr - ROM_BASE
    if off < 0 or off+2 > len(ROM): return None
    return struct.unpack('>H', ROM[off:off+2])[0]

def rom_long(addr):
    off = addr - ROM_BASE
    if off < 0 or off+4 > len(ROM): return None
    return struct.unpack('>I', ROM[off:off+4])[0]

def rom_bytes(addr, n):
    off = addr - ROM_BASE
    if off < 0 or off+n > len(ROM): return None
    return ROM[off:off+n]

# Ellenorizzuk a TRAP #5 vektort (0x94 = vector 37)
TRAP5_VEC = 0x94
trap5_addr = rom_long(TRAP5_VEC)
print(f'TRAP #5 vektor (0x{TRAP5_VEC:04X}): 0x{trap5_addr:08X}')

# A sub_05A070 tartalma
print()
print('=== sub_05A070 raw bytes (TRAP #5 handler?) ===')
sub_a070 = 0x5A070
raw = rom_bytes(sub_a070, 100)
if raw:
    print('  Hex:', ' '.join(f'{b:02X}' for b in raw[:64]))

# A 0x5A070 kornyekere (TRAP #5 ISR) megprobalunk 68k-t olvasni manualis koddal
# A lenyeges instrukciok:
# - milyen cimet olvas a callback-ra?
# - mikor/hogyan zarodik /WE?
# - mi a success flag set-je?
print()
print('=== sub_05A070 szavak (manual disasm) ===')
addr = sub_a070
for i in range(40):
    w = rom_word(addr)
    if w is None: break
    print(f'  {addr:05X}: {w:04X}', end='')
    # Leggyakoribb 68k instrukciok
    if w == 0x4E73:
        print('  rte', end='')
    elif w == 0x4E75:
        print('  rts', end='')
    elif w == 0x4E71:
        print('  nop', end='')
    elif (w >> 8) == 0x4E:
        if (w & 0xFF) == 0x45: print('  trap #5', end='')
        elif (w & 0xFF) == 0x41: print('  trap #1', end='')
        elif (w & 0xFF) in range(0x40, 0x4F): print(f'  trap #{w&0xF}', end='')
    elif w == 0x48E7:
        mask = rom_word(addr+2)
        print(f'  movem.l regs,-(a7)  mask={mask:04X}', end='')
    elif w == 0x4CDF:
        mask = rom_word(addr+2)
        print(f'  movem.l (a7)+,regs  mask={mask:04X}', end='')
    elif w == 0x4CD7:
        mask = rom_word(addr+2)
        print(f'  movem.l (a7),regs  mask={mask:04X}', end='')
    elif w == 0x23FC or w == 0x33FC or w == 0x13FC:
        sz = {0x23FC: 'l', 0x33FC: 'w', 0x13FC: 'b'}[w]
        imm = rom_long(addr+2)
        dst = rom_long(addr+6)
        print(f'  move.{sz} #{imm:08X},{dst:08X}', end='')
    elif w == 0x23D5:
        dst = rom_long(addr+2)
        print(f'  move.l (a5),{dst:08X}', end='')
    elif (w >> 12) == 0x2:  # move.l variations
        pass
    # movem.l / move to/from mem
    # Fobb informaciok: ugrasi instrukciok
    elif (w >> 8) == 0x60:  # bra
        disp = w & 0xFF
        if disp == 0:
            disp = struct.unpack('>h', struct.pack('>H', rom_word(addr+2)))[0]
            print(f'  bra.w   ${addr+2+disp:05X}', end='')
        elif disp == 0xFF:
            disp = struct.unpack('>i', struct.pack('>I', rom_long(addr+2)))[0]
            print(f'  bra.l   ${addr+2+disp:05X}', end='')
        else:
            print(f'  bra.b   ${addr+2+disp:05X}', end='')
    elif (w >> 8) == 0x67:  # beq
        disp = w & 0xFF
        if disp == 0:
            disp16 = struct.unpack('>h', struct.pack('>H', rom_word(addr+2)))[0]
            print(f'  beq.w   ${addr+2+disp16:05X}', end='')
        else:
            disp8 = struct.unpack('>b', bytes([disp]))[0]
            print(f'  beq.b   ${addr+2+disp8:05X}', end='')
    elif (w >> 8) == 0x66:  # bne
        disp = w & 0xFF
        if disp == 0:
            disp16 = struct.unpack('>h', struct.pack('>H', rom_word(addr+2)))[0]
            print(f'  bne.w   ${addr+2+disp16:05X}', end='')
        else:
            disp8 = struct.unpack('>b', bytes([disp]))[0]
            print(f'  bne.b   ${addr+2+disp8:05X}', end='')
    elif w == 0x4EB9:  # jsr addr.l
        jsr_tgt = rom_long(addr+2)
        print(f'  jsr     ${jsr_tgt:08X}', end='')
    elif w == 0x4ED5:
        print('  jmp     (a5)', end='')
    elif w == 0x4E90:
        print('  jsr     (a0)', end='')
    elif w == 0x4E91:
        print('  jsr     (a1)', end='')
    elif w == 0x4E92:
        print('  jsr     (a2)', end='')
    elif w == 0x4E95:
        print('  jsr     (a5)', end='')
    elif w == 0x4E96:
        print('  jsr     (a6)', end='')
    elif w == 0x2053:  # movea.l (a3), a0
        print('  movea.l (a3), a0', end='')
    elif w == 0x2079:  # movea.l addr.l, a0
        adr = rom_long(addr+2)
        print(f'  movea.l ${adr:08X}, a0', end='')
    elif w == 0x2278:  # movea.l addr.w, a1
        adr = rom_word(addr+2)
        print(f'  movea.l ${adr:04X}.w, a1', end='')
    elif w == 0x2279:  # movea.l addr.l, a1
        adr = rom_long(addr+2)
        print(f'  movea.l ${adr:08X}, a1', end='')
    elif w == 0x1039:  # move.b addr.l, d0
        adr = rom_long(addr+2)
        print(f'  move.b  ${adr:08X}, d0', end='')
    elif w == 0x1238:  # move.b addr.w, d1
        adr = rom_word(addr+2)
        print(f'  move.b  ${adr:04X}.w, d1', end='')
    elif w == 0x1239:  # move.b addr.l, d1
        adr = rom_long(addr+2)
        print(f'  move.b  ${adr:08X}, d1', end='')
    elif w == 0x13C0:  # move.b d0, addr.l
        adr = rom_long(addr+2)
        print(f'  move.b  d0, ${adr:08X}', end='')
    elif w == 0x13C1:  # move.b d1, addr.l
        adr = rom_long(addr+2)
        print(f'  move.b  d1, ${adr:08X}', end='')
    elif w == 0x13C6:  # move.b d6, addr.l
        adr = rom_long(addr+2)
        print(f'  move.b  d6, ${adr:08X}', end='')
    elif w == 0x33C0:  # move.w d0, addr.l
        adr = rom_long(addr+2)
        print(f'  move.w  d0, ${adr:08X}', end='')
    elif w == 0x33C6:  # move.w d6, addr.l
        adr = rom_long(addr+2)
        print(f'  move.w  d6, ${adr:08X}', end='')
    elif w == 0x23C0:  # move.l d0, addr.l
        adr = rom_long(addr+2)
        print(f'  move.l  d0, ${adr:08X}', end='')
    elif w == 0x23C4:  # move.l d4, addr.l
        adr = rom_long(addr+2)
        print(f'  move.l  d4, ${adr:08X}', end='')
    elif w == 0x2C78:  # movea.l addr.w, a6
        adr = rom_word(addr+2)
        print(f'  movea.l ${adr:04X}.w, a6', end='')
    elif w == 0x2C79:  # movea.l addr.l, a6
        adr = rom_long(addr+2)
        print(f'  movea.l ${adr:08X}, a6', end='')
    elif w == 0x3038:  # move.w addr.l, d0
        adr = rom_long(addr+2)
        print(f'  move.w  ${adr:08X}, d0', end='')
    elif w == 0x3039:  # move.w addr.l, d0 (different?)
        adr = rom_long(addr+2)
        print(f'  move.w  ${adr:08X}, d0', end='')
    elif w == 0x303900:
        pass
    elif w == 0x3039:
        adr = rom_long(addr+2)
        print(f'  move.w  ${adr:08X}, d0', end='')
    elif w == 0x08000000:
        pass
    # Ismeretlen -> csak hex
    print()
    # Lepjuk az instrukciok meret szerint
    # Egyszerusites: 2 byteot lepunk mindig (nyers hex megjelenites)
    addr += 2

print()
print('=== TRAP #5 vektor kornyeke (vektortabla) ===')
for vec in range(0x88, 0xA0, 4):
    v = rom_long(vec)
    n = (vec - 0x80) // 4
    print(f'  TRAP #{n} ({vec:04X}): {v:08X}')

print()
print('=== sub_05A158 (reszletesen, 80 szoval) ===')
addr = 0x5A158
for i in range(80):
    w = rom_word(addr)
    if w is None: break
    print(f'  {addr:05X}: {w:04X}')
    addr += 2

print()
print('=== 0x12185A kornyeke (settings_ram) - ezert olvassuk el a ROM-bol is ===')
print('  (A settings_ram nem ROM, de nezze meg az MREAD utjan mentett tartalmat)')
print('  ROM: 0x5A126 move.b $12185a.l, d6  -> a close ertek ott van')
print()
print('=== sub_05A070 raw 64 byte ===')
raw2 = rom_bytes(0x5A070, 128)
if raw2:
    for i in range(0, min(128, len(raw2)), 16):
        chunk = raw2[i:i+16]
        hexs = ' '.join(f'{b:02X}' for b in chunk)
        print(f'  5A{0x070+i:03X}: {hexs}')
