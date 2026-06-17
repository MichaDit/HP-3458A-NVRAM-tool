"""
Megkeresi melyik interrupt vektor mutat a sub_05A070-re,
es teljes kepet ad a /WE mechanizmusrol.
"""
import struct, sys

ROM_PATH = r'HP3458A_REV9_assembled_and_analysis\HP3458A_REV9_cpu_order_384K_for_Ghidra.bin'

with open(ROM_PATH, 'rb') as f:
    ROM = f.read()

def rom_long(addr):
    off = addr
    if off < 0 or off+4 > len(ROM): return None
    return struct.unpack('>I', ROM[off:off+4])[0]

def rom_word(addr):
    off = addr
    if off < 0 or off+2 > len(ROM): return None
    return struct.unpack('>H', ROM[off:off+2])[0]

TARGET = 0x0005A070

# ── 1. Vektor tabla ──
print('=== 68000 vektor tabla (0x000-0x0FF): melyik mutat 0x5A070-re? ===')
print()
AUTOVEC_NAMES = {
    0x08: 'Bus error',       0x0C: 'Address error', 0x10: 'Illegal insn',
    0x14: 'Zero divide',     0x18: 'CHK insn',       0x1C: 'TRAPV',
    0x20: 'Priv violation',  0x24: 'Trace',           0x28: 'Line 1010',
    0x2C: 'Line 1111',       0x60: 'Spurious int',
    0x64: 'Level 1 autovec', 0x68: 'Level 2 autovec', 0x6C: 'Level 3 autovec',
    0x70: 'Level 4 autovec', 0x74: 'Level 5 autovec', 0x78: 'Level 6 autovec',
    0x7C: 'Level 7 autovec',
    0x80: 'TRAP #0',  0x84: 'TRAP #1',  0x88: 'TRAP #2',  0x8C: 'TRAP #3',
    0x90: 'TRAP #4',  0x94: 'TRAP #5',  0x98: 'TRAP #6',  0x9C: 'TRAP #7',
    0xA0: 'TRAP #8',  0xA4: 'TRAP #9',  0xA8: 'TRAP #10', 0xAC: 'TRAP #11',
    0xB0: 'TRAP #12', 0xB4: 'TRAP #13', 0xB8: 'TRAP #14', 0xBC: 'TRAP #15',
}

found_vectors = []
for vaddr in range(0, 0x100, 4):
    val = rom_long(vaddr)
    if val is None: continue
    name = AUTOVEC_NAMES.get(vaddr, f'User vec {(vaddr-0x100)//4+64 if vaddr>=0x100 else vaddr//4}')
    if val == TARGET:
        print(f'  *** TALALT: vaddr=0x{vaddr:04X} ({name}) -> 0x{val:08X} ***')
        found_vectors.append(vaddr)
    elif val and val >= 0x5A000 and val <= 0x5B000:
        print(f'  vaddr=0x{vaddr:04X} ({name}) -> 0x{val:08X}   [5Axxx tartomany]')

# User interrupt vektorok 0x100-0x3FF
for vaddr in range(0x100, 0x400, 4):
    val = rom_long(vaddr)
    if val == TARGET:
        print(f'  *** TALALT: user vaddr=0x{vaddr:04X} (vec {vaddr//4}) -> 0x{val:08X} ***')
        found_vectors.append(vaddr)

if not found_vectors:
    print('  Nincs kozvetlen vektor -> 5A070 lehet masodlagos handler')

# ── 2. sub_05A070 pontos disassembly ──
print()
print('=== sub_05A070 pontos 68k disassembly ===')
print()

# A raw bytes alapjan manualis decode
raw = ROM[0x5A070:0x5A070+100]
print('Bytes:', ' '.join(f'{b:02X}' for b in raw[:80]))
print()

# Dekodolas:
# 1A39 000C 0001  = move.b $0C0001.l, d5    (6 bytes)
# 0805 0007       = btst.b #7, d5            (4 bytes)
# 6600 0018       = bne.w  $5A094            (4 bytes)
#
# PATH A (bit7=0, /WE not open):
# 13F9 0012 185A 000C 0001  = move.b $12185A.l, $C0001.l  (10 bytes!)
# 4E71 = nop
# 4E71 = nop
# 46F9 0012 1858  = move.w $121858.l, SR    (6 bytes)
# 4E73 = rte
#
# PATH B (bit7=1, /WE OPEN → WRITE PATH):
# $5A094:
# 2879 0012 1852  = movea.l $121852.l, a4   (6 bytes)
# 4E94 = jsr (a4)                            (2 bytes)
# 13F9 0012 185A 000C 0001 = move.b $12185A, $C0001  (CLOSE /WE)
# 4E71, 4E71, 4E71 = 3x nop (timing)
# 33FC 0001 0012 1856 = move.w #1, $121856  (set success flag)
# 46F9 0012 1858  = move.w $121858, SR      (restore SR)
# 4E73 = rte

print('sub_05A070 (kb. a hardware interrupt handler):')
print()
print('  5A070: 1A39 000C 0001    move.b $0C0001.l, d5          ; read IO port')
print('  5A076: 0805 0007         btst.b #7, d5                  ; test bit7 (/WE open?)')
print('  5A07A: 6600 0018         bne.w  $5A094                  ; IF bit7=1 → write path')
print()
print('  PATH A (/WE not open, bit7=0 → csak lezar):')
print('  5A07E: 13F9 0012185A 000C0001  move.b $12185A, $C0001   ; CLOSE /WE (write close val)')
print('  5A088: 4E71                   nop')
print('  5A08A: 4E71                   nop')
print('  5A08C: 46F9 0012 1858         move.w $121858, SR        ; RESTORE SR')
print('  5A092: 4E73                   rte')
print()
print('  PATH B (bit7=1, /WE open → CAL_RAM WRITE):')
print('  5A094: 2879 0012 1852         movea.l $121852, a4       ; load callback ptr')
print('  5A09A: 4E94                   jsr (a4)                  ; CALL CALLBACK (MOVEP.W write!)')
print('  5A09C: 13F9 0012185A 000C0001 move.b $12185A, $C0001   ; CLOSE /WE')
print('  5A0A6: 4E71 4E71 4E71        nop nop nop')
print('  5A0AC: 33FC 0001 0012 1856    move.w #1, $121856        ; success flag = 1')
print('  5A0B4: 46F9 0012 1858         move.w $121858, SR        ; restore SR')
print('  5A0BA: 4E73                   rte')
print()

# ── 3. TRAP #5 ISR (0x5A0D8) ──
print('=== TRAP #5 ISR (0x5A0D8) ===')
raw_d8 = ROM[0x5A0D8:0x5A0D8+14]
print('Bytes:', ' '.join(f'{b:02X}' for b in raw_d8))
print()
print('  5A0D8: 40F9 0012 1858    move.w SR, $121858   ; SAVE SR')
print('  5A0DE: 007C 02BC         ori.w #$02BC, SR     ; RAISE interrupt level')
print('  5A0E2: 4E73              rte                   ; return (back to trap caller)')
print()
print(f'  ori.w #$02BC, SR: 0x02BC = {0x02BC:016b}b')
print(f'  SR interrupt mask bits [10:8]: {(0x02BC>>8)&0x7:03b}b = level {(0x02BC>>8)&0x7}')
print()
print('MEGJEGYZES: Az ori.w #$02BC a NORMAL CC flageket is modositja (XNZVCbits).')
print('A lenyeg: az interrupt maszkot emeli, hogy a hardware interrupt a DBEQ utan tudjon futni.')
print()

# ── 4. Teljes iras flow ──
print('=== A TELJES /WE IRAs MECHANIZMUS ===')
print()
print('1. sub_05A158 (peldaul) meghivodik egy cal_ram iras kerelem vegett')
print('2. Parameterkent: d0=kalibr. adat, d1=bitmask, a0=cal_ram cim, a1=adat ptr')
print('3. move.w #0, $121856   --> torol success flag')
print('4. trap #5              --> TRAP #5 ISR:')
print('     - save SR → $121858')
print('     - ori SR, raise int level to level ~2-7')
print('     - rte (visszater)')
print('5. lea $5A1D0, a4       --> callback = MOVEP.W writer')
print('   move.l a4, $121852   --> callback pointer beallitva')
print('6. move.b $12185A, d6   --> close value betoltese')
print('   ori.w #$80, d6       --> open value = close | 0x80')
print('7. move.b d6, $C0001    --> /WE MEGNYITAS → HARDWARE INTERRUPT TRIGGER')
print('8. move.w #9, d6; dbeq  --> TIMING LOOP (kb. 10 utasitas kb. 10 usec?)')
print('   -- KOZBEN: hardware interrupt (sub_05A070) fut:')
print('      - olvassa C0001, bit7=1 → write path')
print('      - jsr $121852 → MOVEP.W ir cal_ram-ba')
print('      - move.b $12185A, $C0001  → /WE ZARASA')
print('      - move.w #1, $121856  → success flag')
print('      - move.w $121858, SR  → SR visszaallitas')
print('      - rte')
print('9. move.w $121856, d0; btst #0  --> sikerjelzo ellenorzes')
print('10. Hiba eset: $5A0BE (error handler)')
print()

# ── 5. Mit kell a mi kodunknak csinalni? ──
print('=== MIT KELL A MI INJEKTALT KODUNKNAK CSINALNI? ===')
print()
print('Szukseges lepesek:')
print('A. Sajat callback irasa settings_ram-ba (MOVEP.W + rts)')
print('B. Callback pointer beallitasa: MWRITE $121852 = hi, $121854 = lo (a sajat rutin cime)')
print('C. SUCCESS flag torles: MWRITE $121856, 0')
print('D. trap #5 hivas (emeli az interrupt szintet, menti az SR-t)')
print('E. /WE open ertek kiszamitasa: [0x12185A] | 0x80 = close | 0x80')
print('F. move.b (close|0x80), $C0001  → TRIGGER hardware interrupt')
print('G. DBEQ delay loop (max 10x, hardware interrupt kozben fut)')
print('H. Check [0x121856] bit0 = success?')
print()

# Aktualis close ertek MREAD-del:
print('FIGYELEM: A close value a settings_ram-ban van (0x12185A).')
print('Ez valtozhat! MREAD-del kell olvasni futtatas elott.')
print()
print('Legegyszerubb megoldas: KOZVETLENUL hivjuk a meglevo firmware rutint:')
print('  sub_05A158 = 0x5A158')
print('  Ha ez hozza es visszater, az egesz mechanizmus automatikusan mukodik!')
print()
print('ALTERNATIVA (ha direct ROM call mukodik): JSR 0x5A158 a megfelelo parameterekkel')
print()

# ── 6. sub_05A158 parameterei ──
print('=== sub_05A158 parameterei (C calling convention?) ===')
print()
# 5A158: 202F 0004  move.l $4(a7), d0    <- parameter 1: first stack param
# 5A15C: 45F8 0E30  lea.l $E30.w, a2     <- a2 = 0x0E30 (bitfield/table in ROM)
# 5A160: 2200       move.l d0, d1
# 5A162: E489       lsr.l #2, d1
# 5A164: 0281 FFFE  andi.l #$FFFFFFFE, d1
# 5A16A: 41F9 0006 0000  lea.l $60000, a0  <- cal_ram base
# 5A170: D288       add.l a0, d1   → d1 = cal_ram word address
# 5A172: D5C1       adda.l d1, a2  → a2 = $E30 + cal offset
# 5A174: 2200       move.l d0, d1
# 5A176: 0281 0000 0007  andi.l #$7, d1  → d1 = d0 & 7 (bit sub-index)
# 5A17C: E388       lsl.l #1, d0    → d0 = param1 * 2 (byte → even addr)
# 5A17E: D1C0       adda.l d0, a0  → a0 = cal_ram base + param1*2
# 5A180: 226F 0008  movea.l $8(a7), a1  <- parameter 2: data pointer
# 5A184: 302F 000C  move.w $C(a7), d0   <- parameter 3: count
# 5A188: 5240       addq.w #1, d0
# 5A18A: E240       asr.w #1, d0
# 5A18C: 674E       beq.w ... (if 0, skip)
# 5A18E: 5340       subq.w #1, d0       (d0 = count/2 - 1 for DBRA loop)
# 5A190: 33FC 0000 0012 1856  move.w #0, $121856  (clear success)
# 5A198: 4E45 trap #5
# 5A19A: 49F9 0005 A1D0  lea $5A1D0, a4
# 5A1A0: 23CC 0012 1852  move.l a4, $121852
# 5A1A6: 1C39 0012 185A  move.b $12185A, d6
# 5A1AC: 0046 0080       ori.w #$80, d6
# 5A1B0: 13C6 000C 0001  move.b d6, $C0001
# 5A1B6: 3C3C 0009       move.w #9, d6
# 5A1BA: 57CE FFFE       dbeq d6, *
# 5A1BE: 3039 0012 1856  move.w $121856, d0
# 5A1C4: 0800 0000       btst.b #0, d0
# 5A1C8: 6700 FEF4       beq.w $5A0BE  (error)
# 5A1CC: 4247            clr.w d7
# 5A1CE: 4E75            rts
print('sub_05A158 C-stacked parameterei:')
print('  4(a7) = p1 = cal_ram byte INDEX (d0): a cal_ram bejegyzes sorszama')
print('  8(a7) = p2 = forras adat pointer (a1): honnan irjuk az adatot')
print('  C(a7) = p3 = byte count (d0): hany byteot irunk')
print()
print('  Belso szamitas:')
print('  d1 = p1 >> 2 & ~1  → szaval indexre konvertalas')
print('  a0 = $60000 + p1*2 → cal_ram fizikai cim (even byte mapping)')
print('  a1 = forras adat pointer')
print('  d0 = (p3 + 1) / 2 - 1  → szavak szama (DBRA counter)')
print()
print('  A callback (5A1D0):')
print('    move.w (a1)+, d2     ; olvas forras szot')
print('    movep.w d2, 0(a0)    ; MOVEP.W ir cal_ram-ba (even+even+2 cimekre)')
print('    addq #4, a0          ; kov. cal_ram helyre ugr')
print('    dbra d0, ...         ; loop')
print('    bset.b d1, (a2)      ; bitet allit a checksum tablaban')
print('    rts')
print()
print('EGYSZERUSITES: Ha a0, a1, d0, d1 regisztereket beallitjuk, es')
print('kozvetlenul ugrik a mechanizmusra (nem a teljes sub), akkor:')
print('  1. trap #5  (SR mentes)')
print('  2. lea callback_addr, a4; move.l a4, $121852')
print('  3. move.b $12185A, d6; ori #$80; move.b d6, $C0001')
print('  4. DBEQ loop')
print()
print('Vagy: kozvetlenul hivjuk JSR $5A158-at a megfelelo parameterkkel a stacken.')
