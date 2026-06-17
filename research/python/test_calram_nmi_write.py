"""
cal_ram iras NMI mechanizmuson at.

A Level7 NMI handler (0x5A032) vegzi az irast, ha:
1. 4 varazsszot ellenoriz (DEAF/BAD1/0ACE/BEAD) a settings_ram-ban
2. A callback pointer (0x121852) a MOVEP.W writer-re mutat
3. A /WE nyitas (close_value | 0x80) triggereli az NMI-t

Az injektalt kod (0x12E000):
  trap #5             -- SR mentes, interrupt szint emelese
  move.w #$4200, d2   -- test adat (0x42 a high byte-ba)
  movea.l #$60C4C, a0 -- DOLT[0] fizikai cim
  callback setup      -- sajat movep.w + rts rutinra mutat
  success flag torles
  /WE nyitas          -- NMI triggereles
  DBEQ loop (10x)     -- var

A callback (0x12E100): movep.w d2, $0(a0); rts
"""
import socket, time

BRIDGE_HOST = '192.168.2.88'
BRIDGE_PORT  = 1234
GPIB_ADDR    = 22

s = socket.create_connection((BRIDGE_HOST, BRIDGE_PORT), timeout=15)
s.sendall(b'++mode 1\n')
s.sendall(f'++addr {GPIB_ADDR}\n'.encode())
s.sendall(b'++auto 0\n')
s.sendall(b'++eos 2\n')
s.sendall(b'++eoi 1\n')
s.sendall(b'++read_tmo_ms 3000\n')
time.sleep(0.3)

def send(cmd):
    s.sendall((cmd + '\n').encode())
    time.sleep(0.12)

def recv(timeout=3.0):
    s.sendall(b'++read eoi\n')
    buf = b''
    s.settimeout(timeout)
    try:
        while True:
            b = s.recv(512)
            if not b: break
            buf += b
            if b'\n' in b: break
    except socket.timeout:
        pass
    return buf.decode('ascii', errors='replace').strip()

def q(cmd, timeout=3.0):
    send(cmd); return recv(timeout)

def mread_word(phys):
    r = q(f'MREAD {phys}')
    try: return int(float(r)) & 0xFFFF
    except: return None

def mread_hi(phys):
    w = mread_word(phys)
    return (w >> 8) & 0xFF if w is not None else None

def mwrite(phys, value):
    v = value & 0xFFFF
    signed = v if v <= 32767 else v - 65536
    send(f'MWRITE {phys},{signed}')

def mwrite_words(base, words):
    for i, w in enumerate(words):
        mwrite(base + i*2, w)
    time.sleep(0.15)

def errstr():
    return q('ERRSTR?', timeout=2.0)

def sep(t): print(); print(f'=== {t} ===')

# Init
send('PRESET NORM'); time.sleep(0.8)
send('END ALWAYS');  time.sleep(0.2)
send('BEEP 1');      time.sleep(0.2)
q('ERRSTR?')

DOLT_PHYS  = 0x60000 + 0x626 * 2  # 0x60C4C = 396364
CODE_BASE  = 0x12E000
CB_BASE    = 0x12E100

# ── Allapot leolvasas ──────────────────────────────────────────
sep('0. Kiindulo allapot')

io_word    = mread_word(0x0C0000)
we_close   = mread_hi(0x12185A)   # high byte of [0x12185A]
cb_ptr     = (mread_word(0x121852) << 16) | mread_word(0x121854)
suc_flag   = mread_word(0x121856)
dolt_init  = mread_hi(DOLT_PHYS)

# Magic words
magic_1780 = mread_word(0x121780)
magic_0C90 = mread_word(0x120C90)
magic_1782 = mread_word(0x121782)
magic_0C92 = mread_word(0x120C92)

print(f'  IO port (0x0C0000): 0x{io_word:04X}  (low byte=0x{io_word&0xFF:02X})')
print(f'  /WE close val [0x12185A] high byte: 0x{we_close:02X}')
print(f'  /WE open val: 0x{we_close|0x80:02X}')
print(f'  callback ptr [0x121852]: 0x{cb_ptr:08X}')
print(f'  success flag [0x121856]: 0x{suc_flag:04X}')
print(f'  DOLT[0] (0x{DOLT_PHYS:05X}): 0x{dolt_init:02X}')
print()
print(f'  Magic words:')
print(f'    [0x121780]: 0x{magic_1780:04X}  (kell: 0xDEAF)')
print(f'    [0x120C90]: 0x{magic_0C90:04X}  (kell: 0xBAD1)')
print(f'    [0x121782]: 0x{magic_1782:04X}  (kell: 0x0ACE)')
print(f'    [0x120C92]: 0x{magic_0C92:04X}  (kell: 0xBEAD)')

magic_ok = (magic_1780 == 0xDEAF and magic_0C90 == 0xBAD1 and
            magic_1782 == 0x0ACE and magic_0C92 == 0xBEAD)
print(f'  Magic words megfelelo: {"IGEN" if magic_ok else "NEM - MWRITE-tal beallitjuk"}')

# Eredeti callback mentes (visszaallitashoz)
orig_cb = cb_ptr
orig_we_close = we_close

# ── Magic word beallitas (ha kell) ──────────────────────────────
if not magic_ok:
    sep('0b. Magic words beallitasa MWRITE-tal')
    mwrite(0x121780, 0xDEAF)
    mwrite(0x120C90, 0xBAD1)
    mwrite(0x121782, 0x0ACE)
    mwrite(0x120C92, 0xBEAD)
    time.sleep(0.2)
    v1 = mread_word(0x121780)
    v2 = mread_word(0x120C90)
    v3 = mread_word(0x121782)
    v4 = mread_word(0x120C92)
    print(f'  [0x121780]: 0x{v1:04X}  (vart DEAF)')
    print(f'  [0x120C90]: 0x{v2:04X}  (vart BAD1)')
    print(f'  [0x121782]: 0x{v3:04X}  (vart 0ACE)')
    print(f'  [0x120C92]: 0x{v4:04X}  (vart BEAD)')
    magic_ok = (v1 == 0xDEAF and v2 == 0xBAD1 and v3 == 0x0ACE and v4 == 0xBEAD)
    print(f'  Magic words beallitva: {"IGEN" if magic_ok else "HIBA!"}')

# ── Callback iras (0x12E100) ──────────────────────────────────
sep('1. Callback iras (0x12E100): movep.w d2, 0(a0) + rts')
# movep.w d2, $0(a0) = 0588 0000
# rts               = 4E75
callback_code = [
    0x0588, 0x0000,   # movep.w d2, $0(a0)  -- ir d2 high byte-t (a0)-ra, low byte-t (a0+2)-re
    0x4E75,           # rts
]
mwrite_words(CB_BASE, callback_code)

chk_cb = [mread_word(CB_BASE + i*2) for i in range(len(callback_code))]
cb_ok = all(a == b for a, b in zip(callback_code, chk_cb))
print(f'  Callback kod helyes: {"IGEN" if cb_ok else "HIBA"}')
if not cb_ok:
    for i, (a, b) in enumerate(zip(callback_code, chk_cb)):
        if a != b: print(f'    word {i}: elvart 0x{a:04X}, kapott 0x{b:04X}')

# ── Fo kod iras (0x12E000) ─────────────────────────────────────
sep('2. Fo kod iras (0x12E000)')

# A /WE open ertek: [0x12185A] high byte | 0x80
# De mivel a move.b $12185A, d6 instrukcios elofeszitett ertek kell,
# inkabb kozvetlenul beleegetve a konstanst (or: a kodban tesszuk)

# Az injektalt kod:
# trap #5                              -> 4E45
# move.w #$4200, d2                   -> 343C 4200
# movea.l #$00060C4C, a0              -> 207C 0006 0C4C
# movea.l #$0012E100, a4              -> 287C 0012 E100
# move.l a4, $121852.l                -> 23CC 0012 1852
# move.w #0, $121856.l                -> 33FC 0000 0012 1856
# move.b $12185A.l, d6                -> 1C39 0012 185A
# ori.w #$80, d6                      -> 0046 0080
# move.b d6, $C0001.l                 -> 13C6 000C 0001
# move.w #9, d6                       -> 3C3C 0009
# dbeq d6, *                          -> 57CE FFFE
# rts                                 -> 4E75

main_code = [
    # TRAP #5: SR mentes + interrupt szint emelese
    0x4E45,

    # d2 = test adat (0x42 a high byte-ban -> DOLT[0]-ba fog kerulni)
    0x343C, 0x4200,            # move.w #$4200, d2

    # a0 = DOLT[0] fizikai cim (0x00060C4C)
    0x207C, 0x0006, 0x0C4C,   # movea.l #$00060C4C, a0

    # a4 = callback cim (0x0012E100)
    0x287C, 0x0012, 0xE100,   # movea.l #$0012E100, a4

    # [0x121852] = a4 (callback pointer beallitas)
    0x23CC, 0x0012, 0x1852,   # move.l a4, $121852.l

    # success flag torles
    0x33FC, 0x0000, 0x0012, 0x1856,  # move.w #0, $121856.l

    # /WE nyitas: [0x12185A] high byte | 0x80 -> d6 -> 0x0C0001
    0x1C39, 0x0012, 0x185A,   # move.b $12185A.l, d6  (high byte = close val)
    0x0046, 0x0080,            # ori.w #$80, d6         (set bit7)
    0x13C6, 0x000C, 0x0001,   # move.b d6, $C0001.l    (TRIGGER NMI!)

    # DBEQ timing loop (max 10x, NMI kozben fut)
    0x3C3C, 0x0009,           # move.w #9, d6
    0x57CE, 0xFFFE,           # dbeq d6, *             (loop 10x)

    # Return
    0x4E75,                   # rts
]
mwrite_words(CODE_BASE, main_code)

chk = [mread_word(CODE_BASE + i*2) for i in range(len(main_code))]
code_ok = all(a == b for a, b in zip(main_code, chk))
print(f'  Fo kod helyes: {"IGEN" if code_ok else "HIBA"}')
if not code_ok:
    for i, (a, b) in enumerate(zip(main_code, chk)):
        if a != b: print(f'    word {i} @ 0x{CODE_BASE+i*2:06X}: elvart 0x{a:04X}, kapott 0x{b:04X}')

# ── Futtatas ────────────────────────────────────────────────────
if code_ok and cb_ok and magic_ok:
    sep('3. JSR futtatas')
    dolt_before = mread_hi(DOLT_PHYS)
    suc_before  = mread_word(0x121856)
    io_before   = mread_word(0x0C0000)
    we_open_val = (we_close | 0x80)
    print(f'  DOLT[0] elotte:  0x{dolt_before:02X}')
    print(f'  Success elotte:  0x{suc_before:04X}')
    print(f'  IO port elotte:  0x{io_before:04X}')
    print(f'  /WE open ertek:  0x{we_open_val:02X} (= 0x{we_close:02X} | 0x80)')
    print(f'  >>> JSR {CODE_BASE} <<<')

    send(f'JSR {CODE_BASE}'); time.sleep(1.5)
    e = errstr()

    dolt_after = mread_hi(DOLT_PHYS)
    suc_after  = mread_word(0x121856)
    io_after   = mread_word(0x0C0000)
    cb_after   = (mread_word(0x121852) << 16) | mread_word(0x121854)

    print(f'  JSR eredmeny: {e!r}')
    print(f'  DOLT[0] utana:  0x{dolt_after:02X}  (vart: 0x42)')
    print(f'  Success utana:  0x{suc_after:04X}  (vart: 0x0001)')
    print(f'  IO port utana:  0x{io_after:04X}')
    print(f'  Callback ptr:   0x{cb_after:08X}')

    if dolt_after == 0x42:
        print()
        print('  *** SIKER! DOLT[0] = 0x42 *** cal_ram iras mukodik! ***')
        print()
        sep('4. Visszaallitas: DOLT[0] = 0x00')
        restore_code = [
            0x4E45,
            0x343C, 0x0000,            # move.w #$0000, d2  (visszaallitas)
            0x207C, 0x0006, 0x0C4C,
            0x287C, 0x0012, 0xE100,
            0x23CC, 0x0012, 0x1852,
            0x33FC, 0x0000, 0x0012, 0x1856,
            0x1C39, 0x0012, 0x185A,
            0x0046, 0x0080,
            0x13C6, 0x000C, 0x0001,
            0x3C3C, 0x0009,
            0x57CE, 0xFFFE,
            0x4E75,
        ]
        mwrite_words(CODE_BASE, restore_code)
        send(f'JSR {CODE_BASE}'); time.sleep(1.5)
        e2 = errstr()
        dolt_final = mread_hi(DOLT_PHYS)
        print(f'  Visszaallitas JSR: {e2!r}')
        print(f'  DOLT[0] visszaallitva: 0x{dolt_final:02X}  (vart: 0x00)')
    else:
        print()
        print(f'  Elteres. DOLT[0]={dolt_after:02X}, success={suc_after:04X}')
        print()
        print('  Diagnosztika:')
        if suc_after == 0x0001:
            print('  -> Success flag SET, de DOLT[0] nem valtozott: callback nem irt helyesen')
            print('     (esetleg movep.w cim gond, vagy d2/a0 erteke nem jo)')
        elif suc_after == 0x0000:
            print('  -> Success flag NEM set: NMI handler nem ment vegig a write path-on')
            print('     Okok: magic word hianyzik, vagy bit7 nem volt 1 az NMI-nel')

        # Reszletes debug: volt-e NMI?
        print()
        print('  Debug: NMI handler altal ert cimek:')
        print(f'    [0x121858] (mentett SR): 0x{mread_word(0x121858):04X}')
        print(f'    [0x121780] (magic DEAF): 0x{mread_word(0x121780):04X}')
        print(f'    [0x120C90] (magic BAD1): 0x{mread_word(0x120C90):04X}')
else:
    sep('3. SKIP - kod vagy magic problem')
    print(f'  code_ok={code_ok}, cb_ok={cb_ok}, magic_ok={magic_ok}')

# Callback pointer visszaallitas
sep('5. Callback pointer visszaallitas')
orig_hi = (orig_cb >> 16) & 0xFFFF
orig_lo = orig_cb & 0xFFFF
mwrite(0x121852, orig_hi)
mwrite(0x121854, orig_lo)
cb_restored = (mread_word(0x121852) << 16) | mread_word(0x121854)
print(f'  Callback visszaallitva: 0x{cb_restored:08X}  (elvart: 0x{orig_cb:08X})')

s.close()
print()
print('Teszt befejezve.')
