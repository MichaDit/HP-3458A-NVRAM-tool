"""
HP 3458A cal_ram iras tesztje ket modszerrel:
  Approach A: Teljes kod injekcios (open /WE + write + close /WE + RTS)
  Approach B: TRAP #5 callback hijack (patchelt ISR callback, triggereli a /WE ISR-t)

Cel: DOLT[0] (cal_ram offset 0x626, fizikai 0x60C4C) ertekenek megvaltoztatasa.
Jelenlegi ertek: 0x00 (CAL_NUM futtatta korabban).

68000 opcodes (Approach A), kodblokk 0x12E000-ban:
  1039 000C 0001   move.b $C0001.l, d0  ; IO port olvasasa
  0000 0080        ori.b  #$80, d0      ; bit7 SET = /WE OPEN
  13C0 000C 0001   move.b d0, $C0001.l  ; /WE megnyitasa
  13FC 0042 0006 0C4C  move.b #$42, $60C4C.l  ; DOLT[0] = 0x42
  0200 007F        andi.b #$7F, d0      ; bit7 CLEAR
  13C0 000C 0001   move.b d0, $C0001.l  ; /WE zaras (eredeti IO port ertek)
  4E75             rts

68000 opcodes (Approach B callback), 0x12E100-ban:
  13FC 0055 0006 0C4C  move.b #$55, $60C4C.l  ; DOLT[0] = 0x55
  4E75             rts

68000 opcodes (Approach B trigger), 0x12E200-ban:
  1039 000C 0001   move.b $C0001.l, d0  ; IO port
  0000 0080        ori.b  #$80, d0      ; SET /WE
  13C0 000C 0001   move.b d0, $C0001.l  ; OPEN /WE
  4E45             trap #5               ; ISR: callback hivas + /WE zaras
  0200 007F        andi.b #$7F, d0      ; biztonsagi /WE zaras (ha ISR nem zarta)
  13C0 000C 0001   move.b d0, $C0001.l
  4E75             rts
"""
import socket, time

BRIDGE_HOST = '192.168.2.88'
BRIDGE_PORT  = 1234
GPIB_ADDR    = 22

ORIG_CALLBACK_HI = 0x0005  # 0x0005A24C visszaallitashoz
ORIG_CALLBACK_LO = 0xA24C

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
    time.sleep(0.15)

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
    send(cmd)
    return recv(timeout)

def mread_word(phys):
    r = q(f'MREAD {phys}')
    try:
        return int(float(r)) & 0xFFFF
    except:
        return None

def mread_byte(phys):
    w = mread_word(phys)
    if w is None: return None
    return (w >> 8) & 0xFF  # high byte = DS1220Y even byte

def mwrite_words(phys_addr, words):
    """MWRITE <addr>,<val> — N word iras a fizikai cimre (szavanként)."""
    for i, w in enumerate(words):
        v = w & 0xFFFF
        val_signed = v if v <= 32767 else v - 65536
        send(f'MWRITE {phys_addr + i*2},{val_signed}')
    time.sleep(0.15)

def errstr():
    return q('ERRSTR?', timeout=2.0)

def check_ok(label):
    e = errstr()
    ok = ('NO ERROR' in e) or e.startswith('0,')
    status = 'OK' if ok else f'HIBA: {e}'
    print(f'  {label}: {status}')
    return ok

def sep(t):
    print()
    print('=' * 60)
    print(f'  {t}')
    print('=' * 60)

# Init
send('PRESET NORM'); time.sleep(0.8)
send('END ALWAYS');  time.sleep(0.2)
send('BEEP 1');      time.sleep(0.2)
q('ERRSTR?')

# --- Referencia adatok ---
sep('REFERENCIA: cal_ram jelenlegi allapot')
dolt_phys = 0x60000 + 0x626 * 2   # = 0x60C4C
print(f'  DOLT[0] fizikai cim: 0x{dolt_phys:05X} (dec {dolt_phys})')
b0 = mread_byte(dolt_phys)
print(f'  DOLT[0] jelenlegi ertek: 0x{b0:02X}  (elvart: 0x00)')

cb_hi = mread_word(0x121852)
cb_lo = mread_word(0x121854)
cb = (cb_hi << 16) | cb_lo
print(f'  ISR callback: 0x{cb:08X}')

# ==========================================================
# PHASE 0: FILLBIN mechanizmus ellenorzes (biztonsagi teszt)
# ==========================================================
sep('PHASE 0: MADDR + FILLBIN alap teszt (settings_ram)')
test_addr = 0x12F000
test_val  = 0x5A5A
print(f'  Iras: 0x{test_val:04X} -> 0x{test_addr:06X}')
mwrite_words(test_addr, [test_val])
rb = mread_word(test_addr)
if rb == test_val:
    print(f'  Visszaolvasas: 0x{rb:04X} -- MATCH, FILLBIN mukodik!')
elif rb is not None:
    print(f'  Visszaolvasas: 0x{rb:04X} -- ELTERES! (vart 0x{test_val:04X})')
    print('  FILLBIN nem mukodik vagy eltero szintaxis szukseges.')
    print('  Folytatas csak ha az ellenorzes OK...')
else:
    print('  Visszaolvasas sikertelen (None)')

check_ok('FILLBIN teszt hiba?')

# Ha a teszt sikertelen, alljunk meg
if rb != test_val:
    print()
    print('!!! FILLBIN teszt sikertelen, leallunk.')
    s.close()
    exit(1)

# ==========================================================
# PHASE 1: Approach A -- Teljes kod injekcios
# Kodblokk 0x12E000-ban (18 word = 36 byte)
# ==========================================================
sep('PHASE 1: Approach A -- kod injekcios (open /WE + write + close /WE)')

code_addr_a = 0x12E000

# 68000 opcodes as 16-bit words:
#   move.b $C0001.l, d0
#   ori.b  #$80, d0
#   move.b d0, $C0001.l
#   move.b #$42, $60C4C.l   <- DOLT[0] = 0x42
#   andi.b #$7F, d0
#   move.b d0, $C0001.l
#   rts
code_a = [
    0x1039, 0x000C, 0x0001,   # move.b $C0001.l, d0
    0x0000, 0x0080,            # ori.b  #$80, d0
    0x13C0, 0x000C, 0x0001,   # move.b d0, $C0001.l    (/WE OPEN)
    0x13FC, 0x0042, 0x0006, 0x0C4C,  # move.b #$42, $60C4C.l
    0x0200, 0x007F,            # andi.b #$7F, d0
    0x13C0, 0x000C, 0x0001,   # move.b d0, $C0001.l    (/WE CLOSE)
    0x4E75,                    # rts
]
print(f'  Kod ({len(code_a)} word = {len(code_a)*2} byte) -> 0x{code_addr_a:06X}')
mwrite_words(code_addr_a, code_a)

# Ellenorzes: osszevetjuk az elso es utolso szot
chk1 = mread_word(code_addr_a)
chk2 = mread_word(code_addr_a + (len(code_a)-1)*2)
if chk1 == code_a[0] and chk2 == code_a[-1]:
    print(f'  Kod ellenorzes: OK (0x{chk1:04X} ... 0x{chk2:04X})')
else:
    print(f'  Kod ellenorzes HIBA: 0x{chk1:04X} (vart 0x{code_a[0]:04X}), 0x{chk2:04X} (vart 0x{code_a[-1]:04X})')

# Futtatunk!
print()
print(f'  >>> JSR {code_addr_a} ({code_addr_a} dec) <<<')
print(f'  Varantas: DOLT[0] = 0x42 lesz, IO port valtozatlan marad')
send(f'JSR {code_addr_a}')
time.sleep(0.8)
ok_a = check_ok('JSR Approach A')

# Ellenorzes
b1 = mread_byte(dolt_phys)
print(f'  DOLT[0] iras utan: 0x{b1:02X}  (vart: 0x42)')
if b1 == 0x42:
    print('  *** SIKER: cal_ram iras Approach A-val mukodik! ***')
else:
    print('  Elteres a vart ertektol.')

io_after = mread_word(0x0C0001)
print(f'  IO port iras utan: 0x{io_after:04X}  (alap volt: 0x4E79, bit7 legyen 0)')

# Visszaallitjuk DOLT[0]-t (0x42 -> 0x00)
if b1 == 0x42:
    print()
    print('  Visszaallitas: DOLT[0] = 0x00...')
    restore_code = [
        0x1039, 0x000C, 0x0001,
        0x0000, 0x0080,
        0x13C0, 0x000C, 0x0001,
        0x13FC, 0x0000, 0x0006, 0x0C4C,  # move.b #$00, $60C4C.l
        0x0200, 0x007F,
        0x13C0, 0x000C, 0x0001,
        0x4E75,
    ]
    mwrite_words(code_addr_a, restore_code)
    send(f'JSR {code_addr_a}')
    time.sleep(0.5)
    b_restored = mread_byte(dolt_phys)
    print(f'  DOLT[0] visszaallitva: 0x{b_restored:02X}')

# ==========================================================
# PHASE 2: Approach B -- TRAP #5 callback hijack
# ==========================================================
sep('PHASE 2: Approach B -- TRAP #5 ISR callback hijack')

cb_addr  = 0x12E100   # callback rutin
trig_addr = 0x12E200  # trigger rutin

# Callback kod: move.b #$55, $60C4C.l + rts
callback_code = [
    0x13FC, 0x0055, 0x0006, 0x0C4C,  # move.b #$55, $60C4C.l
    0x4E75,                           # rts
]
# Trigger kod: /WE megnyitasa -> TRAP #5 -> cleanup -> rts
trigger_code = [
    0x1039, 0x000C, 0x0001,   # move.b $C0001.l, d0
    0x0000, 0x0080,            # ori.b  #$80, d0
    0x13C0, 0x000C, 0x0001,   # move.b d0, $C0001.l   (/WE OPEN)
    0x4E45,                    # trap #5  (ISR: callback-t hiv + /WE zar)
    0x0200, 0x007F,            # andi.b #$7F, d0  (biztonsagi zar)
    0x13C0, 0x000C, 0x0001,   # move.b d0, $C0001.l
    0x4E75,                    # rts
]

print(f'  Callback ({len(callback_code)} word) -> 0x{cb_addr:06X}')
mwrite_words(cb_addr, callback_code)
print(f'  Trigger  ({len(trigger_code)} word) -> 0x{trig_addr:06X}')
mwrite_words(trig_addr, trigger_code)

# Callback pointer patch (0x121852 = 32-bit pointer)
# Ertek: 0x0012E100
patch_hi = 0x0012
patch_lo = 0xE100
print(f'  ISR callback pointer patch: 0x121852 -> 0x{patch_hi:04X}{patch_lo:04X} (0x12E100)')
mwrite_words(0x121852, [patch_hi, patch_lo])

# Ellenorzes: vissza is olvassuk
cb_hi_new = mread_word(0x121852)
cb_lo_new = mread_word(0x121854)
print(f'  Callback pointer patch verify: 0x{cb_hi_new:04X}{cb_lo_new:04X}')

print()
print(f'  >>> JSR {trig_addr} ({trig_addr} dec) -- TRAP #5 triggerel <<<')
send(f'JSR {trig_addr}')
time.sleep(1.0)
ok_b = check_ok('JSR Approach B (trigger)')

b2 = mread_byte(dolt_phys)
print(f'  DOLT[0] utan: 0x{b2:02X}  (vart: 0x55)')
if b2 == 0x55:
    print('  *** SIKER: Approach B TRAP #5 callback hijack mukodik! ***')
else:
    print(f'  Elteres (kapott 0x{b2:02X}, vart 0x55)')

# ==========================================================
# CLEANUP: Callback pointer visszaallitasa
# ==========================================================
sep('CLEANUP: ISR callback pointer visszaallitasa')
print(f'  Visszaallitas: 0x121852 -> 0x{ORIG_CALLBACK_HI:04X}{ORIG_CALLBACK_LO:04X}')
mwrite_words(0x121852, [ORIG_CALLBACK_HI, ORIG_CALLBACK_LO])
cb_hi_r = mread_word(0x121852)
cb_lo_r = mread_word(0x121854)
print(f'  Visszaallitva: 0x{cb_hi_r:04X}{cb_lo_r:04X}  (vart: 0x{ORIG_CALLBACK_HI:04X}{ORIG_CALLBACK_LO:04X})')
if cb_hi_r == ORIG_CALLBACK_HI and cb_lo_r == ORIG_CALLBACK_LO:
    print('  ISR callback sikeresen visszaallitva.')
else:
    print('  !!! FIGYELEM: callback visszaallitas sikertelen!')

# DOLT visszaallitas ha szukseges
b_final = mread_byte(dolt_phys)
if b_final != 0x00:
    print(f'  DOLT[0] = 0x{b_final:02X}, visszaallitas 0x00-ra...')
    restore_code2 = [
        0x1039, 0x000C, 0x0001,
        0x0000, 0x0080,
        0x13C0, 0x000C, 0x0001,
        0x13FC, 0x0000, 0x0006, 0x0C4C,
        0x0200, 0x007F,
        0x13C0, 0x000C, 0x0001,
        0x4E75,
    ]
    mwrite_words(code_addr_a, restore_code2)
    send(f'JSR {code_addr_a}')
    time.sleep(0.5)
    b_end = mread_byte(dolt_phys)
    print(f'  DOLT[0] vegleges: 0x{b_end:02X}')

# Vegso allapot
sep('OSSZEFOGLALO')
print()
print('  Approach A (kod injekcios):')
print(f'    Teszt ertek (0x42): {"SIKER" if b1 == 0x42 else "SIKERTELEN"}')
print()
print('  Approach B (TRAP #5 callback hijack):')
print(f'    Teszt ertek (0x55): {"SIKER" if b2 == 0x55 else "SIKERTELEN"}')
print()
print('  ISR callback visszaallitva:', 'IGEN' if (cb_hi_r == ORIG_CALLBACK_HI and cb_lo_r == ORIG_CALLBACK_LO) else 'NEM')

s.close()
print()
print('Teszt befejezve.')
