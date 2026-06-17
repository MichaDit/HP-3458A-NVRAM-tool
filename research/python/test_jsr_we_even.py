"""
/WE teszt: az EVEN byte cimmel (0x0C0000) megnyitjuk a /WE-t.

A debug tesztbol: move.b $C0001.l olvas 0x39-et (nem 0x79-et).
Az even address 0x0C0000 high byte = 0x4E.
Teszteljuk: move.b $C0000.l = 0x4E, bit7=0 -> /WE zart.
Ori #$80 -> 0xCE, bit7=1 -> /WE nyitott.

Ha siker: DOLT[0] (0x60C4C) = 0x42 lesz.
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

def mread_byte_hi(phys):
    w = mread_word(phys)
    return None if w is None else (w >> 8) & 0xFF

def mwrite(phys, value):
    v = value & 0xFFFF
    signed = v if v <= 32767 else v - 65536
    send(f'MWRITE {phys},{signed}')

def mwrite_words(base, words):
    for i, w in enumerate(words):
        mwrite(base + i*2, w)

def errstr():
    return q('ERRSTR?', timeout=2.0)

def sep(t): print(); print(f'=== {t} ===')

# Init
send('PRESET NORM'); time.sleep(0.8)
send('END ALWAYS');  time.sleep(0.2)
send('BEEP 1');      time.sleep(0.2)
q('ERRSTR?')

DOLT_PHYS  = 0x60000 + 0x626 * 2   # 0x60C4C = 396364
TRACE_BASE = 0x12F300

print(f'IO word (0x0C0000): 0x{mread_word(0x0C0000):04X}')
print(f'  high byte (0xC0000) = 0x{mread_byte_hi(0x0C0000):02X}')
print(f'  low byte  (0xC0001) = 0x{mread_word(0x0C0000) & 0xFF:02X}')
print(f'DOLT[0] (0x{DOLT_PHYS:05X}): 0x{mread_byte_hi(DOLT_PHYS):02X}')

# ═══════════════════════════════════════════════════════
sep('TESZT A: move.b $C0000.l, d0 trace (even byte olvas)')
# ═══════════════════════════════════════════════════════
# move.b $C0000.l, d0 -> 1038 000C 0000
# move.b d0, $12F300.l -> 13C0 0012 F300
# rts -> 4E75
# 0x12F300: high=0x0012=18, low=0xF300=62208>32767->signed=-3328

code_a = 0x12E700
words_a = [
    0x1038, 0x000C, 0x0000,    # move.b $C0000.l, d0  (even byte)
    0x13C0, 0x0012, 0xF300,    # move.b d0, $12F300.l
    0x4E75                      # rts
]
mwrite_words(code_a, words_a)
chk = [mread_word(code_a + i*2) for i in range(len(words_a))]
ok = all(a==b for a,b in zip(chk, words_a))
print(f'  Kod irva: {"OK" if ok else "HIBA"}')

before = mread_word(TRACE_BASE)
print(f'  Trace elotte: 0x{before:04X}')
send(f'JSR {code_a}'); time.sleep(0.5)
e = errstr()
after = mread_word(TRACE_BASE)
print(f'  JSR: {e!r}')
print(f'  Trace utana: 0x{after:04X}  -> high byte = 0x{(after>>8)&0xFF:02X}')
io_hi = (after >> 8) & 0xFF
print(f'  Ellenorzes: IO even byte kod altal = 0x{io_hi:02X}, MREAD-del = 0x{mread_byte_hi(0x0C0000):02X}')

# ═══════════════════════════════════════════════════════
sep('TESZT B: /WE MEGNYITAS AZ EVEN BYTE-ON (0x0C0000)')
# ═══════════════════════════════════════════════════════
# move.b $C0000.l, d0          -> 1038 000C 0000
# ori.b  #$80, d0              -> 0000 0080
# move.b d0, $C0000.l          -> 13C0 000C 0000    <-- EVEN address
# move.b #$42, $60C4C.l        -> 13FC 0042 0006 0C4C
# andi.b #$7F, d0              -> 0200 007F
# move.b d0, $C0000.l          -> 13C0 000C 0000
# rts                          -> 4E75
#
# 0x60C4C = 0x00060C4C -> high=0x0006=6, low=0x0C4C=3148

code_b = 0x12E800
words_b = [
    0x1038, 0x000C, 0x0000,        # move.b $C0000.l, d0
    0x0000, 0x0080,                 # ori.b  #$80, d0
    0x13C0, 0x000C, 0x0000,        # move.b d0, $C0000.l  (/WE OPEN)
    0x13FC, 0x0042, 0x0006, 0x0C4C, # move.b #$42, $60C4C.l
    0x0200, 0x007F,                 # andi.b #$7F, d0
    0x13C0, 0x000C, 0x0000,        # move.b d0, $C0000.l  (/WE CLOSE)
    0x4E75                          # rts
]
mwrite_words(code_b, words_b)
chk_b = [mread_word(code_b + i*2) for i in range(len(words_b))]
ok_b = all(a==b for a,b in zip(chk_b, words_b))
print(f'  Kod irva: {"OK" if ok_b else "HIBA"}')
if not ok_b:
    for i,(a,b) in enumerate(zip(words_b, chk_b)):
        if a != b: print(f'    word {i}: elvart 0x{a:04X} kapott 0x{b:04X}')

dolt_before = mread_byte_hi(DOLT_PHYS)
io_before   = mread_word(0x0C0000)
print(f'  DOLT[0] elotte: 0x{dolt_before:02X}')
print(f'  IO word elotte: 0x{io_before:04X}')
print(f'  >>> JSR {code_b} <<<')
send(f'JSR {code_b}'); time.sleep(1.0)
e_b = errstr()
dolt_after = mread_byte_hi(DOLT_PHYS)
io_after   = mread_word(0x0C0000)
print(f'  JSR eredmeny: {e_b!r}')
print(f'  DOLT[0] utana: 0x{dolt_after:02X}  (vart: 0x42)')
print(f'  IO word utana: 0x{io_after:04X}  (bit15 legyen 0 = /WE zart)')

if dolt_after == 0x42:
    print('  *** SIKER: /WE EVEN byte (0x0C0000) megnyitasaval cal_ram iras mukodik! ***')
    print()
    # Visszaallitas
    print('  Visszaallitas DOLT[0] = 0x00...')
    restore = [
        0x1038, 0x000C, 0x0000,
        0x0000, 0x0080,
        0x13C0, 0x000C, 0x0000,
        0x13FC, 0x0000, 0x0006, 0x0C4C,  # move.b #$00 (visszaallitas)
        0x0200, 0x007F,
        0x13C0, 0x000C, 0x0000,
        0x4E75,
    ]
    mwrite_words(code_b, restore)
    send(f'JSR {code_b}'); time.sleep(0.5)
    dolt_final = mread_byte_hi(DOLT_PHYS)
    print(f'  DOLT[0] visszaallitva: 0x{dolt_final:02X}')
else:
    print(f'  Elteres (kapott 0x{dolt_after:02X})')
    print()
    # ═══════════════════════════════════════════════════════
    sep('TESZT C: WORD ACCESS (move.w $C0000) - biztonsagi alternativa')
    # ═══════════════════════════════════════════════════════
    # A 68000 move.w-nel mindket byteot irja egyszerre
    # move.w $C0000.l, d0    -> 3038 000C 0000
    # ori.w  #$8000, d0      -> 0040 8000
    # move.w d0, $C0000.l    -> 33C0 000C 0000
    # move.b #$42, $60C4C.l  -> 13FC 0042 0006 0C4C
    # andi.w #$7FFF, d0      -> 0240 7FFF
    # move.w d0, $C0000.l    -> 33C0 000C 0000
    # rts                    -> 4E75
    code_c = 0x12E900
    words_c = [
        0x3038, 0x000C, 0x0000,        # move.w $C0000.l, d0
        0x0040, 0x8000,                 # ori.w  #$8000, d0  (/WE = high bit of high byte)
        0x33C0, 0x000C, 0x0000,        # move.w d0, $C0000.l
        0x13FC, 0x0042, 0x0006, 0x0C4C,# move.b #$42, $60C4C.l
        0x0240, 0x7FFF,                 # andi.w #$7FFF, d0
        0x33C0, 0x000C, 0x0000,        # move.w d0, $C0000.l
        0x4E75                          # rts
    ]
    mwrite_words(code_c, words_c)
    chk_c = [mread_word(code_c + i*2) for i in range(len(words_c))]
    ok_c = all(a==b for a,b in zip(chk_c, words_c))
    print(f'  Kod irva: {"OK" if ok_c else "HIBA"}')

    dolt_c_before = mread_byte_hi(DOLT_PHYS)
    print(f'  DOLT[0] elotte: 0x{dolt_c_before:02X}')
    print(f'  >>> JSR {code_c} (word access teszt) <<<')
    send(f'JSR {code_c}'); time.sleep(1.0)
    e_c = errstr()
    dolt_c_after = mread_byte_hi(DOLT_PHYS)
    io_c = mread_word(0x0C0000)
    print(f'  JSR eredmeny: {e_c!r}')
    print(f'  DOLT[0] utana: 0x{dolt_c_after:02X}  (vart: 0x42)')
    print(f'  IO word utana: 0x{io_c:04X}')

    if dolt_c_after == 0x42:
        print('  *** SIKER: WORD access-szel /WE megnyitasa mukodik! ***')
        # Visszaallitas
        restore_c = [
            0x3038, 0x000C, 0x0000,
            0x0040, 0x8000,
            0x33C0, 0x000C, 0x0000,
            0x13FC, 0x0000, 0x0006, 0x0C4C,
            0x0240, 0x7FFF,
            0x33C0, 0x000C, 0x0000,
            0x4E75,
        ]
        mwrite_words(code_c, restore_c)
        send(f'JSR {code_c}'); time.sleep(0.5)
        print(f'  DOLT[0] visszaallitva: 0x{mread_byte_hi(DOLT_PHYS):02X}')
    else:
        print(f'  Word access is sikertelen (kapott 0x{dolt_c_after:02X})')

s.close()
print(); print('Teszt befejezve.')
