"""
JSR kod debug: bebizonytjuk, hogy a kod fut, es nyomon kovetjuk az IO port allapotat.

Tesztek (novekvő komplexitas):

1. NOP teszt: JSR → nop + rts → ha hiba nelkul tér vissza, a kod fut
2. TRACE teszt: JSR → move.b #0xAB, $12F100 + rts
   Ha 0x12F100 = 0xAB lesz: kod fut es settings_ram-ba ir
3. IO PORT TRACE: JSR → olvas $C0001 → menti $12F100 → rts
   Ha 0x12F100 = IO port ertek: kod fut es IO portot latja
4. /WE TRACE: JSR → nyit /WE → ment IO port erteket → zarj /WE → rts
   0x12F100 = IO elotte, 0x12F102 = IO koz kozben (WE nyitva), 0x12F104 = IO utan
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

def jsr_call(addr, label, wait=0.5):
    send(f'JSR {addr}')
    time.sleep(wait)
    e = errstr()
    ok = 'NO ERROR' in e or e.startswith('0,')
    print(f'  JSR {addr} ({label}): {"OK" if ok else "HIBA: "+e}')
    return ok

def sep(t): print(); print(f'=== {t} ===')

# Init
send('PRESET NORM'); time.sleep(0.8)
send('END ALWAYS');  time.sleep(0.2)
send('BEEP 1');      time.sleep(0.2)
q('ERRSTR?')

TRACE_BASE = 0x12F100   # trace area a settings_ram-ban (nem hasznalt terulet)

# Kezdeti allapot
print(f'Trace area (0x12F100): 0x{mread_word(TRACE_BASE):04X}')
print(f'IO port (0x0C0001):    0x{mread_word(0x0C0001):04X}')

# ═══════════════════════════════════════════════════════
sep('TESZT 1: NOP + RTS — fut-e egyaltalan a kod?')
# ═══════════════════════════════════════════════════════
# move.b #$AB, 0x12F100:
#   13FC 00AB 0012 F100  (8 bytes = 4 words)
# rts: 4E75 (1 word)
#
# FONTOS: 0xF100 = 61696 > 32767 -> MWRITE-hoz: -3840

nop_code_addr = 0x12E400
nop_code = [
    0x13FC, 0x00AB, 0x0012, 0xF100,   # move.b #$AB, $12F100.l
    0x4E75                              # rts
]

print(f'  Kod: move.b #0xAB, $12F100 + rts -> 0x{nop_code_addr:06X}')
mwrite_words(nop_code_addr, nop_code)

# Ellenorzes: sikeresen be lett irva?
chk = [mread_word(nop_code_addr + i*2) for i in range(len(nop_code))]
print(f'  MWRITE verify: {[f"0x{w:04X}" for w in chk]}')
print(f'  Elvart:        {[f"0x{w:04X}" for w in nop_code]}')
ok_write = all(a == b for a,b in zip(chk, nop_code))
print(f'  Kod helyesen irva: {"IGEN" if ok_write else "NEM - MWRITE HIBA"}')

# Futtatjuk
b_before = mread_byte_hi(TRACE_BASE)
print(f'  Trace 0x12F100 ELOTTE: 0x{b_before:02X}')
jsr_call(nop_code_addr, f'0x{nop_code_addr:06X} = move.b #AB, $12F100')
b_after = mread_byte_hi(TRACE_BASE)
print(f'  Trace 0x12F100 UTANA:  0x{b_after:02X}')

if b_after == 0xAB:
    print('  *** SIKER: a kod fut es settings_ram-ba ir! ***')
elif b_after == b_before:
    print('  !!! HIBA: 0x12F100 nem valtozottF - a kod NEM futott, vagy nem irt')
else:
    print(f'  Reszleges: 0x{b_before:02X} -> 0x{b_after:02X} (varatlan)')

# ═══════════════════════════════════════════════════════
sep('TESZT 2: IO PORT TRACE — latja-e a kod a 0x0C0001-et?')
# ═══════════════════════════════════════════════════════
# move.b $C0001.l, d0    -> 1039 000C 0001
# move.b d0, $12F102.l   -> 13C0 0012 F102
# rts                      -> 4E75
#
# 0x12F102 as 32-bit = 0x0012F102
# High word: 0x0012 = 18
# Low word:  0xF102 = 61698 > 32767 -> signed = -3838

io_trace_addr = 0x12E500
io_trace_code = [
    0x1039, 0x000C, 0x0001,    # move.b $C0001.l, d0
    0x13C0, 0x0012, 0xF102,    # move.b d0, $12F102.l  (trace helye)
    0x4E75                      # rts
]

print(f'  Kod: read IO port 0x0C0001 -> $12F102 -> 0x{io_trace_addr:06X}')
mwrite_words(io_trace_addr, io_trace_code)

# Ellenorzes
chk2 = [mread_word(io_trace_addr + i*2) for i in range(len(io_trace_code))]
ok2 = all(a == b for a,b in zip(chk2, io_trace_code))
print(f'  Kod helyesen irva: {"IGEN" if ok2 else "NEM"}')

if not ok2:
    print(f'  Elvart:   {[f"0x{w:04X}" for w in io_trace_code]}')
    print(f'  Talalt:   {[f"0x{w:04X}" for w in chk2]}')

trace2_before = mread_word(0x12F102)
print(f'  0x12F102 ELOTTE: 0x{trace2_before:04X}')

jsr_call(io_trace_addr, f'IO port trace')

trace2_after = mread_word(0x12F102)
io_word_actual = mread_word(0x0C0001)
print(f'  0x12F102 UTANA:  0x{trace2_after:04X}  (high byte = IO byte at 0xC0001)')
print(f'  MREAD 0x0C0001:  0x{io_word_actual:04X}  (word at 0xC0000, low byte = IO port byte)')

io_port_byte = (io_word_actual) & 0xFF  # low byte = byte at 0xC0001
traced_byte  = (trace2_after >> 8) & 0xFF  # high byte of word at 0x12F102
print(f'  IO port byte (0xC0001): 0x{io_port_byte:02X}')
print(f'  Kod altal mentett byte: 0x{traced_byte:02X}')

if traced_byte == io_port_byte:
    print('  *** EGYEZIK: kod latja az IO portot! ***')
elif trace2_after == trace2_before:
    print('  !!! A kod NEM futott (trace ertek nem valtozott)')
else:
    print(f'  Elteres: kod 0x{traced_byte:02X} != MREAD 0x{io_port_byte:02X}')

# ═══════════════════════════════════════════════════════
sep('TESZT 3: /WE NYITAS TRACE — valtozott-e az IO port?')
# ═══════════════════════════════════════════════════════
# move.b $C0001.l, d0          -> 1039 000C 0001   ; read IO
# move.b d0, $12F200.l         -> 13C0 0012 F200   ; save: IO elotte
# ori.b  #$80, d0              -> 0000 0080         ; set /WE bit
# move.b d0, $C0001.l          -> 13C0 000C 0001   ; OPEN /WE
# move.b $C0001.l, d1          -> 1239 000C 0001   ; verify: read back
# move.b d1, $12F202.l         -> 13C1 0012 F202   ; save: IO WE nyitva
# andi.b #$7F, d0              -> 0200 007F         ; clear /WE bit
# move.b d0, $C0001.l          -> 13C0 000C 0001   ; CLOSE /WE
# rts                          -> 4E75

we_trace_addr = 0x12E600
we_trace_code = [
    0x1039, 0x000C, 0x0001,    # move.b $C0001.l, d0
    0x13C0, 0x0012, 0xF200,    # move.b d0, $12F200.l  (IO elotte)
    0x0000, 0x0080,            # ori.b #$80, d0
    0x13C0, 0x000C, 0x0001,   # move.b d0, $C0001.l  (OPEN /WE)
    0x1239, 0x000C, 0x0001,   # move.b $C0001.l, d1  (verify readback)
    0x13C1, 0x0012, 0xF202,   # move.b d1, $12F202.l (IO WE nyitva)
    0x0200, 0x007F,            # andi.b #$7F, d0
    0x13C0, 0x000C, 0x0001,   # move.b d0, $C0001.l  (CLOSE /WE)
    0x4E75                     # rts
]
# 0x12F200 = 0x0012F200: high=0x0012=18, low=0xF200=61952>32767->signed=-3584
# 0x12F202 = 0x0012F202: high=0x0012=18, low=0xF202=61954>32767->signed=-3582

print(f'  Kod: /WE trace (open+close+readback) -> 0x{we_trace_addr:06X}')
mwrite_words(we_trace_addr, we_trace_code)

chk3 = [mread_word(we_trace_addr + i*2) for i in range(len(we_trace_code))]
ok3 = all(a == b for a,b in zip(chk3, we_trace_code))
print(f'  Kod helyesen irva: {"IGEN" if ok3 else "NEM"}')
if not ok3:
    for i,(a,b) in enumerate(zip(we_trace_code, chk3)):
        if a != b:
            print(f'    Word {i} @ 0x{we_trace_addr+i*2:06X}: elvart 0x{a:04X}, talalt 0x{b:04X}')

before_200 = mread_word(0x12F200)
before_202 = mread_word(0x12F202)
io_before  = mread_word(0x0C0001)
print(f'  ELOTTE: 0x12F200=0x{before_200:04X}, 0x12F202=0x{before_202:04X}, IO=0x{io_before:04X}')

jsr_call(we_trace_addr, '/WE trace open+close', wait=1.0)

after_200 = mread_word(0x12F200)
after_202 = mread_word(0x12F202)
io_after   = mread_word(0x0C0001)
print(f'  UTANA:  0x12F200=0x{after_200:04X}, 0x12F202=0x{after_202:04X}, IO=0x{io_after:04X}')

io_elotte_byte  = (after_200 >> 8) & 0xFF
io_nyitva_byte  = (after_202 >> 8) & 0xFF
io_most_byte    = io_after & 0xFF  # low byte of word at 0xC0000

print()
print(f'  IO port byte 0xC0001 elotte: 0x{io_elotte_byte:02X} (bit7={io_elotte_byte>>7})')
print(f'  IO port byte 0xC0001 /WE ny: 0x{io_nyitva_byte:02X} (bit7={io_nyitva_byte>>7})')
print(f'  IO port byte 0xC0001 most:   0x{io_most_byte:02X} (bit7={io_most_byte>>7})')

if after_200 == before_200 and after_202 == before_202:
    print('  !!! NINCS VALTOZAS: a kod NEM futott!')
elif io_elotte_byte != 0 and (io_nyitva_byte >> 7) == 1:
    print('  *** /WE sikeresen megnyitva es lezarva! ***')
elif io_elotte_byte != 0:
    print(f'  IO port trace OK, de /WE bit allapota: {io_nyitva_byte>>7} (vart: 1)')
else:
    print('  Ertelmezese szukseges...')

s.close()
print()
print('Debug teszt befejezve.')
