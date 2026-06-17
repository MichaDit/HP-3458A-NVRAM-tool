"""
Cal_ram MWRITE nyitási módszer tesztelése.
Tesztelünk: BEEP 2 bypass, MADDR+MWRITE szintaxis.
Biztonságos terület: Defeats[0] @ cal_ram 0x62A, fizikai 0x60C54 = 395348.
"""
import socket, time

s = socket.create_connection(('192.168.2.88', 1234), timeout=10)
s.settimeout(10)
buf = b''

def sw(cmd):
    s.sendall((cmd + '\n').encode('ascii'))

def sr():
    global buf
    while b'\n' not in buf:
        buf += s.recv(4096)
    line, buf = buf.split(b'\n', 1)
    return line.decode('ascii', 'replace').strip()

def sq(cmd):
    sw(cmd); sw('++read'); return sr()

def err():
    return sq('ERRSTR?')

# Init + BEEP 1
sw('++addr 22'); sw('++read_tmo_ms 500'); sw('++clr'); time.sleep(1.0)
for c in ['END ALWAYS', 'NPLC 0', 'NRDGS 1', 'TRIG HOLD', 'QFORMAT NUM']:
    sw(c)
sw('BEEP 1'); time.sleep(0.2)

ADDR = 395348   # Defeats[0], fizikai 0x60C54
MARK = 56832    # 0xDE00 — HIGH byte = 0xDE a DS1220Y-ba

def read_defeats0():
    v = int(sq('MREAD ' + str(ADDR)))
    return v

def check_write(label):
    v_after = read_defeats0()
    high = (v_after >> 8) & 0xFF
    if high == 0xDE:
        print('  ' + label + ' -> SIKERES IRAS! visszaolvasas: ' + hex(v_after))
        return True
    else:
        print('  ' + label + ' -> nem irt, ertek: ' + hex(v_after))
        return False

v0 = read_defeats0()
print('Defeats[0] indulasko: ' + hex(v0) + '  (HIGH byte=' + hex((v0>>8)&0xFF) + ')')
print()

# --- 1. kiserlet: MADDR + MWRITE (szintaxis variacio) ---
print('=== 1. MADDR + MWRITE szintaxis ===')
sw('MADDR ' + str(ADDR))
sw('MWRITE ' + str(MARK))
time.sleep(0.05)
print('  ERRSTR: ' + err())
check_write('MADDR+MWRITE')
print()

# --- 2. kiserlet: BEEP 2 bypass + MWRITE ---
print('=== 2. BEEP 2 + MWRITE ===')
sw('BEEP 2'); time.sleep(0.1)
sw('MWRITE ' + str(ADDR) + ',' + str(MARK)); time.sleep(0.05)
print('  ERRSTR: ' + err())
check_write('BEEP2+MWRITE addr,val')
sw('BEEP 1')  # visszaallitas

# --- 3. kiserlet: SECURE? lekerdezese ---
print()
print('=== 3. SECURE? lekerdezes ===')
r = sq('SECURE?')
print('  SECURE? -> ' + r)
print('  ERRSTR: ' + err())

# --- 4. kiserlet: SECURE erteke (REV9 szerint 22) ---
print()
print('=== 4. SECURE szintaxis variansok ===')
for cmd in ['SECURE 22,1', 'SECURE 1,22', 'SECURE,22', 'SECURE -22']:
    sw(cmd); time.sleep(0.05)
    e = err()
    ok = '  <<< MUKODIK!' if not e.startswith('103') else ''
    print('  ' + cmd + ' -> ' + e + ok)

v_end = read_defeats0()
print()
print('Defeats[0] vegul: ' + hex(v_end))
if (v_end >> 8) & 0xFF == 0xDE:
    print('Valamelyik iras sikeres volt! Visszaallitas...')
    sw('BEEP 1')
    sw('MADDR ' + str(ADDR))
    sw('MWRITE ' + str(v0))

s.sendall(b'TRIG AUTO\nDISP 1\n'); s.close()
