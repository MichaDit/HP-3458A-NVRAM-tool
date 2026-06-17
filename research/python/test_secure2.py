"""
SECURE szintaxis pontosítása — Cal_SecureCode = 0x00000000.
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

def mread(addr):
    return int(sq('MREAD ' + str(addr)))

# Init + BEEP 1
sw('++addr 22'); sw('++read_tmo_ms 500'); sw('++clr'); time.sleep(1.0)
for c in ['END ALWAYS', 'NPLC 0', 'NRDGS 1', 'TRIG HOLD', 'QFORMAT NUM']:
    sw(c)
sw('BEEP 1'); time.sleep(0.2)

ADDR = 395348  # Defeats[0]
MARK = 56832   # 0xDE00

v0 = mread(ADDR)
print('Defeats[0] indulas: ' + hex(v0))
print()

# SECURE szintaxis: elso param a kód, masodik param a mi?
# Cal_SecureCode = 0 -> proba: 0,X
candidates = [
    'SECURE 0,0',
    'SECURE 0,1',
    'SECURE 0,2',
    'SECURE 0,-1',
    'SECURE 0,22',
    'SECURE 22,0',
    'SECURE 22,22',
]

for cmd in candidates:
    sw(cmd); time.sleep(0.05)
    e = err()
    ok = '  <<< MUKODIK!' if ('NO ERROR' in e) else ''
    wrong = '  (rossz kod)' if 'Wrong secure' in e else ''
    print(cmd + '  ->  ' + e + ok + wrong)

    # Ha mukodik, probaljuk meg az MWRITE-ot
    if 'NO ERROR' in e:
        print('  --- MWRITE kiserlet ---')
        sw('MWRITE ' + str(ADDR) + ',' + str(MARK)); time.sleep(0.05)
        e2 = err()
        v1 = mread(ADDR)
        high = (v1 >> 8) & 0xFF
        print('  MWRITE ERRSTR: ' + e2)
        print('  Visszaolvasas: ' + hex(v1) + '  HIGH=0x' + format(high, '02X'))
        if high == 0xDE:
            print('  CAL_RAM MWRITE SIKERES!')
            sw('MWRITE ' + str(ADDR) + ',' + str(v0))  # visszaall
        break

print()
print('Defeats[0] vegul: ' + hex(mread(ADDR)))
s.sendall(b'TRIG AUTO\nDISP 1\n'); s.close()
