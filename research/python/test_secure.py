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

# Init + BEEP 1
sw('++addr 22'); sw('++read_tmo_ms 500'); sw('++clr'); time.sleep(1.0)
for c in ['END ALWAYS', 'NPLC 0', 'NRDGS 1', 'TRIG HOLD', 'QFORMAT NUM']:
    sw(c)
sw('BEEP 1')
time.sleep(0.2)

# MREAD teszt BEEP 1 utan
r = sq('MREAD 395348')
print('MREAD 395348 (BEEP 1 utan) -> ' + r)
print('ERRSTR: ' + sq('ERRSTR?'))

# SECURE szintaxis variansok
candidates = [
    'SECURE 22',
    'SECURE "22"',
    'SECURE 0',
    'SECURE "0"',
    'SECURE "HP3458A"',
    'SECURE "HP 3458A"',
    'SECURE ON,22',
    'SECURE ON,"22"',
]

print()
for cmd in candidates:
    sw(cmd); time.sleep(0.05)
    e = sq('ERRSTR?')
    ok = '' if e.startswith('103') else '  <<< MUKODIK!'
    print(cmd + '  ->  ' + e + ok)

s.sendall(b'TRIG AUTO\nDISP 1\n'); s.close()
