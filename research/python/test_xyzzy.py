"""XYZZY teszt - figyeld a muszert!"""
import socket, time

BRIDGE_HOST = '192.168.2.88'
BRIDGE_PORT = 1234
GPIB_ADDR   = 22

s = socket.create_connection((BRIDGE_HOST, BRIDGE_PORT), timeout=15)
s.sendall(b'++mode 1\n')
s.sendall(f'++addr {GPIB_ADDR}\n'.encode())
s.sendall(b'++auto 0\n')
s.sendall(b'++eos 2\n')
s.sendall(b'++eoi 1\n')
s.sendall(b'++read_tmo_ms 2000\n')
time.sleep(0.3)

def write(cmd):
    s.sendall((cmd + '\n').encode())
    time.sleep(0.15)

def read(timeout=3.0):
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
    write(cmd)
    r = read(timeout)
    print(f'  {cmd!r:30s} -> {r!r}')
    return r

# Init
write('PRESET NORM')
time.sleep(0.8)
write('END ALWAYS')
time.sleep(0.2)
write('BEEP 1')
time.sleep(0.2)
q('ERRSTR?')

print()
print('=== XYZZY direktben (parancsnevvel) ===')
q('XYZZY')
q('ERRSTR?')

print()
print('=== JSR 97184 (0x17BA0 = XYZZY handler) ===')
print('  >>> Figyeld a muszert! <<<')
q('JSR 97184')
q('ERRSTR?')

print()
print('=== Meg egyszer, lassan ===')
time.sleep(1.0)
q('JSR 97184')
time.sleep(0.5)
q('ERRSTR?')

s.close()
print('\nKesz.')
