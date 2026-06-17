"""
Rejtett parancsok elso tesztje.
- TEMP?       : belso homerseklet
- ADDRESS?    : GPIB cim
- DEFKEY?     : F0-F9 definiciok
- NMR?        : Normal Mode Rejection
- DEFEAT?     : auto-defeat filter allapot
- BUSOUT_     : ADC raw output
- BOMB?       : settings_ram debug dump (rovid)
- XYZZY       : easter egg
"""
import socket, time

BRIDGE_HOST = '192.168.2.88'
BRIDGE_PORT = 1234
GPIB_ADDR   = 22

class Bridge:
    def __init__(self):
        self._s = socket.create_connection((BRIDGE_HOST, BRIDGE_PORT), timeout=15)
        self._s.sendall(b'++mode 1\n')
        self._s.sendall(f'++addr {GPIB_ADDR}\n'.encode())
        self._s.sendall(b'++auto 0\n')
        self._s.sendall(b'++eos 2\n')
        self._s.sendall(b'++eoi 1\n')
        self._s.sendall(b'++read_tmo_ms 500\n')
        time.sleep(0.3)

    def write(self, cmd):
        self._s.sendall((cmd + '\n').encode())
        time.sleep(0.08)

    def read(self, timeout=2.0):
        self._s.sendall(b'++read eoi\n')
        buf = b''
        self._s.settimeout(timeout)
        try:
            while True:
                b = self._s.recv(512)
                if not b:
                    break
                buf += b
                if b'\n' in b:
                    break
        except socket.timeout:
            pass
        return buf.decode('ascii', errors='replace').strip()

    def q(self, cmd, timeout=3.0):
        self.write(cmd)
        r = self.read(timeout)
        err = self.q_err()
        return r, err

    def q_err(self):
        self._s.sendall(b'ERRSTR?\n')
        time.sleep(0.05)
        return self.read(1.5)

    def close(self):
        self._s.close()

br = Bridge()

tests = [
    ('TEMP?',    'Belso homerseklet (C?)'),
    ('ADDRESS?', 'GPIB cim'),
    ('NMR?',     'Normal Mode Rejection'),
    ('DEFEAT?',  'Auto-defeat filter allapot'),
    ('DEFKEY?',  'Function key definiciok'),
]

print('=== ALAP LEKERDEZO REJTETT PARANCSOK ===')
br.write('BEEP 1')
time.sleep(0.15)
for cmd, desc in tests:
    r, err = br.q(cmd)
    status = '' if '0,"NO ERROR"' in err else f'  HIBA: {err}'
    print(f'  {cmd:<14}: {r!r:40s}  [{desc}]{status}')

print()
print('=== XYZZY (easter egg) ===')
br.write('XYZZY')
time.sleep(0.3)
xyzzy_err = br.q_err()
print(f'  XYZZY -> ERRSTR?: {xyzzy_err!r}')

print()
print('=== BUSOUT_ (ADC raw output) ===')
r, err = br.q('BUSOUT_', timeout=5.0)
print(f'  Valasz: {r!r}')
print(f'  ERRSTR?: {err!r}')

print()
print('=== BOMB? (settings_ram debug dump) ===')
r, err = br.q('BOMB?', timeout=5.0)
# csak az elso 200 karaktert mutatjuk
r_short = r[:200] if len(r) > 200 else r
print(f'  Valasz (rovid): {r_short!r}')
print(f'  ERRSTR?: {err!r}')

print()
print('=== ECHO teszt ===')
r, err = br.q('ECHO "hello3458"', timeout=2.0)
print(f'  ECHO "hello3458" -> {r!r}')
print(f'  ERRSTR?: {err!r}')

br.close()
print('\nKesz.')
