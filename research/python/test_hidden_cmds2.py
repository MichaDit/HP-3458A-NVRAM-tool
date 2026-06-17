"""
Rejtett parancsok 2. kore - parameterekkel.
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
        time.sleep(0.1)

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
        err = self.qerr()
        return r, err

    def qerr(self):
        self._s.sendall(b'ERRSTR?\n')
        time.sleep(0.06)
        return self.read(1.5)

    def close(self):
        self._s.close()

br = Bridge()
br.write('BEEP 1')
time.sleep(0.15)

# --- DEFKEY? F0..F9 ---
print('=== DEFKEY? (function keys) ===')
for k in range(10):
    r, err = br.q(f'DEFKEY? F{k}')
    ok = '0,"NO ERROR"' in err
    print(f'  DEFKEY? F{k}: {r!r}  {"OK" if ok else "HIBA: "+err}')

# --- BUSOUT_ parameterrel ---
print()
print('=== BUSOUT_ N (ADC raw output) ===')
for n in [0, 1, 2, 4, 8, 16]:
    r, err = br.q(f'BUSOUT_ {n}', timeout=4.0)
    ok = '0,"NO ERROR"' in err
    print(f'  BUSOUT_ {n:3d}: {r!r:30s}  {"OK" if ok else "HIBA: "+err}')

# --- NMR beallitas es visszaolvasas ---
print()
print('=== NMR (Normal Mode Rejection) ===')
for val in [0, 1, 2, 3]:
    br.write(f'NMR {val}')
    time.sleep(0.1)
    r, err = br.q('NMR?')
    ok = '0,"NO ERROR"' in err
    print(f'  NMR {val} -> NMR?: {r!r}  {"OK" if ok else "HIBA: "+err}')
# Vissza az eredeti ertekre
br.write('NMR 3')
time.sleep(0.1)

# --- SWEEP (sepresi mod) ---
print()
print('=== SWEEP ===')
r, err = br.q('SWEEP', timeout=5.0)
print(f'  SWEEP: {r[:100]!r}')
print(f'  ERRSTR?: {err!r}')

# --- RATIO (arany meres) ---
print()
print('=== RATIO ===')
r, err = br.q('RATIO', timeout=5.0)
print(f'  RATIO: {r[:100]!r}')
print(f'  ERRSTR?: {err!r}')

# --- AUXERR? (auxiliary error) ---
print()
print('=== AUXERR? ===')
r, err = br.q('AUXERR?', timeout=2.0)
print(f'  AUXERR?: {r!r}')
print(f'  ERRSTR?: {err!r}')

# --- CAT (katalogus) ---
print()
print('=== CAT ===')
br.write('CAT')
time.sleep(0.5)
r = br.read(3.0)
err = br.qerr()
print(f'  CAT: {r[:200]!r}')
print(f'  ERRSTR?: {err!r}')

# --- DIAGNOST ---
print()
print('=== DIAGNOST ===')
r, err = br.q('DIAGNOST', timeout=5.0)
print(f'  DIAGNOST: {r[:100]!r}')
print(f'  ERRSTR?: {err!r}')

# --- TONE (hang) ---
print()
print('=== TONE (hang) ===')
for freq in [440, 1000, 2000]:
    br.write(f'TONE {freq}')
    time.sleep(0.3)
    err = br.qerr()
    print(f'  TONE {freq}: ERRSTR?={err!r}')
time.sleep(0.2)

# --- WAIT ---
print()
print('=== WAIT 0.1 ===')
r, err = br.q('WAIT 0.1', timeout=3.0)
print(f'  WAIT: {r!r}  ERRSTR?={err!r}')

# --- TERM ---
print()
print('=== TERM? / TERM ===')
r, err = br.q('TERM?')
print(f'  TERM?: {r!r}  ERRSTR?={err!r}')

# --- ACBAND (AC bandwidth limit) ---
print()
print('=== ACBAND ===')
r, err = br.q('ACBAND?', timeout=2.0)
print(f'  ACBAND?: {r!r}  ERRSTR?={err!r}')

br.close()
print('\nKesz.')
