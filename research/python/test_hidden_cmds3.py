"""
Rejtett parancsok 3. kore - mod-specifikus tesztek.
NMR -> ACV/FREQ modban, CAT -> MEM utan, RATIO -> DCV modban.
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

    def qraw(self, cmd, timeout=3.0):
        self.write(cmd)
        return self.read(timeout)

    def qerr(self):
        self._s.sendall(b'ERRSTR?\n')
        time.sleep(0.06)
        return self.read(1.5)

    def close(self):
        self._s.close()

br = Bridge()
br.write('BEEP 1')
time.sleep(0.15)

# --- NMR ACV modban ---
print('=== NMR ACV modban ===')
br.write('ACV')
time.sleep(0.3)
for val in [0, 1, 2, 3]:
    br.write(f'NMR {val}')
    time.sleep(0.15)
    r = br.qraw('NMR?')
    err = br.qerr()
    print(f'  ACV+NMR {val} -> NMR?={r!r}  ERRSTR?={err!r}')

# --- NMR FREQ modban ---
print()
print('=== NMR FREQ modban ===')
br.write('FREQ')
time.sleep(0.3)
for val in [0, 1, 2, 3]:
    br.write(f'NMR {val}')
    time.sleep(0.15)
    r = br.qraw('NMR?')
    err = br.qerr()
    print(f'  FREQ+NMR {val} -> NMR?={r!r}  ERRSTR?={err!r}')

# Vissza DCV
br.write('DCV')
time.sleep(0.3)

# --- CAT MEM utan ---
print()
print('=== CAT MEM utan ===')
br.write('MEM FIFO')
time.sleep(0.2)
r = br.qraw('CAT', timeout=4.0)
err = br.qerr()
print(f'  MEM FIFO + CAT: {r[:200]!r}')
print(f'  ERRSTR?: {err!r}')

# --- RATIO DCV modban ---
print()
print('=== RATIO (DCV) ===')
br.write('DCV')
time.sleep(0.3)
r = br.qraw('RATIO', timeout=5.0)
err = br.qerr()
print(f'  RATIO: {r[:100]!r}  ERRSTR?={err!r}')

# --- SWEEP DCV modban ---
print()
print('=== SWEEP (DCV) ===')
r = br.qraw('SWEEP', timeout=5.0)
err = br.qerr()
print(f'  SWEEP: {r[:100]!r}  ERRSTR?={err!r}')

# --- WAIT ---
print()
print('=== WAIT ===')
br.write('DCV')
time.sleep(0.3)
br.write('WAIT 0.5')
time.sleep(0.8)
err = br.qerr()
print(f'  WAIT 0.5 -> ERRSTR?={err!r}')

# --- TERM ---
print()
print('=== TERM (terminator) ===')
r = br.qraw('TERM?', timeout=2.0)
err = br.qerr()
print(f'  TERM?: {r!r}  ERRSTR?={err!r}')

# --- DIAGNOST (diagnostics) ---
print()
print('=== DIAGNOST (DCV) ===')
br.write('DCV')
time.sleep(0.3)
r = br.qraw('DIAGNOST', timeout=8.0)
err = br.qerr()
print(f'  DIAGNOST: {r[:200]!r}  ERRSTR?={err!r}')

# --- BUSOUT_ ACV modban es DCV modban ---
print()
print('=== BUSOUT_ modban ===')
br.write('DCV')
time.sleep(0.3)
for n in [0, 1, 2]:
    r = br.qraw(f'BUSOUT_ {n}', timeout=4.0)
    err = br.qerr()
    print(f'  DCV+BUSOUT_ {n}: {r!r}  {err!r}')

print()
# Vissza DCV alapallapotba
br.write('PRESET NORM')
time.sleep(0.3)
err = br.qerr()
print(f'PRESET NORM -> {err!r}')

br.close()
print('\nKesz.')
