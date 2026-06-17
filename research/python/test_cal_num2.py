"""
CAL_NUM teszt v2 — nyilvanos parancsokkal ellenorzunk (CAL?, CALNUM?)
es pontosabb DOLT olvasas (4 byte, EVEN bank).
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

    def q(self, cmd, timeout=2.0):
        self.write(cmd)
        return self.read(timeout)

    def raw_mread(self, phys):
        """MREAD visszatert erteket signed int-kent."""
        r = self.q(f'MREAD {phys}')
        try:
            v = int(float(r))
            # signed 16-bit -> unsigned
            if v < 0:
                v = v & 0xFFFF
            return v
        except Exception:
            return None

    def mread_byte(self, phys):
        """EVEN bank byte kiolvasas: a 16-bites szobol a HIGH byte az ervenyes adat."""
        v = self.raw_mread(phys)
        if v is None:
            return None
        return (v >> 8) & 0xFF

    def close(self):
        self._s.close()

def read_cal_state(br, label):
    print(f'\n=== {label} ===')

    # CALNUM? -- nyilvanos lekerdezes
    calnum_q = br.q('CALNUM?')
    print(f'  CALNUM?    : {calnum_q!r}')

    # CAL? -- nyilvanos kalibracios allapot (tartalmazza DOLT-ot)
    cal_q = br.q('CAL?', timeout=5.0)
    print(f'  CAL?       : {cal_q!r}')

    # CALSTR? -- calibration string (0x5CA-0x619)
    calstr_q = br.q('CALSTR?', timeout=3.0)
    print(f'  CALSTR?    : {calstr_q[:60]!r}...' if len(calstr_q) > 60 else f'  CALSTR?    : {calstr_q!r}')

    # Direkt MREAD -- DOLT 4 byte (cal_ram 0x626-0x629, fizikai 0x60C4C-0x60C52)
    # Calnum 4 byte (cal_ram 0x61A-0x61D, fizikai 0x60C34-0x60C3A)
    print()
    print('  Direkt MREAD cal_ram:')
    for name, offset in [('Calnum',  0x61A), ('Calnum+1', 0x61B),
                          ('Calnum+2',0x61C), ('Calnum+3', 0x61D),
                          ('DOLT',    0x626), ('DOLT+1',   0x627),
                          ('DOLT+2',  0x628), ('DOLT+3',   0x629),
                          ('Defeats', 0x62A), ('Defeats+1',0x62B),
                          ('Defeats+2',0x62C),('Defeats+3',0x62D)]:
        phys = 0x60000 + offset * 2
        b = br.mread_byte(phys)
        raw = br.raw_mread(phys)
        print(f'    cal[0x{offset:03X}] phys=0x{phys:05X}: byte=0x{b:02X} ({b:3d}) raw=0x{raw:04X}')

    # ERRSTR?
    err = br.q('ERRSTR?')
    print(f'\n  ERRSTR?    : {err!r}')

br = Bridge()

# --- ELOTT ---
br.write('BEEP 1')
time.sleep(0.15)
read_cal_state(br, 'ELOTT')

# --- CAL_NUM kiadasa ---
print('\n>>> CAL_NUM kuldese...')
br.write('CAL_NUM')
time.sleep(1.0)
print('>>> Kesz.')

# --- UTAN ---
br.write('BEEP 1')
time.sleep(0.15)
read_cal_state(br, 'UTAN')

br.close()
