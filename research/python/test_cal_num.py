"""
CAL_NUM rejtett GPIB parancs tesztje.
Elmelet: DOLT (cal_ram 0x626) es Defeats (0x62A) nullazasa.
Biztonsag: SECURE nem all be, a parancs nincs nyilvanos dokumentumban
de priv=0, tehat hivalato.
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
        time.sleep(0.05)

    def read(self):
        self._s.sendall(b'++read eoi\n')
        buf = b''
        self._s.settimeout(2.0)
        try:
            while True:
                b = self._s.recv(256)
                if not b:
                    break
                buf += b
                if b'\n' in b:
                    break
        except socket.timeout:
            pass
        return buf.decode('ascii', errors='replace').strip()

    def q(self, cmd):
        self.write(cmd)
        return self.read()

    def mread(self, addr):
        r = self.q(f'MREAD {addr}')
        try:
            return int(float(r))
        except Exception:
            return None

    def close(self):
        self._s.close()

def read_dolt_defeats(br):
    """DOLT es Defeats aktualis ertekek olvasasa cal_ram-bol."""
    # DOLT: cal_ram 0x626, fizikai 0x60000+2*0x626 = 0x60C4C (EVEN bank)
    # 4 byte = 2 word: [0x60C4C] high, [0x60C4E] low
    br.write('BEEP 1')
    time.sleep(0.1)
    results = {}
    for name, phys in [('DOLT_hi', 393292), ('DOLT_lo', 393294),
                        ('Defeats_hi', 393300), ('Defeats_lo', 393302)]:
        val = br.mread(phys)
        results[name] = val
    # Ertek ujra szamitas
    if None not in [results['DOLT_hi'], results['DOLT_lo']]:
        dolt = ((results['DOLT_hi'] & 0xFF00) << 8) | ((results['DOLT_lo'] & 0xFF00) >> 8)
        # EVEN bank: HIGH byte ervenyes, LOW 0xB9 szemet
        dolt_hi_b = (results['DOLT_hi'] >> 8) & 0xFF
        dolt_lo_b = (results['DOLT_lo'] >> 8) & 0xFF
        # 4 byte: DOLT = dolt_b0<<24 | dolt_b1<<16 | dolt_b2<<8 | dolt_b3
        # De most csak 2 EVEN byte-ot olvasunk — jo kiszamolashoz tobb kell
        results['DOLT_b0'] = dolt_hi_b
        results['DOLT_b1'] = dolt_lo_b
    if None not in [results['Defeats_hi'], results['Defeats_lo']]:
        results['Defeats_b0'] = (results['Defeats_hi'] >> 8) & 0xFF
        results['Defeats_b1'] = (results['Defeats_lo'] >> 8) & 0xFF
    return results

def read_calnum(br):
    """Calnum aktualis ertek (cal_ram 0x61A)."""
    # cal_ram 0x61A: fizikai 0x60000+2*0x61A = 0x60C34
    phys = 0x60000 + 2 * 0x61A  # = 0x60C34 = 395316
    val = br.mread(395316)
    if val is not None:
        return (val >> 8) & 0xFF
    return None

br = Bridge()

# 1. ERRSTR? init
print('=== CAL_NUM teszt ===')
br.write('BEEP 1')
time.sleep(0.1)
err = br.q('ERRSTR?')
print(f'Init ERRSTR?: {err!r}')

# 2. Elso DOLT+Defeats olvasas
print()
print('--- ELOTT ---')
r_before = read_dolt_defeats(br)
calnum_before = read_calnum(br)
print(f'  Calnum (0x61A) byte[0]: {calnum_before}')
for k, v in r_before.items():
    print(f'  {k}: {v} (0x{v:04X} ha szam)' if v is not None else f'  {k}: None')

# 3. CAL_NUM kiadasa
print()
print('--- CAL_NUM parancs kiadasa ---')
br.write('CAL_NUM')
time.sleep(0.5)
err2 = br.q('ERRSTR?')
print(f'ERRSTR? utan: {err2!r}')

# 4. Masodik olvasas
print()
print('--- UTAN ---')
r_after = read_dolt_defeats(br)
calnum_after = read_calnum(br)
print(f'  Calnum (0x61A) byte[0]: {calnum_after}')
for k, v in r_after.items():
    print(f'  {k}: {v} (0x{v:04X} ha szam)' if v is not None else f'  {k}: None')

# 5. Osszehasonlitas
print()
print('--- VALTOZAS ---')
for k in r_before:
    b = r_before[k]
    a = r_after[k]
    change = '' if b == a else f'  <<< MEGVALTOZOTT: {b} -> {a}'
    print(f'  {k}: {b} -> {a}{change}')

br.close()
print()
print('Kesz.')
