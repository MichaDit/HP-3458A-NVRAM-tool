"""
HP 3458A JSR parancs teszt
==========================
JSR <cim> = GPIB backdoor: tetszoleges ROM/RAM rutin hivalasa.
sub_585A0 decimalis egesz szamot var (IEEE754 double-kent erkezik,
mint minden numerikus GPIB parameter — pl. WAIT N, NMR N).

Tesztelesi sorrend (veszelyesseg szerint):
  1. Baseline: ERRSTR? + ID?
  2. JSR parameter nelkul -> syntax error varhat
  3. JSR 1968  (0x007B0 = ROM-beli sima RTS) -> azonnali visszateres, NOP
  4. JSR 97184 (0x17BA0 = XYZZY handler)     -> beep + LCD, GPIB silent
  5. JSR 196082(0x2FDF2 = CAL_NUM handler)   -> DOLT/Defeats=0 (mar tesztelve)

Celcim tabla:
  1044   = 0x00414  ROM kozeleben levo RTS (ha letezik)
  1968   = 0x007B0  RTS, elotte moveq #1,d7  <-- ELSO TESZT
  97184  = 0x17BA0  XYZZY easter egg
  196082 = 0x2FDF2  CAL_NUM (DOLT+Defeats reset)
  7396   = 0x01CE4  CIIL reset rutin
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
        self._s.sendall(b'++read_tmo_ms 2000\n')
        time.sleep(0.3)

    def write(self, cmd):
        print(f'  TX: {cmd!r}')
        self._s.sendall((cmd + '\n').encode())
        time.sleep(0.12)

    def read(self, timeout=2.5):
        self._s.sendall(b'++read eoi\n')
        buf = b''
        self._s.settimeout(timeout)
        try:
            while True:
                b = self._s.recv(512)
                if not b: break
                buf += b
                if b'\n' in b: break
        except socket.timeout:
            pass
        result = buf.decode('ascii', errors='replace').strip()
        print(f'  RX: {result!r}')
        return result

    def q(self, cmd, timeout=2.5):
        self.write(cmd)
        return self.read(timeout)

    def errstr(self):
        return self.q('ERRSTR?', timeout=2.0)

    def clear_errors(self):
        """Hibak kiurıtese (addig kerdezunk amig 0 nem lesz)."""
        for _ in range(5):
            e = self.errstr()
            if '"NO ERROR"' in e or e.startswith('0,'):
                break

    def close(self):
        self._s.close()

def sep(title):
    print()
    print(f'{"="*55}')
    print(f'  {title}')
    print('='*55)

br = Bridge()

# ─────────────────────────────────────────────
# INIT
# ─────────────────────────────────────────────
sep('INIT')
# Megallitjuk a meresi ciklust (ha fut), beallitjuk a GPIB output modjat
br.write('PRESET NORM')    # TRIG SYN + ismert allapot
time.sleep(0.8)
br.write('END ALWAYS')     # EOI minden valasz vegen - KOTELEZO a ++read eoi-hoz
time.sleep(0.3)
br.write('BEEP 1')         # MREAD-hez kell, ERRSTR? is jobb vele
time.sleep(0.2)
br.clear_errors()

id_resp  = br.q('ID?',  timeout=3.0)
rev_resp = br.q('REV?', timeout=3.0)
print(f'  ID?:  {id_resp!r}')
print(f'  REV?: {rev_resp!r}')

# ─────────────────────────────────────────────
# 1. TESZT: JSR parameter nelkul -> syntax error
# ─────────────────────────────────────────────
sep('1. TESZT: JSR (parameter nelkul) -> syntax error varhat')
br.write('JSR')
time.sleep(0.3)
err = br.errstr()
print(f'  Varantas: syntax error (nem "NO ERROR")')
print(f'  Eredmeny: {"OK - hiba jott" if "NO ERROR" not in err else "PROBLEM - nem adott hibaT!"}')

br.clear_errors()

# ─────────────────────────────────────────────
# 2. TESZT: JSR 1968 = 0x007B0 = sima RTS
# ─────────────────────────────────────────────
sep('2. TESZT: JSR 1968 (0x007B0 = RTS) -> NOP, NO ERROR')
print('  Celcim: 0x007B0')
print('  ROM tartalma: moveq #1,d7 / rts -> azonnali visszateres')
print()

br.write('JSR 1968')
time.sleep(0.5)
err = br.errstr()
print()
print(f'  Varantas: NO ERROR (azonnali RTS, semmi sem tortenik)')
if '"NO ERROR"' in err or err.startswith('0,'):
    print('  *** SIKER: JSR 1968 -> NO ERROR! ***')
    print('  => JSR parancs elerheto GPIB-rol es mukodik!')
else:
    print(f'  !!! HIBA: {err!r}')
    print('  => Lehetseges okok: priv hiba, rossz szintaxis, bridge problem')

br.clear_errors()

# ─────────────────────────────────────────────
# 3. TESZT: JSR 97184 = 0x17BA0 = XYZZY
# ─────────────────────────────────────────────
sep('3. TESZT: JSR 97184 (0x17BA0 = XYZZY handler)')
print('  Celcim: 0x17BA0 = XYZZY easter egg handler')
print('  Varhat: beep es/vagy LCD valtozas a muszeren')
print('  GPIB valasz: nincs (XYZZY GPIB-en silent)')
print()
print('  >>> Figyeld a muszert! <<<')
print()

br.write('JSR 97184')
time.sleep(1.0)   # XYZZY-nek kell egy kis ido (beep)
err = br.errstr()
print()
print(f'  Varantas: NO ERROR + [beep/LCD valtozas a muszeren]')
if '"NO ERROR"' in err or err.startswith('0,'):
    print('  *** SIKER: JSR 97184 -> NO ERROR! ***')
    print('  Ha hallottal beeP-et vagy lattal LCD valtozast: teljes siker!')
else:
    print(f'  Eredmeny: {err!r}')

br.clear_errors()

# ─────────────────────────────────────────────
# 4. TESZT: JSR 196082 = 0x2FDF2 = CAL_NUM
# ─────────────────────────────────────────────
sep('4. TESZT: JSR 196082 (0x2FDF2 = CAL_NUM handler)')
print('  Celcim: 0x2FDF2 = CAL_NUM (DOLT=0, Defeats=0, Calnum=1)')
print('  Ezt direktben mar teszteltuk: CAL_NUM -> NO ERROR')
print('  Most a JSR-en keresztul hivjuk ugyanezt!')
print()

# Elotte CALNUM? lekerdezes
calnum_before = br.q('CALNUM?', timeout=2.0)
print(f'  CALNUM? elotte: {calnum_before!r}')

br.write('JSR 196082')
time.sleep(1.0)
err = br.errstr()

calnum_after = br.q('CALNUM?', timeout=2.0)
print(f'  CALNUM? utana:  {calnum_after!r}')
print()
if '"NO ERROR"' in err or err.startswith('0,'):
    print('  *** SIKER: JSR 196082 -> NO ERROR! ***')
    print('  CAL_NUM a JSR-en keresztul sikeresen lefutott.')
else:
    print(f'  Eredmeny: {err!r}')

br.clear_errors()

# ─────────────────────────────────────────────
# OSSZEFOGLALO
# ─────────────────────────────────────────────
sep('OSSZEFOGLALO')
print()
print('  JSR tesztelesi matrix:')
print('  Parancs          Celcim    Eredmeny')
print('  ---------------  --------  ---------------------------------')
print('  JSR (no param)   -         syntax error')
print('  JSR 1968         0x007B0   NO ERROR (NOP - RTS)')
print('  JSR 97184        0x17BA0   NO ERROR + beep/LCD')
print('  JSR 196082       0x2FDF2   NO ERROR (CAL_NUM)')
print()

# Vegso allapot
br.write('PRESET NORM')
time.sleep(0.3)
err = br.errstr()
print(f'  PRESET NORM -> {err!r}')

br.close()
print()
print('Teszt befejezve.')
