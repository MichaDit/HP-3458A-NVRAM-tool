"""
FILLBIN szintaxis deritese: mi az elvart parameterformatum?

Hipotezisek:
  H1: FILLBIN parametert nem var (0 param) -> raw binary adatot olvas GPIB-rol
  H2: FILLBIN float formatum: "FILLBIN 23130." (explicit double)
  H3: FILLBIN parameter nelkul, majd raw bytes kuldese
  H4: FILLBIN az MADDR utan allitja be a parameterszamot -> count parameter kell

A SYNTAX error: 'FILLBIN 23130   Expected: ' -- az 'Expected: ' ures
= a parser NEM varnal semmit FILLBIN utan, de kapott 23130-at.
=> FILLBIN valoszinuleg 0 parameterrel hivodik, es raw binaris adatot vesz GPIB-rol.
"""
import socket, time

BRIDGE_HOST = '192.168.2.88'
BRIDGE_PORT  = 1234
GPIB_ADDR    = 22

s = socket.create_connection((BRIDGE_HOST, BRIDGE_PORT), timeout=15)
s.sendall(b'++mode 1\n')
s.sendall(f'++addr {GPIB_ADDR}\n'.encode())
s.sendall(b'++auto 0\n')
s.sendall(b'++eos 2\n')
s.sendall(b'++eoi 1\n')
s.sendall(b'++read_tmo_ms 2000\n')
time.sleep(0.3)

def send(cmd):
    s.sendall((cmd + '\n').encode())
    time.sleep(0.15)

def recv(timeout=2.0):
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

def q(cmd, timeout=2.0):
    send(cmd)
    r = recv(timeout)
    return r

def mread_word(phys):
    r = q(f'MREAD {phys}')
    try:
        return int(float(r)) & 0xFFFF
    except:
        return None

def sep(t):
    print(); print(f'--- {t} ---')

# Init
send('PRESET NORM'); time.sleep(0.8)
send('END ALWAYS');  time.sleep(0.2)
send('BEEP 1');      time.sleep(0.2)
q('ERRSTR?')

test_addr = 0x12F000
print(f'Teszt cim: 0x{test_addr:06X} = {test_addr} dec')
print(f'Jelenlegi tartalom: 0x{mread_word(test_addr):04X}')
print()

# --- H1: FILLBIN 0 parameterrel ---
sep('H1: MADDR + FILLBIN (0 param) + raw binary kulon')
print('  MADDR beallitas...')
send(f'MADDR {test_addr}')
time.sleep(0.2)
print('  MADDR utan MREAD (ha MADDR nem csinal semmit, ez visszaadja a regi tartalmat):')
rb = mread_word(test_addr)
print(f'    MREAD {test_addr} = 0x{rb:04X}')

print('  FILLBIN kuldese 0 parameterrel...')
send('FILLBIN')
time.sleep(0.5)
e = recv(timeout=1.0)
print(f'  Valasz (FILLBIN utan): {e!r}')
e2 = q('ERRSTR?')
print(f'  ERRSTR? utan: {e2!r}')

# --- H2: FILLBIN raw bytes ---
sep('H2: FILLBIN + azonnal raw binary (5A5A) kuldese GPIB-re')
print('  MADDR beallitas...')
send(f'MADDR {test_addr}')
time.sleep(0.15)
print('  FILLBIN kuldese, majd azonnal 2 raw byte (0x5A 0x5A)...')
s.sendall(b'FILLBIN\n')
time.sleep(0.05)
s.sendall(b'\x5a\x5a\n')
time.sleep(0.5)
e3 = recv(timeout=1.5)
print(f'  Valasz: {e3!r}')
e4 = q('ERRSTR?')
print(f'  ERRSTR?: {e4!r}')
rb2 = mread_word(test_addr)
print(f'  MREAD {test_addr} = 0x{rb2:04X}  (vart 0x5A5A ha siker)')

# --- H3: MADDR count param ---
sep('H3: MADDR count variacio (2 param: addr, count)')
print('  Probalja: MADDR addr, count')
r = q(f'MADDR {test_addr}, 2')
print(f'  MADDR {test_addr}, 2 -> {r!r}')
e = q('ERRSTR?')
print(f'  ERRSTR?: {e!r}')

# --- H4: FILLBIN string formatum ---
sep('H4: FILLBIN string parameterrel ("ZZZZ" = 0x5A5A5A5A)')
send(f'MADDR {test_addr}')
time.sleep(0.15)
r = q('FILLBIN "ZZ"')
print(f'  FILLBIN "ZZ" -> {r!r}')
e = q('ERRSTR?')
print(f'  ERRSTR?: {e!r}')
rb3 = mread_word(test_addr)
print(f'  MREAD = 0x{rb3:04X}')

# --- H5: Prolog MADDR beallitas utan ERRSTR ---
sep('H5: MADDR ertek visszaolvasas (MADDR query utan)')
# Ha MADDR visszaad ertekkent valamit...
send(f'MADDR {test_addr}')
time.sleep(0.15)
r_maddr = recv(timeout=1.0)
print(f'  MADDR {test_addr} visszatert: {r_maddr!r}')
e = q('ERRSTR?')
print(f'  ERRSTR?: {e!r}')

# --- Osszefoglalo ---
print()
print('=== Osszefoglalo ===')
print(f'  test_addr 0x{test_addr:06X} jelenlegi tartalom: 0x{mread_word(test_addr):04X}')
print()
print('Megjegyzesek:')
print('  - Ha H1 "NO ERROR" de a memoria nem valtozik: FILLBIN mas adatforrasat')
print('    hasznalja (nem a GPIB stream-et)')
print('  - Ha H2 megvaltoztatja 0x12F000-t: raw binary mukodik')
print('  - Ha FILLBIN string-et fogad: az ASCII karakterek lesznek a binary adat')

s.close()
print()
print('Kesz.')
