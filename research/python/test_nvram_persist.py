"""
NVRAM persistencia teszt: cal_ram ir -> power cycle -> visszaolvas.

Eljaras:
  1. Script ir 0xA5-ot DOLT[0]-ba (cal_ram offset 0x626, phys 0x60C4C)
  2. Azonnal visszaolvassa (ellenorzes)
  3. Var: "kapcsold ki a muszerT, majd be, nyomj Entert"
  4. Ujracsatlakozas + MREAD: megmaradt-e 0xA5?
  5. Visszaallitas: DOLT[0] = 0x00

DOLT es Defeats a Cal_Sum tartomanyain kivul vannak -> checksum frissites NEM kell.
"""
import socket, time

BRIDGE_HOST = '192.168.2.88'
BRIDGE_PORT  = 1234
GPIB_ADDR    = 22

TEST_BYTE    = 0xA5
DOLT_PHYS    = 0x60000 + 0x626 * 2   # 0x60C4C = 396364
CODE_BASE    = 0x12E000
CB_BASE      = 0x12E100

def connect():
    s = socket.create_connection((BRIDGE_HOST, BRIDGE_PORT), timeout=15)
    s.sendall(b'++mode 1\n')
    s.sendall(f'++addr {GPIB_ADDR}\n'.encode())
    s.sendall(b'++auto 0\n')
    s.sendall(b'++eos 2\n')
    s.sendall(b'++eoi 1\n')
    s.sendall(b'++read_tmo_ms 3000\n')
    time.sleep(0.3)
    return s

def send(s, cmd):
    s.sendall((cmd + '\n').encode())
    time.sleep(0.12)

def recv(s, timeout=3.0):
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

def q(s, cmd, timeout=3.0):
    send(s, cmd); return recv(s, timeout)

def mread_word(s, phys):
    r = q(s, f'MREAD {phys}')
    try: return int(float(r)) & 0xFFFF
    except: return None

def mread_hi(s, phys):
    w = mread_word(s, phys)
    return (w >> 8) & 0xFF if w is not None else None

def mwrite(s, phys, value):
    v = value & 0xFFFF
    signed = v if v <= 32767 else v - 65536
    send(s, f'MWRITE {phys},{signed}')

def mwrite_words(s, base, words):
    for i, w in enumerate(words):
        mwrite(s, base + i*2, w)
    time.sleep(0.15)

def init_meter(s):
    send(s, 'PRESET NORM'); time.sleep(0.8)
    send(s, 'END ALWAYS');  time.sleep(0.2)
    send(s, 'BEEP 1');      time.sleep(0.2)
    q(s, 'ERRSTR?')

def setup_magic_words(s):
    mwrite(s, 0x121780, 0xDEAF)
    mwrite(s, 0x120C90, 0xBAD1)
    mwrite(s, 0x121782, 0x0ACE)
    mwrite(s, 0x120C92, 0xBEAD)
    time.sleep(0.2)

def write_calram_byte(s, phys_addr, byte_val):
    """Ir 1 byte-ot cal_ram-ba JSR+NMI mechanizmuson keresztul."""
    # Callback: movep.w d2, 0(a0); rts
    callback_code = [0x0588, 0x0000, 0x4E75]
    mwrite_words(s, CB_BASE, callback_code)

    # d2 high byte = az irandó byte, low byte = 0
    data_word = (byte_val << 8) & 0xFF00

    main_code = [
        0x4E45,                           # trap #5
        0x343C, data_word,                # move.w #data, d2
        0x207C, (phys_addr >> 16) & 0xFFFF, phys_addr & 0xFFFF,  # movea.l #addr, a0
        0x287C, 0x0012, 0xE100,          # movea.l #callback, a4
        0x23CC, 0x0012, 0x1852,          # move.l a4, $121852
        0x33FC, 0x0000, 0x0012, 0x1856,  # move.w #0, $121856
        0x1C39, 0x0012, 0x185A,          # move.b $12185A, d6
        0x0046, 0x0080,                   # ori.w #$80, d6
        0x13C6, 0x000C, 0x0001,          # move.b d6, $C0001  (NMI trigger)
        0x3C3C, 0x0009,                   # move.w #9, d6
        0x57CE, 0xFFFE,                   # dbeq d6, *
        0x4E75,                           # rts
    ]
    mwrite_words(s, CODE_BASE, main_code)

    # Mentjuk az eredeti callback pointert
    orig_hi = mread_word(s, 0x121852)
    orig_lo = mread_word(s, 0x121854)

    send(s, f'JSR {CODE_BASE}'); time.sleep(1.5)
    e = q(s, 'ERRSTR?')

    # Callback pointer visszaallitas
    mwrite(s, 0x121852, orig_hi if orig_hi is not None else 0x0005)
    mwrite(s, 0x121854, orig_lo if orig_lo is not None else 0xA24C)

    return 'NO ERROR' in e or e.startswith('0,')

# ═══════════════════════════════════════════════════════════════════
print('=== HP 3458A cal_ram NVRAM persistencia teszt ===')
print()

# ── 1. CSATLAKOZAS + IRAS ────────────────────────────────────────
print('1. Csatlakozas es cal_ram iras...')
s = connect()
init_meter(s)

dolt_before = mread_hi(s, DOLT_PHYS)
print(f'   DOLT[0] elotte: 0x{dolt_before:02X}')

# Magic words beallitasa
setup_magic_words(s)

# Iras
print(f'   Iras: DOLT[0] = 0x{TEST_BYTE:02X}...')
ok = write_calram_byte(s, DOLT_PHYS, TEST_BYTE)
print(f'   JSR eredmeny: {"OK" if ok else "HIBA"}')

# Azonnal visszaolvasas
dolt_written = mread_hi(s, DOLT_PHYS)
print(f'   DOLT[0] kozvetlenul utan: 0x{dolt_written:02X}  (vart: 0x{TEST_BYTE:02X})')

if dolt_written != TEST_BYTE:
    print('   HIBA: az iras nem sikerult! Megallunk.')
    s.close()
    import sys; sys.exit(1)

print(f'   Az iras sikeres: 0x{TEST_BYTE:02X} bekerult a cal_ram NVRAM-ba.')
s.close()
print()

# ── 2. POWER CYCLE ──────────────────────────────────────────────
print('=' * 55)
print()
print('  KAPCSOLD KI A MUSZERT, varj 5 masodpercet, majd kapcsold be.')
print('  Var amig a kijelzo visszater a merest allapotba.')
print()
input('  Ha a muszert ujraindult es kesz, nyomj ENTERT: ')
print()

# ── 3. UJRACSATLAKOZAS + VISSZAOLVASAS ──────────────────────────
print('3. Ujracsatlakozas...')
for attempt in range(5):
    try:
        s2 = connect()
        print('   Csatlakozas OK.')
        break
    except Exception as ex:
        print(f'   Kisr. {attempt+1}: {ex} - var...')
        time.sleep(3)
else:
    print('   Nem sikerult csatlakozni!')
    import sys; sys.exit(1)

init_meter(s2)

dolt_after = mread_hi(s2, DOLT_PHYS)
print()
print('=' * 55)
print(f'  DOLT[0] power cycle ELOTT: 0x{TEST_BYTE:02X}')
print(f'  DOLT[0] power cycle UTAN:  0x{dolt_after:02X}')
print()
if dolt_after == TEST_BYTE:
    print('  *** SIKER! Az adat megmaradt a power cycle utan. ***')
    print('  *** A DS1220Y NVRAM valóban megőrzi az adatot.  ***')
elif dolt_after == dolt_before:
    print(f'  Az ertek visszallt az eredeti ertekre (0x{dolt_before:02X}).')
    print('  Lehetseges okok:')
    print('  - A firmware startup inicializalja a DOLT-ot 0-ra')
    print('  - A NVRAM nem tartotta meg (kevesse valoszinu, ha a write OK volt)')
    print('  - A NVRAM tartalmaza, de a firmware felulirta startup kozben')
else:
    print(f'  Erdekes: sem az irt ertek (0x{TEST_BYTE:02X}), sem az eredeti (0x{dolt_before:02X}) nincs.')
    print(f'  Olvasott: 0x{dolt_after:02X}')
print('=' * 55)
print()

# ── 4. VISSZAALLITAS ────────────────────────────────────────────
if dolt_after == TEST_BYTE:
    print('4. Visszaallitas: DOLT[0] = 0x00...')
    setup_magic_words(s2)
    ok2 = write_calram_byte(s2, DOLT_PHYS, 0x00)
    dolt_restored = mread_hi(s2, DOLT_PHYS)
    print(f'   JSR: {"OK" if ok2 else "HIBA"}, DOLT[0] = 0x{dolt_restored:02X}')
    if dolt_restored == 0x00:
        print('   Visszaallitas sikeres.')

s2.close()
print()
print('Teszt befejezve.')
