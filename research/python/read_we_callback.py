"""
/WE callback pointer es kornyezet kiolvasasa settings_ram-bol.
Cimek (A5 = 0x120000 bazis):
  0x121852 = callback pointer (4 byte, 2 word MREAD)
  0x12185A = /WE zaras ertek (IO port eredeti erteke)
  0x121856 = sikerjelzo flag
"""
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
    time.sleep(0.12)

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
    return read(timeout)

def mread_word(phys):
    """MREAD: fizikai cim -> 16 bites raw ertek."""
    r = q(f'MREAD {phys}')
    try:
        v = int(float(r))
        return v & 0xFFFF
    except:
        return None

def mread_u32(phys):
    """Ket egymas utani WORD = 32-bites ertek (big-endian)."""
    hi = mread_word(phys)
    lo = mread_word(phys + 2)
    if hi is None or lo is None:
        return None
    return (hi << 16) | lo

# Init
write('PRESET NORM')
time.sleep(0.8)
write('END ALWAYS')
time.sleep(0.2)
write('BEEP 1')
time.sleep(0.2)
q('ERRSTR?')

print('=== /WE ISR callback kornyezete (settings_ram) ===')
print()

# Callback pointer: 0x121852 (32-bit, 2 word)
cb = mread_u32(0x121852)
print(f'  0x121852: callback pointer = 0x{cb:08X}  ({cb})')
if cb:
    print(f'            -> ROM cim: 0x{cb:05X}')

# /WE zaras ertek: 0x12185A (az IO port eredeti erteke)
we_close = mread_word(0x12185A)
print(f'  0x12185A: /WE zaras ertek = 0x{we_close:04X}  (bit7={((we_close>>7)&1)})')

# Sikerjelzo: 0x121856
ok_flag = mread_word(0x121856)
print(f'  0x121856: sikerjelzo flag = 0x{ok_flag:04X}')

# IO port jelenlegi erteke (0x0C0001) - csak olvasas
io_port = mread_word(0x0C0001)
print(f'  0x0C0001: IO port aktualis = 0x{io_port:04X}')

print()
print('=== Tervezett kod injekcios cimek ===')
print()
print('  Sajat rutin helye: 0x121100 (settings_ram, jol esik a DSP buffer ala)')
print('  Tartalom: move.b #adat, $60000 + rts')
print()

# Ellenorizzuk hogy 0x121100 kornyeke "biztonságos" (nem hasznalt, vagy ismert tartalom)
print('  0x121100 kornyeke (jelenlegi tartalom):')
for addr in range(0x121100, 0x121120, 2):
    w = mread_word(addr)
    if w is not None:
        print(f'    0x{addr:06X}: 0x{w:04X}')

print()

# Megmutatjuk a callback pointer visszaallitasi erteket is
print(f'  Visszaallitashoz mentett callback: 0x{cb:08X}')
print(f'  Visszaallitashoz mentett MWRITE parancsok:')
if cb:
    hi16 = (cb >> 16) & 0xFFFF
    lo16 = cb & 0xFFFF
    print(f'    MWRITE 0x121852, {hi16}   (0x{hi16:04X})')
    print(f'    MWRITE 0x121854, {lo16}   (0x{lo16:04X})')

# Cal_ram jelenlegi tartalma a DOLT/Defeats teruleten (referenciapontnak)
print()
print('=== Cal_ram referencia pontok (MREAD, high byte) ===')
for name, cal_off in [('Cal_Sum3', 0x624), ('DOLT[0]', 0x626),
                       ('Defeats[0]', 0x62A), ('Calnum[3]', 0x61D)]:
    phys = 0x60000 + cal_off * 2
    w = mread_word(phys)
    b = (w >> 8) & 0xFF if w is not None else None
    print(f'  cal[0x{cal_off:03X}] phys=0x{phys:05X}: byte=0x{b:02X}  (raw=0x{w:04X})')

s.close()
print()
print('Kesz.')
