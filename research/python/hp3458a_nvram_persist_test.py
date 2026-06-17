#!/usr/bin/env python3
"""
HP 3458A NVRAM tartósság teszt — két kísérlet:

  A) settings_ram (DS1235): MWRITE működik, de power cycle után elvész-e?
  B) cal_ram (DS1220Y):     CAL SECURE után MWRITE működik-e, és megmarad-e?

Használat:
  python hp3458a_nvram_persist_test.py sram_write    -- A) settings_ram jelölő beírása
  python hp3458a_nvram_persist_test.py sram_read     -- A) visszaolvasás (power cycle után)

  python hp3458a_nvram_persist_test.py calram_write  -- B) cal_ram Defeats beírása (CAL SECURE)
  python hp3458a_nvram_persist_test.py calram_read   -- B) visszaolvasás (power cycle után)
  python hp3458a_nvram_persist_test.py calram_restore -- B) Defeats visszaállítása 0-ra
"""

import socket
import sys
import time

BRIDGE_HOST = '192.168.2.88'
BRIDGE_PORT = 1234
GPIB_ADDR   = 22

# A) settings_ram: 0x127196 — 14 KB üres terület közepe
SRAM_ADDR_D = 1208726   # 0x127196

# B) cal_ram Defeats: 0x62A–0x62D (u32 big-endian, kívül Cal_Sum tartományokon)
#    Fizikai cím: 0x60000 + 2*offset  (DS1220Y EVEN bank)
DEFEATS_PHYS_D = [395348, 395350, 395352, 395354]   # 0x60C54–0x60C5A

MARKER_SRAM   = 0x5A5A           # settings_ram: egyszerű 16-bit jelölő
MARKER_CALRAM = 0xDEAD_BEEF      # cal_ram: 32-bit jelölő


class Bridge:
    def __init__(self):
        self._s = socket.create_connection((BRIDGE_HOST, BRIDGE_PORT), timeout=10)
        self._s.settimeout(10)
        self._buf = b''

    def write(self, cmd):
        self._s.sendall((cmd + '\n').encode('ascii'))

    def readline(self):
        while b'\n' not in self._buf:
            chunk = self._s.recv(4096)
            if not chunk:
                raise RuntimeError('Bridge kapcsolat megszakadt')
            self._buf += chunk
        line, self._buf = self._buf.split(b'\n', 1)
        return line.decode('ascii', errors='replace').strip()

    def query(self, cmd):
        self.write(cmd)
        self.write('++read')
        return self.readline()

    def close(self):
        try:
            self.write('TRIG AUTO')
            self.write('DISP 1')
        except Exception:
            pass
        self._s.close()


def init(b):
    b.write(f'++addr {GPIB_ADDR}')
    b.write('++read_tmo_ms 500')
    b.write('++clr')
    time.sleep(1.0)
    for cmd in ('END ALWAYS', 'NPLC 0', 'NRDGS 1', 'TRIG HOLD', 'QFORMAT NUM'):
        b.write(cmd)
    time.sleep(0.1)


def mread(b, addr_d):
    return int(b.query(f'MREAD {addr_d}'))


def mwrite(b, addr_d, value):
    b.write(f'MWRITE {addr_d},{value}')
    time.sleep(0.02)


def errstr(b):
    return b.query('ERRSTR?')


def read_defeats(b):
    val = 0
    for dec, shift in zip(DEFEATS_PHYS_D, [24, 16, 8, 0]):
        word = mread(b, dec)
        byte = (word >> 8) & 0xFF
        val |= byte << shift
    return val


def write_defeats(b, u32_val):
    for dec, shift in zip(DEFEATS_PHYS_D, [24, 16, 8, 0]):
        byte = (u32_val >> shift) & 0xFF
        mwrite(b, dec, byte << 8)


# ---------------------------------------------------------------------------

def sram_write(b):
    print('=== A) settings_ram (DS1235) — jelölőérték beírása ===')
    orig = mread(b, SRAM_ADDR_D)
    print(f'  Jelenlegi: 0x{orig:04X}  ({SRAM_ADDR_D} dec)')
    mwrite(b, SRAM_ADDR_D, MARKER_SRAM)
    err = errstr(b)
    readback = mread(b, SRAM_ADDR_D)
    print(f'  MWRITE -> 0x{MARKER_SRAM:04X}   ERRSTR: {err}')
    print(f'  Visszaolvasás: 0x{readback:04X}', '  OK' if readback == MARKER_SRAM else '  HIBA')
    print()
    print('MOST: kapcsold ki és be a műszert, majd futtasd:')
    print('  python hp3458a_nvram_persist_test.py sram_read')


def sram_read(b):
    print('=== A) settings_ram (DS1235) — visszaolvasás power cycle után ===')
    val = mread(b, SRAM_ADDR_D)
    print(f'  Olvasott érték: 0x{val:04X}')
    if val == MARKER_SRAM:
        print('  Megmaradt! (nem várt — a settings_ram tartósan tárolja?)')
    elif val == 0:
        print('  0x0000 — elveszett a power cycle-ben. (Várható: DS1235 firmware újrainicializálja)')
    else:
        print(f'  Más érték (0x{val:04X}) — firmware felülírta vagy elveszett.')


def calram_write(b):
    print('=== B) cal_ram (DS1220Y) — CAL SECURE + MWRITE ===')

    # Jelenlegi Defeats érték
    current = read_defeats(b)
    err0 = errstr(b)
    print(f'  Defeats most: 0x{current:08X}   ERRSTR: {err0}')

    # CAL SECURE megnyitás (Cal_SecureCode = 0x00000000 -> jelszó "0")
    print('  CAL SECURE 0 ...')
    b.write('CAL SECURE 0')
    time.sleep(0.1)
    err1 = errstr(b)
    print(f'  ERRSTR CAL SECURE után: {err1}')

    # MWRITE jelölőértékkel
    print(f'  MWRITE Defeats <- 0x{MARKER_CALRAM:08X}')
    write_defeats(b, MARKER_CALRAM)
    err2 = errstr(b)
    print(f'  ERRSTR írás után: {err2}')

    # Visszaolvasás
    readback = read_defeats(b)
    print(f'  Visszaolvasás: 0x{readback:08X}', '  OK' if readback == MARKER_CALRAM else '  HIBA')

    if readback == MARKER_CALRAM:
        print()
        print('MOST: kapcsold ki és be a műszert, majd futtasd:')
        print('  python hp3458a_nvram_persist_test.py calram_read')
    else:
        print('  Az írás nem sikerült — a /WE lehet hogy még CAL SECURE után is tiltott.')


def calram_read(b):
    print('=== B) cal_ram (DS1220Y) — visszaolvasás power cycle után ===')
    val = read_defeats(b)
    err = errstr(b)
    print(f'  Defeats: 0x{val:08X}   ERRSTR: {err}')
    if val == MARKER_CALRAM:
        print('  MEGMARADT! A cal_ram (DS1220Y) valóban NVRAM — tartós tárolás.')
        print('  A DOLT nullázás power cycle után is érvényes lesz.')
    elif val == 0:
        print('  0x00000000 — elveszett, VAGY nem sikerült az írás.')
    else:
        print(f'  Más érték (0x{val:08X})')
    print()
    print('Visszaállításhoz: python hp3458a_nvram_persist_test.py calram_restore')


def calram_restore(b):
    print('=== B) cal_ram — Defeats visszaállítása ===')
    current = read_defeats(b)
    print(f'  Jelenlegi: 0x{current:08X}')
    b.write('CAL SECURE 0')
    time.sleep(0.1)
    err1 = errstr(b)
    print(f'  CAL SECURE ERRSTR: {err1}')
    write_defeats(b, 0)
    err2 = errstr(b)
    verify = read_defeats(b)
    print(f'  Visszaolvasás: 0x{verify:08X}   ERRSTR: {err2}')
    if verify == 0:
        print('  OK — Defeats visszaállítva 0-ra.')


# ---------------------------------------------------------------------------

MODES = {
    'sram_write':     sram_write,
    'sram_read':      sram_read,
    'calram_write':   calram_write,
    'calram_read':    calram_read,
    'calram_restore': calram_restore,
}

def main():
    if len(sys.argv) < 2 or sys.argv[1] not in MODES:
        print(f'Használat: python {sys.argv[0]} <mód>')
        print(f'Módok: {", ".join(MODES)}')
        sys.exit(1)

    b = Bridge()
    try:
        print(f'[init] bridge {BRIDGE_HOST}:{BRIDGE_PORT} ...')
        init(b)
        MODES[sys.argv[1]](b)
    except Exception as e:
        print(f'HIBA: {e}')
    finally:
        b.close()


if __name__ == '__main__':
    main()
