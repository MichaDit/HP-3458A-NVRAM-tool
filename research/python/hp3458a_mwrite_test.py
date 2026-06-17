#!/usr/bin/env python3
"""
HP 3458A MWRITE kísérlet — Settings_RAM üres területre ír, majd visszaolvas.

Tesztcím: 0x127196 (settings_ram közepén lévő ~14KB üres terület)
Kapcsolat: Prologix bridge, 192.168.2.88:1234
"""

import socket
import time

BRIDGE_HOST = '192.168.2.88'
BRIDGE_PORT = 1234
BRIDGE_TMO  = 10.0   # socket timeout (s)
GPIB_ADDR   = 22

# Settings_RAM üres területe (3 passos dump szerint mind 0x0000)
# 0x127196 = 1208726 dec
TEST_ADDR   = 0x127196
TEST_ADDR_D = 1208726

TEST_VALUE  = 0x5A5A   # 23130 dec  (0101 1010 / 0101 1010 — könnyen felismerhető)
TEST_VALUE_D = 23130


class Bridge:
    def __init__(self, host, port, tmo):
        self._s = socket.create_connection((host, port), timeout=tmo)
        self._s.settimeout(tmo)
        self._buf = b''

    def write(self, cmd):
        if not cmd.endswith('\n'):
            cmd += '\n'
        self._s.sendall(cmd.encode('ascii'))

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
        self._s.close()


def init(b):
    b.write(f'++addr {GPIB_ADDR}')
    b.write('++read_tmo_ms 500')
    b.write('++clr')
    print('  [init] ++clr (Device Clear) elküldve, 1s várakozás...')
    time.sleep(1.0)
    for cmd in ('END ALWAYS', 'NPLC 0', 'NRDGS 1', 'TRIG HOLD', 'QFORMAT NUM'):
        b.write(cmd)
    time.sleep(0.1)
    print('  [init] kész')


def mread(b, addr):
    resp = b.query(f'MREAD {addr}')
    return int(resp)


def mwrite(b, addr, value):
    # MWRITE nem küld vissza választ — csak írás
    b.write(f'MWRITE {addr},{value}')
    time.sleep(0.02)   # DS1220Y/DS1235 write cycle idő


def errstr(b):
    resp = b.query('ERRSTR?')
    return resp


def main():
    print('HP 3458A MWRITE kísérlet')
    print(f'Bridge  : {BRIDGE_HOST}:{BRIDGE_PORT}')
    print(f'Cím     : 0x{TEST_ADDR:06X}  ({TEST_ADDR_D} dec)  — settings_ram üres terület')
    print(f'Érték   : 0x{TEST_VALUE:04X}  ({TEST_VALUE_D} dec)')
    print()

    b = Bridge(BRIDGE_HOST, BRIDGE_PORT, BRIDGE_TMO)
    try:
        init(b)

        # 0. Kezdeti hibastatus
        err0 = errstr(b)
        print(f'[0] ERRSTR?  ->  "{err0}"  (induló állapot)')
        print()

        # 1. Jelenlegi érték kiolvasása
        orig = mread(b, TEST_ADDR_D)
        print(f'[1] MREAD  {TEST_ADDR_D}  ->  {orig}  (0x{orig:04X})')
        if orig != 0:
            print(f'    FIGYELEM: nem 0 az eredeti érték! (elvárt: 0x0000)')

        # 2. Teszt érték írása
        print(f'[2] MWRITE {TEST_ADDR_D},{TEST_VALUE_D}  (0x{TEST_VALUE:04X})')
        mwrite(b, TEST_ADDR_D, TEST_VALUE_D)
        err2 = errstr(b)
        print(f'    ERRSTR?  ->  "{err2}"')

        # 3. Visszaolvasás
        readback = mread(b, TEST_ADDR_D)
        print(f'[3] MREAD  {TEST_ADDR_D}  ->  {readback}  (0x{readback:04X})')
        if readback == TEST_VALUE_D:
            print('    OK — MWRITE sikeresen irt, a visszaolvasott ertek egyezik!')
        else:
            print(f'    HIBA — elvárt: {TEST_VALUE_D} (0x{TEST_VALUE:04X}), kapott: {readback} (0x{readback:04X})')

        # 4. Visszaállítás az eredeti értékre
        print(f'[4] MWRITE {TEST_ADDR_D},{orig}  (visszaallitas: 0x{orig:04X})')
        mwrite(b, TEST_ADDR_D, orig)
        err4 = errstr(b)
        print(f'    ERRSTR?  ->  "{err4}"')

        # 5. Ellenőrzés
        verify = mread(b, TEST_ADDR_D)
        print(f'[5] MREAD  {TEST_ADDR_D}  ->  {verify}  (0x{verify:04X})')
        if verify == orig:
            print('    OK — visszaallitva az eredeti ertekre.')
        else:
            print(f'    HIBA a visszaallitasban: {verify} != {orig}')

        print()
        errors = [e for e in (err0, err2, err4) if not e.startswith('0,')]
        if readback == TEST_VALUE_D and not errors:
            print('EREDMENY: MWRITE MUKODIK, nincs firmware hiba!')
        elif readback == TEST_VALUE_D:
            print(f'EREDMENY: MWRITE irt, de firmware hibak: {errors}')
        else:
            print('EREDMENY: MWRITE nem mutat elvárt viselkedest.')

    except Exception as e:
        print(f'HIBA: {e}')
    finally:
        try:
            b.write('TRIG AUTO')
            b.write('DISP 1')
        except Exception:
            pass
        b.close()


if __name__ == '__main__':
    main()
