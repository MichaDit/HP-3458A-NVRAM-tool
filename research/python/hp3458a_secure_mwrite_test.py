#!/usr/bin/env python3
"""
SECURE 22 + MWRITE teszt a cal_ram-on, és power-cycle visszaolvasás.
"""
import socket, sys, time

BRIDGE = ('192.168.2.88', 1234)

def connect():
    s = socket.create_connection(BRIDGE, timeout=10)
    s.settimeout(10)
    buf = []

    def sw(cmd):
        s.sendall((cmd + '\n').encode('ascii'))

    def sr():
        raw = b''
        while b'\n' not in raw:
            raw += s.recv(4096)
        return raw.split(b'\n')[0].decode('ascii', errors='replace').strip()

    def sq(cmd):
        sw(cmd); sw('++read'); return sr()

    def mread(addr):
        return int(sq('MREAD ' + str(addr)))

    def mwrite(addr, val):
        sw('MWRITE ' + str(addr) + ',' + str(val))
        time.sleep(0.02)

    def err():
        return sq('ERRSTR?')

    def init():
        sw('++addr 22'); sw('++read_tmo_ms 500'); sw('++clr')
        time.sleep(1.0)
        for c in ('END ALWAYS', 'NPLC 0', 'NRDGS 1', 'TRIG HOLD', 'QFORMAT NUM'):
            sw(c)
        time.sleep(0.1)

    def close():
        try: sw('TRIG AUTO'); sw('DISP 1')
        except: pass
        s.close()

    class B:
        pass
    o = B()
    o.sw = sw; o.sr = sr; o.sq = sq; o.mread = mread
    o.mwrite = mwrite; o.err = err; o.init = init; o.close = close
    return o


mode = sys.argv[1] if len(sys.argv) > 1 else 'help'

# settings_ram: 0x127196 = 1208726 dec, jelolo = 0x5A5A = 23130
SRAM_ADDR  = 1208726
SRAM_MARK  = 23130    # 0x5A5A

# cal_ram Defeats[0]: 0x60C54 = 395348 dec, jelolo HIGH byte = 0xDE -> word 0xDE00 = 56832
CALRAM_ADDR = 395348
CALRAM_MARK = 56832   # 0xDE00 -> DS1220Y HIGH byte = 0xDE


if mode == 'sram_read':
    b = connect(); b.init()
    v = b.mread(SRAM_ADDR)
    print('=== settings_ram visszaolvasas (power cycle utan) ===')
    print('Cim: 0x127196  Jelolo: 0x5A5A (' + str(SRAM_MARK) + ')')
    print('Olvasott: ' + hex(v) + ' (' + str(v) + ')')
    if v == SRAM_MARK:
        print('MEGMARADT! (DS1235 is battery-backed, vagy FW nem irta felul)')
    elif v == 0:
        print('0x0000 — elveszett. FW ujrainicializalta.')
    else:
        print('Mas ertek — FW felulirta: ' + hex(v))
    b.close()

elif mode == 'calram_secure_write':
    b = connect(); b.init()
    v0 = b.mread(CALRAM_ADDR)
    print('=== cal_ram SECURE 22 + MWRITE teszt ===')
    print('Defeats[0] most: ' + hex(v0))
    print('ERRSTR: ' + b.err())

    b.sw('SECURE 22'); time.sleep(0.1)
    e1 = b.err()
    print('SECURE 22 -> ERRSTR: ' + e1)

    b.mwrite(CALRAM_ADDR, CALRAM_MARK)
    e2 = b.err()
    print('MWRITE ' + str(CALRAM_ADDR) + ',' + str(CALRAM_MARK) + ' (0xDE00) -> ERRSTR: ' + e2)

    v1 = b.mread(CALRAM_ADDR)
    print('Visszaolvasas: ' + hex(v1) + ' (' + str(v1) + ')')

    if (v1 & 0xFF00) == 0xDE00:
        print('OK! cal_ram MWRITE MUKODIK SECURE 22 utan!')
        print('Visszaallitas...')
        b.mwrite(CALRAM_ADDR, v0)
        v2 = b.mread(CALRAM_ADDR)
        print('Visszaallitva: ' + hex(v2))
    else:
        print('HIBA: nem irt, vagy mas ertek (' + hex(v1) + ')')
    b.close()

elif mode == 'calram_persist_write':
    b = connect(); b.init()
    v0 = b.mread(CALRAM_ADDR)
    print('=== cal_ram tartossag teszt — iras ===')
    print('Defeats[0] most: ' + hex(v0))

    b.sw('SECURE 22'); time.sleep(0.1)
    e1 = b.err()
    print('SECURE 22 -> ERRSTR: ' + e1)

    b.mwrite(CALRAM_ADDR, CALRAM_MARK)
    v1 = b.mread(CALRAM_ADDR)
    print('Iras utan visszaolvasas: ' + hex(v1))
    if (v1 & 0xFF00) == 0xDE00:
        print('Sikeresen irva. KAPCSOLD KI ES BE A MUSZERT!')
        print('Majd: python hp3458a_secure_mwrite_test.py calram_persist_read')
    else:
        print('HIBA az irasban')
    b.close()

elif mode == 'calram_persist_read':
    b = connect(); b.init()
    v = b.mread(CALRAM_ADDR)
    print('=== cal_ram visszaolvasas (power cycle utan) ===')
    print('Olvasott: ' + hex(v) + ' (' + str(v) + ')')
    if (v & 0xFF00) == 0xDE00:
        print('MEGMARADT! DS1220Y valodi NVRAM, MWRITE + SECURE 22 tartosan ir.')
    elif v == 0:
        print('0x0000 — elveszett')
    else:
        print('Mas ertek: ' + hex(v))
    b.close()

elif mode == 'calram_restore':
    b = connect(); b.init()
    b.sw('SECURE 22'); time.sleep(0.1)
    b.mwrite(CALRAM_ADDR, 0)
    v = b.mread(CALRAM_ADDR)
    print('Defeats[0] visszaallitva: ' + hex(v))
    b.close()

else:
    print('Modok:')
    print('  sram_read             — settings_ram 0x5A5A megmaradt-e?')
    print('  calram_secure_write   — SECURE 22 + MWRITE teszt (visszaall)')
    print('  calram_persist_write  — SECURE 22 + MWRITE, power cycle elott')
    print('  calram_persist_read   — visszaolvasas power cycle utan')
    print('  calram_restore        — Defeats visszaallitasa 0-ra')
