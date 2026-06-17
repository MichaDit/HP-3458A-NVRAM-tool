"""Minimális bridge diagnosztika: egy MREAD küldése és a nyers válasz olvasása."""
import socket, time

HOST, PORT = '192.168.2.88', 1234
ADDR = 22
TEST_CASES = [
    ('cal_ram start',    393216),   # 0x060000
    ('vectors start',         0),   # 0x000000
    ('settings_ram start', 1179648), # 0x120000
]

sock = socket.socket()
sock.settimeout(15)
sock.connect((HOST, PORT))
print(f'Csatlakozva: {HOST}:{PORT}')

# Bridge init
sock.sendall(f'++addr {ADDR}\n'.encode())
print('++addr küldve, várok 2s...')
time.sleep(2)

for label, maddr in TEST_CASES:
    print(f'\n--- {label} (addr={maddr} = 0x{maddr:06X}) ---')
    try:
        t0 = time.time()
        sock.sendall(f'MREAD {maddr}\n'.encode())
        sock.sendall(b'++read\n')
        buf = b''
        while b'\n' not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        elapsed = time.time() - t0
        response = buf.split(b'\n')[0].decode('ascii', errors='replace').strip()
        print(f'  Válasz: {response!r}  ({elapsed*1000:.0f}ms)')
    except Exception as e:
        print(f'  HIBA: {e}')
    time.sleep(0.5)

sock.close()
print('\nKész.')
