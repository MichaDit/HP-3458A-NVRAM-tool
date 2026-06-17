"""
A 0x002D88 (CAL RAM WRITE) rutin disassembly-zása a HP3458A ROM binary-ból.
Megkeressük mi vezérli a DS1220Y /WE vonalát.
"""
import struct
import sys

ROM = r'C:\Users\Mate\Desktop\teszt\FW\HP3458A_REV9_assembled_and_analysis\HP3458A_REV9_cpu_order_384K_for_Ghidra.bin'

# Capstone nélküli megközelítés: hex dump + fontos utasítás minták keresése
with open(ROM, 'rb') as f:
    data = f.read()

def hex_dump(offset, length=128):
    print(f'  ROM offset 0x{offset:05X}:')
    for i in range(0, length, 16):
        chunk = data[offset + i:offset + i + 16]
        hex_s = ' '.join(f'{b:02X}' for b in chunk)
        asc_s = ''.join(chr(b) if 0x20 <= b <= 0x7E else '.' for b in chunk)
        print(f'  {offset+i:05X}:  {hex_s:<48}  {asc_s}')

print('=== CAL RAM WRITE rutin: 0x002D88 ===')
hex_dump(0x2D88, 128)

print()
print('=== 0x002DA8 (második referencia) ===')
hex_dump(0x2DA8, 64)

# Keressük az IO port write mintát: MOVE.B #x, addr.l
# DS1220Y /WE vezérléshez valószínűleg egy specifikus cím re ír
# 68000: MOVE.B #imm, (abs.l) = 0x13FC xxxx xxxx xxxx xxxx
# vagy: BCLR/BSET #bit, addr (pl. 0x08B9 = BCLR #0, addr.l)
print()
print('=== Bit-set/clear utasítások (IO port /WE vezérlés jelöltek) ===')
# 08B9 = BCLR Dn,(abs.l)  vagy 08F9 = BSET #imm,(abs.l)
# 01B9 = BCLR #bit,(abs.l)
patterns = [
    (b'\x08\xF9', 'BSET #imm,(abs.l)'),
    (b'\x08\xB9', 'BCLR #imm,(abs.l)'),
    (b'\x13\xFC', 'MOVE.B #imm,(abs.l)'),
    (b'\x13\xBC', 'MOVE.B Dn,(abs.l)'),  # nem standard, de keressük
]
for pat, desc in patterns:
    idx = 0
    count = 0
    while True:
        pos = data.find(pat, idx)
        if pos == -1 or pos > 0x60000:
            break
        # Cím kiolvasás (következő 4 byte = abs.l)
        if pos + 6 <= len(data):
            addr = struct.unpack('>I', data[pos+2:pos+6])[0]
            # Csak az ismeretlen (nem cal/settings RAM) területeket mutatjuk
            if addr < 0x60000 or (addr >= 0x60000 and addr < 0x70000):
                print(f'  0x{pos:05X}: {desc}  -> target=0x{addr:06X}')
                count += 1
        idx = pos + 1
        if count > 30:
            print('  ... (több találat)')
            break

# Capstone próba
print()
print('=== Capstone disassembly kísérlet ===')
try:
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_M68K, capstone.CS_MODE_M68K_000)
    md.detail = True

    def disasm(offset, n_bytes=128, label=None):
        chunk = data[offset:offset + n_bytes]
        if label:
            print(f'\n--- {label} @ 0x{offset:05X} ---')
        for ins in md.disasm(chunk, offset):
            print(f'  {ins.address:05X}:  {ins.bytes.hex():<16}  {ins.mnemonic:<10} {ins.op_str}')

    disasm(0x2D88, 128, 'CAL RAM WRITE @ 0x2D88')
    disasm(0x2DA8, 64, 'CAL RAM WRITE2 @ 0x2DA8')

except ImportError:
    print('  capstone nem elérhető — csak hex dump fent')
except Exception as e:
    print(f'  Hiba: {e}')
