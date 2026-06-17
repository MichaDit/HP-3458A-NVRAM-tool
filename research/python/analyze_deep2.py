import capstone, struct

with open(r'C:\Users\Mate\Desktop\teszt\HP3458\FW\HP3458A_REV9_assembled_and_analysis\HP3458A_REV9_cpu_order_384K_for_Ghidra.bin', 'rb') as f:
    data = f.read()

md = capstone.Cs(capstone.CS_ARCH_M68K, capstone.CS_MODE_BIG_ENDIAN)

def disasm_ann(addr, length=128, label=''):
    print(f'\n=== {label} @ 0x{addr:05X} ===')
    for ins in md.disasm(data[addr:addr+length], addr):
        op = ins.mnemonic.upper()
        ann = ''
        if 'JSR' in op and '(pc)' in ins.op_str:
            disp = struct.unpack_from('>h', data, ins.address+2)[0]
            ann = f'=> 0x{ins.address+2+disp:05X}'
        elif 'BSR' in op:
            disp = struct.unpack_from('>b', data, ins.address+1)[0] if ins.size==2 else struct.unpack_from('>h', data, ins.address+2)[0]
            ann = f'=> 0x{ins.address+2+disp:05X}'
        elif any(b in op for b in ['BEQ','BNE','BRA','BGE','BLE','BGT','BLT','BCC','BCS']):
            disp = struct.unpack_from('>b', data, ins.address+1)[0] if ins.size==2 else struct.unpack_from('>h', data, ins.address+2)[0]
            ann = f'=> 0x{ins.address+2+disp:05X}'
        print(f'  {ins.address:05X}  {ins.bytes.hex():<14}  {ins.mnemonic:<10} {ins.op_str:<36}  {ann}')
    print()

# 1. XYZZY string (0x185C0 - 6 karakter)
print('=== XYZZY string tartalma ===')
s = data[0x185C0:0x185C0+16]
print(f'  Hex: {s.hex()}')
print(f'  ASCII: {repr(s[:6])}')
print(f'  String: {s.split(b"\\x00")[0].decode("ascii","replace")!r}')
print()

# 2. Az alap cim-feloldo (58340)
disasm_ann(0x58340, 96, '0x58340 - cim feldolgozo mag')

# 3. MADDR subtype handlerek: byte (17C9A), word (17CC0), long (17CE6)
disasm_ann(0x17C9A, 80, '0x17C9A - MADDR subtype 1 (byte?)')
disasm_ann(0x17CC0, 80, '0x17CC0 - MADDR subtype 2 (word?)')
disasm_ann(0x17CE6, 80, '0x17CE6 - MADDR subtype 3 (long?)')

# 4. Alap resolver 58340 melletti: 583BA (iras)
disasm_ann(0x583BA, 64, '0x583BA - cim iras / STORE resolver')

# 5. GPIB send fuggveny (50958)
disasm_ann(0x50958, 64, '0x50958 - GPIB send')
