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

# 1. Cim-feloldo fuggveny
disasm_ann(0x585A0, 128, '0x585A0 - cim feloldo (address resolver)')

# 2. MREAD GPIB output rutin
disasm_ann(0x1D8DC, 80, '0x1D8DC - GPIB word output rutin')

# 3. XYZZY handler (valodi, 0x17BA0)
disasm_ann(0x17BA0, 64, '0x17BA0 - XYZZY valodi handler')

# 4. MADDR fo dispatch (0x17D04)
disasm_ann(0x17D04, 80, '0x17D04 - MADDR dispatch')

# 5. ROM ertekek
v1 = struct.unpack_from('>H', data, 0x8A00)[0]
v2 = struct.unpack_from('>H', data, 0x8A02)[0]
print(f'ROM ertek 0x8A00-nal: 0x{v1:04X}')
print(f'ROM ertek 0x8A02-nal: 0x{v2:04X}')
