"""
HP3458A REV9 - Teljes disassembly mentés
Minden kulcsfüggvény annotált 68000 disassembly-je
"""
import capstone, struct, sys

FIRMWARE = r'C:\Users\Mate\Desktop\teszt\HP3458\FW\HP3458A_REV9_assembled_and_analysis\HP3458A_REV9_cpu_order_384K_for_Ghidra.bin'
OUTPUT   = r'C:\Users\Mate\Desktop\teszt\HP3458\FW\HP3458A_REV9_assembled_and_analysis\HP3458A_REV9_disassembly.txt'

with open(FIRMWARE, 'rb') as f:
    data = f.read()

md = capstone.Cs(capstone.CS_ARCH_M68K, capstone.CS_MODE_BIG_ENDIAN)

# Ismert cimek neve
LABELS = {
    0x763A: 'mread_main_logic',
    0x761E: 'mread_output_cleanup',
    0x7BBA: 'mread_entry_lowaddr',
    0x7BCC: 'beep_handler',
    0x7BD6: 'beep_setflag_path',
    0x7C04: 'beep2_mread_bypass',
    0x7C1E: 'beep_mode_dispatch',
    0x7C38: 'common_unlk_rts',
    0x7C3C: 'mwrite_exec_lowaddr',
    0x8908: 'timer_delay',
    0x49DE: 'gpib_output_dispatch',
    0x188C8: 'psos_channel_read_type0',
    0x18918: 'psos_channel_read_type5',
    0x2F96: 'sprintf_like',
    0x5DA0C: 'beep_hw_driver',
    0x17BBA: 'MREAD_handler',
    0x17BF6: 'MWRITE_handler',
    0x17C28: 'JSR_GPIB_handler',
    0x17C58: 'CALLARRAY_handler',
    0x17BA0: 'XYZZY_handler',
    0x17C8C: 'MADDR_handler',
    0x17D04: 'maddr_type_dispatch',
    0x17C9A: 'maddr_type1',
    0x17CC0: 'maddr_type2',
    0x17CE6: 'maddr_type3',
    0x17CF2: 'maddr_type4',
    0x17D1E: 'maddr_encode_and_output',
    0x585A0: 'descriptor_to_addr',
    0x58340: 'ieee754_double_to_int',
    0x583BA: 'int_to_ieee754_double',
    0x585B4: 'store_descriptor',
    0x1D8DC: 'gpib_send_word',
    0x1D900: 'gpib_send_descriptor',
    0x1D8B8: 'gpib_send_string',
    0x50958: 'int_to_decimal_ascii',
    0x1F530: 'gpib_flush',
    0x52FC4: 'gpib_send_descriptor2',
    0x1DC20: 'mwrite_write_core',
    0x5845A: 'fp_convert_sub1',
    0x584BE: 'fp_compare_sub',
    0x8B20:  'cmd_table_start',
    0xA42A:  'cmd_MREAD_name',
    0xA442:  'cmd_MWRITE_name',
    0x185C0: 'xyzzy_string',
    0x84D4:  'str_expected_0_2',
    0x84F4:  'str_OFF',
    0x84FC:  'str_BEEP_fmt',
}

RAM_LABELS = {
    0x13A6: 'beep_mread_enable_flag',
    0x1DB5: 'beep_mode_copy',
    0x144A: 'mwrite_protect_flag',
    0x1B02: 'beep_hw_state',
    0x0BAE: 'timer_cal_constant',
    0x0A48: 'gpib_output_pending',
    0x0F00: 'gpib_channel_descriptor',
}

def branch_target(ins, data):
    op = ins.mnemonic.upper()
    if 'JSR' in op and '(pc)' in ins.op_str:
        disp = struct.unpack_from('>h', data, ins.address+2)[0]
        return ins.address + 2 + disp
    elif 'BSR' in op:
        disp = struct.unpack_from('>b', data, ins.address+1)[0] if ins.size==2 else struct.unpack_from('>h', data, ins.address+2)[0]
        return ins.address + 2 + disp
    elif any(b in op for b in ['BEQ','BNE','BRA','BGE','BLE','BGT','BLT','BCC','BCS','BVC','BVS','BMI','BPL']):
        disp = struct.unpack_from('>b', data, ins.address+1)[0] if ins.size==2 else struct.unpack_from('>h', data, ins.address+2)[0]
        return ins.address + 2 + disp
    return None

def disasm_block(addr, length, label, out):
    out.append(f'\n{"="*78}')
    out.append(f'; {label}')
    out.append(f'; Address: 0x{addr:05X}  Length: {length} bytes')
    out.append(f'{"="*78}')
    if addr in LABELS:
        out.append(f'{LABELS[addr]}:')
    for ins in md.disasm(data[addr:addr+length], addr):
        tgt = branch_target(ins, data)
        ann = ''
        if tgt is not None:
            lbl = LABELS.get(tgt, f'0x{tgt:05X}')
            ann = f'  ; => {lbl}'
        # A5-relativ cim felismeres
        if '(a5)' in ins.op_str:
            for offs_str in ins.op_str.split('(a5)'):
                try:
                    offs = int(offs_str.split()[-1].replace('$',''), 16)
                    if offs in RAM_LABELS:
                        ann += f'  ; [{RAM_LABELS[offs]}]'
                        break
                except:
                    pass
        # Label a cimhez ha van
        prefix = f'  {ins.address:05X}  {ins.bytes.hex():<14}  {ins.mnemonic:<10} {ins.op_str:<38}'
        out.append(f'{prefix}{ann}')
    out.append('')


# =====================================================================
# DISASSEMBLY BLOKKOK
# =====================================================================
sections = [
    # (addr, length, label)
    (0x7BBA, 24,  'MREAD entry (low-addr wrapper) - BEEP/MREAD flag check'),
    (0x7BCC, 80,  'BEEP handler + dispatch (sets A5+0x13A6 = MREAD enable flag)'),
    (0x763A, 96,  'MREAD main logic (low-addr, BEEP-related wrapper)'),
    (0x761E, 32,  'MREAD output cleanup sub (sends type 0x98 EOI, clears pending flag)'),
    (0x7C3C, 80,  'MWRITE execution (low-addr, calls mwrite_write_core)'),
    (0x17BBA,64,  'MREAD_handler (TRUE 24-bit handler) - reads WORD, sends via GPIB'),
    (0x17BF6,48,  'MWRITE_handler (TRUE 24-bit handler) - writes WORD to address'),
    (0x17C28,48,  'JSR_GPIB_handler - resolves address and executes 68000 code!'),
    (0x17C58,64,  'CALLARRAY_handler - vtable method dispatch (offset 0x16)'),
    (0x17BA0,32,  'XYZZY_handler - sends "I see " to GPIB (Adventure easter egg)'),
    (0x17C8C,32,  'MADDR_handler entry'),
    (0x17C9A,160, 'MADDR type dispatch (subtypes 1-4) + encode_and_output'),
    (0x17D04,64,  'MADDR type_dispatch switch (D7=1..4)'),
    (0x585A0,48,  'descriptor_to_addr - IEEE754 double descriptor -> integer address'),
    (0x58340,112, 'ieee754_double_to_int - IEEE754 double -> integer core'),
    (0x583BA,80,  'int_to_ieee754_double - integer -> IEEE754 double core'),
    (0x585B4,32,  'store_descriptor - write back descriptor'),
    (0x1D8DC,48,  'gpib_send_word - send integer word to GPIB'),
    (0x50958,80,  'int_to_decimal_ascii - integer -> +/-XXXXX ASCII for GPIB'),
    (0x8908, 32,  'timer_delay - delay(n * cal_constant) busy-wait'),
    (0x188C8,80,  'psos_channel_read - pSOS TRAP#0 sys call #24 (GPIB I/O channel)'),
    (0x5DA0C,48,  'beep_hw_driver - sets beep hardware state'),
]

lines = []
lines.append('=' * 78)
lines.append('HP3458A REV9 FIRMWARE — ANNOTÁLT 68000 DISASSEMBLY')
lines.append('Generálva: 2026-06-04  |  Capstone M68K engine')
lines.append('')
lines.append('KULCS-MEGÁLLAPÍTÁSOK:')
lines.append('  1. Handler-cím ek 24-bitesek: 0x00017xxx (flag2 mező = magas 2 byte)')
lines.append('  2. BEEP 0/1/2: A5+0x13A6 flag -> MREAD engedélyezés/tiltás/bypass')
lines.append('  3. BEEP 2 = MREAD bypass (security check kihagyva!)')
lines.append('  4. Minden érték IEEE 754 double deszkriptorban tárolva')
lines.append('  5. MREAD/MWRITE mindig WORD (2 bájt) hozzáférés')
lines.append('  6. JSR GPIB-parancs = tetszőleges 68000 kód futtatása GPIB-ből')
lines.append('  7. pSOS RTOS: TRAP #0 / D7=#24 = I/O csatorna rendszerhívás')
lines.append('  8. XYZZY -> "I see " (Adventure idézet, 6 karakter GPIB-re)')
lines.append('  9. Build dátum: Fri Jan 19 1990 @ 0x053E')
lines.append('=' * 78)
lines.append('')

lines.append('ISMERT CIMEK (LABELS):')
for addr, lbl in sorted(LABELS.items()):
    lines.append(f'  0x{addr:05X}  {lbl}')
lines.append('')

lines.append('RAM OFFSZETEK (A5 bázistól):')
for offs, lbl in sorted(RAM_LABELS.items()):
    lines.append(f'  A5+0x{offs:04X}  {lbl}')
lines.append('')

for addr, length, label in sections:
    disasm_block(addr, length, label, lines)

# XYZZY string
lines.append('=' * 78)
lines.append('; XYZZY easter egg string @ 0x185C0')
lines.append('=' * 78)
s = data[0x185C0:0x185C0+32]
lines.append(f'  Hex:    {s[:16].hex()}')
lines.append(f'  ASCII:  {repr(s.split(b"\\x00")[0].decode("ascii","replace"))}')
lines.append(f'  Kuldo:  "I see " (6 karakter, Adventure: "I see no cave here")')
lines.append('')

# Parancs tabla excerpt
lines.append('=' * 78)
lines.append('; PARANCS TÁBLA RÉSZLET (0x8B20 - 0xAF80) — 388 × 24 bájt')
lines.append('; Rekord: [name_len:2][name:10][cmd_id:2][flags:2][0x89EA:2][flag2:2][handler_lo:2][priv:2]')
lines.append('; Valódi handler = 0x0001_HHHH ahol HHHH = handler_lo mező')
lines.append('=' * 78)

def parse_entry(data, offset):
    name_len = struct.unpack_from('>H', data, offset)[0]
    if name_len == 0 or name_len > 10: return None
    name_bytes = data[offset+2:offset+2+name_len]
    if not all(0x20 <= b < 0x7F for b in name_bytes): return None
    name = name_bytes.decode('ascii')
    pad = data[offset+2+name_len:offset+12]
    if any(b != 0 for b in pad): return None
    cmd_id = struct.unpack_from('>H', data, offset+12)[0]
    flags  = struct.unpack_from('>H', data, offset+14)[0]
    const  = struct.unpack_from('>H', data, offset+16)[0]
    flag2  = struct.unpack_from('>H', data, offset+18)[0]
    handler= struct.unpack_from('>H', data, offset+20)[0]
    priv   = struct.unpack_from('>H', data, offset+22)[0]
    if const != 0x89EA: return None
    return (name, cmd_id, flags, flag2, handler, priv)

TABLE_START = 0x8B20
ENTRY_SIZE  = 24
lines.append(f'; {"#":>4}  {"Parancs":<12} {"CmdID":>6}  {"Flag2":>5}  {"Handler_lo":>10}  {"Valódi_handler":>14}  {"Priv":>4}  Leírás')
lines.append(f'; {"-"*90}')

FLAG2_DESC = {
    0x0000: 'token/keyword',
    0x0001: 'egyszerű parancs',
    0x0002: 'query',
    0x0003: 'mérési parancs',
    0x0004: 'CAL/privilegizált',
    0x0005: 'math/stack',
}
PRIV_DESC = {
    0x0000: 'szabad',
    0x0001: 'standard',
    0x0002: 'CIIL option',
    0x0003: 'magas priv',
}

count = 0
offset = TABLE_START
while offset + ENTRY_SIZE <= len(data):
    e = parse_entry(data, offset)
    if e is None: break
    name, cmd_id, flags, flag2, handler, priv = e
    real_handler = 0x10000 | handler if flag2 != 0x0000 and handler != 0 else handler
    fdesc = FLAG2_DESC.get(flag2, f'0x{flag2:04X}')
    pdesc = PRIV_DESC.get(priv, f'0x{priv:04X}')
    lines.append(f'; {count:>4}  {name:<12} 0x{cmd_id:04X}  0x{flag2:04X}  0x{handler:04X}      0x{real_handler:08X}      0x{priv:04X}  {fdesc}')
    count += 1
    offset += ENTRY_SIZE
lines.append(f'; Összesen: {count} bejegyzés')
lines.append('')

with open(OUTPUT, 'w', encoding='utf-8') as f:
    f.write('\n'.join(lines))

print(f'Mentve: {OUTPUT}')
print(f'Sorok száma: {len(lines)}')
print(f'Fájl mérete: {sum(len(l)+1 for l in lines)} bájt')
