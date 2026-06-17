"""
Az osszes rejtett/ismeretlen GPIB parancs disassembly-ja.
Kimenet: hidden_cmds_disasm.txt
"""
import struct, re, sys

try:
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_M68K, capstone.CS_MODE_M68K_000)
    md.detail = False
except ImportError:
    print('pip install capstone'); sys.exit(1)

ROM = r'C:\Users\Mate\Desktop\teszt\FW\HP3458A_REV9_assembled_and_analysis\HP3458A_REV9_cpu_order_384K_for_Ghidra.bin'
with open(ROM, 'rb') as f:
    rom = f.read()

OUT = r'C:\Users\Mate\Desktop\teszt\FW\hidden_cmds_disasm.txt'

CMD_TABLE_START = 0x08B20
CMD_ENTRY_SIZE  = 24

PUBLIC = {
    'DCV','ACV','DCI','ACI','OHM','OHMF','LFREQ','FREQ','PER',
    'NPLC','NRDGS','TRIG','TARM','DELAY','TIMER','APER',
    'LEVEL','SLOPE','SSRC','DSAC','DSDC','DISP',
    'BEEP','END','ERRSTR?','EMASK','ERR?',
    'MREAD','MWRITE','MFORMAT',
    'CAL','CAL?','CALSTR','CALSTR?','CALNUM?','SECURE','ACAL','SCAL',
    'MEM','RMEM','SCRATCH','STORE','RECALL',
    'FUNC','RANGE','FIXEDZ','LFILTER','MATH',
    'INBUF','OUTBUF',
    'ID?','REV?','SRQ','SYST',
    'PRESET','RESET','TEST',
    'DCVSET','DCVOFFSET',
    'SETACV','ACDCV',
    'QFORMAT','FORMAT',
    'NDIG','OFORMAT',
    'SUBPROG','CALL','CALLARRAY',
    'SADCV','SADCI',
    'ISCALE?','SCALE',
    'AZERO','ARANGE',
    'REFORMAT','ONCE',
    'LIMIT','HIGH','LOW','RMATH',
    'LOCK','UNLOCK','TOPO','LINE',
    'APER?','AZERO?','ARANGE?','BEEP?','CALSTR?',
    'DELAY?','DISP?','EMASK?','END?','FIXEDZ?',
    'FUNC?','INBUF?','LEVEL?','LFILTER?','LFREQ?',
    'LOCK?','MATH?','MEM?','MFORMAT?','NDIG?',
    'NPLC?','NRDGS?','OFORMAT?','QFORMAT?','RANGE?',
    'SETACV?','SLOPE?','SSRC?','TARM?','TIMER?','TRIG?',
}

def parse_cmd_table():
    entries = []
    off = CMD_TABLE_START
    while off + CMD_ENTRY_SIZE <= len(rom):
        chunk = rom[off:off + CMD_ENTRY_SIZE]
        name_len = struct.unpack('>H', chunk[0:2])[0]
        if name_len == 0 or name_len > 10:
            break
        name = chunk[2:2+name_len].decode('ascii', errors='replace')
        cmd_id    = struct.unpack('>H', chunk[12:14])[0]
        handler_hi = struct.unpack('>H', chunk[18:20])[0]
        handler_lo = struct.unpack('>H', chunk[20:22])[0]
        priv      = struct.unpack('>H', chunk[22:24])[0]
        handler   = (handler_hi << 16) | handler_lo
        entries.append({'name': name, 'cmd_id': cmd_id,
                        'handler': handler, 'priv': priv})
        off += CMD_ENTRY_SIZE
    return entries

cmds = parse_cmd_table()

def annotate(ins):
    ops = ins.op_str
    mn  = ins.mnemonic.lower()
    flag = ''
    m = re.search(r'\$([0-9a-fA-F]+)\.l', ops)
    if m:
        t = int(m.group(1), 16)
        if t < 0x20000 and mn not in ('jsr','lea','movea.l','pea','bra','bne','beq','bcc','bcs','bge','bgt','ble','blt','bra.b','bra.w','bne.b','bne.w'):
            flag = f'  # IO {t:05X}'
        elif 0x60000 <= t <= 0x60FFF and mn not in ('jsr','lea','pea'):
            flag = f'  # CALRAM {t:06X}'
    m2 = re.search(r'\$([0-9a-fA-F]{5,6})\.l', ops)
    if m2:
        t2 = int(m2.group(1), 16)
        if 0x60000 <= t2 <= 0x60FFF and mn not in ('jsr','lea','pea'):
            flag = f'  # CALRAM {t2:06X}'
        elif 0xC0000 <= t2 <= 0xCFFFF and mn not in ('jsr','lea','pea'):
            flag = f'  # /WE {t2:06X}'
        elif 0x120000 <= t2 <= 0x12FFFF and mn not in ('lea','pea'):
            flag = f'  # SRAM {t2:06X}'
    return flag

lines = []
lines.append('HP 3458A REV9 -- Rejtett GPIB parancsok disassembly')
lines.append('=' * 70)
lines.append('')

# Token-only parancsok osszefoglaloja (nem disasm-ozzuk egyenkent)
tokens = [c for c in cmds if c['handler'] == 0 and c['name'] not in PUBLIC]
if tokens:
    lines.append('--- TOKEN-ONLY parancsok (nincs sajat handler, mas parancs argumentuma) ---')
    for c in tokens:
        lines.append(f"  {c['name']:<16} cmd_id=0x{c['cmd_id']:04X}  priv={c['priv']}")
    lines.append('')

# Handler-rel rendelkezo rejtett parancsok
hidden_with_handler = [
    c for c in cmds
    if c['handler'] != 0
    and c['name'] not in PUBLIC
    and c['name'].rstrip('?').rstrip('_') not in PUBLIC
]

lines.append(f'--- HANDLER-REL RENDELKEZO REJTETT PARANCSOK ({len(hidden_with_handler)} db) ---')
lines.append('')

seen_handlers = {}  # handler_addr -> parancs neve (duplikat handler-ek jelzese)

for c in hidden_with_handler:
    h = c['handler']
    name = c['name']
    priv = c['priv']
    cmd_id = c['cmd_id']

    hdr = f'[{name}]  handler=0x{h:06X}  priv={priv}  cmd_id=0x{cmd_id:04X}'
    if h in seen_handlers:
        hdr += f'  (== {seen_handlers[h]})'
    else:
        seen_handlers[h] = name
    lines.append(hdr)

    # Disassembly
    off = h
    if off < 0 or off >= len(rom):
        lines.append('  (ROM-on kivul)')
        lines.append('')
        continue

    insns = list(md.disasm(rom[off:off+400], h))
    if not insns:
        lines.append('  (nem disassemblyzthato)')
        lines.append('')
        continue

    for ins in insns:
        flag = annotate(ins)
        lines.append(f'  {ins.address:05X}  {ins.mnemonic:<8} {ins.op_str}{flag}')
        if ins.mnemonic.lower() == 'rts':
            break

    lines.append('')

# Kiiras fajlba
with open(OUT, 'w', encoding='utf-8') as f:
    f.write('\n'.join(lines))

print(f'Kesz. {len(hidden_with_handler)} rejtett parancs disassemblyzve.')
print(f'Kimenet: {OUT}')

# Rovid kivonat a legfontosabbakrol
print()
print('=== CALRAM-BA IRO / /WE-T ERINTETT PARANCSOK ===')
for c in hidden_with_handler:
    h = c['handler']
    off = h
    if off < 0 or off >= len(rom):
        continue
    insns = list(md.disasm(rom[off:off+600], h))
    for ins in insns:
        ops = ins.op_str
        m2 = re.search(r'\$([0-9a-fA-F]{5,6})\.l', ops)
        if m2:
            t2 = int(m2.group(1), 16)
            if (0x60000 <= t2 <= 0x60FFF) or (0xC0000 <= t2 <= 0xCFFFF):
                print(f"  {c['name']:<14} handler=0x{h:06X}: {ins.address:05X} {ins.mnemonic} {ops}")
                break
        # sub_05BC2C vagy sub_05A158 hivasa
        if '5bc2c' in ops.lower() or '5a158' in ops.lower() or '5bb22' in ops.lower():
            print(f"  {c['name']:<14} handler=0x{h:06X}: {ins.address:05X} {ins.mnemonic} {ops}  # CAL_WRITER")
            break
        if ins.mnemonic.lower() == 'rts':
            break
