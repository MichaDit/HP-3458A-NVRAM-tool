"""
Az osszes GPIB parancs listazasa a parancstablabol.
Kereszthivatkozas a nyilvanos dokumentacioval, rejtett parancsok kiemelese.
"""
import struct

ROM = r'C:\Users\Mate\Desktop\teszt\FW\HP3458A_REV9_assembled_and_analysis\HP3458A_REV9_cpu_order_384K_for_Ghidra.bin'
with open(ROM, 'rb') as f:
    rom = f.read()

CMD_TABLE_START = 0x08B20
CMD_ENTRY_SIZE  = 24

def parse_cmd_table():
    entries = []
    off = CMD_TABLE_START
    idx = 0
    while off + CMD_ENTRY_SIZE <= len(rom):
        chunk = rom[off:off + CMD_ENTRY_SIZE]
        name_len = struct.unpack('>H', chunk[0:2])[0]
        if name_len == 0 or name_len > 10:
            break
        name = chunk[2:2+name_len].decode('ascii', errors='replace')
        cmd_id    = struct.unpack('>H', chunk[12:14])[0]
        flags     = struct.unpack('>H', chunk[14:16])[0]
        marker    = struct.unpack('>H', chunk[16:18])[0]
        handler_hi = struct.unpack('>H', chunk[18:20])[0]
        handler_lo = struct.unpack('>H', chunk[20:22])[0]
        priv      = struct.unpack('>H', chunk[22:24])[0]
        handler   = (handler_hi << 16) | handler_lo
        entries.append({
            'idx': idx, 'name': name, 'cmd_id': cmd_id, 'flags': flags,
            'marker': marker, 'handler': handler, 'priv': priv, 'off': off
        })
        off += CMD_ENTRY_SIZE
        idx += 1
    return entries

cmds = parse_cmd_table()
print(f'Osszes parancs a tablabol: {len(cmds)}\n')

# Ismert nyilvanos parancsok (HP 3458A Programming Reference alapjan)
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
    'REFORMAT',
    'ONCE',
    'LIMIT',
    'HIGH','LOW',
    'RMATH',
    'LOCK','UNLOCK',
    'TOPO',
    'LINE',
}

print(f'{"#":<4} {"Nev":<14} {"cmd_id":<8} {"handler":<10} {"priv":<5} {"flags":<6} Megjegyzes')
print('-' * 75)

# Csoportositjuk
unknown = []
for c in cmds:
    name = c['name']
    h = c['handler']
    hstr = f'0x{h:06X}' if h else '(token)'
    priv_flag = 'PRIV' if c['priv'] else ''

    # Nyilvanos-e?
    base = name.rstrip('?').rstrip('_')
    is_public = name in PUBLIC or base in PUBLIC

    note = ''
    if not is_public:
        note = '  <<< ISMERETLEN/REJTETT'
        unknown.append(c)
    if '_' in name and not name.endswith('?'):
        note += ' [UNDERSCORE]'
    if c['priv'] == 0 and h != 0:
        note += ' [NO-PRIV]'

    print(f"{c['idx']:<4} {name:<14} 0x{c['cmd_id']:04X}   {hstr:<10} {priv_flag:<5} 0x{c['flags']:04X} {note}")

print()
print(f'=== REJTETT / ISMERETLEN PARANCSOK ({len(unknown)} db) ===')
for c in unknown:
    h = c['handler']
    hstr = f'0x{h:06X}' if h else '(token/stub)'
    print(f"  {c['name']:<14} handler={hstr}  priv={c['priv']}  cmd_id=0x{c['cmd_id']:04X}")
