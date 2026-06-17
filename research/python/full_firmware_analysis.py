import os
import struct
import capstone
from collections import defaultdict

# 2026-06-16: a projekt átrendezése után a nyers ROM binárisok (amiket nem mi
# készítettünk, a műszer firmware-jéből lettek kiolvasva) az external_sources/
# mappába kerültek, ez a script pedig research/python/-ba (FW/research/python/).
# __file__-relatív útvonal, hogy bárhonnan futtatva is megtalálja.
ROM_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '..', '..',
    'external_sources', 'HP3458A_REV9_cpu_order_384K_for_Ghidra.bin',
)
ROM_SIZE  = 0x60000   # 384 KB

CMD_TABLE_START = 0x08B20
CMD_ENTRY_SIZE  = 24

KNOWN_LABELS = {
    0x02F96: 'sprintf_like',
    0x049DE: 'gpib_output_dispatch',
    0x0761E: 'mread_output_cleanup',
    0x0763A: 'mread_main_logic',
    0x07BBA: 'mread_entry_lowaddr',
    0x07BCC: 'beep_handler',
    0x07BD6: 'beep_setflag_path',
    0x07C04: 'beep2_mread_bypass',
    0x07C1E: 'beep_mode_dispatch',
    0x07C38: 'common_unlk_rts',
    0x07C3C: 'mwrite_exec_lowaddr',
    0x08908: 'timer_delay',
    0x08B20: 'cmd_table_start',
    0x0A42A: 'cmd_MREAD_name',
    0x0A442: 'cmd_MWRITE_name',
    0x17BA0: 'XYZZY_handler',
    0x17BBA: 'MREAD_handler',
    0x17BF6: 'MWRITE_handler',
    0x17C28: 'JSR_GPIB_handler',
    0x17C58: 'CALLARRAY_handler',
    0x17C8C: 'MADDR_handler',
    0x17C9A: 'maddr_type1',
    0x17CC0: 'maddr_type2',
    0x17CE6: 'maddr_type3',
    0x17CF2: 'maddr_type4',
    0x17D04: 'maddr_type_dispatch',
    0x17D1E: 'maddr_encode_and_output',
    0x185C0: 'xyzzy_string',
    0x188C8: 'psos_channel_read_type0',
    0x18918: 'psos_channel_read_type5',
    0x1D8B8: 'gpib_send_string',
    0x1D8DC: 'gpib_send_word',
    0x1D900: 'gpib_send_descriptor',
    0x1DC20: 'mwrite_write_core',
    0x1F530: 'gpib_flush',
    0x50958: 'int_to_decimal_ascii',
    0x52FC4: 'gpib_send_descriptor2',
    0x58340: 'ieee754_double_to_int',
    0x583BA: 'int_to_ieee754_double',
    0x5845A: 'fp_convert_sub1',
    0x584BE: 'fp_compare_sub',
    0x585A0: 'descriptor_to_addr',
    0x585B4: 'store_descriptor',
    0x5DA0C: 'beep_hw_driver',
}

A5_SYMBOLS = {
    0x0A48: 'gpib_output_pending',
    0x0BAE: 'timer_cal_constant',
    0x0F00: 'gpib_channel_descriptor',
    0x13A6: 'beep_mread_enable_flag',
    0x144A: 'mwrite_protect_flag',
    0x1B02: 'beep_hw_state',
    0x1DB5: 'beep_mode_copy',
}

_md = capstone.Cs(capstone.CS_ARCH_M68K, capstone.CS_MODE_BIG_ENDIAN)


# ─── Task 1: ROM loader ───────────────────────────────────────────────────────

def load_rom():
    with open(ROM_PATH, 'rb') as f:
        return f.read()


# ─── Task 2: Vektortábla parser ───────────────────────────────────────────────

def parse_vectors(rom):
    """256 db 68000 exception vektor kinyerése. Visszaad egy listát érvényes ROM-cím entry pontokból."""
    entries = []
    for i in range(1, 256):   # i=0 = Initial SP, kizárva
        offset = i * 4
        addr = struct.unpack_from('>L', rom, offset)[0]
        if addr == 0:
            continue
        if addr < 2 or addr >= ROM_SIZE:
            continue
        if addr % 2 != 0:
            continue
        entries.append(addr)
    return list(dict.fromkeys(entries))  # duplikátum-mentes, sorrend megtartva


# ─── Task 3: cmd_table seed extractor ────────────────────────────────────────

def parse_cmd_seeds(rom):
    """Kinyeri a (cmd_name, handler_addr) párokat a parancs-dispatch táblából."""
    entries = []
    off = CMD_TABLE_START
    while off + CMD_ENTRY_SIZE <= len(rom):
        chunk = rom[off:off + CMD_ENTRY_SIZE]
        name_len = struct.unpack_from('>H', chunk, 0)[0]
        if name_len == 0 or name_len > 10:
            break
        name = chunk[2:2 + name_len].decode('ascii', errors='replace')
        handler_hi = struct.unpack_from('>H', chunk, 18)[0]
        handler_lo = struct.unpack_from('>H', chunk, 20)[0]
        handler = (handler_hi << 16) | handler_lo
        if handler != 0 and 2 <= handler < ROM_SIZE:
            entries.append((name, handler))
        off += CMD_ENTRY_SIZE
    return entries


# ─── Task 4: Utasítás-dekódoló és branch-target számítás ─────────────────────

_BRANCH_MNEMS = {'bra', 'bsr', 'beq', 'bne', 'bge', 'bgt', 'ble', 'blt',
                 'bcc', 'bcs', 'bmi', 'bpl', 'bvc', 'bvs', 'bhi', 'bls'}
_TERM_MNEMS   = {'rts', 'rte', 'stop', 'reset', 'illegal'}
_UNCOND_MNEMS = {'bra', 'jmp'}
_CALL_MNEMS   = {'jsr', 'bsr'}


def decode_one(rom, addr):
    """Dekódol egyetlen M68K utasítást addr-nál. Visszaad Instruction-t vagy None-t."""
    if addr < 0 or addr + 2 > len(rom):
        return None
    end = min(addr + 10, len(rom))
    return next(_md.disasm(rom[addr:end], addr), None)


def get_branch_target(rom, insn):
    """Visszaadja a branch/jump célcímét, vagy None-t indirekt/nem-branch esetén."""
    mnem = insn.mnemonic.split('.')[0].lower()
    op   = insn.op_str.strip()
    addr = insn.address

    # Feltételes és feltétel nélküli ágak, BSR
    if mnem in _BRANCH_MNEMS:
        if insn.size == 2:
            disp = struct.unpack_from('>b', rom, addr + 1)[0]
        else:
            disp = struct.unpack_from('>h', rom, addr + 2)[0]
        return (addr + 2 + disp) & 0xFFFFFF

    # PC-relatív JSR/JMP: op_str-ben '(pc)' szerepel
    if '(pc)' in op.lower():
        disp = struct.unpack_from('>h', rom, addr + 2)[0]
        return (addr + 2 + disp) & 0xFFFFFF

    # Abszolút JSR/JMP: op_str '$XXXX' zárójelek nélkül
    if op.startswith('$') and '(' not in op:
        try:
            return int(op.lstrip('$').split('.')[0], 16)
        except ValueError:
            return None

    return None  # Regiszter-indirekt vagy egyéb — nem oldható fel statikusan


# ─── Task 5: Rekurzív descent engine ─────────────────────────────────────────

def recursive_descent(rom, seeds):
    """
    Rekurzív descent disassembly az összes seed entry pointtól.
    Visszaad: (visited dict[addr→insn], call_graph dict[callee→set(caller)])
    """
    from collections import deque
    visited    = {}
    call_graph = defaultdict(set)
    queue      = deque()

    for addr in seeds:
        if 0 < addr < ROM_SIZE and addr % 2 == 0:
            queue.append(addr)

    while queue:
        addr = queue.popleft()
        if addr in visited or addr < 2 or addr >= ROM_SIZE:
            continue

        insn = decode_one(rom, addr)
        if insn is None:
            continue

        visited[addr] = insn
        mnem = insn.mnemonic.split('.')[0].lower()
        next_addr = addr + insn.size

        if mnem in _TERM_MNEMS:
            pass  # ág lezárul

        elif mnem in _UNCOND_MNEMS:
            target = get_branch_target(rom, insn)
            if target and 0 < target < ROM_SIZE:
                queue.append(target)
            # ág lezárul — next_addr NEM kerül queue-ba

        elif mnem in _CALL_MNEMS:
            target = get_branch_target(rom, insn)
            if target and 0 < target < ROM_SIZE:
                call_graph[target].add(addr)
                queue.append(target)
            queue.append(next_addr)  # folytatódik a hívás után

        elif mnem in _BRANCH_MNEMS:
            target = get_branch_target(rom, insn)
            if target and 0 < target < ROM_SIZE:
                queue.append(target)
            queue.append(next_addr)  # feltételes: mindkét ág

        else:
            queue.append(next_addr)

    return visited, dict(call_graph)


# ─── Task 6: Write-utasítás detektor ─────────────────────────────────────────

_WRITE_MNEMS = {
    'move', 'movea', 'movem', 'movep',
    'clr', 'st', 'sf', 'seq', 'sne', 'sge', 'sgt', 'sle', 'slt',
    'scc', 'scs', 'smi', 'spl', 'svc', 'svs', 'shi', 'sls', 'sf',
    'bset', 'bclr', 'bchg', 'tas', 'nbcd',
    'add', 'addi', 'addq', 'sub', 'subi', 'subq',
    'and', 'andi', 'or', 'ori', 'eor', 'eori',
    'neg', 'negx', 'not',
    'asl', 'asr', 'lsl', 'lsr', 'rol', 'ror', 'roxl', 'roxr',
}

_REG_NAMES = {
    'd0','d1','d2','d3','d4','d5','d6','d7',
    'a0','a1','a2','a3','a4','a5','a6','a7','sp','usp','ssp',
    'sr','ccr','pc',
}


def _is_reg_operand(s):
    s = s.strip().lower()
    if s in _REG_NAMES:
        return True
    # Ha zárójeleket tartalmaz, az memória-cím (pl. -(a7), (a0)+, $10(a5))
    if '(' in s or ')' in s:
        return False
    # Regiszter lista (MOVEM): D0-D7/A0-A6 stb.
    if '/' in s or ('-' in s and any(r in s for r in ('d','a'))):
        return True
    return False


def is_write_insn(insn):
    """True ha az utasítás memóriába ír (nem csak regiszterbe)."""
    mnem = insn.mnemonic.split('.')[0].lower()
    if mnem not in _WRITE_MNEMS:
        return False
    op = insn.op_str.strip()

    _ALWAYS_MEM = {'clr','neg','negx','not','tas','nbcd',
                   'bset','bclr','bchg',
                   'asl','asr','lsl','lsr','rol','ror','roxl','roxr'}
    if mnem in _ALWAYS_MEM or mnem.startswith('s'):
        return not _is_reg_operand(op)

    # Két-operandusú (MOVE, ADD, ...): cél a második operandus
    if ',' in op:
        dest = op.rsplit(',', 1)[1].strip()
        return not _is_reg_operand(dest) and not dest.startswith('#')

    return False


def get_write_dest(insn):
    """
    Visszaadja (kategória, info, annotáció) hármasát a write célcíméről.
    Kategóriák: 'ROM_WRITE', 'A5_REL', 'ABS_RAM', 'INDIRECT', 'STACK'
    """
    op = insn.op_str.strip()
    dest = op.rsplit(',', 1)[1].strip() if ',' in op else op.strip()
    dest_low = dest.lower()

    # Stack műveletek: -(A7) vagy -(SP)
    if dest_low in {'-(a7)', '-(sp)'}:
        return ('STACK', None, 'stack push')

    # A5-relatív: $XXXX(A5)
    if '(a5)' in dest_low:
        try:
            offset_str = dest_low.split('(')[0].lstrip('$').lstrip('-')
            sign = -1 if dest_low.startswith('-') else 1
            offset = sign * int(offset_str, 16)
            sym = A5_SYMBOLS.get(offset & 0xFFFF, '')
            ann = f'A5+0x{offset & 0xFFFF:04X}'
            if sym:
                ann += f' [{sym}]'
            return ('A5_REL', offset, ann)
        except (ValueError, IndexError):
            return ('A5_REL', None, dest)

    # Abszolút cím: $XXXX vagy $XXXXXXXX (zárójelek nélkül)
    if dest.startswith('$') and '(' not in dest:
        try:
            abs_addr = int(dest.lstrip('$').split('.')[0], 16)
            if abs_addr < ROM_SIZE:
                return ('ROM_WRITE', abs_addr, f'GYANÚS — ROM-ba ír! 0x{abs_addr:06X}')
            return ('ABS_RAM', abs_addr, f'0x{abs_addr:06X}')
        except ValueError:
            pass

    # Minden más: regiszter-indirekt
    return ('INDIRECT', None, dest)


# ─── Task 7: Lineáris sweep ───────────────────────────────────────────────────

def linear_sweep(rom, visited):
    """
    Bejárja a ROM összes, visited-ben még nem szereplő, páros cím-sorát.
    Visszaad: dict[addr → insn] az orphan kód régiókhoz.
    """
    orphans = {}
    addr = 0
    while addr < ROM_SIZE:
        if addr not in visited:
            insn = decode_one(rom, addr)
            if insn is not None:
                orphans[addr] = insn
                addr += insn.size
                continue
        addr += 2
    return orphans


# ─── Task 8: Hívási lánc visszakövetés ───────────────────────────────────────

def trace_callers(start_addr, call_graph, max_depth=20):
    """
    Visszakövet minden hívási láncot start_addr-tól a gyökerekig.
    Visszaad: list[list[int]] — minden lánc [gyök, ..., start_addr] alakú.
    """
    results = []

    def dfs(current, chain, depth):
        if depth > max_depth:
            results.append(['[MAX MÉLYSÉG]'] + chain)
            return
        callers = call_graph.get(current, set())
        if not callers:
            results.append(chain)
            return
        for caller in sorted(callers):
            if caller in chain:
                results.append(['[KÖRÖS HÍVÁS]'] + chain)
                continue
            dfs(caller, [caller] + chain, depth + 1)

    dfs(start_addr, [start_addr], 0)
    return results


# ─── Task 9: full_disasm.txt kimenet ─────────────────────────────────────────

def _fmt_insn(addr, insn, rom):
    """Formáz egyetlen utasítást + annotáció."""
    label = KNOWN_LABELS.get(addr, '')
    label_str = f'\n{label}:\n' if label else ''
    target = get_branch_target(rom, insn)
    ann = ''
    if target is not None:
        tgt_label = KNOWN_LABELS.get(target, '')
        ann = f' ; => 0x{target:06X}' + (f' [{tgt_label}]' if tgt_label else '')
    elif '(a5)' in insn.op_str.lower():
        for off, sym in A5_SYMBOLS.items():
            if f'${off:x}(a5)' in insn.op_str.lower() or f'${off:X}(a5)' in insn.op_str.lower():
                ann = f' ; [{sym}]'
                break
    raw = insn.bytes.hex()
    return f'{label_str}  {addr:06X}  {raw:<12}  {insn.mnemonic:<10} {insn.op_str:<32}{ann}'


def write_disasm_listing(rom, visited, orphans, vectors, out_path):
    """Kiírja a full_disasm.txt fájlt."""
    lines = []
    SEP = '=' * 78

    # --- SECTION: VECTORS ---
    lines.append(SEP)
    lines.append('SECTION: VECTORS (0x000000 – 0x0003FF)')
    lines.append(SEP)
    lines.append(f'  000000  initial_sp = 0x{struct.unpack_from(">L", rom, 0)[0]:08X}')
    for i in range(1, 256):
        vec = struct.unpack_from('>L', rom, i * 4)[0]
        if vec == 0:
            continue
        label = KNOWN_LABELS.get(vec, '')
        ann = f' [{label}]' if label else ''
        lines.append(f'  {i*4:06X}  vec[{i:3d}] -> 0x{vec:06X}{ann}')
    lines.append('')

    # --- SECTION: CODE (recursive descent) ---
    lines.append(SEP)
    lines.append('SECTION: CODE (recursive descent)')
    lines.append(SEP)
    for addr in sorted(visited.keys()):
        lines.append(_fmt_insn(addr, visited[addr], rom))
    lines.append('')

    # --- SECTION: ORPHAN CODE ---
    if orphans:
        lines.append(SEP)
        lines.append('SECTION: ORPHAN CODE (lineáris sweep — nem elérhető entry pontokból)')
        lines.append(SEP)
        prev = -999
        for addr in sorted(orphans.keys()):
            if addr - prev > 4:
                lines.append(f'\n[ORPHAN @ 0x{addr:06X}]')
            lines.append(_fmt_insn(addr, orphans[addr], rom))
            prev = addr + orphans[addr].size
    lines.append('')

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    print(f'full_disasm.txt -> {out_path}  ({len(visited)+len(orphans)} utasítás)')


# ─── Task 10: write_report.txt + main() ──────────────────────────────────────

def write_write_report(rom, visited, call_graph, cmd_seeds, out_path):
    """Kiírja a write_report.txt fájlt minden memóriaírással és hívási lánccal."""
    cmd_by_handler = {h: name for name, h in cmd_seeds}
    lines = []
    SEP = '=' * 78

    lines.append(SEP)
    lines.append('HP 3458A REV9 — MEMÓRIA-ÍRÁSOK TELJES LISTÁJA')
    lines.append(f'Generálva: {__import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M")}')
    lines.append(SEP)
    lines.append('')

    writes = []
    for addr, insn in sorted(visited.items()):
        if is_write_insn(insn):
            cat, info, ann = get_write_dest(insn)
            writes.append((cat, addr, insn, info, ann))

    order = {'ROM_WRITE': 0, 'A5_REL': 1, 'ABS_RAM': 2, 'STACK': 3, 'INDIRECT': 4}
    writes.sort(key=lambda x: (order.get(x[0], 99), x[1]))

    current_cat = None
    for cat, addr, insn, info, ann in writes:
        if cat != current_cat:
            lines.append('')
            lines.append(f'{"─"*78}')
            cat_titles = {
                'ROM_WRITE': '!!! ROM-BA ÍRÁS (GYANÚS) !!!',
                'A5_REL':    'A5-RELATÍV (munkamemória)',
                'ABS_RAM':   'ABSZOLÚT RAM / NVRAM / I/O',
                'STACK':     'VEREM MŰVELETEK (STACK)',
                'INDIRECT':  'INDIREKT (statikusan nem oldható fel)',
            }
            lines.append(f'KATEGÓRIA: {cat_titles.get(cat, cat)}')
            lines.append(f'{"─"*78}')
            current_cat = cat

        label = KNOWN_LABELS.get(addr, '')
        label_str = f' [{label}]' if label else ''
        raw = insn.bytes.hex()
        lines.append(f'\n  ÍRÁS @ 0x{addr:06X}{label_str}')
        lines.append(f'    Utasítás : {insn.mnemonic} {insn.op_str}  ({raw})')
        lines.append(f'    Cél      : {ann}')

        chains = trace_callers(addr, call_graph)
        lines.append(f'    Hívási lánc(ok):')
        for chain in chains[:5]:
            parts = []
            for c in chain:
                lbl = KNOWN_LABELS.get(c, '')
                cmd = cmd_by_handler.get(c, '')
                if isinstance(c, str):
                    parts.append(c)
                elif cmd:
                    parts.append(f'0x{c:06X} [GPIB:{cmd}]')
                elif lbl:
                    parts.append(f'0x{c:06X} [{lbl}]')
                else:
                    parts.append(f'0x{c:06X}')
            lines.append('      ' + ' → '.join(parts))
        if len(chains) > 5:
            lines.append(f'      ... és még {len(chains)-5} lánc')

    lines.append('')
    lines.append(SEP)
    lines.append(f'Összesen: {len(writes)} memóriaírás azonosítva ({len(visited)} utasítás lefedve)')
    lines.append(SEP)

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    print(f'write_report.txt -> {out_path}  ({len(writes)} írás)')


def main():
    print('HP 3458A REV9 — Teljes firmware elemzés indul...')
    rom = load_rom()
    print(f'ROM betöltve: {len(rom)} byte')

    vectors   = parse_vectors(rom)
    cmd_seeds = parse_cmd_seeds(rom)
    print(f'Vektorok: {len(vectors)} entry pont | Parancsok: {len(cmd_seeds)} handler')

    seeds = list(dict.fromkeys(vectors + [h for _, h in cmd_seeds]))
    print(f'Rekurzív descent indul ({len(seeds)} seed)...')
    visited, call_graph = recursive_descent(rom, seeds)
    print(f'Lefedett utasítások: {len(visited)}')

    print('Lineáris sweep (orphan régiók)...')
    orphans = linear_sweep(rom, visited)
    print(f'Orphan utasítások: {len(orphans)}')

    # 2026-06-16: korábban HP3458A_REV9_assembled_and_analysis\ alá írt —
    # az a mappa megszűnt az átrendezésnél. A script most research/python/-ban
    # van, a kimenetek a vele egy szinten lévő research/firmware_analysis/-ba.
    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'firmware_analysis')
    os.makedirs(out_dir, exist_ok=True)
    disasm_path = os.path.join(out_dir, 'full_disasm.txt')
    report_path = os.path.join(out_dir, 'write_report.txt')

    write_disasm_listing(rom, visited, orphans, vectors, disasm_path)
    write_write_report(rom, visited, call_graph, cmd_seeds, report_path)
    print('Kész.')


if __name__ == '__main__':
    main()
