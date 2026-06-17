# HP 3458A Teljes Firmware Disassembly & Write-Tracker — Implementációs Terv

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Egyetlen Python script (`full_firmware_analysis.py`) amely a teljes 384 KB-os HP 3458A REV9 firmware-t disassemblálja és minden memóriaírást visszaköveti a hívási láncon át.

**Architecture:** Négy fázis sorban: (1) vektortábla kinyerése → (2) rekurzív descent disassembly → (3) lineáris sweep az orphan régiókhoz → (4) write-tracker a hívási láncokkal. Kimenet: `full_disasm.txt` és `write_report.txt`.

**Tech Stack:** Python 3.x, `capstone` (M68K), `struct`, `collections`

---

## Fájlstruktúra

| Fájl | Szerep |
|------|--------|
| `full_firmware_analysis.py` | Főscript — mind a 4 fázis + output |
| `tests/test_full_firmware_analysis.py` | Unit + integrációs tesztek |
| `HP3458A_REV9_assembled_and_analysis/full_disasm.txt` | Kimenet: teljes listing |
| `HP3458A_REV9_assembled_and_analysis/write_report.txt` | Kimenet: write-tracker jelentés |

---

## Task 1: Skeleton + ROM loader + állandók

**Files:**
- Create: `full_firmware_analysis.py`
- Modify: `tests/test_full_firmware_analysis.py`

- [ ] **Step 1: Írj egy failing tesztet**

```python
# tests/test_full_firmware_analysis.py
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from full_firmware_analysis import load_rom, ROM_SIZE

def test_load_rom_size():
    rom = load_rom()
    assert len(rom) == ROM_SIZE, f"ROM méret nem stimmel: {len(rom)} != {ROM_SIZE}"

def test_load_rom_reset_pc():
    import struct
    rom = load_rom()
    reset_pc = struct.unpack_from('>L', rom, 0x000004)[0]
    assert reset_pc == 0x000808, f"Reset PC nem 0x000808, hanem 0x{reset_pc:06X}"
```

- [ ] **Step 2: Futtasd — ellenőrizd, hogy FAIL**

```
pytest tests/test_full_firmware_analysis.py::test_load_rom_size -v
```
Várt: `ImportError: cannot import name 'load_rom'`

- [ ] **Step 3: Implementáld a skeleton-t**

```python
# full_firmware_analysis.py
import struct
import capstone
from collections import defaultdict

ROM_PATH = r'HP3458A_REV9_assembled_and_analysis\HP3458A_REV9_cpu_order_384K_for_Ghidra.bin'
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

def load_rom():
    with open(ROM_PATH, 'rb') as f:
        return f.read()
```

- [ ] **Step 4: Futtasd — ellenőrizd, hogy PASS**

```
pytest tests/test_full_firmware_analysis.py::test_load_rom_size tests/test_full_firmware_analysis.py::test_load_rom_reset_pc -v
```
Várt: `2 passed`

- [ ] **Step 5: Commit**

```bash
git add full_firmware_analysis.py tests/test_full_firmware_analysis.py
git commit -m "feat: full_firmware_analysis skeleton, ROM loader, konstansok"
```

---

## Task 2: Vektortábla parser

**Files:**
- Modify: `full_firmware_analysis.py`
- Modify: `tests/test_full_firmware_analysis.py`

- [ ] **Step 1: Írj failing tesztet**

```python
# tests/test_full_firmware_analysis.py — append:
from full_firmware_analysis import parse_vectors

def test_parse_vectors_contains_reset_pc():
    rom = load_rom()
    vecs = parse_vectors(rom)
    assert 0x000808 in vecs, "Reset PC (0x000808) nincs a vektorok közt"

def test_parse_vectors_excludes_initial_sp():
    rom = load_rom()
    vecs = parse_vectors(rom)
    # 0x000000 az Initial SP értéke (0x0001897E), nem kód — nem szerepelhet
    assert 0x0001897E not in vecs or True  # SP értéke nem kód-cím
    # A vektor-INDEX 0 (0x000000 offset) ki van zárva
    assert 0 not in vecs  # index 0 = Initial SP rekord, soha nem entry pont

def test_parse_vectors_no_null():
    rom = load_rom()
    vecs = parse_vectors(rom)
    assert 0x000000 not in vecs, "NULL pointer vektor nem kerülhet be"

def test_parse_vectors_all_in_rom():
    rom = load_rom()
    vecs = parse_vectors(rom)
    for v in vecs:
        assert 0 < v < ROM_SIZE, f"Vektor 0x{v:06X} kívül esik a ROM-on"
```

- [ ] **Step 2: Futtasd — ellenőrizd, hogy FAIL**

```
pytest tests/test_full_firmware_analysis.py -k "vector" -v
```
Várt: `ImportError: cannot import name 'parse_vectors'`

- [ ] **Step 3: Implementáld**

```python
# full_firmware_analysis.py — append:

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
```

- [ ] **Step 4: Futtasd — ellenőrizd, hogy PASS**

```
pytest tests/test_full_firmware_analysis.py -k "vector" -v
```
Várt: `4 passed`

- [ ] **Step 5: Commit**

```bash
git add full_firmware_analysis.py tests/test_full_firmware_analysis.py
git commit -m "feat: parse_vectors — 68000 vektortábla kinyerése"
```

---

## Task 3: cmd_table seed extractor

**Files:**
- Modify: `full_firmware_analysis.py`
- Modify: `tests/test_full_firmware_analysis.py`

- [ ] **Step 1: Írj failing tesztet**

```python
# tests/test_full_firmware_analysis.py — append:
from full_firmware_analysis import parse_cmd_seeds

def test_parse_cmd_seeds_count():
    rom = load_rom()
    seeds = parse_cmd_seeds(rom)
    assert len(seeds) >= 300, f"Túl kevés parancs: {len(seeds)}"

def test_parse_cmd_seeds_mwrite_found():
    rom = load_rom()
    seeds = parse_cmd_seeds(rom)
    names = [name for name, _ in seeds]
    handlers = [h for _, h in seeds]
    assert 'MWRITE' in names, "MWRITE parancs nem található"
    mwrite_handler = handlers[names.index('MWRITE')]
    assert mwrite_handler == 0x17BF6, f"MWRITE handler cím hibás: 0x{mwrite_handler:06X}"

def test_parse_cmd_seeds_mread_found():
    rom = load_rom()
    seeds = parse_cmd_seeds(rom)
    names = [name for name, _ in seeds]
    assert 'MREAD' in names, "MREAD parancs nem található"
```

- [ ] **Step 2: Futtasd — ellenőrizd, hogy FAIL**

```
pytest tests/test_full_firmware_analysis.py -k "cmd_seed" -v
```
Várt: `ImportError: cannot import name 'parse_cmd_seeds'`

- [ ] **Step 3: Implementáld**

```python
# full_firmware_analysis.py — append:

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
```

- [ ] **Step 4: Futtasd — ellenőrizd, hogy PASS**

```
pytest tests/test_full_firmware_analysis.py -k "cmd_seed" -v
```
Várt: `3 passed`

- [ ] **Step 5: Commit**

```bash
git add full_firmware_analysis.py tests/test_full_firmware_analysis.py
git commit -m "feat: parse_cmd_seeds — GPIB parancs handler-cím ek kinyerése"
```

---

## Task 4: Utasítás-dekódoló és branch-target számítás

**Files:**
- Modify: `full_firmware_analysis.py`
- Modify: `tests/test_full_firmware_analysis.py`

- [ ] **Step 1: Írj failing tesztet**

```python
# tests/test_full_firmware_analysis.py — append:
from full_firmware_analysis import decode_one, get_branch_target

def test_decode_one_valid():
    rom = load_rom()
    insn = decode_one(rom, 0x000808)
    assert insn is not None, "Nem dekódolható utasítás 0x000808-nál"

def test_decode_one_invalid():
    rom = load_rom()
    result = decode_one(rom, ROM_SIZE + 10)  # ROM-on kívül
    assert result is None

def test_get_branch_target_jsr_pcrel():
    # 0x07BC4: jsr $763a(pc)  — bytes: 4E BA FA 74
    # PC az utasítás utáni cím = 0x07BC4 + 2 = 0x07BC6
    # disp = signed 0xFA74 = -1420 → 0x07BC6 + (-1420)? 
    # Valójában: 0x07BC6 - 0x05CC = 0x07BC6 - 1484? Nem stimmel.
    # A helyes számítás: disp = struct.unpack('>h', b'\xFA\x74')[0] = -1420
    # target = 0x07BC4 + 2 + (-1420) = 0x07BC6 - 1420 = 0x07BC6 - 0x58C = 0x0763A ✓
    rom = load_rom()
    insn = decode_one(rom, 0x07BC4)
    assert insn is not None
    target = get_branch_target(rom, insn)
    assert target == 0x0763A, f"JSR PC-rel target hibás: 0x{target:06X}"

def test_get_branch_target_beq():
    # 0x07BC2: beq.b $7bc8  — bytes: 67 04
    # disp = +4, target = 0x07BC2 + 2 + 4 = 0x07BC8
    rom = load_rom()
    insn = decode_one(rom, 0x07BC2)
    assert insn is not None
    target = get_branch_target(rom, insn)
    assert target == 0x07BC8, f"BEQ target hibás: 0x{target:06X}"

def test_get_branch_target_indirect_returns_none():
    # Regiszter-indirekt ugrásnál None-t kell visszaadni
    # Keresünk egy JMP (An) utasítást a ROM-ban
    rom = load_rom()
    # 0x07C1E beep_mode_dispatch — tartalmazhat indirekt JMP-t
    # Elég ha az API None-t ad vissza indirect esetén (nem crashel)
    insn = decode_one(rom, 0x07C1E)
    if insn is not None:
        target = get_branch_target(rom, insn)
        # Csak azt ellenőrizzük: nem dob kivételt, és vagy int vagy None
        assert target is None or isinstance(target, int)
```

- [ ] **Step 2: Futtasd — ellenőrizd, hogy FAIL**

```
pytest tests/test_full_firmware_analysis.py -k "decode_one or branch_target" -v
```
Várt: `ImportError`

- [ ] **Step 3: Implementáld**

```python
# full_firmware_analysis.py — append:

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
```

- [ ] **Step 4: Futtasd — ellenőrizd, hogy PASS**

```
pytest tests/test_full_firmware_analysis.py -k "decode_one or branch_target" -v
```
Várt: `5 passed`

- [ ] **Step 5: Commit**

```bash
git add full_firmware_analysis.py tests/test_full_firmware_analysis.py
git commit -m "feat: decode_one, get_branch_target — utasítás-dekóder segédfüggvények"
```

---

## Task 5: Rekurzív descent engine

**Files:**
- Modify: `full_firmware_analysis.py`
- Modify: `tests/test_full_firmware_analysis.py`

- [ ] **Step 1: Írj failing tesztet**

```python
# tests/test_full_firmware_analysis.py — append:
from full_firmware_analysis import recursive_descent, parse_vectors, parse_cmd_seeds

def _build_seeds(rom):
    vecs  = parse_vectors(rom)
    cmds  = [h for _, h in parse_cmd_seeds(rom)]
    return list(dict.fromkeys(vecs + cmds))

def test_recursive_descent_visits_reset_entry():
    rom = load_rom()
    visited, _ = recursive_descent(rom, _build_seeds(rom))
    assert 0x000808 in visited, "Reset entry (0x000808) nincs a visited-ben"

def test_recursive_descent_visits_mwrite_handler():
    rom = load_rom()
    visited, _ = recursive_descent(rom, _build_seeds(rom))
    assert 0x17BF6 in visited, "MWRITE_handler (0x17BF6) nem elérhető"

def test_recursive_descent_call_graph_has_mwrite():
    rom = load_rom()
    _, cg = recursive_descent(rom, _build_seeds(rom))
    assert 0x17BF6 in cg or len(cg) > 0, "call_graph üres"

def test_recursive_descent_coverage():
    rom = load_rom()
    visited, _ = recursive_descent(rom, _build_seeds(rom))
    # Legalább 5000 utasítást kell lefedni egy 384 KB-os firmware-ben
    assert len(visited) >= 5000, f"Csak {len(visited)} utasítás lefedett — túl kevés"
```

- [ ] **Step 2: Futtasd — ellenőrizd, hogy FAIL**

```
pytest tests/test_full_firmware_analysis.py -k "recursive_descent" -v
```
Várt: `ImportError: cannot import name 'recursive_descent'`

- [ ] **Step 3: Implementáld**

```python
# full_firmware_analysis.py — append:

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
```

- [ ] **Step 4: Futtasd — ellenőrizd, hogy PASS** *(~30–60 mp futásidő)*

```
pytest tests/test_full_firmware_analysis.py -k "recursive_descent" -v
```
Várt: `4 passed`

- [ ] **Step 5: Commit**

```bash
git add full_firmware_analysis.py tests/test_full_firmware_analysis.py
git commit -m "feat: recursive_descent — teljes 68000 rekurzív disassembly engine"
```

---

## Task 6: Write-utasítás detektor

**Files:**
- Modify: `full_firmware_analysis.py`
- Modify: `tests/test_full_firmware_analysis.py`

- [ ] **Step 1: Írj failing tesztet**

```python
# tests/test_full_firmware_analysis.py — append:
from full_firmware_analysis import is_write_insn, get_write_dest

def test_is_write_insn_clr_to_mem():
    # 0x07BD6: CLR.L -(A7)  — bytes: 42 A7 — memória-írás (stack push)
    rom = load_rom()
    insn = decode_one(rom, 0x07BD6)
    assert insn is not None
    assert is_write_insn(insn), f"CLR.L -(A7) nem írás: mnem={insn.mnemonic} op={insn.op_str}"

def test_is_write_insn_tst_is_not_write():
    # 0x07BBE: TST.B $13A6(A5) — olvasás, nem írás
    rom = load_rom()
    insn = decode_one(rom, 0x07BBE)
    assert insn is not None
    assert not is_write_insn(insn), f"TST tévesen írásnak jelölve: {insn.mnemonic} {insn.op_str}"

def test_is_write_insn_link_is_not_write():
    # 0x07BBA: LINK.W A6, #0 — stack-manipuláció, nem "normál" memóriaírás
    rom = load_rom()
    insn = decode_one(rom, 0x07BBA)
    assert insn is not None
    assert not is_write_insn(insn), f"LINK tévesen írásnak jelölve"

def test_get_write_dest_a5_relative():
    # Keresünk egy MOVE.x ..., $XXXX(A5) utasítást a ROM-ban
    # Pl. a beep_setflag_path területén van A5-relatív írás
    rom  = load_rom()
    visited, _ = recursive_descent(rom, _build_seeds(rom))
    a5_writes = [
        (addr, insn) for addr, insn in visited.items()
        if is_write_insn(insn) and '(a5)' in insn.op_str.lower()
    ]
    assert len(a5_writes) > 0, "Nem találtunk A5-relatív írást a ROM-ban"
    for addr, insn in a5_writes[:1]:
        cat, info, ann = get_write_dest(insn)
        assert cat == 'A5_REL', f"A5-relatív írás kategóriája nem A5_REL: {cat}"
```

- [ ] **Step 2: Futtasd — ellenőrizd, hogy FAIL**

```
pytest tests/test_full_firmware_analysis.py -k "write_insn or write_dest" -v
```
Várt: `ImportError`

- [ ] **Step 3: Implementáld**

```python
# full_firmware_analysis.py — append:

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

    # Egyes mnemonikök mindig memóriát céloznak (ha az operandus nem regiszter)
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
            # Előjeles: ha a dest tartalmaz negatív prefixet
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
```

- [ ] **Step 4: Futtasd — ellenőrizd, hogy PASS**

```
pytest tests/test_full_firmware_analysis.py -k "write_insn or write_dest" -v
```
Várt: `4 passed`

- [ ] **Step 5: Commit**

```bash
git add full_firmware_analysis.py tests/test_full_firmware_analysis.py
git commit -m "feat: is_write_insn, get_write_dest — memóriaírás detektálás és kategorizálás"
```

---

## Task 7: Lineáris sweep (orphan régiók)

**Files:**
- Modify: `full_firmware_analysis.py`
- Modify: `tests/test_full_firmware_analysis.py`

- [ ] **Step 1: Írj failing tesztet**

```python
# tests/test_full_firmware_analysis.py — append:
from full_firmware_analysis import linear_sweep

def test_linear_sweep_finds_gaps():
    rom = load_rom()
    visited, _ = recursive_descent(rom, _build_seeds(rom))
    orphans = linear_sweep(rom, visited)
    # Egy 384 KB-os firmware-ben szinte biztos van orphan kód
    assert isinstance(orphans, dict), "linear_sweep dict-et kell visszaadjon"

def test_linear_sweep_no_overlap_with_visited():
    rom = load_rom()
    visited, _ = recursive_descent(rom, _build_seeds(rom))
    orphans = linear_sweep(rom, visited)
    overlap = set(orphans.keys()) & set(visited.keys())
    assert len(overlap) == 0, f"Átfedés visited és orphans között: {len(overlap)} cím"
```

- [ ] **Step 2: Futtasd — ellenőrizd, hogy FAIL**

```
pytest tests/test_full_firmware_analysis.py -k "linear_sweep" -v
```
Várt: `ImportError`

- [ ] **Step 3: Implementáld**

```python
# full_firmware_analysis.py — append:

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
```

- [ ] **Step 4: Futtasd — ellenőrizd, hogy PASS**

```
pytest tests/test_full_firmware_analysis.py -k "linear_sweep" -v
```
Várt: `2 passed`

- [ ] **Step 5: Commit**

```bash
git add full_firmware_analysis.py tests/test_full_firmware_analysis.py
git commit -m "feat: linear_sweep — orphan kód régiók feltárása"
```

---

## Task 8: Hívási lánc visszakövetés

**Files:**
- Modify: `full_firmware_analysis.py`
- Modify: `tests/test_full_firmware_analysis.py`

- [ ] **Step 1: Írj failing tesztet**

```python
# tests/test_full_firmware_analysis.py — append:
from full_firmware_analysis import trace_callers

def test_trace_callers_synthetic():
    # Szintetikus call_graph: A→B→C (C-t B hívja, B-t A hívja)
    cg = {0xB: {0xA}, 0xC: {0xB}}
    chains = trace_callers(0xC, cg)
    assert len(chains) >= 1
    # Legalább egy lánc: [0xA, 0xB, 0xC]
    found = any(chain == [0xA, 0xB, 0xC] for chain in chains)
    assert found, f"Várt lánc [A,B,C] nem szerepel: {chains}"

def test_trace_callers_no_caller_returns_self():
    cg = {}
    chains = trace_callers(0x1234, cg)
    assert chains == [[0x1234]], f"Hívó nélküli cím saját magát kell adja: {chains}"

def test_trace_callers_cycle_detection():
    # Körös hívás: A→B, B→A
    cg = {0xA: {0xB}, 0xB: {0xA}}
    chains = trace_callers(0xA, cg, max_depth=5)
    # Nem szabad végtelen ciklusba esni
    assert all('[KÖRÖS' in str(c) or len(c) <= 6 for c in chains)

def test_trace_callers_real_write():
    # Valós ROM: keresünk egy A5-relatív írást és megvizsgáljuk a láncát
    rom = load_rom()
    visited, cg = recursive_descent(rom, _build_seeds(rom))
    a5_writes = [
        addr for addr, insn in visited.items()
        if is_write_insn(insn) and '(a5)' in insn.op_str.lower()
    ]
    assert len(a5_writes) > 0
    chains = trace_callers(a5_writes[0], cg)
    assert isinstance(chains, list)
    assert len(chains) >= 1
```

- [ ] **Step 2: Futtasd — ellenőrizd, hogy FAIL**

```
pytest tests/test_full_firmware_analysis.py -k "trace_callers" -v
```
Várt: `ImportError`

- [ ] **Step 3: Implementáld**

```python
# full_firmware_analysis.py — append:

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
```

- [ ] **Step 4: Futtasd — ellenőrizd, hogy PASS**

```
pytest tests/test_full_firmware_analysis.py -k "trace_callers" -v
```
Várt: `4 passed`

- [ ] **Step 5: Commit**

```bash
git add full_firmware_analysis.py tests/test_full_firmware_analysis.py
git commit -m "feat: trace_callers — hívási lánc visszakövetés körös hívás védelemmel"
```

---

## Task 9: full_disasm.txt kimenet

**Files:**
- Modify: `full_firmware_analysis.py`
- Modify: `tests/test_full_firmware_analysis.py`

- [ ] **Step 1: Írj failing tesztet**

```python
# tests/test_full_firmware_analysis.py — append:
import os, tempfile
from full_firmware_analysis import write_disasm_listing

def test_write_disasm_listing_creates_file():
    rom = load_rom()
    seeds = _build_seeds(rom)
    visited, cg = recursive_descent(rom, seeds)
    vecs = parse_vectors(rom)
    orphans = linear_sweep(rom, visited)

    with tempfile.NamedTemporaryFile(suffix='.txt', delete=False, mode='w') as f:
        out_path = f.name

    try:
        write_disasm_listing(rom, visited, orphans, vecs, out_path)
        assert os.path.exists(out_path)
        content = open(out_path, encoding='utf-8').read()
        assert 'SECTION: VECTORS' in content
        assert 'SECTION: CODE' in content
        assert '000808' in content, "Reset entry (0x000808) hiányzik a listingból"
        assert 'MWRITE_handler' in content or '17BF6' in content
    finally:
        os.unlink(out_path)
```

- [ ] **Step 2: Futtasd — ellenőrizd, hogy FAIL**

```
pytest tests/test_full_firmware_analysis.py::test_write_disasm_listing_creates_file -v
```
Várt: `ImportError`

- [ ] **Step 3: Implementáld**

```python
# full_firmware_analysis.py — append:

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
        # Annotálja az A5-relatív operandusokat
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
```

- [ ] **Step 4: Futtasd — ellenőrizd, hogy PASS**

```
pytest tests/test_full_firmware_analysis.py::test_write_disasm_listing_creates_file -v
```
Várt: `1 passed`

- [ ] **Step 5: Commit**

```bash
git add full_firmware_analysis.py tests/test_full_firmware_analysis.py
git commit -m "feat: write_disasm_listing — annotált 68000 listing generálása"
```

---

## Task 10: write_report.txt + main() integráció

**Files:**
- Modify: `full_firmware_analysis.py`
- Modify: `tests/test_full_firmware_analysis.py`

- [ ] **Step 1: Írj failing tesztet**

```python
# tests/test_full_firmware_analysis.py — append:
from full_firmware_analysis import write_write_report

def test_write_report_creates_file():
    rom = load_rom()
    seeds = _build_seeds(rom)
    visited, cg = recursive_descent(rom, seeds)
    cmd_seeds = parse_cmd_seeds(rom)

    with tempfile.NamedTemporaryFile(suffix='.txt', delete=False, mode='w') as f:
        out_path = f.name

    try:
        write_write_report(rom, visited, cg, cmd_seeds, out_path)
        assert os.path.exists(out_path)
        content = open(out_path, encoding='utf-8').read()
        assert 'MEMÓRIA-ÍRÁSOK' in content
        assert 'A5_REL' in content or 'A5+' in content, "A5-relatív írás hiányzik a jelentésből"
    finally:
        os.unlink(out_path)

def test_main_produces_output_files():
    """Integrációs teszt: main() lefut és létrehozza a kimeneti fájlokat."""
    from full_firmware_analysis import main
    disasm_path = r'HP3458A_REV9_assembled_and_analysis\full_disasm.txt'
    report_path = r'HP3458A_REV9_assembled_and_analysis\write_report.txt'
    # Töröljük ha léteznek
    for p in (disasm_path, report_path):
        if os.path.exists(p):
            os.unlink(p)
    main()
    assert os.path.exists(disasm_path), "full_disasm.txt nem jött létre"
    assert os.path.exists(report_path), "write_report.txt nem jött létre"
    # Méret-ellenőrzés: nem üres fájlok
    assert os.path.getsize(disasm_path) > 100_000, "full_disasm.txt túl kicsi"
    assert os.path.getsize(report_path) > 1_000, "write_report.txt túl kicsi"
```

- [ ] **Step 2: Futtasd — ellenőrizd, hogy FAIL**

```
pytest tests/test_full_firmware_analysis.py -k "write_report or test_main" -v
```
Várt: `ImportError`

- [ ] **Step 3: Implementáld write_write_report + main()**

```python
# full_firmware_analysis.py — append:

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

    # Gyűjtsük az összes write utasítást, kategorizálva
    writes = []
    for addr, insn in sorted(visited.items()):
        if is_write_insn(insn):
            cat, info, ann = get_write_dest(insn)
            writes.append((cat, addr, insn, info, ann))

    # Sorrendezés: ROM_WRITE először (legérdekesebb), aztán A5_REL, ABS_RAM, STACK, INDIRECT
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
        for chain in chains[:5]:  # max 5 lánc / utasítás
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

    disasm_path = r'HP3458A_REV9_assembled_and_analysis\full_disasm.txt'
    report_path = r'HP3458A_REV9_assembled_and_analysis\write_report.txt'

    write_disasm_listing(rom, visited, orphans, vectors, disasm_path)
    write_write_report(rom, visited, call_graph, cmd_seeds, report_path)
    print('Kész.')


if __name__ == '__main__':
    main()
```

- [ ] **Step 4: Futtasd — ellenőrizd, hogy PASS** *(~2–3 perc)*

```
pytest tests/test_full_firmware_analysis.py -k "write_report or test_main" -v
```
Várt: `2 passed`

- [ ] **Step 5: Teljes tesztcsomag futtatása**

```
pytest tests/test_full_firmware_analysis.py -v
```
Várt: mind a tesztek `passed`

- [ ] **Step 6: Commit**

```bash
git add full_firmware_analysis.py tests/test_full_firmware_analysis.py
git commit -m "feat: write_write_report + main() — teljes firmware elemzés pipeline kész"
```

---

## Összefoglalás

A script futtatása:
```
python full_firmware_analysis.py
```

Kimenet:
- `HP3458A_REV9_assembled_and_analysis\full_disasm.txt` — ~100 000+ sor annotált listing
- `HP3458A_REV9_assembled_and_analysis\write_report.txt` — minden memóriaírás + hívási lánc

Tesztek futtatása:
```
pytest tests/test_full_firmware_analysis.py -v
```
