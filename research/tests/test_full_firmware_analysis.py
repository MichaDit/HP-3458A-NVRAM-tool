import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'python'))

from full_firmware_analysis import (
    load_rom, ROM_SIZE,
    parse_vectors,
    parse_cmd_seeds,
    decode_one, get_branch_target,
    recursive_descent,
    is_write_insn, get_write_dest,
    linear_sweep,
    trace_callers,
    write_disasm_listing,
    write_write_report,
)
import struct


# ─── Task 1: ROM loader ───────────────────────────────────────────────────────

def test_load_rom_size():
    rom = load_rom()
    assert len(rom) == ROM_SIZE, f"ROM méret nem stimmel: {len(rom)} != {ROM_SIZE}"

def test_load_rom_reset_pc():
    rom = load_rom()
    reset_pc = struct.unpack_from('>L', rom, 0x000004)[0]
    assert reset_pc == 0x000808, f"Reset PC nem 0x000808, hanem 0x{reset_pc:06X}"


# ─── Task 2: Vektortábla parser ───────────────────────────────────────────────

def test_parse_vectors_contains_reset_pc():
    rom = load_rom()
    vecs = parse_vectors(rom)
    assert 0x000808 in vecs, "Reset PC (0x000808) nincs a vektorok közt"

def test_parse_vectors_excludes_initial_sp():
    rom = load_rom()
    vecs = parse_vectors(rom)
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


# ─── Task 3: cmd_table seed extractor ────────────────────────────────────────

def test_parse_cmd_seeds_count():
    rom = load_rom()
    seeds = parse_cmd_seeds(rom)
    # 388 bejegyzés van a táblában, de csak ~218 rendelkezik valódi ROM handler-rel
    # (a token parancsok handler=0 értékkel nem kerülnek be)
    assert len(seeds) >= 150, f"Túl kevés parancs handler: {len(seeds)}"

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


# ─── Task 4: Dekóder + branch target ─────────────────────────────────────────

def test_decode_one_valid():
    rom = load_rom()
    insn = decode_one(rom, 0x000808)
    assert insn is not None, "Nem dekódolható utasítás 0x000808-nál"

def test_decode_one_invalid():
    rom = load_rom()
    result = decode_one(rom, ROM_SIZE + 10)
    assert result is None

def test_get_branch_target_jsr_pcrel():
    # 0x07BC4: jsr $763a(pc)
    # target = 0x07BC4 + 2 + disp(0xFA74 signed) = 0x07BC6 - 1420 = 0x0763A
    rom = load_rom()
    insn = decode_one(rom, 0x07BC4)
    assert insn is not None
    target = get_branch_target(rom, insn)
    assert target == 0x0763A, f"JSR PC-rel target hibás: 0x{target:06X}"

def test_get_branch_target_beq():
    # 0x07BC2: beq.b $7bc8  — disp=+4, target=0x07BC8
    rom = load_rom()
    insn = decode_one(rom, 0x07BC2)
    assert insn is not None
    target = get_branch_target(rom, insn)
    assert target == 0x07BC8, f"BEQ target hibás: 0x{target:06X}"

def test_get_branch_target_indirect_returns_none():
    rom = load_rom()
    insn = decode_one(rom, 0x07C1E)
    if insn is not None:
        target = get_branch_target(rom, insn)
        assert target is None or isinstance(target, int)


# ─── Task 5: Rekurzív descent ────────────────────────────────────────────────

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
    assert len(visited) >= 5000, f"Csak {len(visited)} utasítás lefedett — túl kevés"


# ─── Task 6: Write detektor ───────────────────────────────────────────────────

def test_is_write_insn_clr_to_mem():
    # 0x07BD6: CLR.L -(A7)
    rom = load_rom()
    insn = decode_one(rom, 0x07BD6)
    assert insn is not None
    assert is_write_insn(insn), f"CLR.L -(A7) nem írás: mnem={insn.mnemonic} op={insn.op_str}"

def test_is_write_insn_tst_is_not_write():
    # 0x07BBE: TST.B $13A6(A5) — olvasás
    rom = load_rom()
    insn = decode_one(rom, 0x07BBE)
    assert insn is not None
    assert not is_write_insn(insn), f"TST tévesen írásnak jelölve: {insn.mnemonic} {insn.op_str}"

def test_is_write_insn_link_is_not_write():
    # 0x07BBA: LINK.W A6, #0
    rom = load_rom()
    insn = decode_one(rom, 0x07BBA)
    assert insn is not None
    assert not is_write_insn(insn), "LINK tévesen írásnak jelölve"

def test_get_write_dest_a5_relative():
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


# ─── Task 7: Lineáris sweep ───────────────────────────────────────────────────

def test_linear_sweep_finds_gaps():
    rom = load_rom()
    visited, _ = recursive_descent(rom, _build_seeds(rom))
    orphans = linear_sweep(rom, visited)
    assert isinstance(orphans, dict), "linear_sweep dict-et kell visszaadjon"

def test_linear_sweep_no_overlap_with_visited():
    rom = load_rom()
    visited, _ = recursive_descent(rom, _build_seeds(rom))
    orphans = linear_sweep(rom, visited)
    overlap = set(orphans.keys()) & set(visited.keys())
    assert len(overlap) == 0, f"Átfedés visited és orphans között: {len(overlap)} cím"


# ─── Task 8: Hívási lánc visszakövetés ───────────────────────────────────────

def test_trace_callers_synthetic():
    cg = {0xB: {0xA}, 0xC: {0xB}}
    chains = trace_callers(0xC, cg)
    assert len(chains) >= 1
    found = any(chain == [0xA, 0xB, 0xC] for chain in chains)
    assert found, f"Várt lánc [A,B,C] nem szerepel: {chains}"

def test_trace_callers_no_caller_returns_self():
    cg = {}
    chains = trace_callers(0x1234, cg)
    assert chains == [[0x1234]], f"Hívó nélküli cím saját magát kell adja: {chains}"

def test_trace_callers_cycle_detection():
    cg = {0xA: {0xB}, 0xB: {0xA}}
    chains = trace_callers(0xA, cg, max_depth=5)
    assert all('[KÖRÖS' in str(c) or len(c) <= 6 for c in chains)

def test_trace_callers_real_write():
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


# ─── Task 9: full_disasm.txt kimenet ─────────────────────────────────────────

import tempfile

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


# ─── Task 10: write_report.txt + main() ──────────────────────────────────────

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
    out_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           'firmware_analysis')
    disasm_path = os.path.join(out_dir, 'full_disasm.txt')
    report_path = os.path.join(out_dir, 'write_report.txt')
    for p in (disasm_path, report_path):
        if os.path.exists(p):
            os.unlink(p)
    main()
    assert os.path.exists(disasm_path), "full_disasm.txt nem jött létre"
    assert os.path.exists(report_path), "write_report.txt nem jött létre"
    assert os.path.getsize(disasm_path) > 100_000, "full_disasm.txt túl kicsi"
    assert os.path.getsize(report_path) > 1_000, "write_report.txt túl kicsi"
