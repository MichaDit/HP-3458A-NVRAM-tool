import json as json_mod
import os
import struct
import sys
from unittest.mock import MagicMock, patch

import pytest

# __file__-relatív, hogy ne csak egy adott cwd-ből futva találja meg a modult
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'python'))
from hp3458a_cal_dump import (
    GpibSession,
    auto_detect_regions,
    compute_hash,
    compute_regions,
    dump_regions,
    format_diff,
    main,
    parse_args,
    run_differential,
    save_binary,
    save_hexdump,
    save_json,
    save_summary,
    scan_is_active,
    verify_dumps,
)


# ── CLI tesztek ───────────────────────────────────────────────────────────────

def test_cli_default_no_fixed_regions():
    sys.argv = ['hp3458a_cal_dump.py']
    args = parse_args()
    assert args.fixed_regions is False
    assert args.diff is True


def test_cli_fixed_regions_flag():
    sys.argv = ['hp3458a_cal_dump.py', '--fixed-regions']
    args = parse_args()
    assert args.fixed_regions is True


def test_cli_no_diff_flag():
    sys.argv = ['hp3458a_cal_dump.py', '--no-diff']
    args = parse_args()
    assert args.diff is False


def test_cli_bridge_flag():
    sys.argv = ['hp3458a_cal_dump.py', '--bridge', '192.168.1.1:1234']
    args = parse_args()
    assert args.bridge == '192.168.1.1:1234'


# ── scan_is_active tesztek ────────────────────────────────────────────────────

def test_scan_is_active_rejects_dead_bus_b9b9():
    assert scan_is_active(-17991) is False  # 0xB9B9 = -17991


def test_scan_is_active_rejects_all_zeros():
    assert scan_is_active(0) is False


def test_scan_is_active_rejects_all_ones():
    assert scan_is_active(-1) is False  # 0xFFFF


def test_scan_is_active_accepts_cal_ram_word():
    assert scan_is_active(-7239) is True   # 0xE3B9: real cal data


def test_scan_is_active_accepts_mixed_bytes():
    assert scan_is_active(0x40B9 - 65536) is True  # hi=0x40, lo=0xB9


def test_scan_is_active_accepts_symmetric_non_noise():
    assert scan_is_active(0x4040) is True  # hi==lo but not a known noise value


# ── GpibSession tesztek ───────────────────────────────────────────────────────

def _make_mock_inst():
    mock_rm   = MagicMock()
    mock_inst = MagicMock()
    mock_rm.open_resource.return_value = mock_inst
    return mock_rm, mock_inst


def test_session_init_sends_required_commands():
    mock_rm, mock_inst = _make_mock_inst()
    with patch('pyvisa.ResourceManager', return_value=mock_rm):
        with GpibSession():
            pass
    written = [c.args[0] for c in mock_inst.write.call_args_list]
    for cmd in ('END ALWAYS', 'NPLC 0', 'NRDGS 1', 'TRIG HOLD', 'QFORMAT NUM'):
        assert cmd in written, f'Hiányzó init parancs: {cmd}'


def test_session_cleanup_restores_state():
    mock_rm, mock_inst = _make_mock_inst()
    with patch('pyvisa.ResourceManager', return_value=mock_rm):
        with GpibSession():
            pass
    written = [c.args[0] for c in mock_inst.write.call_args_list]
    for cmd in ('BEEP 0', 'TRIG AUTO', 'DISP 1'):
        assert cmd in written, f'Hiányzó cleanup parancs: {cmd}'


def test_mread_word_parses_signed_response():
    mock_rm, mock_inst = _make_mock_inst()
    mock_inst.query.side_effect = ['-1']
    with patch('pyvisa.ResourceManager', return_value=mock_rm):
        with patch('time.sleep'):
            with GpibSession() as s:
                result = s.mread_word(0x120000)
    assert result == -1


def test_mread_word_raises_on_invalid_response():
    mock_rm, mock_inst = _make_mock_inst()
    # 'abc' nem parseable, de nem null byte → azonnal ValueError → 'MREAD invalid response'
    mock_inst.query.side_effect = ['abc']
    with patch('pyvisa.ResourceManager', return_value=mock_rm):
        with patch('time.sleep'):
            with GpibSession() as s:
                with pytest.raises(RuntimeError, match='MREAD invalid'):
                    s.mread_word(0x120000)


def test_mread_word_retries_on_null_bytes():
    mock_rm, mock_inst = _make_mock_inst()
    # Első 2 kísérlet null byte-os, 3. helyes
    mock_inst.query.side_effect = ['\x00' * 10, '\x00' * 10, '42']
    with patch('pyvisa.ResourceManager', return_value=mock_rm):
        with patch('time.sleep'):
            with GpibSession() as s:
                result = s.mread_word(0x120000)
    assert result == 42


def test_mread_word_retries_on_err():
    mock_rm, mock_inst = _make_mock_inst()
    # Bridge ibrd timeout → 'ERR', majd helyes válasz
    mock_inst.query.side_effect = ['ERR', '99']
    with patch('pyvisa.ResourceManager', return_value=mock_rm):
        with patch('time.sleep'):
            with GpibSession() as s:
                result = s.mread_word(0x120000)
    assert result == 99


def test_mread_word_retries_on_timeout():
    mock_rm, mock_inst = _make_mock_inst()
    # Socket TimeoutError, majd helyes válasz
    mock_inst.query.side_effect = [TimeoutError('timed out'), '77']
    with patch('pyvisa.ResourceManager', return_value=mock_rm):
        with patch('time.sleep'):
            with GpibSession() as s:
                result = s.mread_word(0x120000)
    assert result == 77


# ── compute_regions tesztek ───────────────────────────────────────────────────

def test_compute_regions_returns_three_fixed_regions():
    regs = compute_regions()
    assert len(regs) == 3
    names = [r[0] for r in regs]
    assert 'cal_ram' in names
    assert 'settings_ram' in names
    assert 'vectors' in names


def test_compute_regions_cal_ram_at_correct_address():
    regs = compute_regions()
    cal = next(r for r in regs if r[0] == 'cal_ram')
    assert cal[1] == 0x060000
    assert cal[2] == 0x1000 // 2
    assert cal[3] == 8  # DS1220Y: 8-bit chip, EVEN bank


def test_compute_regions_vectors_at_zero():
    regs = compute_regions()
    vec = next(r for r in regs if r[0] == 'vectors')
    assert vec[1] == 0x000000


# ── dump_regions tesztek ──────────────────────────────────────────────────────

def test_dump_regions_addresses_word_step():
    session = MagicMock()
    session.mread_word.return_value = 42
    result = dump_regions(session, [('test', 0x1000, 3, 16)])
    assert set(result.keys()) == {0x1000, 0x1002, 0x1004}


def test_dump_regions_stores_mread_values():
    session = MagicMock()
    session.mread_word.side_effect = [10, -1, 32767]
    result = dump_regions(session, [('test', 0x1000, 3, 16)])
    assert result == {0x1000: 10, 0x1002: -1, 0x1004: 32767}


def test_dump_regions_multiple_regions():
    session = MagicMock()
    session.mread_word.return_value = 0
    result = dump_regions(session, [('a', 0x1000, 2, 16), ('b', 0x2000, 1, 16)])
    assert 0x1000 in result
    assert 0x2000 in result
    assert session.mread_word.call_count == 3


# ── auto_detect_regions tesztek ───────────────────────────────────────────────

def test_auto_detect_finds_known_region():
    session = MagicMock()

    def fake_mread(addr):
        # Csak a 0x60000-0x60FFE tartomány aktív
        if 0x60000 <= addr < 0x61000:
            return -7239  # 0xE3B9, aktív
        return -17991  # 0xB9B9, inaktív

    session.mread_word.side_effect = fake_mread
    regions = auto_detect_regions(session, max_addr=0x080000,
                                  coarse_step=0x2000, fine_step=0x200)
    names = [r[0] for r in regions]
    assert 'cal_ram' in names


def test_auto_detect_fallback_when_no_hits():
    session = MagicMock()
    session.mread_word.return_value = -17991   # minden inaktív
    regions = auto_detect_regions(session, max_addr=0x010000,
                                  coarse_step=0x2000, fine_step=0x200)
    # Fallback: compute_regions() eredménye
    assert len(regions) == 3


def test_auto_detect_skips_timeout_addresses():
    session = MagicMock()

    def fake_mread(addr):
        if addr == 0x40000:
            raise RuntimeError('timeout')
        return -17991  # inaktív egyébként

    session.mread_word.side_effect = fake_mread
    # Nem dob exception, simán fut
    regions = auto_detect_regions(session, max_addr=0x060000,
                                  coarse_step=0x2000, fine_step=0x200)
    assert isinstance(regions, list)


# ── hash / verify tesztek ─────────────────────────────────────────────────────

def test_compute_hash_is_deterministic():
    d = {0x1000: 1, 0x1002: -1, 0x1004: 32767}
    assert compute_hash(d) == compute_hash(d)


def test_compute_hash_differs_for_different_values():
    assert compute_hash({0x1000: 1}) != compute_hash({0x1000: 2})


def test_compute_hash_differs_for_different_addresses():
    assert compute_hash({0x1000: 1}) != compute_hash({0x1002: 1})


def test_verify_dumps_three_identical_passes():
    d = {0x1000: 1, 0x1002: 2}
    ok, hashes = verify_dumps([d, d.copy(), d.copy()])
    assert ok is True
    assert len(set(hashes)) == 1


def test_verify_dumps_one_differs_fails():
    d1 = {0x1000: 1, 0x1002: 2}
    d3 = {0x1000: 1, 0x1002: 99}
    ok, hashes = verify_dumps([d1, d1.copy(), d3])
    assert ok is False
    assert hashes[0] == hashes[1]
    assert hashes[0] != hashes[2]


# ── save_ tesztek ─────────────────────────────────────────────────────────────

def test_save_json_addresses_hex_keys(tmp_path):
    dump = {0x1000: 1, 0x1002: -1}
    p = tmp_path / 'dump.json'
    save_json(dump, {'meta': 'x'}, p)
    data = json_mod.loads(p.read_text())
    assert '0x00001000' in data['data']
    assert data['data']['0x00001002'] == -1


def test_save_binary_16bit_region_writes_full_words(tmp_path):
    dump = {0x1000: 0x0102, 0x1002: -1}
    regions = [('test16', 0x1000, 2, 16)]
    save_binary(dump, regions, tmp_path / 'dump')
    raw = (tmp_path / 'dump_test16.bin').read_bytes()
    assert raw[:2] == b'\x01\x02'
    assert raw[2:4] == b'\xff\xff'


def test_save_binary_8bit_region_writes_high_bytes_only(tmp_path):
    # 0xE3B9 → HIGH=0xE3 (adat), LOW=0xB9 (lebegő busz)
    dump = {0x60000: 0xE3B9 - 0x10000, 0x60002: 0x7FB9}  # signed: -7239, 32697
    regions = [('cal_ram', 0x60000, 2, 8)]
    save_binary(dump, regions, tmp_path / 'dump')
    raw = (tmp_path / 'dump_cal_ram.bin').read_bytes()
    assert len(raw) == 2          # csak HIGH byte-ok → 2 bájt, nem 4
    assert raw[0] == 0xE3
    assert raw[1] == 0x7F


def test_save_binary_creates_per_region_files(tmp_path):
    dump = {0x60000: 0x4AB9 - 0x10000, 0x1000: 0x1234}
    regions = [('cal_ram', 0x60000, 1, 8), ('test16', 0x1000, 1, 16)]
    save_binary(dump, regions, tmp_path / 'dump_01')
    assert (tmp_path / 'dump_01_cal_ram.bin').exists()
    assert (tmp_path / 'dump_01_test16.bin').exists()


def test_save_hexdump_contains_address_and_hex(tmp_path):
    dump = {0x1000 + i * 2: i for i in range(16)}
    p = tmp_path / 'dump.hex'
    save_hexdump(dump, p)
    text = p.read_text()
    assert '0x00001000:' in text
    assert '0x00001010:' in text


def test_save_summary_writes_valid_json(tmp_path):
    regs = [('cal_ram', 0x60000, 512, 8), ('vectors', 0, 256, 16)]
    save_summary(['aabbcc', 'aabbcc', 'aabbcc'], True, tmp_path, regs)
    s = json_mod.loads((tmp_path / 'summary.json').read_text())
    assert s['consistent'] is True
    assert len(s['hashes']) == 3
    assert any(r['name'] == 'cal_ram' for r in s['regions'])


# ── format_diff / run_differential tesztek ───────────────────────────────────

def test_format_diff_lists_changed_words():
    baseline = {0x1000: 10, 0x1002: 20, 0x1004: 30}
    modified = {0x1000: 10, 0x1002: 99, 0x1004: 30}
    diff = format_diff(baseline, modified)
    assert '0x00001002' in diff
    assert '0x00001000' not in diff
    assert '1 word' in diff


def test_format_diff_no_changes():
    d = {0x1000: 42}
    assert '0 word' in format_diff(d, d.copy())


def test_run_differential_writes_diff_file(tmp_path, monkeypatch):
    monkeypatch.setattr('builtins.input', lambda _: '')
    session = MagicMock()
    session.mread_word.return_value = 5
    run_differential(session, {0x1000: 1, 0x1002: 2}, tmp_path, [('test', 0x1000, 2, 16)])
    assert (tmp_path / 'diff.txt').exists()


def test_format_diff_ignores_extra_keys_in_modified():
    baseline = {0x1000: 10}
    modified = {0x1000: 20, 0x1002: 99}
    diff = format_diff(baseline, modified)
    assert '0x00001002' not in diff
    assert '0x00001000' in diff


# ── main() integráció ─────────────────────────────────────────────────────────

def test_main_fixed_regions_creates_output_directory(tmp_path, monkeypatch):
    sys.argv = ['hp3458a_cal_dump.py', '--fixed-regions', '--no-diff']
    monkeypatch.chdir(tmp_path)

    mock_rm   = MagicMock()
    mock_inst = MagicMock()
    mock_rm.open_resource.return_value = mock_inst
    mock_inst.query.return_value = '+0,"NO ERROR"'

    with patch('pyvisa.ResourceManager', return_value=mock_rm):
        with patch('time.sleep'):
            with patch('hp3458a_cal_dump.dump_regions',
                       return_value={0x60000: 0, 0x60002: 1}) as mock_dump:
                main()

    dirs = list(tmp_path.glob('dump_*'))
    assert len(dirs) == 1
    outdir = dirs[0]
    assert (outdir / 'dump_01.json').exists()
    assert (outdir / 'dump_01_cal_ram.bin').exists()   # per-régiós fájl
    assert (outdir / 'dump_01.hex').exists()
    assert (outdir / 'summary.json').exists()
    assert mock_dump.call_count == 3
