# Research

A visszafejtési/feltárási folyamat során írt scriptek és az általuk
generált bizonyítékok — ez mutatja meg lépésről lépésre, **hogyan** jutottunk
el a `program/`-ban található működő megoldásig.

## Almappák

| Mappa | Tartalom |
|---|---|
| `python/` | A feltáráshoz írt scriptek (GPIB parancs-feltárás, firmware disassembly, NMI/cal_ram írás kísérletek, diagnosztika) — lásd lent a kategóriák. |
| `firmware_analysis/` | A ROM disassembly elemzés szöveges kimenetei (`full_disasm.txt`, `write_report.txt`, parancs-feltérképezés). A bemenete az `external_sources/`-ben lévő nyers ROM, az összeállító/elemző script a `python/` mappában (`assemble_rev9.py`, `full_firmware_analysis.py`). |
| `dumps/` | Saját műszer-dumpok (cal_ram/settings_ram .bin fájlok, decoded .txt riportok) és a GUI futás-naplója (`hp3458a_tool.log`) — ezek bizonyítják, hogy az állítások valós hardware-en lettek tesztelve. |
| `screenshots/` | Hibaüzenetek / GUI állapotok képernyőképei a fejlesztés során. |
| `docs/` | Tervezési dokumentumok (specifikációk, implementációs tervek) a fejlesztés egyes szakaszaiból. |
| `tests/` | Pytest unit tesztek a `python/hp3458a_cal_dump.py` és `python/full_firmware_analysis.py` scriptekhez. Futtatás: `python -m pytest research/tests/` (bárhonnan). |

> Megjegyzés: ez a mappa még alakul (a felhasználó tovább szelektálja a
> tartalmát) — ez a README a 2026-06-16 állapotot írja le.

## `python/` scriptek kategóriái

- **GPIB parancs-feltárás**: `analyze_*.py`, `list_all_commands.py`, `trace_*.py`, `read_we_callback.py`
- **Firmware disassembly**: `disasm_*.py`, `find_*.py`, `full_firmware_analysis.py`, `assemble_rev9.py`
- **NMI/cal_ram írás kísérletek (a sikeres mechanizmushoz vezető lépések)**: `test_jsr*.py`, `test_calram*.py`, `hp3458a_mwrite_test.py`, `hp3458a_nvram_persist_test.py`, `hp3458a_secure_mwrite_test.py`
- **Egyéb diagnosztika**: `compare_ref.py`, `detail_check.py`, `diag_mread.py`, `scan_settings_for_cal_cache.py`, `hp3458a_cal_dump.py`, `hp3458a_settings_decoder.py`
