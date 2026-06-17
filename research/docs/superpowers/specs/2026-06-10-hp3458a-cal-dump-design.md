# HP 3458A CAL RAM Dump Script — Design Spec
**Dátum:** 2026-06-10  
**Projekt:** HP3458A REV9 firmware visszafejtés  
**Státusz:** Jóváhagyva

---

## Összefoglalás

Egyetlen Python script (`hp3458a_cal_dump.py`) amely GPIB-en (pyvisa) keresztül
feltérképezi a HP 3458A multimeter RAM-ját, meghatározza az A5 globális
adatbázis-regiszter értékét, elvégez 3× verifikált memória-dumpot, és az
eredményt JSON + bináris + hexdump formátumban menti. Opcionálisan differenciális
elemzést is végez a CAL RAM határainak azonosításához.

---

## CLI

```
python hp3458a_cal_dump.py --mode b   # gyors, ajánlott (B mód)
python hp3458a_cal_dump.py --mode c   # teljes RAM-scan (C mód)
python hp3458a_cal_dump.py --mode b --no-diff   # differenciális elemzés kihagyása
```

---

## GPIB konfiguráció

- Erőforrás: `GPIB0::22::INSTR`
- Timeout: 5000 ms (normál MREAD), 30 000 ms (scan fázis)
- Minden MADDR + MREAD pár között: 50 ms késleltetés (stabilitás)
- A műszer IEEE 488.1 — `*IDN?`, `*RST`, `*OPC?` NEM működik; helyette `ID?`, `RESET`
- Terminálási karakter (`read_termination`) ki kell kapcsolni, csak EOI-ra támaszkodni

### Kötelező inicializáló szekvencia

```
PRESET NORM     ; ismert, távvezérlés-barát állapot
END ALWAYS      ; EOI minden válasz végén — e nélkül MREAD timeout!
TARM HOLD       ; mérési trigger felfüggesztése — ADC ne írjon RAM-ba dump közben
INBUF ON        ; parancspuffer: busz hamarabb felszabadul
DISP 2          ; teljes kijelző-blank (DISP OFF csak csíkot hagy — firmware igazolja)
ERRSTR?         ; hibasor kiürítése (ismételd, amíg 0)
```

### Hibamentés

Ha a busz beragad: GPIB Device Clear (SDC) küldése — kiüríti a puffereket
a beállítások elrontása nélkül (`inst.clear()` pyvisa-ban).

---

## Fázis 1 — A5 detekció

### Gyors hipotézis-ellenőrzés (mindkét módban első lépés)

Feltételezés: `A5 = 0x120000` (az ismert pSOS abszolút cím `0x120C6E = A5+0x0C6E` alapján).

Protokoll:
1. `BEEP 1` → `MADDR 0x1213A6` → `MREAD` → értéknek ≠ 0-nak kell lennie
2. `BEEP 0` → `MREAD` (ugyanaz a cím) → értéknek 0-nak kell lennie
3. Ha mindkét feltétel teljesül: **A5 = 0x120000 megerősítve**, scan kihagyva
4. Keresztellenőrzés: `BEEP 1` → `MADDR 0x121DB5` (`A5+0x1DB5 = beep_mode_copy`) → ≠ 0

### Koarse+fine scan (fallback, ha hipotézis nem stimmel)

Két lépéses, gyors scan:

**1. Koarse lépés (0x100 = 256 bájt lépésköz):**

| Mód | Tartomány | Lépés | Olvasás | Becsült idő |
|-----|-----------|-------|---------|-------------|
| B   | `0x11C000–0x126000` | `0x100` | ~160 | ~3 mp |
| C   | `0x100000–0x140000` | `0x100` | ~1024 | ~20 mp |

Algoritmus:
- `BEEP 0` → teljes tartomány koarse olvasása (baseline)
- `BEEP 1` → ugyanazok a koarse címek újra
- Amely cím `0 → ≠0` változott: ez az A5+0x13A6 régiója (±128 bájt)

**2. Fine lépés (0x2 lépésköz):**
- Az azonosított 256-bájtos ablak teljes pásztázása
- A `0 → ≠0` változás pontos cím e: `A5 + 0x13A6`
- `A5 = found_addr - 0x13A6`

**Hibakezelés:**
- Ha a scan után sem található egyező cím : `RuntimeError("A5 nem azonosítható")`
- Felhasználónak jelzi a tartomány kibővítésének lehetőségét (`--mode c`)

---

## Fázis 2 — Dump hatókör

Az A5 meghatározása után a következő tartományokat dumpoljuk:

| Régió | Tartomány | Méret | Cél |
|-------|-----------|-------|-----|
| Fő RAM (A5-relatív) | `A5+0x0000 .. A5+0x3000` | 12 KB | CAL konstansok, settings, flagek |
| Vektor terület | `0x000000 .. 0x000400` | 1 KB | 68000 reset/interrupt vektorok |
| MADDR regiszter | `0x0023F0 .. 0x0023F2` | 2 bájt | aktuális MADDR érték |

Teljes dump: ~3330 MREAD hívás, ~2-3 perc/dump (30 ms/olvasás becsléssel).
Megjegyzés: a MADDR parancs decimális számot vár; a script minden hex cím et automatikusan konvertál.

### 3× verifikáció

- 3 egymást követő dump ugyanarról a tartományról
- SHA-256 hash minden dumphoz (teljes bináris kimenet alapján)
- Ha mind 3 hash egyezik: ✅ konzisztens, folytatás
- Ha bármelyik eltér: ⚠️ figyelmeztetés + összes dump mentése + leállás
  - Lehetséges ok: belső ADC mérés folyamatban írja a RAM-ot

---

## Fázis 3 — Differenciális elemzés (opcionális)

Ha `--no-diff` nincs megadva:

1. Script megáll: `"Változtass egy front-panel értéket (pl. NPLC), majd nyomj ENTER-t..."`
2. 4. dump ugyanarról a tartományról
3. Byte-szintű diff: alap dump #1 vs. módosított dump #4
4. Megváltozott word-ök listája cím ekkel és előtte/utána értékekkel
5. Elmentve `diff.txt`-be

Ez azonosítja a settings/CAL/counter területek pontos cím tartományát.

---

## Fázis 4 — Kimenet

### Könyvtárstruktúra

```
dump_YYYYMMDD_HHMMSS/
  ├── summary.json        ← A5 érték, mód, hash-ek, konzisztencia, időbélyeg
  ├── dump_01.json        ← {hex_addr: signed_word_value, ...}
  ├── dump_01.bin         ← nyers bináris, word-onként big-endian
  ├── dump_01.hex         ← xxd-szerű hexdump szöveg
  ├── dump_02.json/bin/hex
  ├── dump_03.json/bin/hex
  └── diff.txt            ← differenciális elemzés (ha futott)
```

### JSON séma (dump_NN.json)

```json
{
  "metadata": {
    "timestamp": "2026-06-10T14:32:00",
    "a5_base": "0x120000",
    "mode": "b",
    "gpib": "GPIB0::22::INSTR",
    "sha256": "abc123..."
  },
  "regions": [
    {"name": "main_ram", "start": "0x120000", "end": "0x123000"},
    {"name": "vectors",  "start": "0x000000", "end": "0x000400"},
    {"name": "maddr_reg","start": "0x0023F0", "end": "0x0023F2"}
  ],
  "data": {
    "0x120000": 0,
    "0x120002": 1234,
    "...": "..."
  }
}
```

### Hexdump formátum

```
0x120000: 0000 04D2 FFFF 0001 0000 0000 A5B3 0000  ....J..........
0x120010: ...
```

---

## Függvénystruktúra

```
hp3458a_cal_dump.py
  ├── GpibSession (context manager)
  │     mread_word(addr) → int
  │     mwrite_word(addr, val)          # nem használt a dump scriptben
  │     set_maddr(addr)
  ├── detect_a5(session, mode) → int
  │     _fast_hypothesis_check(session) → int | None
  │     _coarse_fine_scan(session, start, end) → int
  ├── dump_region(session, regions) → dict[int, int]
  ├── verify_dumps(dumps: list[dict]) → bool
  ├── save_outputs(dump, outdir, index)
  │     _save_json(...)
  │     _save_binary(...)
  │     _save_hexdump(...)
  ├── run_differential(session, baseline, outdir)
  └── main() — CLI parsing + orchestration
```

---

## Biztonsági megszorítások

- A script kizárólag MREAD-et használ (csak olvasás)
- MWRITE, SECURE, CAL, JSR parancsok **nem szerepelnek** ebben a scriptben
- BEEP 0/1 csak az A5 detekció idejére módosul; dump előtt `BEEP 1` marad
- A dump befejezése után `BEEP 0` visszaállítás

---

## Függőségek

```
pyvisa >= 1.12
pyvisa-py  (vagy NI-VISA backend)
```
