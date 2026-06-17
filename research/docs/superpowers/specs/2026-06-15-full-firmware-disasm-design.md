# HP 3458A REV9 — Teljes Firmware Disassembly & Write-Tracker

**Dátum:** 2026-06-15  
**Státusz:** Jóváhagyott  
**Cél:** A teljes 384 KB-os 68000 firmware disassembly-je + minden memóriaírás visszakövetése a hívási láncon át

---

## Összefoglalás

Egyetlen Python script (`full_firmware_analysis.py`) négy fázisban dolgozza fel a
`HP3458A_REV9_cpu_order_384K_for_Ghidra.bin` binárist. Kimenet: `full_disasm.txt`
(annotált listing) és `write_report.txt` (write-tracker jelentés).

---

## Architektúra

```
HP3458A_REV9_cpu_order_384K_for_Ghidra.bin  (input, 384 KB, base 0x000000)
            │
    ┌───────▼────────┐
    │  VectorTable   │  256 × 4 byte long, 0x000000–0x0003FF
    └───────┬────────┘
            │ entry pont lista
    ┌───────▼────────┐
    │ RecursiveDes-  │  visited: dict[addr → Instruction]
    │ cender         │  call_graph: dict[addr → set(callerek)]
    └───────┬────────┘
            │ lefedett címek halmaza
    ┌───────▼────────┐
    │ LinearSweep    │  orphan régiók + adat régiók
    │ (kiegészítő)   │
    └───────┬────────┘
            │ teljes utasítás-készlet
    ┌───────▼────────┐
    │  WriteTracker  │  write utasítások + hívási lánc visszakövetés
    └───────┬────────┘
            │
    full_disasm.txt      write_report.txt
```

---

## Firmware alapadatok

| Adat | Érték |
|------|-------|
| CPU | MC68HC000PB (Motorola 68000, big-endian) |
| Binary | `HP3458A_REV9_cpu_order_384K_for_Ghidra.bin` |
| Méret | 393 216 byte (384 KB) |
| Base cím | 0x000000 |
| Reset SP | 0x0001897E |
| Reset PC | 0x000808 |
| Aktív tartalom | 3 × 128 KB = 384 KB (bank0+1+2) |

---

## Fázis 1 — Vektortábla kinyerése

A 68000 vektortábla `0x000000`-tól, 256 × 4 byte long pointer.

**Kizárások:**
- `0x000000` (Initial SP — nem kód)
- NULL pointerek (0x000000 értékű vektorok)
- ROM-tartományon kívüli pointerek

**Különösen fontos vektorok:**
- `0x000004` Reset PC → 0x000808
- `0x000008` Bus Error ISR
- `0x00000C` Address Error ISR
- `0x000080` TRAP#0 — pSOS rendszerhívás
- `0x0000BC` TRAP#15 — LEVEL7 NMI / cal RAM write kapu

**Parancs-dispatch tábla seed-ek:**  
`cmd_table_start = 0x08B20` — az összes GPIB parancs handler-cím kinyerése
és hozzáadása az entry pont listához.

---

## Fázis 2 — Rekurzív descent disassembly

### Algoritmus

```
queue = [összes vektor-cím] + [cmd_table handler-címek]
visited = {}          # addr → Instruction
call_graph = {}       # addr → set(caller_addr-ek)

while queue:
    addr = queue.pop()
    if addr in visited or addr kívül esik a ROM-on: skip

    insn = capstone.disasm(data[addr:addr+10], addr)
    if nem dekódolható: jelöld DATA-nak, skip
    visited[addr] = insn
    következő = addr + insn.size

    match insn.mnemonic:
        BRA / JMP (abszolút):
            queue.add(target)
            # ág lezárul, NE add hozzá következő-t

        BSR / JSR (PC-relatív vagy abszolút):
            call_graph[target].add(addr)
            queue.add(target)
            queue.add(következő)   # visszatérés után folytatódik

        BEQ/BNE/BGE/... (feltételes):
            queue.add(branch_target)
            queue.add(következő)

        RTS / RTE / STOP:
            # ág lezárul

        JMP/JSR regiszter-indirekt:
            # [INDIRECT — nem követhető] megjegyzés
            queue.add(következő)

        egyéb:
            queue.add(következő)
```

### Korlátok

- Max hívási mélység visszakövetésnél: **20 szint** (körkörös hívások elleni védelem)
- PC-relatív JSR target kiszámítása: `addr + 2 + sign_extend(disp)`

---

## Fázis 3 — Lineáris kiegészítő sweep

A `visited` halmaz után maradó, le nem fedett régiók bejárása:

```
for addr in range(0, len(data), 2):
    if addr in visited: skip
    próbál Capstone utasítást dekódolni
    ha sikeres: ORPHAN_CODE jelölés
    ha nem: DATA jelölés
```

Az orphan blokkok a `full_disasm.txt`-ben külön `[ORPHAN]` fejléccel jelennek meg.

---

## Fázis 4 — Write-tracker

### Figyelt utasítások (memória-írás)

| Mnemonik | Feltétel |
|----------|----------|
| MOVE / MOVEA / MOVEM | cél operandus memória (nem regiszter) |
| CLR | mindig memória |
| ST / SF | mindig memória |
| BSET / BCLR / BCHG | ha cél memória |
| ADD / SUB / AND / OR / EOR / NEG / NOT | ha cél memória |

### Cím-kategorizálás

| Tartomány | Kategória |
|-----------|-----------|
| 0x000000 – 0x05FFFF | ROM (write = GYANÚS, külön jelölve) |
| A5 + offset | Munkamemória (szimbolikus névvel annotálva) |
| Egyéb | RAM / NVRAM / I/O |

### Szimbólumtábla (A5-relatív)

| Offset | Szimbólum |
|--------|-----------|
| A5+0x0A48 | gpib_output_pending |
| A5+0x0BAE | timer_cal_constant |
| A5+0x0F00 | gpib_channel_descriptor |
| A5+0x13A6 | beep_mread_enable_flag |
| A5+0x144A | mwrite_protect_flag |
| A5+0x1B02 | beep_hw_state |
| A5+0x1DB5 | beep_mode_copy |

### Hívási lánc visszakövetése

A `call_graph` (Fázis 2) alapján minden write-hoz:

```
write @ 0x002D88
  ← 0x002CC0  (cal_write_core)
    ← 0x17BF6  (MWRITE_handler)
      ← cmd_table entry
        ← GPIB: "MWRITE"
```

Max mélység: 20 szint. Körkörös referencia: `[KÖRÖS HÍVÁS]` jelöléssel megáll.

---

## Ismert szimbólumok (annotációhoz)

```python
KNOWN_LABELS = {
    0x02F96: 'sprintf_like',
    0x049DE: 'gpib_output_dispatch',
    0x0761E: 'mread_output_cleanup',
    0x0763A: 'mread_main_logic',
    0x07BBA: 'mread_entry_lowaddr',
    0x07BCC: 'beep_handler',
    0x07C3C: 'mwrite_exec_lowaddr',
    0x08908: 'timer_delay',
    0x08B20: 'cmd_table_start',
    0x17BA0: 'XYZZY_handler',
    0x17BBA: 'MREAD_handler',
    0x17BF6: 'MWRITE_handler',
    0x17C28: 'JSR_GPIB_handler',
    0x17C58: 'CALLARRAY_handler',
    0x17C8C: 'MADDR_handler',
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
```

---

## Kimenet

### full_disasm.txt

```
==============================================================================
SECTION: VECTORS (0x000000 – 0x0003FF)
==============================================================================
000000  initial_sp = 0x0001897E
000004  reset_pc   = 0x000808
000008  bus_error  -> 0x0xxxxx
...

==============================================================================
SECTION: CODE (recursive descent)
==============================================================================
reset_entry:
  000808  xxxx  MOVE.L  #..., SP
  ...

==============================================================================
SECTION: ORPHAN CODE (lineáris sweep — nem elérhető entry pontokból)
==============================================================================
[ORPHAN @ 0x03F200]
  03F200  xxxx  ...

==============================================================================
SECTION: DATA REGIONS
==============================================================================
[DATA @ 0x084D4 – 0x084F3]
  084D4  ...raw bytes...
```

### write_report.txt

```
==============================================================================
HP 3458A REV9 — MEMÓRIA-ÍRÁSOK TELJES LISTÁJA
==============================================================================

[ROM-BA ÍRÁS — GYANÚS]
  addr: 0xxxxx  insn: MOVE.W D0, $0012A0
  hívási lánc: ...

[RAM ÍRÁS — A5+0x13A6 = beep_mread_enable_flag]
  addr: 0x07BD6  insn: MOVE.B D7, $13A6(A5)
  hívási lánc:
    0x07BD6  beep_setflag_path
    ← 0x07BCC  beep_handler
    ← cmd_table entry: BEEP

[RAM ÍRÁS]
  addr: 0x002D88  insn: MOVE.W D0, $xxxx
  hívási lánc:
    ...
```

---

## Fájlok

| Fájl | Szerep |
|------|--------|
| `full_firmware_analysis.py` | Egyetlen script, mind a 4 fázis |
| `HP3458A_REV9_assembled_and_analysis/HP3458A_REV9_cpu_order_384K_for_Ghidra.bin` | Input binary |
| `HP3458A_REV9_assembled_and_analysis/full_disasm.txt` | Teljes annotált listing |
| `HP3458A_REV9_assembled_and_analysis/write_report.txt` | Write-tracker jelentés |

---

## Függőségek

- Python 3.x
- `capstone` (már használt a projektben)
- `struct` (stdlib)
- `collections` (stdlib)
