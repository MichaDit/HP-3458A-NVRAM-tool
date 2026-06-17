# External sources

Ezeket a fájlokat **nem mi készítettük** — ezek a HP 3458A REV9 firmware
ROM chipjeiből (U110–U115) kiolvasott nyers binárisok, illetve azok
átrendezett/összefűzött változatai a könnyebb disassembly-hez.

| Fájl | Tartalom |
|---|---|
| `HP3458A_REV9_bank{0,1,2}_U11{0-5}_raw_128K.bin` | Az egyes ROM chip-páronkénti nyers kiolvasás (interleaved bank-formátum). |
| `HP3458A_REV9_bank{0,1,2}_U11{0-5}_cpu_order_128K.bin` | Ugyanaz, de a 68000 CPU által ténylegesen látott byte-sorrendben. |
| `HP3458A_REV9_interleaved_raw_384K_from_U110-U115.bin` | A 3 bank összefűzve, nyers (interleaved) sorrendben. |
| `HP3458A_REV9_interleaved_raw_512K_padded_FF.bin` | Ugyanaz, 512K-ra paddelve (0xFF). |
| `HP3458A_REV9_cpu_order_384K_for_Ghidra.bin` | A teljes 384K ROM, CPU-sorrendben — **ezt használja a `research/full_firmware_analysis.py`**. |
| `HP3458A_REV9_cpu_order_512K_for_Ghidra_padded_FF.bin` | Ugyanaz, 512K-ra paddelve, Ghidra/IDA betöltéshez. |

Az összefűzést/átrendezést végző script (`research/firmware_analysis/assemble_rev9.py`)
dokumentálja, hogyan állt elő ezekből a fájlokból a végső ROM image — bár
az eredeti, egyenkénti chip-dumpok (`*_u110.bin` stb.) már nem részei a
projektnek, csak a belőlük már összeállított bank-fájlok.
