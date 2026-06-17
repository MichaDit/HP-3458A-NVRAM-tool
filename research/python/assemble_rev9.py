from pathlib import Path

def interleave(a: bytes, b: bytes) -> bytes:
    out = bytearray(len(a) * 2)
    out[0::2] = a
    out[1::2] = b
    return bytes(out)

def bswap16(data: bytes) -> bytes:
    out = bytearray(len(data))
    out[0::2] = data[1::2]
    out[1::2] = data[0::2]
    return bytes(out)

names = [
    "03458_88890_061108_rev9_u110.bin",
    "03458_88891_061108_rev9_u111.bin",
    "03458_88892_061108_rev9_u112.bin",
    "03458_88893_061108_rev9_u113.bin",
    "03458_88894_061108_rev9_u114.bin",
    "03458_88895_061108_rev9_u115.bin",
]
roms = [Path(n).read_bytes() for n in names]
raw_384 = interleave(roms[0], roms[1]) + interleave(roms[2], roms[3]) + interleave(roms[4], roms[5])
raw_512 = raw_384 + (b"\xff" * (512 * 1024 - len(raw_384)))
cpu_384 = bswap16(raw_384)
cpu_512 = bswap16(raw_512)
Path("HP3458A_REV9_interleaved_raw_384K_from_U110-U115.bin").write_bytes(raw_384)
Path("HP3458A_REV9_interleaved_raw_512K_padded_FF.bin").write_bytes(raw_512)
Path("HP3458A_REV9_cpu_order_384K_for_Ghidra.bin").write_bytes(cpu_384)
Path("HP3458A_REV9_cpu_order_512K_for_Ghidra_padded_FF.bin").write_bytes(cpu_512)
print("Done")
