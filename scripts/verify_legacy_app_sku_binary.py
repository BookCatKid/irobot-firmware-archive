#!/usr/bin/env python3
"""Verify historical ARM64 SKU classifiers from an existing 2017 iRobot APK.

Read-only verification. Never installs or executes the APK or its native code.
The ELF-derived addresses and hashes are pinned to the evidence JSON.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "data/research/legacy-2017-native-sku-evidence-2026-11-10.json"


def _vaddr_to_file_offset(elf: bytes, addr: int) -> int:
    if elf[:4] != b"\x7fELF" or elf[4] != 2 or elf[5] != 1:
        raise ValueError("Not a little-endian ELF64 file")
    phoff = struct.unpack_from("<Q", elf, 32)[0]
    entsize, count = struct.unpack_from("<HH", elf, 54)
    if entsize < 56 or count > 1000 or phoff + entsize * count > len(elf):
        raise ValueError("Invalid ELF program-header table")
    for i in range(count):
        off = phoff + i * entsize
        p_type, _flags, fileoff, vaddr, _paddr, filelen, _memlen, _align = struct.unpack_from("<IIQQQQQQ", elf, off)
        if p_type == 1 and vaddr <= addr < vaddr + filelen:
            return fileoff + addr - vaddr
    raise ValueError(f"Address 0x{addr:x} not backed by a PT_LOAD file mapping")


def _word(elf: bytes, va: int) -> int:
    return struct.unpack_from("<I", elf, _vaddr_to_file_offset(elf, va))[0]


def _aarch64_adrp_target(pc: int, instruction: int) -> int:
    if instruction & 0x9F000000 != 0x90000000:
        raise ValueError("Expected ADRP instruction")
    imm = ((instruction >> 5) & 0x7FFFF) << 2 | ((instruction >> 29) & 3)
    if imm & (1 << 20):
        imm -= 1 << 21
    return (pc & ~0xFFF) + (imm << 12)


def _aarch64_add_immediate(instruction: int) -> int:
    if instruction & 0xFF000000 != 0x91000000:
        raise ValueError("Expected ADD immediate instruction")
    if (instruction & 31) != 12 or (instruction >> 5) & 31 != 12:
        raise ValueError("Expected ADD x12, x12, #immediate")
    return ((instruction >> 10) & 0xFFF) << (12 if instruction & (1 << 22) else 0)


def verify(apk_path: Path) -> list[dict]:
    evidence = json.loads(EVIDENCE.read_text())
    source = evidence["source"]
    apk_sha = hashlib.sha256(apk_path.read_bytes()).hexdigest()
    if apk_sha != source["apk_sha256"]:
        raise ValueError(f"Unexpected APK hash: {apk_sha}")
    with zipfile.ZipFile(apk_path) as z:
        elf = z.read(source["native_library"])
        embedded = z.read(evidence["embedded_firmware"]["apk_path"])
    if hashlib.sha256(elf).hexdigest() != source["native_library_sha256"]:
        raise ValueError("Unexpected native library hash")
    if hashlib.sha256(embedded).hexdigest() != evidence["embedded_firmware"]["sha256"]:
        raise ValueError("Unexpected app-embedded firmware hash")
    checked = []
    for classifier in evidence["native_classifiers"]:
        function = classifier["function_va"]
        literal = classifier["literal_va"]
        expected = classifier["prefix"].encode() + b"\x00"
        loff = _vaddr_to_file_offset(elf, literal)
        if elf[loff:loff + len(expected)] != expected:
            raise ValueError(f"Incorrect literal at 0x{literal:x}")
        # In the reverse-engineered compiler output:
        # +0x00 loads the libc++ string's first byte,
        # +0x3c / +0x40 form ADRP+ADD x12 to reference the prefix literal,
        # +0x4c compares the candidate's first byte to ASCII 'R'.
        if _word(elf, function) != 0x39400008:
            raise ValueError(f"Unexpected start of {classifier['function']}")
        if _word(elf, function + 0x4c) != 0x710149BF:
            raise ValueError(f"Missing SKU initial-R comparison in {classifier['function']}")
        adrp = _word(elf, function + 0x3c)
        add = _word(elf, function + 0x40)
        target = _aarch64_adrp_target(function + 0x3c, adrp) + _aarch64_add_immediate(add)
        if target != literal:
            raise ValueError(f"Instruction literal reference mismatch in {classifier['function']}")
        checked.append({"function": classifier["function"], "prefix": classifier["prefix"], "literal_va":hex(literal)})
    return checked


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", required=True, type=Path, help="Read-only input APK")
    args = parser.parse_args()
    for item in verify(args.apk):
        print(json.dumps(item, sort_keys=True))


if __name__ == "__main__":
    main()
