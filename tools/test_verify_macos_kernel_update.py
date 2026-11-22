#!/usr/bin/env python3
"""Verify the Mach-O boundary with synthetic public fixtures, without Apple payloads."""
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

import verify_macos_kernel_update as verifier


def synthetic_macho(*, filetype=2, segment="__TEXT_EXEC", protection=5,
                    flags=0x80000400, kind=0x0F, index=1, delta=0, duplicate=False, missing=False):
    code_offset, code_size = 208, 16
    base = 0 if filetype == 1 else 0x100000000
    address = 0 if filetype == 1 else base + code_offset
    symbols = [("_another_method" if missing else verifier.SYMBOL, kind, index, address + delta),
               ("_following_method", 0x0F, 1, address + 12)]
    if duplicate:
        symbols.append((verifier.SYMBOL, kind, index, address))
    strings, entries = bytearray(b"\0"), bytearray()
    for name, symbol_kind, section_index, value in symbols:
        string_index = len(strings)
        strings.extend(name.encode() + b"\0")
        entries.extend(struct.pack("<IBBHQ", string_index, symbol_kind, section_index, 0, value))
    symoff = code_offset + code_size
    stroff = symoff + len(entries)
    total = stroff + len(strings)
    header = struct.pack("<8I", 0xFEEDFACF, 0x100000C, 2, filetype, 2, 176, 0, 0)
    segment_name = "" if filetype == 1 else segment
    segment_offset, segment_size = (code_offset, code_size) if filetype == 1 else (0, total)
    segment_command = struct.pack("<II16s4Q4I", 0x19, 152, segment_name.encode(), base,
                                  code_size if filetype == 1 else 0x1000,
                                  segment_offset, segment_size, protection, protection, 1, 0)
    section = struct.pack("<16s16sQQ8I", b"__text", segment.encode(), address, code_size,
                          code_offset, 2, 0, 0, flags, 0, 0, 0)
    symtab = struct.pack("<6I", 2, 24, symoff, len(symbols), stroff, len(strings))
    # Public ARM instructions authored for this fixture: HVC, SMC, RET, NOP.
    code = bytes.fromhex("020000d4030000d4c0035fd61f2003d5")
    return header + segment_command + section + symtab + code + entries + strings


class CompiledMethodBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "synthetic.macho"

    def inspect(self, data, expected_filetype=2):
        self.path.write_bytes(data)
        return verifier.compiled_method(self.path, expected_filetype)

    def test_kernel_text_exec_is_defined_executable_code_with_section_bounded_extent(self):
        method = self.inspect(synthetic_macho())
        self.assertEqual(method["filetype"], 2)
        self.assertEqual(method["segment"], "__TEXT_EXEC")
        self.assertEqual(method["section"], "__text")
        self.assertEqual(method["n_type"], "0xf")
        self.assertEqual(method["method_bytes"], 12)

    def test_relocatable_object_text_is_verified_by_its_actual_section(self):
        method = self.inspect(synthetic_macho(filetype=1, segment="__TEXT", protection=7), 1)
        self.assertEqual(method["address"], "0x0")
        self.assertEqual(method["filetype"], 1)

    def test_missing_duplicate_absolute_undefined_and_stab_symbols_fail(self):
        for parameters in ({"missing": True}, {"duplicate": True}, {"kind": 3}, {"kind": 1}, {"kind": 0xEF}):
            with self.subTest(parameters=parameters), self.assertRaises(ValueError):
                self.inspect(synthetic_macho(**parameters))

    def test_data_non_executable_and_non_instruction_sections_fail(self):
        for parameters in ({"segment": "__DATA"}, {"protection": 3}, {"flags": 0}, {"flags": 0x80000401}):
            with self.subTest(parameters=parameters), self.assertRaises(ValueError):
                self.inspect(synthetic_macho(**parameters))

    def test_wrong_section_indices_and_addresses_fail(self):
        for parameters in ({"index": 0}, {"index": 2}, {"delta": -1}, {"delta": 16}):
            with self.subTest(parameters=parameters), self.assertRaises(ValueError):
                self.inspect(synthetic_macho(**parameters))

    def test_wrong_file_identity_and_truncated_or_out_of_range_metadata_fail(self):
        wrong_table = bytearray(synthetic_macho())
        struct.pack_into("<I", wrong_table, 192, 0xFFFFFFFF)
        bad_command = bytearray(synthetic_macho())
        struct.pack_into("<I", bad_command, 36, 4)
        for data in (synthetic_macho(filetype=1), synthetic_macho()[:31], bytes(wrong_table), bytes(bad_command)):
            with self.subTest(length=len(data)), self.assertRaises(ValueError):
                self.inspect(data)

    def test_collection_method_validation_keeps_the_same_executable_section_gate(self):
        section = {"name": "__text", "segment": "__TEXT_EXEC", "va": 0x1000, "size": 16,
                   "fileoff": 0, "flags": 0x80000400, "maxprot": 5, "initprot": 5}
        symbols = [(verifier.SYMBOL, 0x0F, 1, 0, 0x1000), ("_next", 0x0F, 1, 0, 0x100C)]
        self.assertEqual(verifier.method_record(symbols, [section], 16)["method_bytes"], 12)
        with self.assertRaises(ValueError):
            verifier.method_record(symbols, [dict(section, initprot=3)], 16)

    def test_llvm_nm_kernel_s_letter_does_not_decide_whether_the_section_is_code(self):
        nm = os.environ.get("MACOS_TEST_LLVM_NM") or shutil.which("llvm-nm")
        if nm is None:
            self.skipTest("LLVM nm is unavailable; direct Mach-O boundary tests still run")
        self.path.write_bytes(synthetic_macho())
        rows = subprocess.check_output([nm, "--defined-only", "--no-sort", str(self.path)], text=True).splitlines()
        matches = [row.split() for row in rows if row.split()[-1] == verifier.SYMBOL]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0][-2].upper(), "S")
        self.assertEqual(verifier.compiled_method(self.path, 2)["section"], "__text")
        self.path.write_bytes(synthetic_macho(filetype=1, segment="__TEXT", protection=7))
        rows = subprocess.check_output([nm, "--defined-only", "--no-sort", str(self.path)], text=True).splitlines()
        matches = [row.split() for row in rows if row.split()[-1] == verifier.SYMBOL]
        self.assertEqual(matches[0][-2].upper(), "T")


if __name__ == "__main__":
    unittest.main()
