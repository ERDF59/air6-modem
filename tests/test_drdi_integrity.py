# SPDX-License-Identifier: MIT
"""Synthetic P54 layout: no vendor payloads required for regression tests."""
import hashlib
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import drdi_integrity as d


class IntegrityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rom = bytearray(d.DIGESTS + d.COUNT * 32)
        drdi = bytes(i % 251 for i in range(d.COUNT * 8))
        for i in range(d.COUNT):
            struct.pack_into('<III', rom, d.REGISTRY + i * 12, d.DRDI_BASE + i * 8, 0x60000000 + i * 8, 8)
            struct.pack_into('<II', rom, d.TARGETS + i * 8, 0x60000000 + i * 8, 8)
            rom[d.DIGESTS + i * 32:d.DIGESTS + (i + 1) * 32] = hashlib.sha256(drdi[i * 8:(i + 1) * 8]).digest()
        cls.rom, cls.drdi = bytes(rom), drdi

    def container(self, rom, drdi):
        out = bytearray()
        for name, payload in (('md1rom', rom), ('md1drdi', drdi)):
            h = bytearray(512)
            struct.pack_into('<II', h, 0, 0x58881688, len(payload))
            h[8:8 + len(name)] = name.encode()
            struct.pack_into('<I', h, 52, 512)
            struct.pack_into('<I', h, 68, 16)
            out += h + payload + bytes(-len(payload) % 16)
        return bytes(out)

    def candidate(self):
        changed = bytearray(self.drdi)
        changed[448 * 8] ^= 1
        changed[449 * 8] ^= 1
        return self.container(self.rom, changed)

    def test_valid_input_stays_identical(self):
        baseline = self.container(self.rom, self.drdi)
        output, report = d.repair_image(baseline)
        self.assertEqual(output, baseline)
        self.assertEqual(report['edits'], [])
        self.assertEqual(report['after']['valid'], 640)

    def test_two_stale_ranges_and_exact_rollback(self):
        before = self.candidate()
        self.assertEqual(d.audit_image(before)['mismatched_indices'], [448, 449])
        after, report = d.repair_image(before)
        allowed = {i for e in report['edits'] for i in range(e['file_offset'], e['file_offset'] + 32)}
        self.assertEqual(len(after), len(before))
        self.assertTrue(all(a == b or i in allowed for i, (a, b) in enumerate(zip(before, after))))
        self.assertEqual(d.audit_image(after)['valid'], 640)
        self.assertEqual(d.restore_image(after, report), before)
        self.assertEqual(d.repair_image(after)[1]['edits'], [])

    def test_bad_range_and_target_layout_rejected(self):
        for at in (d.REGISTRY, d.TARGETS):
            bad = bytearray(self.rom)
            struct.pack_into('<I', bad, at, 0xFFFFFFFF)
            with self.assertRaises(ValueError):
                d.refresh_payloads(bad, self.drdi)

    def test_wrong_or_truncated_container_rejected(self):
        blob = self.container(self.rom, self.drdi)
        for bad in (b'', blob[:100], blob[:-1], blob + bytes(512)):
            with self.assertRaises(ValueError):
                d.audit_image(bad)

    def test_tampered_rollback_rejected(self):
        after, report = d.repair_image(self.candidate())
        tampered = bytearray(after)
        tampered[1000] ^= 1
        with self.assertRaises(ValueError):
            d.restore_image(tampered, report)

    def test_cli_audit_repair_restore_and_no_overwrite(self):
        tool = Path(d.__file__)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            old, new, report, restored = (root / n for n in ('old.img', 'new.img', 'report.json', 'restored.img'))
            old.write_bytes(self.candidate())
            def run(*args):
                return subprocess.run([sys.executable, str(tool), *map(str, args)], capture_output=True, text=True)
            self.assertEqual(run('audit', old).returncode, 1)
            args = ('repair', old, '--output', new, '--report', report)
            self.assertEqual(run(*args).returncode, 0)
            before = new.read_bytes()
            self.assertEqual(run(*args).returncode, 2)
            self.assertEqual(new.read_bytes(), before)
            self.assertEqual(run('audit', new).returncode, 0)
            self.assertEqual(run('restore', new, '--report', report, '--output', restored).returncode, 0)
            self.assertEqual(restored.read_bytes(), old.read_bytes())


if __name__ == '__main__':
    unittest.main()
