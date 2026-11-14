#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit/refresh existing P54 DRDI SHA-256 words in unsigned images, offline."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

REGISTRY = 0x2150D2C
TARGETS = 0x2152B2C
DIGESTS = 0x2153F2C
COUNT = 640
DRDI_BASE = 0x50000000


def sha(data):
    return hashlib.sha256(data).hexdigest()


def range_digests(rom, drdi):
    """Validate both P54 range tables completely before computing replacements."""
    if len(rom) < DIGESTS + COUNT * 32:
        raise ValueError('Truncated P54 ROM tables')
    rows = []
    for i in range(COUNT):
        src, dst, size = struct.unpack_from('<III', rom, REGISTRY + i * 12)
        if (dst, size) != struct.unpack_from('<II', rom, TARGETS + i * 8):
            raise ValueError(f'Range/target table mismatch at {i}')
        start = src - DRDI_BASE
        if not 0 <= start <= start + size <= len(drdi):
            raise ValueError(f'DRDI range outside payload at {i}')
        rows.append(hashlib.sha256(drdi[start:start + size]).digest())
    return rows


def audit_payloads(rom, drdi):
    digests = range_digests(rom, drdi)
    bad = [i for i, digest in enumerate(digests)
           if rom[DIGESTS + i * 32:DIGESTS + (i + 1) * 32] != digest]
    return dict(checked=COUNT, valid=COUNT - len(bad), mismatched_indices=bad)


def refresh_payloads(rom, drdi):
    """Return a ROM copy; change digest words only and retain native check code."""
    result = bytearray(rom)
    edits = []
    for i, digest in enumerate(range_digests(rom, drdi)):
        at = DIGESTS + i * 32
        old = bytes(rom[at:at + 32])
        if old != digest:
            edits.append(dict(index=i, group=i // 64, profile=i % 64,
                              rom_offset=at, old=old.hex(), new=digest.hex()))
            result[at:at + 32] = digest
    if audit_payloads(result, drdi)['valid'] != COUNT:
        raise ValueError('Digest refresh verification failed')
    return result, edits


def sections(blob):
    """Require an exact unsigned MTK container, not a padded/signed partition."""
    pos, parts = 0, {}
    while pos < len(blob):
        if len(blob) - pos < 512 or struct.unpack_from('<I', blob, pos)[0] != 0x58881688:
            raise ValueError('Expected an unpadded, unsigned MTK container')
        size = struct.unpack_from('<I', blob, pos + 4)[0]
        header = struct.unpack_from('<I', blob, pos + 52)[0]
        align = struct.unpack_from('<I', blob, pos + 68)[0]
        if header != 512 or align != 16:
            raise ValueError('Unsupported MTK header/alignment')
        name = blob[pos + 8:pos + 40].split(b'\0')[0].decode('ascii')
        start, end = pos + header, pos + header + size
        next_pos = end + (-size % align)
        if next_pos > len(blob) or name in parts:
            raise ValueError('Truncated or duplicate MTK section')
        parts[name] = (start, end)
        pos = next_pos
    if not {'md1rom', 'md1drdi'} <= parts.keys():
        raise ValueError('Missing md1rom/md1drdi')
    return parts


def audit_image(blob):
    p = sections(blob)
    return audit_payloads(blob[slice(*p['md1rom'])], blob[slice(*p['md1drdi'])])


def repair_image(blob):
    p = sections(blob)
    rom, edits = refresh_payloads(blob[slice(*p['md1rom'])], blob[slice(*p['md1drdi'])])
    result = bytearray(blob)
    result[slice(*p['md1rom'])] = rom
    for e in edits:
        e['file_offset'] = p['md1rom'][0] + e['rom_offset']
    report = dict(schema='p54-drdi-sha256-v1', input_sha256=sha(blob),
                  output_sha256=sha(result), before=audit_image(blob),
                  after=audit_image(result), edits=edits,
                  change_scope='existing digest words only; no native check code changes')
    return bytes(result), report


def restore_image(blob, report):
    if report.get('schema') != 'p54-drdi-sha256-v1' or sha(blob) != report['output_sha256']:
        raise ValueError('Restore input/report hash mismatch')
    rom_start = sections(blob)['md1rom'][0]
    result, seen = bytearray(blob), set()
    for e in report['edits']:
        i, at = e['index'], e['file_offset']
        old, new = bytes.fromhex(e['old']), bytes.fromhex(e['new'])
        if (not 0 <= i < COUNT or i in seen or at != rom_start + DIGESTS + i * 32
                or len(old) != 32 or len(new) != 32 or blob[at:at + 32] != new):
            raise ValueError('Invalid digest restore entry')
        seen.add(i)
        result[at:at + 32] = old
    if sha(result) != report['input_sha256']:
        raise ValueError('Restored image is not byte-exact input')
    return bytes(result)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode', choices=('audit', 'repair', 'restore'))
    p.add_argument('input', type=Path)
    p.add_argument('--output', type=Path)
    p.add_argument('--report', type=Path)
    a = p.parse_args()
    try:
        blob = a.input.read_bytes()
        if a.mode == 'audit':
            report = audit_image(blob)
            print(json.dumps(report, sort_keys=True))
            return 0 if report['valid'] == COUNT else 1
        if a.output is None or a.report is None:
            p.error('repair/restore require --output and --report')
        if a.output.exists() or (a.mode == 'repair' and a.report.exists()):
            raise ValueError('Choose new output/report paths; existing files are preserved')
        if a.output.resolve() == a.input.resolve() or a.report.resolve() in (a.output.resolve(), a.input.resolve()):
            raise ValueError('Input, output and report must have distinct paths')
        if a.mode == 'repair':
            result, report = repair_image(blob)
        else:
            report = json.loads(a.report.read_text())
            result = restore_image(blob, report)
        with a.output.open('xb') as f:
            f.write(result)
        if sha(a.output.read_bytes()) != sha(result):
            raise ValueError('Output readback mismatch')
        if a.mode == 'repair':
            with a.report.open('x') as f:
                json.dump(report, f, indent=2)
        print(a.mode.upper() + '_PASS', sha(result))
        return 0
    except (OSError, ValueError, KeyError, TypeError, struct.error) as e:
        p.exit(2, str(e) + '\n')


if __name__ == '__main__':
    raise SystemExit(main())
