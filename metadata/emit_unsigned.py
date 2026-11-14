"""Compose metadata-only unsigned research image. No native hooks or authorization."""
import json,struct,hashlib
from audit_migration import sections,R,H
import sys
sys.path.insert(0,str(R.parent))
from drdi_integrity import refresh_payloads,audit_payloads
source=(R/'sb_rudolf_v1.01.85_single/modem-verified.img').read_bytes()
p=sections(source);original=p['md1rom']['data']
rom=bytearray((R/'draft_rom_without_tail.bin').read_bytes());drdi=(R/'draft_drdi.bin').read_bytes()
edits=[]
for row in json.loads((R/'bss_mapping_audit.json').read_text())['mapping_references']:
 at=int(row['file'],16)-512;old=bytes.fromhex(row['old']);new=bytes.fromhex(row['new'])
 assert rom[at:at+len(old)]==old
 rom[at:at+len(new)]=new;edits.append(row)
# Refresh native digest words after all DRDI edits, then check every range.
rom,drdi_digest_edits=refresh_payloads(rom,drdi)
drdi_integrity=audit_payloads(rom,drdi)
rom.extend(bytes(-len(rom)%16));tail=bytearray(original[-512:]);assert tail[:12]==b'CHECK_HEADER'
growth=len(rom)+512-len(original);struct.pack_into('<I',tail,176,struct.unpack_from('<I',tail,176)[0]+growth)
assert struct.unpack_from('<II',tail,284)==(0xad30000,0x68d0000)
assert struct.unpack_from('<II',tail,316)==(0,0)
struct.pack_into('<II',tail,284,0xad30000,0x10000)
struct.pack_into('<II',tail,316,0xad50000,0x68b0000)
end=(len(rom)+512+65535)&~65535;assert end<=0x2400000
struct.pack_into('<II',tail,300,end,0x2400000-end);rom.extend(tail)
output=bytearray()
for name,payload in [('md1rom',rom),('md1drdi',drdi)]:
 head=bytearray(p[name]['header']);struct.pack_into('<I',head,4,len(payload))
 output.extend(head);output.extend(payload);output.extend(bytes(-len(payload)%16))
out=R.parent/'build';out.mkdir(exist_ok=True)
(out/'modem-unsigned.img').write_bytes(output)
(out/'report.json').write_text(json.dumps(dict(status='UNSIGNED_METADATA_ONLY_NOT_DEVICE_VALIDATED',sha256=H(output),source_sha256=H(source),native_hooks=False,device_authorization=False,vendor_signed=False,mapping_edits=edits,drdi_integrity=drdi_integrity,drdi_digest_edits=drdi_digest_edits),indent=2))
print('UNSIGNED_METADATA_ONLY',len(output),H(output))
