# SoftBank Air 6 (A775) — P54 modem research

**English** | [简体中文](README.zh-CN.md)

An authorization-free public subset of P54 modem frequency metadata migration specifically for the **SoftBank Air 6 (A775)** home router, using the Quectel RG620T-SBK modem. No device-bound licensing logic, fingerprint implementation, authorization hooks, issuer keys, vendor signing SDK/tool, signer executable or ready-to-flash release package is included.

## Target bands

This project migrates P54 modem band metadata for **SoftBank Air 6 (A775)**. The target set contains **12 LTE bands + 13 NR bands: 25 RAT-specific band entries**:

| RAT | Count | Target bands |
| --- | --- | --- |
| LTE / 4G | 12 | B1, B3, B5, B7, B8, B20, B28, B38, B40, B41, B42, B43 |
| NR / 5G | 13 | n1, n3, n5, n7, n8, n20, n28, n38, n40, n41, n77, n78, n79 |

“Unlocking” here means migrating and expanding permitted band metadata. It does not mean removing a SIM/operator network lock or implementing device-bound licensing. LTE B1 and NR n1 are counted separately. These 25 entries do not imply simultaneous operation or 25-carrier aggregation.

The public version excludes device-bound licensing and authorization hooks; building requires no fingerprint or unlock code. Run `python3 test.py` as documented below to produce and check `build/modem-unsigned.img`. The result still requires independent vendor signing and hardware validation; it is not a signed package accepted by the web updater.

This is a migration target list, not a claim that every band has passed RF/network testing. Availability depends on board RF hardware, calibration, antennas, SIM, coverage and applicable local requirements. The n78 screenshots show the private reference version. This public experiment has yet to be validated on a device.

## Carrier aggregation and contributions

**Carrier aggregation (CA) is currently unsupported in this public experiment; no CA combination is promised to work.** Preserving original CA metadata does not establish implemented, enabled or network-validated CA behavior.

Contributions on CA, NR/LTE combinations, RF behavior and long-term stability are welcome. Submit reproducible code and redacted test reports through Issues or Pull Requests. Include the operator, RAT, bands, bandwidths, image hashes and steps. A UI indicator alone is not evidence of active aggregation.

**The maintainer can help sign candidate modem images for device testing.** Contact [hchyhchyxh](https://github.com/hchyhchyxh) through repository Issues to discuss candidates and tests. Signing tools and private keys remain private. A signature does not guarantee boot acceptance or CA functionality.

## Included scripts

- `metadata/audit_migration.py`: parse and validate md1rom/md1drdi container sections.
- `metadata/build_p54_eu25.py`: preserve original P54 nodes, migrate donor metadata and generate ROM/DRDI drafts with change records.
- `metadata/emit_unsigned.py`: apply pinned BSS array mappings, rebuild section hashes and CHECK_HEADER, and emit an unsigned research image without authorization runtime/hooks.
- `build.py`: run draft generation and image assembly in order.
- `test.py`: check pinned inputs, build output and unchanged original runtime entry points; verify no private authorization runtime is injected.
- JSON files: record layouts, NR graphs, migration plans and input hashes.

## External reference inputs

Vendor firmware images are not distributed in this repository. Obtain legally sourced inputs yourself and place them at the paths below before building. `inputs.lock.json` specifies the required SHA-256 values. These ignored files must not be committed.

- `metadata/sb_rudolf_v1.01.85_single/modem-verified.img`
- `fullband_eu_bucket_order_fix_20mhz/modem.img`
- `fullband_eu_bucket_order_fix_20mhz/manifest.json` (reference metadata)

## Build and test

Python 3 is required. The private signing SDK is not required:

```bash
git clone https://github.com/hchyhchyxh/air6-modem.git
cd air6-modem
python3 test.py
# Build only:
python3 build.py
```

Do not use Python `-O` or disable assertions. Outputs are `build/modem-unsigned.img` and `build/report.json`, with intermediate drafts under `metadata/`. Passing these checks is not vendor-signature, secure-boot, RF, CA or long-term stability acceptance. This authorization-free experiment differs from the private licensed modem and has not been flashed or device validated.

## Reference interface

The related [OpenWrt AIR6 project](https://github.com/hchyhchyxh/openwrt-air6) provides the router interface. The following images were captured after real China Telecom **5G n78** registration and data connectivity on November 8, 2026. Device identifiers and addresses are redacted. They show the private reference system's interface and do not establish device validation of this repository's unsigned experiment.

![5G n78 network overview](docs/images/overview.png)

![SIM registration and APN](docs/images/cellular.png)

- [Cellular API telemetry: CA, EN-DC and cell measurements](docs/cellular-telemetry-api.md)

- [P54 CA audit: RF routes and status checks (November 11, 2026)](docs/ca-audit-20261111.md)

- [P54 native CA lookup and n78 reuse](docs/ca-native-check-20261111.md)

## License and project notice

See the [licensing scope](LICENSING.md) and the [disclaimer, trademark and rights-request policies](DISCLAIMER.md).

## P54 DRDI integrity

[DRDI SHA-256 refresh, audit and offline rollback](docs/drdi-integrity-20261115.md) documents the 640-range check and reusable CLI. The metadata build now uses this shared implementation and records the result in `build/report.json`. It does not establish n41/CA support.

Independent regression tests without firmware inputs: `python3 -m unittest discover -s tests -p test_drdi_integrity.py -v`.

## Support development

If you would like to support continued development, please donate only what you can comfortably afford. Donations are entirely voluntary, and all proceeds go toward purchasing AI tokens for development. Please keep discussions respectful.

![Donation QR codes](docs/images/donation-qr.jpg)
