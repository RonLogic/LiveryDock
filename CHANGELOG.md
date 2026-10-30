# Changelog

## 0.4.1 — 2026-10-30

Release review of the existing 0.4.0 source, retaining the 0.3.1 PTP conversion flow and 0.4.0 native PMDG ZIP support.

- Reject unsafe Windows archive names, linked paths, malformed CAB data and invalid native product identities.
- Harden install rollback, managed uninstall validation, backup handling and ordering of overlapping livery installations.
- Run selected installations sequentially and capture GUI settings before background work starts.
- Correct 64-bit Windows drag-and-drop handle declarations and release the window hook on close.
- Add synthetic PTP/CAB, native bundle, rollback, path safety and GUI coordination regression coverage.
- Add English documentation, release validation notes, package metadata, CI checks and clean release packaging with checksums.

## 0.4.0

- Add direct native PMDG MSFS 2024 livery ZIP/folder support, including the 777-200ER.
- Read `productPackage` and `liveryId` from `livery.json` without requiring source manifest/layout files.
- Install nested ZIP bundles with common textures before variants; preserve original IDs and fallbacks.
- Install native KTX2 textures without SDK conversion; omit embedded helper executables and optional dirty textures.

## 0.3.1

- Built-in PMDG CRYP PTP extraction without CabLib.dll.
- Convert legacy 737 DDS liveries to native KTX2 using the MSFS 2024 SDK and matching installed aircraft templates.

Earlier entries describe inherited functionality, not new simulator verification in this release.
