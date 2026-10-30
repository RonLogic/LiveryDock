# LiveryDock 0.4.1

Reviewed release of LiveryDock 0.4.0 with installation safety, rollback and Windows fixes. The legacy 0.3.1 PTP flow and native 0.4.0 PMDG 777 ZIP support are retained.

## Download

- **Windows x64 ZIP:** extract and run `LiveryDock.exe`; no separate Python installation required.
- **Source ZIP:** Python 3.11+ with Tkinter is required; see the README for setup.
- **SHA256SUMS.txt:** checksums for both ZIP files.

## Changes

- Stronger checks for archive paths, linked directories, native product metadata and malformed PTP/CAB data.
- Safer rollback and uninstall, including common/variant bundles and overlapping installations.
- Sequential installation, background task cleanup and a 64-bit drag-and-drop fix.
- Expanded synthetic regression tests, English/Hebrew documentation and clean release packaging.

Native PMDG KTX2 ZIPs do not require the SDK. Legacy PTP DDS conversion requires the official **MSFS 2024 SDK** and the matching installed native PMDG aircraft/template. RAR/7Z require 7-Zip. The executable is unsigned.

No proprietary aircraft, livery samples, texture archives, PMDG DLLs or credentials are distributed. See [release validation](https://github.com/RonLogic/LiveryDock/blob/main/docs/RELEASE_VALIDATION.md) for test evidence and simulator verification limits.
