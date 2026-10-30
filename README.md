# LiveryDock

A Windows livery installer for Microsoft Flight Simulator 2024, with built-in PMDG PTP extraction and support for native PMDG 777 livery ZIPs.

[Download the latest release](https://github.com/RonLogic/LiveryDock/releases/latest) · [מדריך בעברית](README_HE.md)

## Get started

1. Download `LiveryDock-0.4.1-Windows-x64.zip` from Releases and extract it.
2. Run `LiveryDock.exe`. Python is included in this build; no separate Python installation is needed.
3. Confirm the detected **Community2024** and **Legacy Community** folders, or choose them with Browse.
4. Drop a livery archive or extracted folder into the window. Review its identity and target, then choose **Install selected**.
5. Use **Managed Liveries → Uninstall / restore previous** to remove an installed item and restore the version it replaced. Remove overlapping installs in reverse installation order.

The executable is unsigned. Release assets include SHA-256 checksums. LiveryDock never installs or replaces the base aircraft; the matching MSFS 2024 aircraft must already be installed.

## Supported inputs

| Input | Behavior | Additional requirement |
| --- | --- | --- |
| Standard MSFS package ZIP or extracted folder | Finds `manifest.json` and `layout.json`, including inside wrapper folders | Matching aircraft |
| RAR / 7Z | Validates and extracts through 7-Zip | Installed 7-Zip |
| Native PMDG MSFS 2024 ZIP or folder | Reads `livery.json`, `livery.cfg`, `model.airframe` and native KTX2 textures; no manifest/layout required in the source | Matching PMDG aircraft |
| Bundle of native PMDG ZIPs | Installs common textures first, preserves original livery IDs and relative fallbacks, and rolls back the bundle on failure | All entries must target the same supported product |
| Legacy PMDG `.ptp` for the 737 family | Built-in CRYP/CAB extraction, native template selection and DDS → KTX2 conversion | Matching native PMDG 737 and the official MSFS 2024 SDK |

Native ZIP support includes PMDG 777-200ER (`pmdg-aircraft-77er`), including GE/RR variants and common/variant bundles. Already-native KTX2 ZIPs **do not need the SDK**. Optional `Dirty Version` texture folders are omitted; install uses the main textures. Embedded executables and scripts are excluded from native PMDG payloads.

The PTP flow introduced in 0.3.1 is retained. It needs no `CabLib.dll` or Operations Center. Automatic legacy conversion focuses on PMDG 736/737/738/739, with 739ER and winglets identified from metadata. It converts liveries, not MSFS 2020 aircraft. FSX/Prepar3D PTP variants and every third-party livery are not guaranteed to work.

## Targets, backups and logs

Auto mode sends ordinary native packages to Community2024 and legacy packages to Community. For native PMDG liveries it prefers the configured Community folder containing the matching base/livery package. PTP conversion uses the selected Legacy Community folder.

PMDG liveries are installed under the matching `pmdg-aircraft-*-liveries/SimObjects/Airplanes/.../liveries/pmdg` package. A missing livery package can be created when the matching base aircraft exists. Layout metadata is rebuilt after changes. Installations run sequentially to protect shared layouts and the registry.

Registry, logs and backups are kept in `%LOCALAPPDATA%\LiveryDock`. Keep backups if you want to restore replaced liveries. If the registry is damaged, preserve it and the backups before attempting recovery. **Open log** opens the diagnostic log, which can contain local paths; review it before sharing.

Unsafe archive paths, links and Windows path aliases are rejected. Installation into an `Official` folder is refused. No aircraft, texture packs, livery samples or SDK binaries are included in this repository or release.

## SDK for PTP conversion

Install the official MSFS 2024 SDK using the simulator's developer tools. LiveryDock looks for:

```text
C:\MSFS 2024 SDK\Tools\bin\fspackagetool.exe
```

If needed, select the SDK root with **Browse**. Conversion also needs a suitable native livery template in the installed PMDG aircraft. A missing tool, template, or converted texture stops installation with an error.

## Run from source

Use Windows 10/11 x64 and Python 3.11 or newer with Tkinter:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe main.pyw
```

Alternatively, `Run LiveryDock.cmd` creates a local environment and installs the runtime dependencies. Dragging an archive onto that launcher passes it to the app.

## Test and build

```powershell
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m PyInstaller --noconfirm --clean LiveryDock.spec
.\.venv\Scripts\python.exe tools\package_release.py
```

`Build EXE.cmd` installs the build dependencies, runs the tests, and builds `dist\LiveryDock.exe`. The packaging tool creates a Windows ZIP, a source ZIP and SHA-256 checksums under `release/` using an explicit file allowlist. Build from a clean checkout. CI runs tests on Python 3.11–3.13; the build workflow produces Windows packages for version tags. Release assets are published after review.

Tests create synthetic packages and encrypted PTP/CAB fixtures at runtime. SDK calls are mocked in the automated suite; successful unit tests do not establish compatibility inside the simulator. See [release validation](docs/RELEASE_VALIDATION.md) for the checks actually run for this release.

## License and contribution

LiveryDock source is [MIT licensed](LICENSE). Python and bundled dependencies retain their own licenses, included in the Windows package. Microsoft Flight Simulator and PMDG are trademarks of their respective owners; this is an independent utility.

Please report the app version, input format, error text and steps to reproduce in an [issue](https://github.com/RonLogic/LiveryDock/issues). Do not upload paid aircraft, proprietary textures, livery archives or credentials. Small synthetic fixtures and redacted logs are welcome.
