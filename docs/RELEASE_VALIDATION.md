# Release validation — 0.4.1

Reviewed on 2026-10-30 from the existing Desktop LiveryDock source. Both `pyproject.toml` and the inherited module identified it as 0.4.0. The referenced chat's `/mnt/data/LiveryDock_0.4.0.zip` was not present on this Windows host; no claim of byte-for-byte equivalence to that archive is made. Older Desktop build outputs were excluded.

## Automated checks

- **126 tests passed, no skips** on Windows 11 x64 / Python 3.12.14. The final run allowed temporary Windows junction creation so the real link-safety tests executed.
- The original 16-test suite remains, with its UserCfg assertion corrected to compare paths consistently on Windows.
- New coverage exercises actual encrypted CRYP/CAB and MSZIP round trips, multi-block PTP decryption, corrupt inputs, bounded decompression, DDS alpha, SDK command ordering/output validation, native 777 bundles, common fallbacks, duplicate IDs, unsafe paths, backup/rollback failures, uninstall order, overlapping PTP/native installs, registry corruption and GUI task coordination.
- Fixtures are generated at runtime from synthetic text and small fake or generated texture bytes. No proprietary livery archives are stored in tests.
- `pip check`, editable package installation and Python compilation passed.

## SDK integration

The locally installed official MSFS 2024 SDK successfully converted one freshly generated 64×64 RGBA DDS image using `convert_dds_to_ktx2`. It produced a non-empty KTX2 file and its metadata, including `HasTransp=true`. The generated files remained outside the release inputs. This validates the real SDK invocation and conversion stage on this machine.

## Windows application and packaging

- A fresh Windows x64 one-file executable was built with Python 3.12.14, PyInstaller 6.22.3, cryptography 50.0.2 and Pillow 13.0.0.
- The source GUI creates and closes successfully, including enabling and restoring the 64-bit Windows file-drop window hook.
- The executable was launched and visually inspected. The layout reserves space for the details, action buttons and log/status footer at the initial window size.
- A real user-supplied `BAW_GVIIX_KT.zip` was revalidated without modification. In an isolated Community folder with a dummy base-package directory, the native API installed the original `BAW_GVIIX_KT` ID for `pmdg-aircraft-77er`, including 42 non-empty KTX2 textures and 93 layout entries. Uninstall removed the companion, preserved the dummy base and emptied the isolated registry. Size, timestamp and SHA-256 of the original archive were unchanged. No proprietary payload from this check is included in publication inputs.
- Release packaging uses a source allowlist; the Windows ZIP includes the executable, user documentation and runtime license notices. SHA-256 sums accompany both ZIPs.
- No existing `build`/`dist` content, third-party livery ZIPs, aircraft, textures, PMDG DLLs, SDK binaries, local installation registry, backups, credentials or local environment files are published.

## Limits

No end-to-end install into the user's active simulator folders, real third-party PTP revalidation, or in-simulator rendering/selection was performed in this release review. Real native ZIP revalidation is limited to the one British Airways archive described above. Unit tests cover the inherited PTP and bundle behaviors, and the separate SDK integration uses a synthetic texture. The binary is unsigned. These are verification limits, not hidden successful tests.

The GitHub workflow runs the suite on Windows/Python 3.11, 3.12 and 3.13 and builds packages for version tags or manual runs. Its actual run status is available in the repository's Actions tab.
