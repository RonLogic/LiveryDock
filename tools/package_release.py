"""Package reviewed project files only; never collect arbitrary workspace files."""
from __future__ import annotations

import hashlib
import importlib.metadata
from pathlib import Path
import sys
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = tomllib.loads((ROOT / "pyproject.toml").read_text("utf-8"))["project"]["version"]
TOP_LEVEL = (
    "README.md", "README_HE.md", "LICENSE", "CHANGELOG.md", "pyproject.toml",
    "main.pyw", "Run LiveryDock.cmd", "Build EXE.cmd", "LiveryDock.spec", ".gitignore",
    "requirements-build.txt",
)
FOLDERS = {"liverydock": {".py"}, "tests": {".py"}, "tools": {".py", ".txt"},
           "docs": {".md"}, ".github": {".yml", ".yaml", ".md"}}


def source_files() -> list[Path]:
    files = [ROOT / name for name in TOP_LEVEL]
    for folder, suffixes in FOLDERS.items():
        files.extend(p for p in (ROOT / folder).rglob("*") if p.is_file() and p.suffix in suffixes)
    for path in files:
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"Missing or linked release input: {path.relative_to(ROOT)}")
    return sorted(files)


def third_party_licenses() -> dict[str, bytes]:
    notices = {}
    for name in ("cryptography", "Pillow", "cffi", "pycparser", "pyinstaller"):
        dist = importlib.metadata.distribution(name)
        for file in dist.files or []:
            if not any(word in str(file).lower() for word in ("license", "copying", "notice")):
                continue
            path = Path(dist.locate_file(file))
            if path.is_file() and ".dist-info" in str(file):
                notices[f"THIRD_PARTY_LICENSES/{name}/{path.name}"] = path.read_bytes()
    python_license = Path(sys.base_prefix) / "LICENSE.txt"
    if not python_license.is_file():
        python_license = Path(sys.base_prefix) / "LICENSE"
    if not python_license.is_file():
        raise RuntimeError("Python license not found in the build runtime")
    notices["THIRD_PARTY_LICENSES/Python-LICENSE.txt"] = python_license.read_bytes()
    for library in ("tcl8.6", "tk8.6"):
        license_path = Path(sys.base_prefix) / "tcl" / library / "license.terms"
        if not license_path.is_file():
            # CPython's bundled third-party notices include the full Tcl/Tk terms.
            text = python_license.read_text("utf-8")
            if "Tcl/Tk" not in text or "Sun Microsystems" not in text:
                raise RuntimeError(f"Tcl/Tk license not found: {license_path}")
            notices[f"THIRD_PARTY_LICENSES/{library}-Python-bundled-notices.txt"] = python_license.read_bytes()
        else:
            notices[f"THIRD_PARTY_LICENSES/{library}-license.terms"] = license_path.read_bytes()
    return notices


def main() -> None:
    release = ROOT / "release"
    release.mkdir(exist_ok=True)
    binary = ROOT / "dist" / "LiveryDock.exe"
    if not binary.is_file():
        raise RuntimeError("Build dist/LiveryDock.exe before packaging")
    archives = []
    source = release / f"LiveryDock-{VERSION}-Source.zip"
    with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in source_files():
            archive.write(path, f"LiveryDock-{VERSION}/{path.relative_to(ROOT).as_posix()}")
    archives.append(source)
    windows = release / f"LiveryDock-{VERSION}-Windows-x64.zip"
    with zipfile.ZipFile(windows, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(binary, "LiveryDock.exe")
        for name in ("README.md", "README_HE.md", "LICENSE", "CHANGELOG.md"):
            archive.write(ROOT / name, name)
        for name, data in third_party_licenses().items():
            archive.writestr(name, data)
    archives.append(windows)
    checksum_lines = []
    for path in archives:
        with path.open("rb") as handle:
            checksum_lines.append(f"{hashlib.file_digest(handle, 'sha256').hexdigest()}  {path.name}")
    (release / "SHA256SUMS.txt").write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")
    print("\n".join(checksum_lines))


if __name__ == "__main__":
    main()
