from __future__ import annotations

import io
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
import zlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Iterable

from .core import LiveryDockError, UnsafeArchiveError, _safe_member_path

PTP_KEY = b"PMDG_SecurityCode"
ENCRYPTION_START = 0x38


@dataclass(slots=True)
class CabFile:
    name: str
    size: int
    offset: int
    folder_index: int


@dataclass(slots=True)
class CabFolder:
    data_offset: int
    block_count: int
    compression: int


def _blowfish_cipher():
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, modes
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms import Blowfish
        except ImportError:
            from cryptography.hazmat.primitives.ciphers.algorithms import Blowfish
    except ImportError as exc:
        raise LiveryDockError(
            "The built-in PTP engine requires the Python 'cryptography' package. "
            "Close LiveryDock and run 'Run LiveryDock.cmd' again; it installs this dependency automatically."
        ) from exc
    return Cipher(Blowfish(PTP_KEY), modes.ECB())


def _swap_words_32(data: bytes) -> bytes:
    if len(data) % 8:
        raise LiveryDockError("Invalid encrypted PTP block length.")
    out = bytearray(len(data))
    out[0::8] = data[3::8]
    out[1::8] = data[2::8]
    out[2::8] = data[1::8]
    out[3::8] = data[0::8]
    out[4::8] = data[7::8]
    out[5::8] = data[6::8]
    out[6::8] = data[5::8]
    out[7::8] = data[4::8]
    return bytes(out)


def decrypt_ptp_to_cab(ptp_path: Path, cab_path: Path) -> int:
    """Decrypt PMDG CRYP PTP into a standard MSCF CAB. Returns CAB logical size."""
    ptp_path = ptp_path.expanduser().resolve()
    if not ptp_path.is_file():
        raise LiveryDockError(f"PTP file not found: {ptp_path}")
    with ptp_path.open("rb") as src:
        header = src.read(ENCRYPTION_START)
        if len(header) < ENCRYPTION_START or header[:4] != b"CRYP":
            raise LiveryDockError("Not a supported PMDG PTP: CRYP cabinet header is missing.")
        cab_size = struct.unpack_from("<I", header, 8)[0]
        if cab_size < ENCRYPTION_START or cab_size > ptp_path.stat().st_size + 8:
            raise LiveryDockError("The PTP cabinet size field is invalid or the file is corrupt.")
        header = b"MSCF" + header[4:]
        cab_path.parent.mkdir(parents=True, exist_ok=True)
        cipher = _blowfish_cipher().decryptor()
        written = len(header)
        with cab_path.open("wb") as dst:
            dst.write(header)
            remaining = cab_size - ENCRYPTION_START
            while remaining > 0:
                # Blowfish operates in 8-byte blocks; source may include up to 7 padding bytes.
                want = min(8 * 8192, ((remaining + 7) // 8) * 8)
                chunk = src.read(want)
                if not chunk:
                    raise LiveryDockError("PTP ended before the encrypted CAB payload was complete.")
                usable = len(chunk) - (len(chunk) % 8)
                if usable <= 0:
                    raise LiveryDockError("PTP encrypted payload is not aligned to Blowfish blocks.")
                chunk = chunk[:usable]
                transformed = _swap_words_32(chunk)
                plain = cipher.update(transformed)
                plain = _swap_words_32(plain)
                take = min(remaining, len(plain))
                dst.write(plain[:take])
                written += take
                remaining -= take
            try:
                cipher.finalize()
            except Exception:
                pass
        if written != cab_size:
            raise LiveryDockError("Internal PTP decryption length mismatch.")
        return cab_size


def _read_c_string(handle) -> str:
    raw = bytearray()
    while True:
        b = handle.read(1)
        if not b:
            raise LiveryDockError("Unexpected end of CAB while reading a file name.")
        if b == b"\x00":
            break
        raw.extend(b)
        if len(raw) > 32768:
            raise LiveryDockError("CAB contains an unreasonable file name length.")
    for encoding in ("utf-8", "cp1252", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1", errors="replace")


def _parse_cab(cab_path: Path) -> tuple[list[CabFolder], list[CabFile], int]:
    with cab_path.open("rb") as f:
        hdr = f.read(36)
        if len(hdr) != 36 or hdr[:4] != b"MSCF":
            raise LiveryDockError("Decrypted PTP is not a valid Microsoft CAB file.")
        cb_cabinet = struct.unpack_from("<I", hdr, 8)[0]
        coff_files = struct.unpack_from("<I", hdr, 16)[0]
        c_folders, c_files, flags = struct.unpack_from("<HHH", hdr, 26)
        if cb_cabinet != cab_path.stat().st_size or not 36 <= coff_files < cb_cabinet:
            raise LiveryDockError("Corrupt CAB size or file table offset.")
        if flags & ~0x0007:
            raise LiveryDockError("CAB contains unsupported header flags.")
        reserve_folder = reserve_data = 0
        if flags & 0x0004:  # RESERVE_PRESENT
            reserve_hdr = f.read(4)
            if len(reserve_hdr) != 4:
                raise LiveryDockError("Corrupt CAB reserve header.")
            cb_header, reserve_folder, reserve_data = struct.unpack("<HBB", reserve_hdr)
            f.seek(cb_header, os.SEEK_CUR)
        if flags & 0x0001:  # PREV_CABINET
            _read_c_string(f); _read_c_string(f)
        if flags & 0x0002:  # NEXT_CABINET
            _read_c_string(f); _read_c_string(f)

        folders: list[CabFolder] = []
        for _ in range(c_folders):
            raw = f.read(8)
            if len(raw) != 8:
                raise LiveryDockError("Corrupt CAB folder table.")
            data_offset, block_count, compression = struct.unpack("<IHH", raw)
            if reserve_folder:
                f.seek(reserve_folder, os.SEEK_CUR)
            folders.append(CabFolder(data_offset, block_count, compression & 0x000F))

        if f.tell() > coff_files:
            raise LiveryDockError("CAB folder and file tables overlap.")

        f.seek(coff_files)
        files: list[CabFile] = []
        for _ in range(c_files):
            raw = f.read(16)
            if len(raw) != 16:
                raise LiveryDockError("Corrupt CAB file table.")
            size, offset, folder_index, _date, _time, _attrs = struct.unpack("<IIHHHH", raw)
            name = _read_c_string(f).replace("\\", "/")
            _safe_member_path(name)
            if folder_index >= len(folders):
                raise LiveryDockError("Split/multi-cabinet PTP files are not supported by the built-in extractor.")
            files.append(CabFile(name, size, offset, folder_index))
        table_end = f.tell()
        for folder in folders:
            if not table_end <= folder.data_offset <= cb_cabinet or (folder.block_count and folder.data_offset == cb_cabinet):
                raise LiveryDockError("CAB folder data points outside the cabinet payload.")
        return folders, files, reserve_data


def _inflate_folder(cab_path: Path, folder: CabFolder, reserve_data: int, output: BinaryIO | None = None) -> bytes:
    if folder.compression not in (0, 1):
        raise LiveryDockError(
            f"Unsupported PTP CAB compression type {folder.compression}. "
            "The built-in engine currently supports uncompressed and MSZIP PMDG packages."
        )
    out = bytearray()
    history = b""
    with cab_path.open("rb") as f:
        f.seek(folder.data_offset)
        for _ in range(folder.block_count):
            raw = f.read(8)
            if len(raw) != 8:
                raise LiveryDockError("Corrupt CAB data block header.")
            _checksum, cb_data, cb_uncomp = struct.unpack("<IHH", raw)
            # CAB blocks expand to at most 32 KiB. Bound zlib before allocating
            # output, rather than checking a potentially huge expansion later.
            if not 0 < cb_uncomp <= 32768:
                raise LiveryDockError("Invalid or split CAB data block size.")
            if reserve_data:
                f.seek(reserve_data, os.SEEK_CUR)
            data = f.read(cb_data)
            if len(data) != cb_data:
                raise LiveryDockError("Corrupt CAB data block.")
            if folder.compression == 0:
                block = data
            else:
                if len(data) < 2 or data[:2] != b"CK":
                    raise LiveryDockError("Invalid MSZIP block in PMDG PTP.")
                try:
                    dec = zlib.decompressobj(-15, zdict=history) if history else zlib.decompressobj(-15)
                    block = dec.decompress(data[2:], cb_uncomp + 1)
                    if dec.unconsumed_tail or not dec.eof or dec.unused_data:
                        raise LiveryDockError("Invalid or oversized PMDG PTP MSZIP block.")
                except zlib.error as exc:
                    raise LiveryDockError(f"Could not decompress PMDG PTP MSZIP block: {exc}") from exc
                history = (history + block)[-32768:]
            if len(block) != cb_uncomp:
                raise LiveryDockError("PMDG PTP decompression produced an unexpected block size.")
            if output is None:
                out.extend(block)
            else:
                output.write(block)
    return bytes(out)


def extract_pmdg_ptp(ptp_path: Path, destination: Path) -> list[Path]:
    """Fully offline PMDG PTP extraction. Does not use CabLib.dll or PMDG OC."""
    destination = destination.expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=True)
    temp = Path(tempfile.mkdtemp(prefix="liverydock-cab-"))
    cab = temp / "payload.cab"
    try:
        decrypt_ptp_to_cab(ptp_path, cab)
        folders, files, reserve_data = _parse_cab(cab)
        # Inflate to temporary files so large liveries do not accumulate every
        # uncompressed CAB folder in memory at the same time.
        folder_payloads: dict[int, Path] = {}
        for idx, folder in enumerate(folders):
            payload_path = temp / f"folder-{idx}.bin"
            with payload_path.open("wb") as handle:
                _inflate_folder(cab, folder, reserve_data, output=handle)
            folder_payloads[idx] = payload_path
        destinations: list[tuple[CabFile, Path]] = []
        seen: set[str] = set()
        for entry in files:
            rel = _safe_member_path(entry.name)
            dest = destination.joinpath(*rel.parts)
            try:
                dest.resolve().relative_to(destination)
            except ValueError as exc:
                raise UnsafeArchiveError(f"PTP file escapes the extraction folder: {entry.name}") from exc
            key = str(dest).casefold()
            if key in seen:
                raise UnsafeArchiveError(f"PTP contains duplicate file destinations: {entry.name}")
            seen.add(key)
            if entry.offset + entry.size > folder_payloads[entry.folder_index].stat().st_size:
                raise LiveryDockError(f"PTP file entry points outside decompressed data: {entry.name}")
            destinations.append((entry, dest))
        extracted: list[Path] = []
        for entry, dest in destinations:
            dest.parent.mkdir(parents=True, exist_ok=True)
            with folder_payloads[entry.folder_index].open("rb") as payload, dest.open("wb") as handle:
                payload.seek(entry.offset)
                remaining = entry.size
                while remaining:
                    chunk = payload.read(min(remaining, 1024 * 1024))
                    if not chunk:
                        raise LiveryDockError(f"PTP folder data ended unexpectedly: {entry.name}")
                    handle.write(chunk)
                    remaining -= len(chunk)
            extracted.append(dest)
        if not extracted:
            raise LiveryDockError("PTP contained no files.")
        return extracted
    finally:
        shutil.rmtree(temp, ignore_errors=True)


def parse_ini_like(path: Path) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    section = ""
    try:
        lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    except OSError:
        return result
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith((";", "#")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            result.setdefault(section, {})
            continue
        key, sep, value = line.partition("=")
        if sep:
            result.setdefault(section, {})[key.strip().lower()] = value.strip().strip('"')
    return result


def read_legacy_pmdg_metadata(extracted: Path) -> dict[str, str]:
    cfg = parse_ini_like(extracted / "Config.cfg")
    settings = parse_ini_like(extracted / "Settings.dat")
    flt = next((v for k, v in cfg.items() if k.startswith("fltsim.")), {})
    st = settings.get("settings", {})
    merged = {
        "title": flt.get("title", st.get("name", extracted.name)),
        "atc_airline": flt.get("atc_airline", ""),
        "icao_airline": flt.get("icao_airline", ""),
        "atc_id": flt.get("atc_id", ""),
        "ui_variation": flt.get("ui_variation", flt.get("title", st.get("name", ""))),
        "model": flt.get("model", ""),
        "sim": flt.get("sim", ""),
        "texture": flt.get("texture", ""),
        "aircraft": st.get("aircraft", ""),
        "variant": st.get("variant", ""),
        "name": st.get("name", ""),
    }
    return merged


def infer_737_tags(meta: dict[str, str], product_code: str) -> list[str]:
    haystack = " ".join(meta.values()).upper()
    model = meta.get("model", "").upper()
    # Product exterior tag names used by PMDG native MSFS 2024 liveries.
    if product_code == "739":
        ext = "b739er_ext" if ("900ER" in haystack or "ER" in model) else "b739_ext"
    elif product_code == "738":
        ext = "b738_ext"
    elif product_code == "737":
        ext = "b737_ext"
    elif product_code == "736":
        ext = "b736_ext"
    else:
        ext = f"b{product_code}_ext" if product_code else ""
    wing = "SSW" if "SSW" in model or "SCIMITAR" in haystack else "BW"
    tags = [ext] if ext else []
    tags.extend([f"{wing}_L", f"{wing}_R"])
    return tags


def find_msfs2024_sdk() -> Path | None:
    candidates: list[Path] = []
    for env in ("MSFS2024_SDK", "MSFS_SDK_2024"):
        value = os.environ.get(env)
        if value:
            candidates.append(Path(value))
    for drive in (os.environ.get("SystemDrive", "C:"), "C:", "D:", "E:"):
        candidates.append(Path(f"{drive}\\MSFS 2024 SDK"))
    for candidate in candidates:
        tool = candidate / "Tools" / "bin" / "fspackagetool.exe"
        if tool.is_file():
            return candidate.resolve()
        tool = candidate / "tools" / "bin" / "fspackagetool.exe"
        if tool.is_file():
            return candidate.resolve()
    return None


def _texture_kind(name: str) -> str:
    u = name.upper()
    if "_COMP" in u:
        return "MTL_BITMAP_METAL_ROUGH_AO"
    if "_NORM" in u:
        return "MTL_BITMAP_NORMAL"
    return "MTL_BITMAP_DECAL0"


def _source_image_name(dds: Path) -> str:
    # Preserve the source base name expected by MSFS (FOO.PNG.DDS -> FOO.PNG).
    name = dds.name
    if name.lower().endswith(".dds"):
        name = name[:-4]
    if not name.lower().endswith((".png", ".tif", ".tiff")):
        name += ".PNG"
    return name


def _dds_to_source_image(dds: Path, output: Path) -> Path:
    try:
        from PIL import Image
    except ImportError as exc:
        raise LiveryDockError(
            "DDS conversion requires Pillow. Re-run 'Run LiveryDock.cmd'; it installs Pillow automatically."
        ) from exc
    out = output / _source_image_name(dds)
    out.parent.mkdir(parents=True, exist_ok=True)
    try:
        try:
            image_ctx = Image.open(dds)
        except NotImplementedError:
            raise
        except Exception as first_exc:
            # Pillow treats some DXGI *_SRGB codes as unsupported even though the
            # BC payload is byte-for-byte compatible with the matching UNORM decoder.
            # Patch only the DX10 format id in memory; the source DDS is never modified.
            raw = bytearray(dds.read_bytes())
            if len(raw) < 148 or raw[:4] != b"DDS ":
                raise first_exc
            dxgi = struct.unpack_from("<I", raw, 128)[0]
            srgb_to_unorm = {72: 71, 75: 74, 78: 77, 99: 98}
            if dxgi not in srgb_to_unorm:
                raise first_exc
            struct.pack_into("<I", raw, 128, srgb_to_unorm[dxgi])
            image_ctx = Image.open(io.BytesIO(raw))
        with image_ctx as image:
            image.load()
            # Keep alpha where present; SDK handles output compression.
            if out.suffix.lower() in {".tif", ".tiff"}:
                image.save(out, format="TIFF")
            else:
                image.save(out, format="PNG")
    except Exception as exc:
        # One more in-memory sRGB fallback for Pillow's explicit NotImplementedError.
        try:
            raw = bytearray(dds.read_bytes())
            if len(raw) >= 148 and raw[:4] == b"DDS ":
                dxgi = struct.unpack_from("<I", raw, 128)[0]
                srgb_to_unorm = {72: 71, 75: 74, 78: 77, 99: 98}
                if dxgi in srgb_to_unorm:
                    struct.pack_into("<I", raw, 128, srgb_to_unorm[dxgi])
                    with Image.open(io.BytesIO(raw)) as image:
                        image.load()
                        image.save(out, format="TIFF" if out.suffix.lower() in {".tif", ".tiff"} else "PNG")
                    return out
        except Exception:
            pass
        raise LiveryDockError(f"Could not convert DDS texture {dds.name}: {exc}") from exc
    return out


def _write_bitmap_xml(image: Path) -> None:
    kind = _texture_kind(image.name)
    extra = "\n  <ForceNoAlpha>true</ForceNoAlpha>" if kind == "MTL_BITMAP_METAL_ROUGH_AO" else ""
    xml = (
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
        "<BitmapConfiguration>\n"
        f"  <BitmapSlot>{kind}</BitmapSlot>\n"
        "  <UserFlags type=\"_DEFAULT\">QUALITYHIGH</UserFlags>"
        f"{extra}\n"
        "</BitmapConfiguration>\n"
    )
    Path(str(image) + ".xml").write_text(xml, encoding="utf-8")


def convert_dds_to_ktx2(dds_files: list[Path], sdk_root: Path, output: Path, steam: bool = False) -> list[Path]:
    """Convert legacy DDS textures with the official MSFS 2024 SDK package builder."""
    if not dds_files:
        raise LiveryDockError("No DDS textures were supplied for conversion.")
    expected: set[str] = set()
    for dds in dds_files:
        name = (_source_image_name(dds) + ".KTX2").casefold()
        if name in expected:
            raise LiveryDockError(f"PTP contains conflicting texture names: {dds.name}")
        expected.add(name)
    sdk_root = sdk_root.expanduser().resolve()
    tool = sdk_root / "Tools" / "bin" / "fspackagetool.exe"
    if not tool.is_file():
        tool = sdk_root / "tools" / "bin" / "fspackagetool.exe"
    if not tool.is_file():
        raise LiveryDockError(
            "MSFS 2024 SDK was not found. Install it from MSFS 2024 Developer Mode (Help > SDK Installer), then restart LiveryDock."
        )
    work = Path(tempfile.mkdtemp(prefix="liverydock-ktx2-"))
    try:
        tex_src = work / "PackageSources" / "SimObjects" / "Airplanes" / "liverydock-textures" / "common" / "texture"
        tex_src.mkdir(parents=True, exist_ok=True)
        (work / "PackageDefinitions").mkdir(parents=True, exist_ok=True)
        for dds in dds_files:
            image = _dds_to_source_image(dds, tex_src)
            _write_bitmap_xml(image)
        package_def = """<?xml version=\"1.0\" encoding=\"utf-8\"?>
<AssetPackage Version=\"0.1.0\">
  <ItemSettings><ContentType>AIRCRAFT</ContentType><Title>LiveryDock Texture Converter</Title><Manufacturer>LiveryDock</Manufacturer><Creator>LiveryDock</Creator></ItemSettings>
  <Flags><VisibleInStore>false</VisibleInStore><CanBeReferenced>false</CanBeReferenced></Flags>
  <AssetGroups><AssetGroup Name=\"Textures\"><Type>ModularSimObject</Type><Flags><FSXCompatibility>false</FSXCompatibility></Flags><AssetDir>PackageSources\\SimObjects\\Airplanes\\liverydock-textures\\</AssetDir><outputDir>SimObjects\\Airplanes\\liverydock-textures\\</outputDir></AssetGroup></AssetGroups>
</AssetPackage>
"""
        (work / "PackageDefinitions" / "liverydock-textures.xml").write_text(package_def, encoding="utf-8")
        project = """<?xml version=\"1.0\" encoding=\"utf-8\"?>
<Project Version=\"2\" Name=\"LiveryDockTextures\" FolderName=\"Packages\" MetadataFolderName=\"PackagesMetadata\"><OutputDirectory>.</OutputDirectory><TemporaryOutputDirectory>_PackageInt</TemporaryOutputDirectory><Packages><Package>PackageDefinitions\\liverydock-textures.xml</Package></Packages></Project>
"""
        project_path = work / "liverydock-textures.xml"
        project_path.write_text(project, encoding="utf-8")
        # FsPackageTool 2024 expects the project XML as the first argument,
        # followed by optional switches. Passing switches before the project can
        # make recent SDK builds parse the project path twice and fail with
        # "more than one XML project path given".
        args = [str(tool), str(project_path)]
        if steam:
            args.append("-forcesteam")
        args.extend(["-rebuild", "-nopause"])
        proc = subprocess.run(args, cwd=str(work), capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()
            raise LiveryDockError(f"MSFS 2024 SDK texture conversion failed: {detail or f'exit code {proc.returncode}'}")
        built = work / "Packages" / "liverydock-textures" / "SimObjects" / "Airplanes" / "liverydock-textures" / "common" / "texture"
        if not built.is_dir():
            raise LiveryDockError(
                "MSFS 2024 SDK finished but did not create the expected KTX2 output. Check BuilderLogError.txt and ensure the SDK matches your MSFS 2024 installation."
            )
        actual = {p.name.casefold() for p in built.iterdir() if p.is_file() and p.suffix.lower() == ".ktx2" and p.stat().st_size}
        missing = expected - actual
        if missing:
            raise LiveryDockError(f"SDK did not produce all required KTX2 textures: {', '.join(sorted(missing))}")
        output.mkdir(parents=True, exist_ok=True)
        results: list[Path] = []
        for item in built.iterdir():
            if item.is_file() and (item.name.lower().endswith(".ktx2") or item.name.lower().endswith(".ktx2.json")):
                dest = output / item.name
                shutil.copy2(item, dest)
                results.append(dest)
        if not any(p.name.lower().endswith(".ktx2") for p in results):
            raise LiveryDockError("SDK produced no KTX2 textures.")
        return results
    finally:
        shutil.rmtree(work, ignore_errors=True)


def find_native_pmdg_templates(search_roots: Iterable[Path], product_code: str) -> list[Path]:
    candidates: list[Path] = []
    for root in search_roots:
        if not root or not root.exists():
            continue
        # Narrow to product packages first where possible.
        package_names = [f"pmdg-aircraft-{product_code}", f"pmdg-aircraft-{product_code}-liveries"]
        packages = [root / name for name in package_names]
        packages.extend([p for p in root.glob(f"pmdg-aircraft-{product_code}*") if p.is_dir()])
        for package in dict.fromkeys(packages):
            if not package.is_dir():
                continue
            try:
                for cfg in package.rglob("livery.cfg"):
                    parent = cfg.parent
                    if "liveries" in {part.lower() for part in parent.parts} and parent.is_dir():
                        candidates.append(parent)
            except OSError:
                continue
    # Unique, shallower paths first.
    uniq: dict[str, Path] = {}
    for p in candidates:
        uniq[str(p.resolve()).lower()] = p.resolve()
    return sorted(uniq.values(), key=lambda p: (len(p.parts), str(p).lower()))


def _required_tags(livery_dir: Path) -> set[str]:
    data = parse_ini_like(livery_dir / "livery.cfg")
    value = data.get("selection", {}).get("required_tags", "")
    return {v.strip().lower() for v in value.split(",") if v.strip()}


def choose_native_template(templates: list[Path], desired_tags: list[str]) -> Path | None:
    desired = {t.lower() for t in desired_tags}
    if not templates:
        return None
    ranked: list[tuple[int, Path]] = []
    for template in templates:
        tags = _required_tags(template)
        score = len(desired & tags) * 10 - len(desired - tags) * 3
        if desired and desired <= tags:
            score += 100
        # Prefer house/blank liveries as a clean fallback texture source.
        name = template.name.lower()
        if "house" in name or "blank" in name or "pmdg" in name:
            score += 2
        ranked.append((score, template))
    ranked.sort(key=lambda item: (-item[0], str(item[1]).lower()))
    return ranked[0][1]


def safe_livery_id(meta: dict[str, str], fallback: str) -> str:
    base = "_".join(v for v in (meta.get("atc_airline"), meta.get("atc_id")) if v).strip("_") or fallback
    base = re.sub(r"[^A-Za-z0-9_-]+", "_", base).strip("_")
    return base or "converted_livery"


def _update_cfg_file(path: Path, meta: dict[str, str], desired_tags: list[str]) -> None:
    # Generate a clean PMDG/MSFS 2024 modular livery.cfg while preserving version from template when possible.
    existing = parse_ini_like(path)
    version = existing.get("version", {})
    major = version.get("major", "1")
    minor = version.get("minor", "4")
    name = meta.get("ui_variation") or meta.get("title") or meta.get("name") or "Converted Livery"
    content = (
        "[Version]\n"
        f"major = {major}\nminor = {minor}\n\n"
        "[Selection]\n"
        f"required_tags = {','.join(desired_tags)}\n\n"
        "[GENERAL]\n"
        f"name = {name}\n"
        f"atc_airline = {meta.get('atc_airline','')}\n"
        f"icao_airline = {meta.get('icao_airline','')}\n"
        f"ui_variation = {name}\n\n"
        "[FLTSIM]\n"
        f"atc_id = {meta.get('atc_id','')}\n"
    )
    path.write_text(content, encoding="utf-8")


def _update_livery_json(path: Path, meta: dict[str, str], livery_id: str, desired_tags: list[str]) -> None:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig")) if path.exists() else {}
    except (OSError, json.JSONDecodeError):
        data = {}
    title = meta.get("atc_airline") or meta.get("name") or meta.get("ui_variation") or "Converted Livery"
    reg = meta.get("atc_id", "")
    data.update({
        "title": title,
        "subtitle": f"({reg})" if reg else "",
        "airline": meta.get("atc_airline", ""),
        "airlineIcao": meta.get("icao_airline", ""),
        "registration": reg,
        "liveryId": livery_id,
        "tags": [tag.replace("_L", "").replace("_R", "") for tag in desired_tags if tag in {"BW_L", "SSW_L"}],
    })
    data.setdefault("rev", 2)
    data.setdefault("version", 1000)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def build_native_livery_from_legacy(
    extracted: Path,
    template: Path,
    destination_livery: Path,
    product_code: str,
    sdk_root: Path,
    steam: bool = False,
) -> tuple[dict[str, str], list[str]]:
    meta = read_legacy_pmdg_metadata(extracted)
    desired_tags = infer_737_tags(meta, product_code)
    destination_livery.parent.mkdir(parents=True, exist_ok=True)
    if destination_livery.exists():
        shutil.rmtree(destination_livery)
    shutil.copytree(template, destination_livery)

    # Texture folder is always simply 'texture' in native modular liveries.
    tex_dest = destination_livery / "texture"
    tex_dest.mkdir(parents=True, exist_ok=True)
    texture_dirs = [p for p in extracted.iterdir() if p.is_dir() and p.name.lower().startswith("texture")]
    dds_files: list[Path] = []
    for tex in texture_dirs:
        dds_files.extend([p for p in tex.rglob("*") if p.is_file() and p.suffix.lower() == ".dds"])
    if not dds_files:
        raise LiveryDockError("The PTP contains no DDS textures to convert.")
    convert_dds_to_ktx2(dds_files, sdk_root, tex_dest, steam=steam)

    _update_cfg_file(destination_livery / "livery.cfg", meta, desired_tags)
    livery_id = safe_livery_id(meta, destination_livery.name)
    _update_livery_json(destination_livery / "livery.json", meta, livery_id, desired_tags)

    # Preserve PMDG airframe options for manual/work-folder use; native template options remain if present.
    aircraft_ini = extracted / "Aircraft.ini"
    if aircraft_ini.is_file():
        shutil.copy2(aircraft_ini, destination_livery / "options.ini")
    return meta, desired_tags
