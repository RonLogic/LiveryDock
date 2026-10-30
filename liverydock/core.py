from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import uuid
import zipfile
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path, PurePosixPath
import threading
from typing import Any, Iterable, Literal


class LiveryDockError(RuntimeError):
    """Base exception for user-facing LiveryDock failures."""


class UnsafeArchiveError(LiveryDockError):
    """Raised when an archive contains unsafe paths or links."""


class PackageValidationError(LiveryDockError):
    """Raised when a folder is not a valid installable MSFS package."""


PackageFormat = Literal["native-2024", "legacy-2020", "pmdg-ptp", "pmdg-native-2024", "unknown"]
TargetKind = Literal["community2024", "community"]


@dataclass(slots=True)
class CommunityPaths:
    community2024: Path | None
    community: Path | None
    source: str
    usercfg: Path | None = None


@dataclass(slots=True)
class PackageAnalysis:
    package_root: Path
    package_name: str
    title: str
    creator: str
    version: str
    content_type: str
    is_livery: bool
    package_format: PackageFormat
    target_hint: TargetKind
    reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    manifest: dict[str, Any] = field(default_factory=dict)
    source_kind: str = "package"
    ptp_product_code: str = ""
    ptp_target_package: str = ""
    pmdg_product_package: str = ""
    pmdg_livery_id: str = ""
    pmdg_airplane_folder: str = ""
    pmdg_bundle_entries: list[str] = field(default_factory=list)

    @property
    def display_name(self) -> str:
        return self.title or self.package_name


@dataclass(slots=True)
class PreparedSource:
    source: Path
    root: Path
    package_roots: list[Path]
    temporary_root: Path | None = None
    source_kind: str = "package"

    def cleanup(self) -> None:
        if self.temporary_root and self.temporary_root.exists():
            shutil.rmtree(self.temporary_root, ignore_errors=True)


@dataclass(slots=True)
class InstallRecord:
    id: str
    package_name: str
    title: str
    version: str
    package_format: PackageFormat
    target_kind: TargetKind
    destination: str
    source: str
    backup: str | None
    installed_at: str
    manifest_sha256: str
    install_kind: str = "package"
    metadata: dict[str, Any] = field(default_factory=dict)


_USERCFG_RE = re.compile(r'^\s*InstalledPackagesPath\s+"(?P<path>.+?)"\s*$', re.IGNORECASE)
_INVALID_NAME_CHARS = re.compile(r"[^a-zA-Z0-9._-]+")
_WINDOWS_RESERVED_RE = re.compile(
    r"(?:con|prn|aux|nul|conin\$|conout\$|com[1-9¹²³]|lpt[1-9¹²³])[ .]*(?:\..*)?",
    re.IGNORECASE,
)


def app_data_root() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    if base:
        return Path(base) / "LiveryDock"
    return Path.home() / ".liverydock"


def registry_path() -> Path:
    return app_data_root() / "installed.json"


def log_path() -> Path:
    return app_data_root() / "liverydock.log"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def append_log(message: str) -> None:
    # A full or unavailable log must not turn a committed installation into a
    # failed transaction or prevent an otherwise valid uninstall.
    try:
        root = app_data_root()
        root.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().astimezone().isoformat(timespec="seconds")
        with log_path().open("a", encoding="utf-8") as handle:
            handle.write(f"[{stamp}] {message}\n")
    except OSError:
        pass


def parse_usercfg(path: Path) -> Path | None:
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return None
    for line in text.splitlines():
        match = _USERCFG_RE.match(line)
        if match:
            raw = os.path.expandvars(match.group("path"))
            return Path(raw)
    return None


def _candidate_usercfg_files() -> list[Path]:
    appdata = Path(os.environ.get("APPDATA", Path.home() / "AppData/Roaming"))
    local = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local"))
    return [
        appdata / "Microsoft Flight Simulator 2024" / "UserCfg.opt",
        local / "Packages" / "Microsoft.Limitless_8wekyb3d8bbwe" / "LocalCache" / "UserCfg.opt",
        local / "Packages" / "Microsoft.Limitless_8wekyb3d8bbwe" / "LocalState" / "UserCfg.opt",
    ]


def detect_community_paths() -> CommunityPaths:
    """Detect MSFS 2024 package roots without modifying UserCfg.opt."""
    for cfg in _candidate_usercfg_files():
        base = parse_usercfg(cfg)
        if base:
            return CommunityPaths(
                community2024=base / "Community2024",
                community=base / "Community",
                source=f"UserCfg.opt ({cfg})",
                usercfg=cfg,
            )

    appdata = Path(os.environ.get("APPDATA", Path.home() / "AppData/Roaming"))
    local = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local"))
    steam_base = appdata / "Microsoft Flight Simulator 2024" / "Packages"
    store_base = local / "Packages" / "Microsoft.Limitless_8wekyb3d8bbwe" / "LocalCache" / "Packages"

    candidates = [steam_base, store_base]
    existing = next((candidate for candidate in candidates if candidate.exists()), None)
    base = existing or steam_base
    source = "default existing path" if existing else "default Steam path (not yet confirmed)"
    return CommunityPaths(base / "Community2024", base / "Community", source)


def _safe_member_path(name: str) -> PurePosixPath:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if not normalized or normalized in {".", "./"}:
        return path
    if path.is_absolute() or normalized.startswith("/"):
        raise UnsafeArchiveError(f"Archive contains an absolute path: {name}")
    if re.match(r"^[A-Za-z]:", normalized):
        raise UnsafeArchiveError(f"Archive contains a drive-qualified path: {name}")
    if any(part == ".." for part in path.parts):
        raise UnsafeArchiveError(f"Archive attempts path traversal: {name}")
    for part in path.parts:
        if (part.endswith((".", " ")) or re.search(r'[<>:"|?*\x00-\x1f]', part)
                or _WINDOWS_RESERVED_RE.fullmatch(part)):
            raise UnsafeArchiveError(f"Archive contains an unsafe Windows filename: {name}")
    return path


def _is_link(path: Path) -> bool:
    if path.is_symlink():
        return True
    try:
        # Python 3.11 has no Path.is_junction(). Windows exposes both junctions
        # and symbolic links through their reparse tags in lstat().
        return getattr(path.lstat(), "st_reparse_tag", 0) in {0xA0000003, 0xA000000C}
    except FileNotFoundError:
        return False


def _reject_link_ancestors(path: Path) -> None:
    for candidate in (path, *path.parents):
        if _is_link(candidate):
            raise LiveryDockError(f"Refusing to follow a symbolic link or junction: {candidate}")


def ensure_safe_tree(root: Path) -> None:
    """Validate a copied/written tree without traversing links or junctions."""
    _reject_link_ancestors(root)
    if not root.exists():
        return
    pending = [root]
    while pending:
        folder = pending.pop()
        if not folder.is_dir():
            continue
        for child in folder.iterdir():
            if _is_link(child):
                raise LiveryDockError(f"Package contains a symbolic link or junction: {child}")
            if child.is_dir():
                pending.append(child)


def safe_target_path(root: Path, relative: str | Path) -> Path:
    """Resolve an untrusted relative filename inside a writable package."""
    rel = _safe_member_path(str(relative))
    if not rel.parts:
        raise LiveryDockError("An empty relative path is not a managed file or livery.")
    destination = root.joinpath(*rel.parts)
    _reject_link_ancestors(destination)
    try:
        destination.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise LiveryDockError("Managed path escapes its package folder.") from exc
    return destination


def validate_livery_relative_path(raw: str) -> PurePosixPath:
    rel = _safe_member_path(raw)
    if (len(rel.parts) != 6 or tuple(part.casefold() for part in rel.parts[:2]) != ("simobjects", "airplanes")
            or tuple(part.casefold() for part in rel.parts[3:5]) != ("liveries", "pmdg")):
        raise LiveryDockError("Managed livery path must identify one PMDG livery folder.")
    return rel


def _same_destination(first: str, second: str) -> bool:
    return str(Path(first).resolve()).casefold() == str(Path(second).resolve()).casefold()


def _managed_livery_paths(record: InstallRecord) -> set[str]:
    if record.install_kind == "pmdg-native":
        raw = record.metadata.get("livery_rels", [])
        return {str(item).replace("\\", "/").casefold() for item in raw} if isinstance(raw, list) else set()
    raw = record.metadata.get("livery_rel", "")
    return {str(raw).replace("\\", "/").casefold()} if raw else set()


_OPERATION_LOCK = threading.RLock()
_OPERATION_STATE = threading.local()


@contextmanager
def mutation_lock():
    """Serialize filesystem/registry transactions across threads and app instances."""
    with _OPERATION_LOCK:
        if getattr(_OPERATION_STATE, "active", False):
            yield
            return
        root = app_data_root()
        root.mkdir(parents=True, exist_ok=True)
        lock = (root / "operation.lock").open("a+b")
        locked = False
        try:
            lock.seek(0, os.SEEK_END)
            if not lock.tell():
                lock.write(b"0")
                lock.flush()
            lock.seek(0)
            try:
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise LiveryDockError("Another LiveryDock instance is changing installed liveries. Try again when it finishes.") from exc
            locked = True
            _OPERATION_STATE.active = True
            yield
        finally:
            _OPERATION_STATE.active = False
            if locked:
                lock.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            lock.close()


def serialized_operation(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        with mutation_lock():
            return function(*args, **kwargs)
    return wrapped


def _is_zip_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    return (mode & 0o170000) == 0o120000


def safe_extract_zip(archive: Path, destination: Path) -> None:
    _reject_link_ancestors(destination)
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as zf:
        seen: set[str] = set()
        for info in zf.infolist():
            rel = _safe_member_path(info.filename)
            if _is_zip_symlink(info):
                raise UnsafeArchiveError(f"Archive contains a symbolic link: {info.filename}")
            if not rel.parts:
                if info.is_dir():
                    continue
                raise UnsafeArchiveError("Archive contains an empty file path.")
            key = rel.as_posix().casefold()
            if key in seen:
                raise UnsafeArchiveError(f"Archive contains duplicate Windows paths: {info.filename}")
            seen.add(key)
            safe_target_path(destination, rel.as_posix())
        for info in zf.infolist():
            rel = _safe_member_path(info.filename)
            if not rel.parts:
                continue
            target = safe_target_path(destination, rel.as_posix())
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output, 1024 * 1024)


def find_7zip() -> Path | None:
    candidates: list[Path] = []
    for env_name in ("ProgramFiles", "ProgramFiles(x86)"):
        value = os.environ.get(env_name)
        if value:
            candidates.append(Path(value) / "7-Zip" / "7z.exe")
    for name in ("7z", "7zz", "7za"):
        resolved = shutil.which(name)
        if resolved:
            candidates.append(Path(resolved))
    return next((path for path in candidates if path.exists()), None)


def _list_7zip_entries(seven_zip: Path, archive: Path) -> list[str]:
    proc = subprocess.run(
        [str(seven_zip), "l", "-slt", "-sccUTF-8", str(archive)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if proc.returncode != 0:
        raise LiveryDockError(proc.stderr.strip() or proc.stdout.strip() or "7-Zip could not read the archive.")
    entries: list[str] = []
    in_items = False
    for line in proc.stdout.splitlines():
        if line.startswith("----------"):
            in_items = True
            continue
        if in_items and line.startswith("Path = "):
            entries.append(line[7:])
        if in_items and (
            (line.startswith(("Symbolic Link = ", "Hard Link = ")) and line.partition(" = ")[2].strip())
            or line.startswith("Reparse = +")
            or (line.startswith(("Attributes = ", "Mode = ")) and re.search(r"\bl[rwx-]{9}\b", line))
        ):
            raise UnsafeArchiveError("Archive contains a symbolic link, hard link, or junction.")
    return entries


def safe_extract_7zip(archive: Path, destination: Path) -> None:
    seven_zip = find_7zip()
    if not seven_zip:
        raise LiveryDockError(
            "RAR/7Z support requires 7-Zip. Install 7-Zip or extract the archive manually and add the folder."
        )
    entries = _list_7zip_entries(seven_zip, archive)
    _reject_link_ancestors(destination)
    seen: set[str] = set()
    for entry in entries:
        rel = _safe_member_path(entry)
        key = rel.as_posix().casefold()
        if key in seen:
            raise UnsafeArchiveError(f"Archive contains duplicate Windows paths: {entry}")
        seen.add(key)
        safe_target_path(destination, rel.as_posix())
    # Do not let an external extractor follow pre-existing links inside a
    # destination selected by its caller.
    ensure_safe_tree(destination)
    destination.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        [str(seven_zip), "x", "-y", f"-o{destination}", str(archive)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if proc.returncode not in (0, 1):
        raise LiveryDockError(proc.stderr.strip() or proc.stdout.strip() or "7-Zip extraction failed.")
    ensure_safe_tree(destination)


def discover_package_roots(root: Path, max_packages: int = 100) -> list[Path]:
    roots: list[Path] = []
    if (root / "manifest.json").is_file() and (root / "layout.json").is_file():
        roots.append(root)
    try:
        manifests = root.rglob("manifest.json")
        for manifest in manifests:
            parent = manifest.parent
            if "__MACOSX" in parent.parts:
                continue
            if (parent / "layout.json").is_file() and parent not in roots:
                roots.append(parent)
                if len(roots) >= max_packages:
                    break
    except OSError as exc:
        raise LiveryDockError(f"Could not scan package folder: {exc}") from exc
    return sorted(roots, key=lambda p: (len(p.parts), str(p).lower()))


def prepare_source(source: Path) -> PreparedSource:
    source = source.expanduser().resolve()
    if not source.exists():
        raise LiveryDockError(f"Source does not exist: {source}")

    # PMDG native MSFS 2024 liveries are commonly distributed as lightweight
    # livery ZIPs/folders without manifest.json/layout.json. Detect those before
    # the generic MSFS package path. Import lazily to avoid a module cycle.
    from .pmdg_native import detect_native_source_kind

    if source.is_dir():
        ensure_safe_tree(source)
        roots = discover_package_roots(source)
        if roots:
            return PreparedSource(source=source, root=source, package_roots=roots)
        native_kind = detect_native_source_kind(source)
        if native_kind:
            return PreparedSource(source=source, root=source, package_roots=[], source_kind=native_kind)
        raise PackageValidationError(
            "No installable livery was found. Expected an MSFS package (manifest.json + layout.json) "
            "or a PMDG native livery folder (livery.json + livery.cfg)."
        )

    suffix = source.suffix.lower()
    if suffix == ".ptp":
        return PreparedSource(
            source=source,
            root=source.parent,
            package_roots=[],
            temporary_root=None,
            source_kind="pmdg-ptp",
        )
    if suffix not in {".zip", ".rar", ".7z"}:
        raise LiveryDockError("Supported inputs are ZIP, RAR, 7Z, PTP, or an extracted folder.")

    if suffix == ".zip":
        native_kind = detect_native_source_kind(source)
        if native_kind:
            return PreparedSource(
                source=source,
                root=source.parent,
                package_roots=[],
                temporary_root=None,
                source_kind=native_kind,
            )

    temp_root = Path(tempfile.mkdtemp(prefix="liverydock-"))
    extract_root = temp_root / "extracted"
    try:
        if suffix == ".zip":
            safe_extract_zip(source, extract_root)
        else:
            safe_extract_7zip(source, extract_root)
        roots = discover_package_roots(extract_root)
        if roots:
            return PreparedSource(source=source, root=extract_root, package_roots=roots, temporary_root=temp_root)
        native_kind = detect_native_source_kind(extract_root)
        if native_kind:
            return PreparedSource(
                source=source,
                root=extract_root,
                package_roots=[],
                temporary_root=temp_root,
                source_kind=native_kind,
            )
        raise PackageValidationError(
            "The archive was extracted, but no MSFS package or supported PMDG native livery was found."
        )
    except Exception:
        shutil.rmtree(temp_root, ignore_errors=True)
        raise


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig", errors="strict"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PackageValidationError(f"Invalid {label}: {exc}") from exc
    if not isinstance(data, dict):
        raise PackageValidationError(f"Invalid {label}: root value must be an object.")
    return data


def _manifest_value(manifest: dict[str, Any], *keys: str, default: str = "") -> str:
    lowered = {str(k).lower(): v for k, v in manifest.items()}
    for key in keys:
        value = lowered.get(key.lower())
        if value is not None:
            if isinstance(value, (str, int, float)):
                return str(value).strip()
    return default


def _extract_dependencies(manifest: dict[str, Any]) -> list[str]:
    value = manifest.get("dependencies") or manifest.get("Dependencies") or []
    result: list[str] = []
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                result.append(item)
            elif isinstance(item, dict):
                name = item.get("name") or item.get("package_name") or item.get("Name")
                if name:
                    result.append(str(name))
    elif isinstance(value, dict):
        result.extend(str(key) for key in value)
    return sorted(set(result), key=str.lower)


def _read_cfg_texts(package_root: Path, filename: str, limit: int = 100) -> list[tuple[Path, str]]:
    result: list[tuple[Path, str]] = []
    for path in package_root.rglob(filename):
        if len(result) >= limit:
            break
        try:
            text = path.read_text(encoding="utf-8-sig", errors="replace")
        except OSError:
            continue
        result.append((path, text))
    return result


def _validate_layout(package_root: Path, warnings: list[str]) -> None:
    layout = _read_json(package_root / "layout.json", "layout.json")
    content = layout.get("content") or layout.get("Content")
    if not isinstance(content, list):
        warnings.append("layout.json does not contain a standard content array.")
        return
    missing: list[str] = []
    unsafe: list[str] = []
    for item in content:
        if not isinstance(item, dict):
            continue
        raw = item.get("path") or item.get("Path")
        if not isinstance(raw, str):
            continue
        try:
            rel = _safe_member_path(raw)
        except UnsafeArchiveError:
            unsafe.append(raw)
            continue
        candidate = package_root.joinpath(*rel.parts)
        if not candidate.exists():
            missing.append(raw)
    if unsafe:
        raise PackageValidationError(f"layout.json contains unsafe paths, for example: {unsafe[0]}")
    if missing:
        sample = ", ".join(missing[:3])
        warnings.append(f"layout.json references {len(missing)} missing file(s): {sample}")


def sanitize_package_name(value: str) -> str:
    value = value.strip().replace(" ", "-")
    value = _INVALID_NAME_CHARS.sub("-", value)
    value = re.sub(r"-+", "-", value).strip("-._")
    value = value[:128] or "livery-package"
    if _WINDOWS_RESERVED_RE.fullmatch(value):
        value = "livery-" + value
    return value


def analyze_package(package_root: Path) -> PackageAnalysis:
    ensure_safe_tree(package_root)
    package_root = package_root.resolve()
    if not (package_root / "manifest.json").is_file() or not (package_root / "layout.json").is_file():
        raise PackageValidationError("Package root must contain manifest.json and layout.json.")

    manifest = _read_json(package_root / "manifest.json", "manifest.json")
    warnings: list[str] = []
    reasons: list[str] = []
    _validate_layout(package_root, warnings)

    content_type = _manifest_value(manifest, "content_type", "contentType", default="")
    title = _manifest_value(manifest, "title", "display_name", "name", default=package_root.name)
    creator = _manifest_value(manifest, "creator", "manufacturer", default="")
    version = _manifest_value(manifest, "package_version", "version", default="")
    manifest_name = _manifest_value(manifest, "package_name", "packageName", default=package_root.name)
    package_name = sanitize_package_name(manifest_name or package_root.name)

    livery_cfgs = _read_cfg_texts(package_root, "livery.cfg")
    aircraft_cfgs = _read_cfg_texts(package_root, "aircraft.cfg")
    has_native_livery_cfg = bool(livery_cfgs)
    has_livery_section = any(
        re.search(r"^\s*\[LIVERY\]\s*$", text, re.IGNORECASE | re.MULTILINE)
        or re.search(r"^\s*base_container\s*=", text, re.IGNORECASE | re.MULTILINE)
        for _, text in aircraft_cfgs
    )
    has_texture_variant = any(
        part.lower().startswith("texture.")
        for path in package_root.rglob("*")
        if path.is_dir()
        for part in (path.name,)
    )
    has_airplanes_tree = any(
        tuple(part.lower() for part in path.parts[-2:]) == ("simobjects", "airplanes")
        for path in package_root.rglob("Airplanes")
        if path.is_dir() and len(path.parts) >= 2
    )
    has_modular_liveries_folder = any(
        path.is_dir() and path.name.lower() == "liveries"
        for path in package_root.rglob("liveries")
    )

    if content_type.lower() == "livery":
        reasons.append("manifest content type is LIVERY")
    if has_native_livery_cfg:
        reasons.append("contains livery.cfg (native modular livery marker)")
    if has_livery_section:
        reasons.append("aircraft.cfg contains a livery base-container reference")
    if has_texture_variant and has_airplanes_tree:
        reasons.append("contains an aircraft texture variation")

    is_livery = bool(reasons)
    if has_native_livery_cfg or has_modular_liveries_folder:
        package_format: PackageFormat = "native-2024"
        target_hint: TargetKind = "community2024"
    elif has_livery_section or (has_texture_variant and has_airplanes_tree):
        package_format = "legacy-2020"
        target_hint = "community"
    else:
        package_format = "unknown"
        target_hint = "community"

    if not is_livery:
        warnings.append("The package is structurally valid, but no clear livery marker was found.")
    if package_format == "unknown":
        warnings.append("Package generation could not be identified; legacy Community is the safer automatic target.")

    return PackageAnalysis(
        package_root=package_root,
        package_name=package_name,
        title=title,
        creator=creator,
        version=version,
        content_type=content_type,
        is_livery=is_livery,
        package_format=package_format,
        target_hint=target_hint,
        reasons=reasons,
        warnings=warnings,
        dependencies=_extract_dependencies(manifest),
        manifest=manifest,
    )


_PTP_PRODUCT_PATTERNS: list[tuple[str, tuple[str, ...]]] = [
    ("736", (r"pmdg\s*736", r"737[-_ ]?600", r"\b736\b")),
    ("737", (r"pmdg\s*737(?![-_ ]?8|[-_ ]?9)", r"737[-_ ]?700", r"\b737[-_ ]?7\b")),
    ("738", (r"pmdg\s*738", r"737[-_ ]?800", r"\b738\b")),
    ("739", (r"pmdg\s*739", r"739\s*er", r"737[-_ ]?900(?:er)?", r"\b739\b")),
    ("77w", (r"pmdg\s*77w", r"777[-_ ]?300er", r"\b77w\b")),
    ("77f", (r"pmdg\s*77f", r"777[-_ ]?f", r"777[-_ ]?freighter", r"\b77f\b")),
    ("77l", (r"pmdg\s*77l", r"777[-_ ]?200lr", r"\b77l\b")),
    ("77e", (r"pmdg\s*77e", r"777[-_ ]?200er", r"\b77e\b")),
]


def infer_pmdg_product_code(value: str) -> str:
    lowered = value.lower()
    for code, patterns in _PTP_PRODUCT_PATTERNS:
        if any(re.search(pattern, lowered, re.IGNORECASE) for pattern in patterns):
            return code
    return ""


def ptp_target_package_name(product_code: str) -> str:
    return f"pmdg-aircraft-{product_code}-liveries" if product_code else ""


def analyze_ptp(source: Path) -> PackageAnalysis:
    source = source.expanduser().resolve()
    if not source.is_file() or source.suffix.lower() != ".ptp":
        raise PackageValidationError("PMDG PTP analysis requires a .ptp file.")
    try:
        with source.open("rb") as handle:
            header = handle.read(64)
    except OSError as exc:
        raise LiveryDockError(f"Could not read PTP file: {exc}") from exc
    if len(header) < 16 or header[:4] != b"CRYP":
        raise PackageValidationError(
            "This .ptp file does not have the PMDG CRYP cabinet header and cannot be handled as a PMDG livery."
        )

    product_code = infer_pmdg_product_code(source.stem)
    target_package = ptp_target_package_name(product_code)
    reasons = ["PMDG encrypted PTP cabinet (CRYP header)"]
    warnings: list[str] = []
    dependencies: list[str] = []
    if product_code:
        reasons.append(f"filename maps to PMDG product code {product_code}")
        dependencies.append(target_package)
    else:
        warnings.append(
            "PMDG product could not be inferred from the filename. LiveryDock will try to infer the target from installed PMDG livery packages during installation."
        )
    warnings.append(
        "Legacy PMDG MSFS 2020 PTP detected. LiveryDock will decrypt it internally and convert the DDS paint into the native MSFS 2024 PMDG livery structure; the official MSFS 2024 SDK is required for the KTX2 build step."
    )
    return PackageAnalysis(
        package_root=source.parent,
        package_name=sanitize_package_name(f"ptp-{source.stem}"),
        title=source.stem,
        creator="PMDG PTP",
        version="",
        content_type="LIVERY",
        is_livery=True,
        package_format="pmdg-ptp",
        target_hint="community",
        reasons=reasons,
        warnings=warnings,
        dependencies=dependencies,
        manifest={},
        source_kind="pmdg-ptp",
        ptp_product_code=product_code,
        ptp_target_package=target_package,
    )


def _windows_filetime(path: Path) -> int:
    try:
        mtime = path.stat().st_mtime
    except OSError:
        mtime = datetime.now().timestamp()
    return int((mtime + 11644473600) * 10_000_000)


def _load_layout_for_merge(layout_path: Path) -> dict[str, Any]:
    if not layout_path.exists():
        return {"content": []}
    data = _read_json(layout_path, "layout.json")
    content = data.get("content")
    if not isinstance(content, list):
        data["content"] = []
    return data


def merge_layout_entries(package_root: Path, relative_paths: Iterable[Path]) -> None:
    ensure_safe_tree(package_root)
    layout_path = package_root / "layout.json"
    layout = _load_layout_for_merge(layout_path)
    content = layout.setdefault("content", [])
    normalized_paths = [_safe_member_path(p.as_posix()).as_posix() for p in relative_paths]
    for rel in normalized_paths:
        safe_target_path(package_root, rel)
    lower = {value.lower() for value in normalized_paths}
    content[:] = [
        item for item in content
        if not (isinstance(item, dict) and isinstance(item.get("path"), str) and item["path"].lower() in lower)
    ]
    for rel in normalized_paths:
        full = safe_target_path(package_root, rel)
        if full.is_file():
            content.append({"path": rel, "size": full.stat().st_size, "date": _windows_filetime(full)})
    layout_path.write_text(json.dumps(layout, indent=2, ensure_ascii=False), encoding="utf-8")


def remove_layout_entries(package_root: Path, relative_paths: Iterable[str]) -> None:
    layout_path = package_root / "layout.json"
    if not layout_path.exists():
        return
    layout = _load_layout_for_merge(layout_path)
    content = layout.setdefault("content", [])
    lower = {str(value).replace("\\", "/").lower() for value in relative_paths}
    content[:] = [
        item for item in content
        if not (
            isinstance(item, dict)
            and isinstance(item.get("path"), str)
            and item["path"].replace("\\", "/").lower() in lower
        )
    ]
    layout_path.write_text(json.dumps(layout, indent=2, ensure_ascii=False), encoding="utf-8")


def _update_manifest_total_size(package_root: Path) -> None:
    ensure_safe_tree(package_root)
    manifest_path = package_root / "manifest.json"
    if not manifest_path.exists():
        return
    try:
        manifest = _read_json(manifest_path, "manifest.json")
    except PackageValidationError:
        return
    if "total_package_size" not in manifest:
        return
    total = 0
    for path in package_root.rglob("*"):
        if path.is_file() and path.name.lower() not in {"layout.json", "manifest.json"}:
            try:
                total += path.stat().st_size
            except OSError:
                pass
    manifest["total_package_size"] = str(total)
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")


_PMDG_AIRPLANE_FOLDERS = {
    "736": "PMDG 737-600",
    "737": "PMDG 737-700",
    "738": "PMDG 737-800",
    "739": "PMDG 737-900",
    "77w": "PMDG 777-300ER",
    "77f": "PMDG 777F",
    "77l": "PMDG 777-200LR",
    "77e": "PMDG 777-200ER",
}


def _ensure_pmdg_livery_skeleton(target: Path, analysis: PackageAnalysis) -> bool:
    """Create an OC3-style companion livery package if needed. Returns True if created."""
    if target.exists():
        if not target.is_dir():
            raise LiveryDockError(f"PMDG livery target exists but is not a folder: {target}")
        return False
    safe_target_path(target.parent, target.name)
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".liverydock-skeleton-", dir=target.parent))
    airplane = _PMDG_AIRPLANE_FOLDERS.get(analysis.ptp_product_code, f"PMDG {analysis.ptp_product_code}")
    manifest = {
        "dependencies": [],
        "content_type": "AIRCRAFT",
        "title": f"PMDG {analysis.ptp_product_code.upper()} Liveries",
        "manufacturer": "PMDG",
        "creator": "LiveryDock",
        "package_version": "1.0.0",
        "minimum_game_version": "1.20.6",
        "release_notes": {"neutral": {"LastUpdate": "", "OlderHistory": ""}},
        "total_package_size": "0",
    }
    try:
        (staging / "SimObjects" / "Airplanes" / airplane / "liveries" / "pmdg").mkdir(parents=True, exist_ok=True)
        (staging / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        (staging / "layout.json").write_text('{"content": []}\n', encoding="utf-8")
        os.replace(staging, target)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return True


def _pmdg_search_roots(community_root: Path) -> list[Path]:
    """Locations that may contain the installed PMDG base aircraft/native template.

    Community remains the write target. Official/Official2024 are searched read-only
    so Marketplace/streamed installations can still provide a native template.
    """
    roots = [community_root]
    parent = community_root.parent
    for name in ("Community", "Community2024"):
        candidate = parent / name
        if candidate not in roots:
            roots.append(candidate)
    for name in ("Official", "Official2024"):
        official = parent / name
        if not official.is_dir():
            continue
        if official not in roots:
            roots.append(official)
        try:
            for child in official.iterdir():
                if child.is_dir() and child not in roots:
                    roots.append(child)
        except OSError:
            pass
    return roots


def resolve_pmdg_livery_target(community_root: Path, analysis: PackageAnalysis, *, allow_create: bool = True) -> Path:
    community_root = community_root.expanduser().resolve()
    _ensure_safe_target_root(community_root)
    if not community_root.exists():
        community_root.mkdir(parents=True, exist_ok=True)

    if analysis.ptp_target_package:
        if analysis.ptp_target_package != ptp_target_package_name(analysis.ptp_product_code):
            raise LiveryDockError("PMDG target package does not match its aircraft product.")
        target = safe_target_path(community_root, analysis.ptp_target_package)
        ensure_safe_tree(target)
        if target.is_dir() and (target / "layout.json").is_file():
            return target
        base_name = analysis.ptp_target_package.removesuffix("-liveries")
        base_found = any((root / base_name).is_dir() for root in _pmdg_search_roots(community_root))
        if base_found and allow_create:
            return target
        if base_found:
            raise LiveryDockError(f"{analysis.ptp_target_package} is not installed yet.")
        raise LiveryDockError(
            f"The required PMDG MSFS 2024 aircraft was not found: {base_name}. Install the aircraft first, then retry."
        )

    candidates = sorted(
        p for p in community_root.glob("pmdg-aircraft-*-liveries")
        if p.is_dir() and (p / "layout.json").is_file()
    )
    if len(candidates) == 1:
        ensure_safe_tree(candidates[0])
        return candidates[0]
    if not candidates:
        raise LiveryDockError("No installed PMDG livery/base package was found for this PTP.")
    raise LiveryDockError(
        "The PTP filename does not identify its PMDG product and multiple PMDG products are installed. "
        "Rename the file to include the aircraft code (for example PMDG739)."
    )


def rebuild_layout_all(package_root: Path) -> None:
    ensure_safe_tree(package_root)
    entries: list[dict[str, Any]] = []
    for path in package_root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(package_root)
        if len(rel.parts) == 1 and rel.name.lower() in {"layout.json", "manifest.json"}:
            continue
        if rel.name.lower().startswith("layout.json.bak-"):
            continue
        entries.append({"path": rel.as_posix(), "size": path.stat().st_size, "date": _windows_filetime(path)})
    entries.sort(key=lambda item: str(item["path"]).lower())
    (package_root / "layout.json").write_text(json.dumps({"content": entries}, indent=2), encoding="utf-8")
    _update_manifest_total_size(package_root)


@serialized_operation
def install_pmdg_ptp(
    analysis: PackageAnalysis,
    source: Path,
    community_root: Path,
    sdk_root: Path | None = None,
    *,
    steam: bool = False,
) -> InstallRecord:
    """Extract a legacy PMDG PTP and convert it to the native MSFS 2024 livery format."""
    if analysis.source_kind != "pmdg-ptp":
        raise LiveryDockError("install_pmdg_ptp called for a non-PTP source.")
    if analysis.ptp_product_code not in {"736", "737", "738", "739"}:
        raise LiveryDockError(
            "This LiveryDock build currently performs automatic native PTP conversion for the PMDG 737-600/700/800/900 family."
        )

    from .ptp import (
        build_native_livery_from_legacy,
        choose_native_template,
        extract_pmdg_ptp as extract_ptp_builtin,
        find_msfs2024_sdk,
        find_native_pmdg_templates,
        infer_737_tags,
        read_legacy_pmdg_metadata,
        safe_livery_id,
    )

    old_records = load_registry()
    target = resolve_pmdg_livery_target(community_root, analysis, allow_create=True)
    search_roots = _pmdg_search_roots(community_root)
    temp_root = Path(tempfile.mkdtemp(prefix="liverydock-ptp-native-"))
    extracted = temp_root / "extracted"
    stage = temp_root / "native"
    backup_root = app_data_root() / "Backups" / f"ptp-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"
    target_created = False
    destination: Path | None = None
    installed = False
    previous_moved = False
    committed = False
    metadata_changed = False
    original_metadata: dict[str, bytes | None] = {}
    transaction = target.parent / f".liverydock-ptp-{uuid.uuid4().hex}"
    previous = transaction / "previous"

    try:
        extract_ptp_builtin(source, extracted)
        meta = read_legacy_pmdg_metadata(extracted)
        desired_tags = infer_737_tags(meta, analysis.ptp_product_code)

        templates = find_native_pmdg_templates(search_roots, analysis.ptp_product_code)
        template = choose_native_template(templates, desired_tags)
        if template is None:
            raise LiveryDockError(
                "A native PMDG MSFS 2024 livery template could not be found. "
                "Make sure the PMDG aircraft is installed and has at least its PMDG House/native livery."
            )

        resolved_sdk = sdk_root.expanduser().resolve() if sdk_root else find_msfs2024_sdk()
        if not resolved_sdk:
            raise LiveryDockError(
                "The MSFS 2024 SDK is required to convert the old DDS textures to native KTX2. "
                "Install the SDK from MSFS 2024 Developer Mode, then restart LiveryDock. "
                "The usual path is C:\\MSFS 2024 SDK."
            )

        livery_id = safe_livery_id(meta, source.stem)
        staged_livery = stage / livery_id
        build_native_livery_from_legacy(
            extracted,
            template,
            staged_livery,
            analysis.ptp_product_code,
            resolved_sdk,
            steam=steam,
        )
        ensure_safe_tree(staged_livery)

        # Existing companion folders can be incomplete. Remember absence as
        # well as bytes so rollback removes metadata generated by this attempt.
        for name in ("layout.json", "manifest.json"):
            metadata_path = target / name
            if metadata_path.exists() and not metadata_path.is_file():
                raise LiveryDockError(f"PMDG package metadata is not a file: {metadata_path}")
            original_metadata[name] = metadata_path.read_bytes() if metadata_path.is_file() else None
        target_created = _ensure_pmdg_livery_skeleton(target, analysis)
        airplane_folder = _PMDG_AIRPLANE_FOLDERS[analysis.ptp_product_code]
        livery_rel = f"SimObjects/Airplanes/{airplane_folder}/liveries/pmdg/{livery_id}"
        validate_livery_relative_path(livery_rel)
        destination = safe_target_path(target, livery_rel)

        _reject_link_ancestors(backup_root)
        backup_root.mkdir(parents=True, exist_ok=False)
        if (target / "layout.json").is_file():
            shutil.copy2(target / "layout.json", backup_root / "layout.json")
        if (target / "manifest.json").is_file():
            shutil.copy2(target / "manifest.json", backup_root / "manifest.json")
        overwritten = destination.exists()
        if overwritten:
            ensure_safe_tree(destination)
            shutil.copytree(destination, backup_root / "livery")
        transaction.mkdir(parents=True, exist_ok=False)
        staged_destination = transaction / "new"
        shutil.copytree(staged_livery, staged_destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if overwritten:
            os.replace(destination, previous)
            previous_moved = True
        os.replace(staged_destination, destination)
        installed = True
        metadata_changed = True
        rebuild_layout_all(target)

        record = InstallRecord(
            id=uuid.uuid4().hex,
            package_name=analysis.package_name,
            title=meta.get("title") or analysis.title,
            version="",
            package_format="pmdg-ptp",
            target_kind="community",
            destination=str(target),
            source=str(source),
            backup=str(backup_root),
            installed_at=utc_now(),
            manifest_sha256=sha256_file(target / "manifest.json") if (target / "manifest.json").is_file() else "",
            install_kind="pmdg-ptp",
            metadata={
                "native_conversion": True,
                "product_code": analysis.ptp_product_code,
                "target_package": target.name,
                "livery_rel": destination.relative_to(target).as_posix(),
                "target_created": target_created,
                "overwritten_livery": overwritten,
                "template": str(template),
                "sdk": str(resolved_sdk),
                "required_tags": desired_tags,
                "registration": meta.get("atc_id", ""),
            },
        )
        records = list(old_records)
        records.append(record)
        save_registry(records)
        committed = True
    except Exception:
        try:
            if installed and destination and destination.exists():
                shutil.rmtree(destination)
                if not previous_moved:
                    _remove_empty_parent_dirs(destination, target)
            if previous_moved and destination and previous.exists():
                destination.parent.mkdir(parents=True, exist_ok=True)
                os.replace(previous, destination)
            if target.exists() and metadata_changed:
                for name, content in original_metadata.items():
                    if content is None:
                        (target / name).unlink(missing_ok=True)
                    else:
                        (target / name).write_bytes(content)
            if target_created and target.exists():
                shutil.rmtree(target)
        except OSError as exc:
            raise LiveryDockError(f"PTP installation failed and rollback could not finish. Recovery files remain in {backup_root} and {transaction}.") from exc
        shutil.rmtree(backup_root, ignore_errors=True)
        raise
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)
        if committed or not previous.exists():
            shutil.rmtree(transaction, ignore_errors=True)
    append_log(f"Converted PMDG PTP {source.name} to native MSFS 2024 livery at {destination}")
    return record

def _remove_empty_parent_dirs(path: Path, stop: Path) -> None:
    current = path.parent
    while current != stop:
        try:
            current.relative_to(stop)
        except ValueError:
            break
        try:
            current.rmdir()
        except OSError:
            break
        current = current.parent


@serialized_operation
def uninstall_pmdg_ptp_record(record: InstallRecord) -> None:
    if record.metadata.get("native_conversion"):
        target, backup_root = validate_managed_record(record)
        current_records = load_registry()
        livery_raw = str(record.metadata.get("livery_rel", ""))
        if not livery_raw:
            raise LiveryDockError("Managed PTP record is missing its native livery path.")
        validate_livery_relative_path(livery_raw)
        livery_path = safe_target_path(target, livery_raw)
        ensure_safe_tree(target)
        if backup_root:
            ensure_safe_tree(backup_root)
        if record.metadata.get("overwritten_livery") and not (backup_root and (backup_root / "livery").is_dir()):
            raise LiveryDockError("The previous livery backup is missing. No files were removed.")

        index = next(i for i, item in enumerate(current_records) if item.id == record.id)
        for other in current_records[index + 1:]:
            if _same_destination(other.destination, record.destination) and (
                other.install_kind == "package" or livery_raw.replace("\\", "/").casefold() in _managed_livery_paths(other)
            ):
                raise LiveryDockError("A newer managed install replaced this livery. Uninstall the newer one first.")

        transaction = target.parent / f".liverydock-remove-ptp-{uuid.uuid4().hex}"
        previous = transaction / "previous"
        moved = False
        restored = False
        metadata_files = {name: (target / name).read_bytes() if (target / name).is_file() else None for name in ("layout.json", "manifest.json")}
        try:
            transaction.mkdir(parents=True, exist_ok=False)
            if backup_root and (backup_root / "livery").is_dir():
                shutil.copytree(backup_root / "livery", transaction / "restored")
            if livery_path.exists():
                os.replace(livery_path, previous)
                moved = True
            if (transaction / "restored").exists():
                livery_path.parent.mkdir(parents=True, exist_ok=True)
                os.replace(transaction / "restored", livery_path)
                restored = True
            if target.exists():
                rebuild_layout_all(target)
            save_registry([r for r in current_records if r.id != record.id])
        except Exception:
            if restored and livery_path.exists():
                shutil.rmtree(livery_path)
            if moved and previous.exists():
                livery_path.parent.mkdir(parents=True, exist_ok=True)
                os.replace(previous, livery_path)
            for name, content in metadata_files.items():
                if content is None:
                    (target / name).unlink(missing_ok=True)
                else:
                    (target / name).write_bytes(content)
            shutil.rmtree(transaction, ignore_errors=True)
            raise
        shutil.rmtree(transaction, ignore_errors=True)
        if record.metadata.get("target_created") and not any(
            path.is_file() and path.relative_to(target).as_posix().casefold() not in {"manifest.json", "layout.json"}
            for path in target.rglob("*")
        ):
            shutil.rmtree(target, ignore_errors=True)
        if backup_root:
            shutil.rmtree(backup_root, ignore_errors=True)
        append_log(f"Uninstalled native PMDG PTP conversion {record.title} from {target}")
        return

    target, backup_root = validate_managed_record(record)
    ensure_safe_tree(target)
    if backup_root:
        ensure_safe_tree(backup_root)
    for key in ("copied_files", "added_files", "overwritten_files"):
        if not isinstance(record.metadata.get(key, []), list) or any(not isinstance(value, str) for value in record.metadata.get(key, [])):
            raise LiveryDockError("The managed legacy PTP record has invalid file lists.")
    copied = record.metadata.get("copied_files", [])
    added = set(record.metadata.get("added_files", []))
    overwritten = set(record.metadata.get("overwritten_files", []))
    if not added.isdisjoint(overwritten) or not (added | overwritten).issubset(set(copied)):
        raise LiveryDockError("The managed legacy PTP record has inconsistent file lists.")
    paths = {raw: safe_target_path(target, raw) for raw in copied}
    backups = {raw: safe_target_path(backup_root / "files", raw) for raw in overwritten} if backup_root else {}
    if any(raw not in backups or not backups[raw].is_file() for raw in overwritten):
        raise LiveryDockError("A previous PTP file backup is missing. No files were removed.")

    current_records = load_registry()
    overlap_set = {v.replace("\\", "/").casefold() for v in copied}
    index = next(i for i, item in enumerate(current_records) if item.id == record.id)
    for other in current_records[index + 1:]:
        if not _same_destination(other.destination, record.destination):
            continue
        other_files = {str(v).replace("\\", "/").casefold() for v in other.metadata.get("copied_files", [])}
        other_folders = _managed_livery_paths(other)
        if (other.install_kind == "package" or overlap_set & other_files
                or any(value.startswith(folder + "/") or value == folder for value in overlap_set for folder in other_folders)):
            raise LiveryDockError(
                "A newer managed PTP import modified some of the same files. Uninstall the newer PTP livery first to preserve rollback safety."
            )

    transaction = target.parent / f".liverydock-remove-legacy-{uuid.uuid4().hex}"
    snapshots: dict[str, Path | None] = {}
    metadata_files = {name: (target / name).read_bytes() if (target / name).is_file() else None for name in ("layout.json", "manifest.json")}
    touched = False
    try:
        transaction.mkdir(parents=True, exist_ok=False)
        for raw, dest in paths.items():
            if dest.exists() and not dest.is_file():
                raise LiveryDockError(f"A managed PTP file is now a directory: {dest}")
            snapshot = safe_target_path(transaction / "files", raw) if dest.is_file() else None
            snapshots[raw] = snapshot
            if snapshot:
                snapshot.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(dest, snapshot)
        touched = True
        restored: list[Path] = []
        for raw, dest in paths.items():
            if raw in overwritten:
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(backups[raw], dest)
                restored.append(Path(*_safe_member_path(raw).parts))
            elif raw in added and dest.is_file():
                dest.unlink()
        remove_layout_entries(target, copied)
        if restored:
            merge_layout_entries(target, restored)
        _update_manifest_total_size(target)
        save_registry([r for r in current_records if r.id != record.id])
    except Exception:
        if touched:
            for raw, snapshot in snapshots.items():
                dest = paths[raw]
                if snapshot:
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(snapshot, dest)
                else:
                    dest.unlink(missing_ok=True)
            for name, content in metadata_files.items():
                if content is None:
                    (target / name).unlink(missing_ok=True)
                else:
                    (target / name).write_bytes(content)
        shutil.rmtree(transaction, ignore_errors=True)
        raise
    shutil.rmtree(transaction, ignore_errors=True)
    if backup_root:
        shutil.rmtree(backup_root, ignore_errors=True)
    append_log(f"Uninstalled managed PMDG PTP import {record.title} from {target}")

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_registry_data() -> list[dict[str, Any]]:
    path = registry_path()
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LiveryDockError(f"The managed-livery registry could not be read. Restore or repair {path} before changing liveries.") from exc
    if not isinstance(data, list):
        raise LiveryDockError(f"Invalid managed-livery registry: {path}")
    return data


def load_registry() -> list[InstallRecord]:
    records: list[InstallRecord] = []
    for raw in _load_registry_data():
        if not isinstance(raw, dict):
            raise LiveryDockError("The managed-livery registry contains an invalid record.")
        try:
            record = InstallRecord(**raw)
        except TypeError as exc:
            raise LiveryDockError("The managed-livery registry contains an invalid record.") from exc
        if (not isinstance(record.metadata, dict)
                or any(not isinstance(getattr(record, name), str) for name in (
                    "id", "package_name", "title", "version", "package_format", "target_kind",
                    "destination", "source", "installed_at", "manifest_sha256", "install_kind"))
                or (record.backup is not None and not isinstance(record.backup, str))):
            raise LiveryDockError("The managed-livery registry contains invalid field types.")
        if any(previous.id == record.id for previous in records):
            raise LiveryDockError("The managed-livery registry contains duplicate record IDs.")
        records.append(record)
    return records


def save_registry(records: Iterable[InstallRecord]) -> None:
    path = registry_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}-{uuid.uuid4().hex}.tmp")
    try:
        temp.write_text(json.dumps([asdict(record) for record in records], indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def validate_managed_record(record: InstallRecord) -> tuple[Path, Path | None]:
    """Refuse stale records and unsafe destinations before any uninstall writes."""
    current = next((item for item in load_registry() if item.id == record.id), None)
    if current is None or asdict(current) != asdict(record):
        raise LiveryDockError("This managed-livery record changed or no longer exists. Refresh the list and try again.")
    destination = Path(record.destination)
    if not destination.is_absolute() or destination == Path(destination.anchor):
        raise LiveryDockError("The managed-livery record has an invalid destination.")
    _ensure_safe_target_root(destination)
    _reject_link_ancestors(destination)
    if record.install_kind == "package":
        if destination.name != record.package_name or sanitize_package_name(record.package_name) != record.package_name:
            raise LiveryDockError("The managed package destination does not match its package name.")
    elif record.install_kind in {"pmdg-native", "pmdg-ptp"}:
        if not re.fullmatch(r"pmdg-aircraft-[a-z0-9]+-liveries", destination.name, re.IGNORECASE):
            raise LiveryDockError("The managed PMDG destination is not a companion livery package.")
    else:
        raise LiveryDockError("The managed-livery record has an unknown installation kind.")
    backup = Path(record.backup) if record.backup else None
    if backup:
        if not backup.is_absolute():
            raise LiveryDockError("The managed backup path is not absolute.")
        _reject_link_ancestors(backup)
        backup_base = (app_data_root() / "Backups").resolve()
        try:
            relative = backup.resolve().relative_to(backup_base)
        except ValueError as exc:
            raise LiveryDockError("The managed backup is outside LiveryDock's Backups folder.") from exc
        if not relative.parts:
            raise LiveryDockError("The managed backup path does not identify one backup.")
    return destination, backup


def find_installed_package(package_name: str, community_paths: CommunityPaths) -> list[Path]:
    matches: list[Path] = []
    for root in (community_paths.community2024, community_paths.community):
        if not root or not root.exists():
            continue
        direct = root / package_name
        if direct.exists():
            matches.append(direct)
        for manifest in root.glob("*/manifest.json"):
            try:
                data = _read_json(manifest, "manifest.json")
            except PackageValidationError:
                continue
            found = sanitize_package_name(_manifest_value(data, "package_name", "packageName", default=manifest.parent.name))
            if found.lower() == package_name.lower() and manifest.parent not in matches:
                matches.append(manifest.parent)
    return matches


def _ensure_safe_target_root(community_root: Path) -> None:
    lowered = {part.lower() for path in (community_root, community_root.resolve()) for part in path.parts}
    if any(part.startswith("official") for part in lowered):
        raise LiveryDockError("Refusing to install into an Official package folder.")


@serialized_operation
def install_package(
    analysis: PackageAnalysis,
    source: Path,
    community_root: Path,
    target_kind: TargetKind,
) -> InstallRecord:
    _ensure_safe_target_root(community_root)
    community_root = community_root.expanduser().resolve()
    _ensure_safe_target_root(community_root)
    community_root.mkdir(parents=True, exist_ok=True)

    if sanitize_package_name(analysis.package_name) != analysis.package_name:
        raise PackageValidationError("The package folder name is unsafe.")
    destination = safe_target_path(community_root, analysis.package_name)
    # Keep the copied package under its final package-folder name while it is
    # staged. Some third-party manifests omit package_name, so package identity
    # falls back to the package root folder name. Copying directly into a
    # randomly named staging folder would therefore change that identity.
    staging_parent = community_root / f".liverydock-staging-{uuid.uuid4().hex}"
    staging = staging_parent / analysis.package_name
    previous = staging_parent / ".previous-version"
    backup: Path | None = None
    backup_root = app_data_root() / "Backups" / f"{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:12]}"
    old_records = load_registry()
    installed = False
    moved_previous = False

    source_root = analysis.package_root.resolve()
    if source_root == destination.resolve() or source_root in destination.resolve().parents or destination.resolve() in source_root.parents:
        raise LiveryDockError("The source package and installation destination must be separate folders.")

    try:
        staging_parent.mkdir(parents=True, exist_ok=False)
        ensure_safe_tree(analysis.package_root)
        shutil.copytree(analysis.package_root, staging)
        copied = analyze_package(staging)
        if copied.package_name != analysis.package_name:
            raise PackageValidationError(
                "Copied package identity changed during staging validation. "
                f"Expected {analysis.package_name!r}, got {copied.package_name!r}."
            )
        if destination.exists():
            ensure_safe_tree(destination)
            backup = backup_root / destination.name
            _reject_link_ancestors(backup_root)
            backup.parent.mkdir(parents=True, exist_ok=False)
            shutil.copytree(destination, backup)
            os.replace(destination, previous)
            moved_previous = True
        os.replace(staging, destination)
        installed = True

        record = InstallRecord(
            id=uuid.uuid4().hex,
            package_name=analysis.package_name,
            title=analysis.title,
            version=analysis.version,
            package_format=analysis.package_format,
            target_kind=target_kind,
            destination=str(destination),
            source=str(source),
            backup=str(backup) if backup else None,
            installed_at=utc_now(),
            manifest_sha256=sha256_file(destination / "manifest.json"),
        )
        records = [r for r in old_records if not (r.install_kind == "package" and Path(r.destination) == destination)]
        records.append(record)
        save_registry(records)
    except Exception:
        if installed and destination.exists():
            shutil.rmtree(destination)
        if moved_previous and previous.exists():
            os.replace(previous, destination)
        shutil.rmtree(staging_parent, ignore_errors=True)
        if backup_root.exists():
            shutil.rmtree(backup_root, ignore_errors=True)
        raise
    shutil.rmtree(staging_parent, ignore_errors=True)
    append_log(f"Installed {analysis.package_name} to {destination}")
    return record


@serialized_operation
def uninstall_record(record: InstallRecord, restore_backup: bool = True) -> None:
    destination, backup = validate_managed_record(record)
    if record.install_kind == "pmdg-native":
        from .pmdg_native import uninstall_pmdg_native_record
        uninstall_pmdg_native_record(record)
        return
    if record.install_kind == "pmdg-ptp":
        uninstall_pmdg_ptp_record(record)
        return
    current = load_registry()
    index = next(i for i, item in enumerate(current) if item.id == record.id)
    if any(_same_destination(other.destination, record.destination) for other in current[index + 1:]):
        raise LiveryDockError("A newer managed install changed this package. Uninstall the newer item first.")
    if restore_backup and backup and not backup.is_dir():
        raise LiveryDockError("The previous package backup is missing. No files were removed.")
    ensure_safe_tree(destination)
    if restore_backup and backup:
        ensure_safe_tree(backup)
    # Keep rollback on the same volume so replacing the live package is atomic.
    transaction = destination.parent / f".liverydock-remove-{uuid.uuid4().hex}"
    removed = transaction / "removed"
    staged_backup = transaction / "restored"
    moved = False
    restored = False
    try:
        transaction.mkdir(parents=True, exist_ok=False)
        if restore_backup and backup:
            shutil.copytree(backup, staged_backup)
        if destination.exists():
            os.replace(destination, removed)
            moved = True
        if staged_backup.exists():
            os.replace(staged_backup, destination)
            restored = True
        save_registry([r for r in current if r.id != record.id])
    except Exception:
        if restored and destination.exists():
            shutil.rmtree(destination)
        if moved and removed.exists():
            os.replace(removed, destination)
        shutil.rmtree(transaction, ignore_errors=True)
        raise
    # Preserve removed files for manual recovery. Failure to archive them must
    # not reverse an already committed registry change.
    if moved:
        trash_root = app_data_root() / "Removed" / f"{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:12]}"
        try:
            trash_root.mkdir(parents=True, exist_ok=False)
            shutil.move(str(removed), str(trash_root / destination.name))
        except OSError:
            append_log(f"Removed package retained for recovery at {removed}")
    if not removed.exists():
        shutil.rmtree(transaction, ignore_errors=True)
    if restore_backup and backup:
        shutil.rmtree(backup, ignore_errors=True)
    append_log(f"Removed managed package {destination}")


def choose_target_path(paths: CommunityPaths, target: TargetKind) -> Path:
    selected = paths.community2024 if target == "community2024" else paths.community
    if selected is None:
        raise LiveryDockError("The selected Community folder could not be detected. Choose it manually.")
    return selected
