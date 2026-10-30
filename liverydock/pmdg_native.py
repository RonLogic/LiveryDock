from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import uuid
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from .core import (
    CommunityPaths,
    InstallRecord,
    LiveryDockError,
    PackageAnalysis,
    PackageValidationError,
    UnsafeArchiveError,
    _ensure_safe_target_root,
    _is_zip_symlink,
    _pmdg_search_roots,
    _safe_member_path,
    app_data_root,
    append_log,
    load_registry,
    rebuild_layout_all,
    save_registry,
    sanitize_package_name,
    sha256_file,
    ensure_safe_tree,
    safe_target_path,
    serialized_operation,
    validate_managed_record,
    validate_livery_relative_path,
    utc_now,
)


_PMDG_PRODUCT_TO_AIRPLANE = {
    "pmdg-aircraft-736": "PMDG 737-600",
    "pmdg-aircraft-737": "PMDG 737-700",
    "pmdg-aircraft-738": "PMDG 737-800",
    "pmdg-aircraft-739": "PMDG 737-900",
    "pmdg-aircraft-77er": "PMDG 777-200ER",
    "pmdg-aircraft-77e": "PMDG 777-200ER",
    "pmdg-aircraft-77l": "PMDG 777-200LR",
    "pmdg-aircraft-77w": "PMDG 777-300ER",
    "pmdg-aircraft-77f": "PMDG 777F",
}

_ARCHIVE_RE = re.compile(r"^(pmdg-aircraft-[a-z0-9]+)(?:-|$)", re.IGNORECASE)
_INVALID_WINDOWS_NAME = re.compile(r'[<>:"/\\|?*\x00-\x1f]+')
_PRODUCT_RE = re.compile(r"^pmdg-aircraft-[a-z0-9]+$")
_RESERVED_WINDOWS_NAME = re.compile(r"^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)", re.IGNORECASE)


def safe_livery_folder_name(value: str, fallback: str = "PMDG-Livery") -> str:
    cleaned = _INVALID_WINDOWS_NAME.sub("_", value).strip(" .")
    cleaned = cleaned[:180] or fallback
    return f"_{cleaned}" if _RESERVED_WINDOWS_NAME.match(cleaned) else cleaned


def _validate_livery_id(value: str) -> str:
    # Changing an explicit ID would break texture.cfg references to a common livery.
    if (not value or value != safe_livery_folder_name(value) or value in {".", ".."}
            or _RESERVED_WINDOWS_NAME.match(value)):
        raise PackageValidationError(f"liveryId is not a safe Windows folder name: {value!r}")
    return value


def _zip_names(zf: zipfile.ZipFile) -> list[str]:
    return [_safe_member_path(info.filename).as_posix() for info in zf.infolist()]


def _native_prefix_from_names(names: list[str]) -> str | None:
    normalized = {name.lower() for name in names}
    # A complete MSFS package can itself contain many native livery metadata
    # pairs. Keep it on the ordinary package path instead of installing only
    # whichever embedded livery happened to be found first.
    if any(name.endswith("manifest.json") and name[:-len("manifest.json")] + "layout.json" in normalized
           for name in normalized):
        return None
    candidates: list[str] = []
    for name in names:
        if PurePosixPath(name).name.lower() == "livery.json":
            parent = name[: -len("livery.json")]
            if (parent + "livery.cfg").lower() in normalized:
                candidates.append(parent)
    if not candidates:
        return None
    if len(candidates) > 1:
        raise PackageValidationError("ZIP contains multiple native livery roots. Use a bundle of separate livery ZIPs.")
    return candidates[0]


def direct_pmdg_zip_prefix(archive: Path) -> str | None:
    try:
        with zipfile.ZipFile(archive) as zf:
            _validate_zip_security(zf)
            return _native_prefix_from_names(_zip_names(zf))
    except (OSError, zipfile.BadZipFile):
        return None


def direct_pmdg_folder_root(folder: Path) -> Path | None:
    folder = folder.expanduser().resolve()
    if (folder / "livery.json").is_file() and (folder / "livery.cfg").is_file():
        return folder
    # Support a single wrapper directory without scanning arbitrary deep trees.
    try:
        children = [p for p in folder.iterdir() if p.is_dir() and p.name != "__MACOSX"]
    except OSError:
        return None
    if len(children) == 1 and (children[0] / "livery.json").is_file() and (children[0] / "livery.cfg").is_file():
        return children[0]
    return None


def nested_pmdg_zip_members(archive: Path) -> list[str]:
    """Return root-level nested ZIPs that look like one PMDG product bundle."""
    try:
        with zipfile.ZipFile(archive) as zf:
            _validate_zip_security(zf)
            infos = [i for i in zf.infolist() if not i.is_dir()]
            if not infos:
                return []
            members: list[str] = []
            for info in infos:
                name = _safe_member_path(info.filename).as_posix()
                # Bundle support is intentionally conservative: only root-level ZIPs.
                if "/" in name or not name.lower().endswith(".zip"):
                    return []
                if not _ARCHIVE_RE.match(Path(name).stem):
                    return []
                members.append(name)
            return members if len(members) >= 2 else []
    except (OSError, zipfile.BadZipFile):
        return []


def detect_native_source_kind(source: Path) -> str | None:
    source = source.expanduser().resolve()
    if source.is_dir():
        return "pmdg-native" if direct_pmdg_folder_root(source) else None
    if source.suffix.lower() != ".zip":
        return None
    if direct_pmdg_zip_prefix(source) is not None:
        return "pmdg-native"
    if nested_pmdg_zip_members(source):
        return "pmdg-native-bundle"
    return None


def _parse_ini_text(text: str) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    section = ""
    for raw in text.splitlines():
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


def _read_direct_metadata(source: Path) -> tuple[dict[str, Any], str, str, list[str], bool]:
    """Return (livery.json, livery.cfg text, prefix, names, has_optional_alt_texture)."""
    source = source.expanduser().resolve()
    if source.is_dir():
        root = direct_pmdg_folder_root(source)
        if root is None:
            raise PackageValidationError("Folder is not a PMDG native livery (livery.json/livery.cfg were not found).")
        ensure_safe_tree(root)
        try:
            raw_json = json.loads((root / "livery.json").read_text(encoding="utf-8-sig", errors="strict"))
            cfg = (root / "livery.cfg").read_text(encoding="utf-8-sig", errors="replace")
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise PackageValidationError(f"Could not read PMDG native livery metadata: {exc}") from exc
        names = [p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()]
        alt = any("dirty version" in n.lower() for n in names)
        return raw_json, cfg, "", names, alt

    try:
        with zipfile.ZipFile(source) as zf:
            _validate_zip_security(zf)
            names = _zip_names(zf)
            prefix = _native_prefix_from_names(names)
            if prefix is None:
                raise PackageValidationError("ZIP is not a PMDG native livery (livery.json/livery.cfg were not found together).")
            members = {name.lower(): info for name, info in zip(names, zf.infolist())}
            raw_json = json.loads(zf.read(members[(prefix + "livery.json").lower()]).decode("utf-8-sig"))
            cfg = zf.read(members[(prefix + "livery.cfg").lower()]).decode("utf-8-sig", errors="replace")
            rel_names = [n[len(prefix):] for n in names if n.lower().startswith(prefix.lower())]
            alt = any("dirty version" in n.lower() for n in rel_names)
            return raw_json, cfg, prefix, rel_names, alt
    except zipfile.BadZipFile as exc:
        raise PackageValidationError(f"Invalid ZIP: {exc}") from exc
    except (KeyError, UnicodeError, json.JSONDecodeError) as exc:
        raise PackageValidationError(f"Could not read PMDG native livery metadata: {exc}") from exc


def _product_from_bundle_members(members: list[str]) -> str:
    products: set[str] = set()
    for member in members:
        match = _ARCHIVE_RE.match(Path(member).stem)
        if match:
            products.add(match.group(1).lower())
    return next(iter(products)) if len(products) == 1 else ""


def _airplane_for_product(product_package: str, cfg_text: str = "") -> str:
    product = product_package.lower().strip()
    if product in _PMDG_PRODUCT_TO_AIRPLANE:
        return _PMDG_PRODUCT_TO_AIRPLANE[product]
    required = _parse_ini_text(cfg_text).get("selection", {}).get("required_tags", "").lower()
    if "b772_ext" in required:
        return "PMDG 777-200ER"
    if "b77w_ext" in required:
        return "PMDG 777-300ER"
    raise PackageValidationError(
        f"LiveryDock does not yet know the SimObject folder for PMDG product {product_package!r}."
    )


def analyze_pmdg_native(source: Path, source_kind: str | None = None) -> PackageAnalysis:
    source = source.expanduser().resolve()
    kind = source_kind or detect_native_source_kind(source)
    if kind == "pmdg-native-bundle":
        members = nested_pmdg_zip_members(source)
        if not members:
            raise PackageValidationError("The ZIP does not contain a supported PMDG nested livery bundle.")
        product = _product_from_bundle_members(members)
        warnings: list[str] = []
        if not product:
            warnings.append("The nested archives do not all identify one PMDG product; each archive will be validated during installation.")
        airplane = _PMDG_PRODUCT_TO_AIRPLANE.get(product, "")
        return PackageAnalysis(
            package_root=source.parent,
            package_name=sanitize_package_name(f"pmdg-bundle-{source.stem}"),
            title=f"{source.stem} ({len(members)} liveries)",
            creator="PMDG native livery bundle",
            version="",
            content_type="LIVERY",
            is_livery=True,
            package_format="pmdg-native-2024",
            target_hint="community2024",
            reasons=[f"contains {len(members)} nested PMDG native livery ZIPs"],
            warnings=warnings,
            dependencies=[product] if product else [],
            manifest={},
            source_kind="pmdg-native-bundle",
            pmdg_product_package=product,
            pmdg_airplane_folder=airplane,
            pmdg_bundle_entries=members,
        )

    if kind != "pmdg-native":
        raise PackageValidationError("Source is not a supported PMDG native MSFS 2024 livery ZIP/folder.")
    meta, cfg_text, _prefix, names, has_alt = _read_direct_metadata(source)
    if not isinstance(meta, dict):
        raise PackageValidationError("livery.json root must be an object.")
    product = str(meta.get("productPackage") or "").strip().lower()
    if not _PRODUCT_RE.fullmatch(product):
        raise PackageValidationError("livery.json does not contain a valid PMDG productPackage.")
    airplane = _airplane_for_product(product, cfg_text)
    cfg = _parse_ini_text(cfg_text)
    general = cfg.get("general", {})
    selection = cfg.get("selection", {})
    title = str(meta.get("title") or general.get("name") or source.stem).strip()
    explicit_id = meta.get("liveryId")
    livery_id = (_validate_livery_id(str(explicit_id)) if explicit_id
                 else safe_livery_folder_name(title or source.stem))
    version = str(meta.get("version") or "")
    tags = selection.get("required_tags", "")
    has_ktx2 = any(name.lower().endswith(".ktx2") for name in names)
    reasons = ["contains PMDG livery.json + livery.cfg"]
    if has_ktx2:
        reasons.append("contains native MSFS 2024 KTX2 textures (no SDK conversion needed)")
    if tags:
        reasons.append(f"required_tags = {tags}")
    warnings: list[str] = []
    if not has_ktx2:
        warnings.append("No KTX2 textures were found; the livery may be incomplete.")
    if has_alt:
        warnings.append("Optional texture/Dirty Version payload detected; LiveryDock installs the main livery and skips this alternate/helper folder.")
    return PackageAnalysis(
        package_root=source if source.is_dir() else source.parent,
        package_name=sanitize_package_name(f"pmdg-native-{livery_id}"),
        title=title,
        creator="PMDG native livery",
        version=version,
        content_type="LIVERY",
        is_livery=True,
        package_format="pmdg-native-2024",
        target_hint="community2024",
        reasons=reasons,
        warnings=warnings,
        dependencies=[product],
        manifest=meta,
        source_kind="pmdg-native",
        pmdg_product_package=product,
        pmdg_livery_id=livery_id,
        pmdg_airplane_folder=airplane,
    )


def _base_or_livery_exists(root: Path, product_package: str) -> tuple[bool, bool]:
    target = root / f"{product_package}-liveries"
    base = root / product_package
    return base.is_dir(), target.is_dir() and (target / "layout.json").is_file()


def choose_pmdg_native_root(paths: CommunityPaths, analysis: PackageAnalysis) -> Path:
    product = analysis.pmdg_product_package
    roots = [r for r in (paths.community2024, paths.community) if r]
    if not roots:
        raise LiveryDockError("No Community folder is configured.")
    ranked: list[tuple[int, Path]] = []
    for root in roots:
        root = root.expanduser()
        base_here, livery_here = _base_or_livery_exists(root, product) if product else (False, False)
        any_base = False
        if product:
            any_base = any((search_root / product).is_dir() for search_root in _pmdg_search_roots(root))
        score = (8 if livery_here else 0) + (4 if base_here else 0) + (2 if any_base else 0)
        if paths.community2024 and root == paths.community2024:
            score += 1
        ranked.append((score, root))
    ranked.sort(key=lambda item: item[0], reverse=True)
    return ranked[0][1]


def _target_package_name(product_package: str) -> str:
    return product_package if product_package.endswith("-liveries") else f"{product_package}-liveries"


def _ensure_base_installed(community_root: Path, product_package: str) -> None:
    if any((root / product_package).is_dir() for root in _pmdg_search_roots(community_root)):
        return
    raise LiveryDockError(
        f"The required PMDG MSFS 2024 aircraft was not found: {product_package}. Install the aircraft first, then retry."
    )


def _ensure_livery_skeleton(target: Path, product_package: str, airplane: str) -> bool:
    if target.exists():
        if not target.is_dir():
            raise LiveryDockError(f"PMDG livery target exists but is not a folder: {target}")
        return False
    target.mkdir(parents=True, exist_ok=False)
    (target / "SimObjects" / "Airplanes" / airplane / "liveries" / "pmdg").mkdir(parents=True, exist_ok=True)
    manifest = {
        "dependencies": [],
        "content_type": "AIRCRAFT",
        "title": f"{product_package} Liveries",
        "manufacturer": "PMDG",
        "creator": "LiveryDock",
        "package_version": "1.0.0",
        "minimum_game_version": "1.20.6",
        "release_notes": {"neutral": {"LastUpdate": "", "OlderHistory": ""}},
        "total_package_size": "0",
    }
    (target / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (target / "layout.json").write_text('{"content": []}\n', encoding="utf-8")
    return True


def _skip_rel(rel: PurePosixPath) -> bool:
    lowered = [part.lower() for part in rel.parts]
    if "__macosx" in lowered:
        return True
    # These are creator helper/alternate files, not runtime livery payload.
    if len(lowered) >= 2 and lowered[0] == "texture" and lowered[1] == "dirty version":
        return True
    if rel.name.lower() in {"msfslayoutgenerator.exe", ".ds_store", "thumbs.db", "desktop.ini"}:
        return True
    if rel.suffix.lower() in {".exe", ".com", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".scr", ".msi", ".dll", ".lnk", ".url", ".hta", ".cpl"}:
        return True
    return False


def _validate_zip_security(zf: zipfile.ZipFile) -> None:
    seen: set[str] = set()
    for info in zf.infolist():
        rel = _safe_member_path(info.filename)
        key = rel.as_posix().casefold()
        if key in seen:
            raise UnsafeArchiveError(f"Archive contains duplicate Windows paths: {info.filename}")
        seen.add(key)
        if _is_zip_symlink(info):
            raise UnsafeArchiveError(f"Archive contains a symbolic link: {info.filename}")


def _extract_direct_zip_to(source: Path, destination: Path) -> None:
    with zipfile.ZipFile(source) as zf:
        _validate_zip_security(zf)
        names = _zip_names(zf)
        prefix = _native_prefix_from_names(names)
        if prefix is None:
            raise PackageValidationError("PMDG native ZIP metadata root could not be found.")
        for info in zf.infolist():
            raw = _safe_member_path(info.filename).as_posix()
            if not raw.lower().startswith(prefix.lower()):
                continue
            rel_raw = raw[len(prefix):]
            if not rel_raw:
                continue
            rel = _safe_member_path(rel_raw)
            if _skip_rel(rel):
                continue
            dest = destination.joinpath(*rel.parts)
            if info.is_dir() or raw.endswith("/"):
                dest.mkdir(parents=True, exist_ok=True)
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, dest.open("wb") as out:
                shutil.copyfileobj(src, out, 1024 * 1024)


def _copy_direct_folder_to(source: Path, destination: Path) -> None:
    root = direct_pmdg_folder_root(source)
    if root is None:
        raise PackageValidationError("PMDG native livery folder could not be found.")
    ensure_safe_tree(root)
    for path in root.rglob("*"):
        rel = _safe_member_path(path.relative_to(root).as_posix())
        if _skip_rel(rel):
            continue
        dest = destination.joinpath(*rel.parts)
        if path.is_dir():
            dest.mkdir(parents=True, exist_ok=True)
        elif path.is_file():
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, dest)


def _install_one_payload(source: Path, analysis: PackageAnalysis, target: Path, backup_root: Path, index: int) -> tuple[str, dict[str, str] | None]:
    airplane = analysis.pmdg_airplane_folder or _airplane_for_product(analysis.pmdg_product_package)
    livery_id = _validate_livery_id(analysis.pmdg_livery_id or safe_livery_folder_name(analysis.title, fallback=f"Livery-{index+1}"))
    rel = Path("SimObjects") / "Airplanes" / airplane / "liveries" / "pmdg" / livery_id
    destination = safe_target_path(target, rel.as_posix())
    backup_info: dict[str, str] | None = None
    destination.parent.mkdir(parents=True, exist_ok=True)
    transaction = Path(tempfile.mkdtemp(prefix=".liverydock-native-", dir=target.parent))
    staged = transaction / "payload"
    staged.mkdir()
    original = transaction / "original"
    preserve_recovery = False
    try:
        if source.is_dir():
            _copy_direct_folder_to(source, staged)
        else:
            _extract_direct_zip_to(source, staged)
        if destination.exists():
            ensure_safe_tree(destination)
            backup_name = f"livery-{index:03d}"
            backup_dest = backup_root / backup_name
            shutil.copytree(destination, backup_dest)
            backup_info = {"livery_rel": rel.as_posix(), "backup_subdir": backup_name}
            # Both renames stay on the Community drive. An unsuccessful swap
            # can restore the intact old directory without deleting its files.
            destination.replace(original)
        staged.replace(destination)
    except Exception:
        if original.exists():
            try:
                original.replace(destination)
            except OSError as exc:
                preserve_recovery = True
                raise LiveryDockError(f"Could not restore the previous livery. Its intact files are preserved at {original}") from exc
        raise
    finally:
        if not preserve_recovery:
            shutil.rmtree(transaction, ignore_errors=True)
    return rel.as_posix(), backup_info


@serialized_operation
def install_pmdg_native(analysis: PackageAnalysis, source: Path, community_root: Path) -> InstallRecord:
    if analysis.source_kind not in {"pmdg-native", "pmdg-native-bundle"}:
        raise LiveryDockError("install_pmdg_native called for a non-native PMDG source.")
    community_root = community_root.expanduser().resolve()
    _ensure_safe_target_root(community_root)
    community_root.mkdir(parents=True, exist_ok=True)

    product = analysis.pmdg_product_package
    if not _PRODUCT_RE.fullmatch(product):
        raise LiveryDockError("The PMDG product could not be identified from this livery bundle.")
    airplane = analysis.pmdg_airplane_folder or _PMDG_PRODUCT_TO_AIRPLANE.get(product, "")
    if not airplane:
        raise LiveryDockError(f"Unsupported PMDG product: {product}")
    _ensure_base_installed(community_root, product)

    target = community_root / _target_package_name(product)
    target = safe_target_path(community_root, target.name)
    if target.exists():
        ensure_safe_tree(target)
    backup_root = app_data_root() / "Backups" / f"native-{uuid.uuid4().hex}"
    backup_root.mkdir(parents=True, exist_ok=False)
    target_created = False
    installed_rels: list[str] = []
    replaced: list[dict[str, str]] = []
    seen_liveries: set[str] = set()

    try:
        if target.exists():
            if (target / "layout.json").is_file():
                shutil.copy2(target / "layout.json", backup_root / "layout.json")
            if (target / "manifest.json").is_file():
                shutil.copy2(target / "manifest.json", backup_root / "manifest.json")
        target_created = _ensure_livery_skeleton(target, product, airplane)

        if analysis.source_kind == "pmdg-native":
            fresh = analyze_pmdg_native(source, "pmdg-native")
            if fresh.pmdg_product_package != product:
                raise LiveryDockError(
                    f"Livery product changed during validation: expected {product}, got {fresh.pmdg_product_package}."
                )
            rel, backup_info = _install_one_payload(source, fresh, target, backup_root, 0)
            installed_rels.append(rel)
            if backup_info:
                replaced.append(backup_info)
            title = fresh.title
        else:
            members = sorted(analysis.pmdg_bundle_entries or nested_pmdg_zip_members(source),
                             key=lambda name: ("common" not in name.lower(), name.lower()))
            if not members:
                raise LiveryDockError("No nested PMDG livery ZIPs were found in this bundle.")
            title = analysis.title
            with zipfile.ZipFile(source) as outer:
                _validate_zip_security(outer)
                outer_members = {_safe_member_path(info.filename).as_posix(): info for info in outer.infolist()}
                for index, member in enumerate(members):
                    suffix = ".zip"
                    fd, temp_name = tempfile.mkstemp(prefix="liverydock-inner-", suffix=suffix)
                    os.close(fd)
                    temp_path = Path(temp_name)
                    try:
                        with outer.open(outer_members[member]) as src, temp_path.open("wb") as out:
                            shutil.copyfileobj(src, out, 1024 * 1024)
                        inner = analyze_pmdg_native(temp_path, "pmdg-native")
                        if inner.pmdg_product_package != product:
                            raise LiveryDockError(
                                f"Nested livery {member} targets {inner.pmdg_product_package}, but this bundle targets {product}."
                            )
                        identity = inner.pmdg_livery_id.casefold()
                        if identity in seen_liveries:
                            raise PackageValidationError(f"Bundle contains duplicate liveryId: {inner.pmdg_livery_id}")
                        seen_liveries.add(identity)
                        rel, backup_info = _install_one_payload(temp_path, inner, target, backup_root, index)
                        installed_rels.append(rel)
                        if backup_info:
                            replaced.append(backup_info)
                    finally:
                        temp_path.unlink(missing_ok=True)

        rebuild_layout_all(target)
        record = InstallRecord(
            id=uuid.uuid4().hex,
            package_name=analysis.package_name,
            title=title,
            version=analysis.version,
            package_format="pmdg-native-2024",
            target_kind="community2024" if community_root.name.lower() == "community2024" else "community",
            destination=str(target),
            source=str(source),
            backup=str(backup_root),
            installed_at=utc_now(),
            manifest_sha256=sha256_file(target / "manifest.json") if (target / "manifest.json").is_file() else "",
            install_kind="pmdg-native",
            metadata={
                "product_package": product,
                "airplane_folder": airplane,
                "livery_rels": installed_rels,
                "replaced": replaced,
                "target_created": target_created,
                "bundle": analysis.source_kind == "pmdg-native-bundle",
            },
        )
        records = load_registry()
        records.append(record)
        save_registry(records)
        try:
            append_log(f"Installed PMDG native livery source {source.name} into {target} ({len(installed_rels)} livery folder(s))")
        except OSError:
            pass  # A diagnostic log failure must not undo a committed installation.
        return record
    except Exception:
        for rel_raw in reversed(installed_rels):
            rel = PurePosixPath(rel_raw)
            shutil.rmtree(target.joinpath(*rel.parts), ignore_errors=True)
        for info in replaced:
            rel = PurePosixPath(info["livery_rel"])
            dest = target.joinpath(*rel.parts)
            backup = backup_root / info["backup_subdir"]
            if backup.is_dir():
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copytree(backup, dest, dirs_exist_ok=True)
        if target_created:
            shutil.rmtree(target, ignore_errors=True)
        elif target.exists():
            if (backup_root / "layout.json").is_file():
                shutil.copy2(backup_root / "layout.json", target / "layout.json")
            if (backup_root / "manifest.json").is_file():
                shutil.copy2(backup_root / "manifest.json", target / "manifest.json")
        shutil.rmtree(backup_root, ignore_errors=True)
        raise


def _record_livery_rels(record: InstallRecord) -> set[str]:
    if record.install_kind == "pmdg-native":
        value = record.metadata.get("livery_rels", [])
        if isinstance(value, list):
            return {str(item) for item in value}
    if record.install_kind == "pmdg-ptp":
        value = str(record.metadata.get("livery_rel", ""))
        return {value} if value else set()
    return set()


@serialized_operation
def uninstall_pmdg_native_record(record: InstallRecord) -> None:
    target, backup_root = validate_managed_record(record)
    current = load_registry()
    rels = _record_livery_rels(record)
    if not rels:
        raise LiveryDockError("Managed native livery record is missing its livery paths.")
    destinations = {raw: safe_target_path(target, validate_livery_relative_path(raw).as_posix()) for raw in rels}
    identities = {raw.replace("\\", "/").casefold() for raw in rels}
    position = next(index for index, item in enumerate(current) if item.id == record.id)
    for other in current[position + 1:]:
        if str(Path(other.destination).resolve()).casefold() != str(target.resolve()).casefold():
            continue
        other_rels = {raw.replace("\\", "/").casefold() for raw in _record_livery_rels(other)}
        if identities.intersection(other_rels):
            raise LiveryDockError("A newer managed install replaced one or more of these liveries. Uninstall the newer item first.")

    replaced_lookup: dict[str, Path] = {}
    raw_replaced = record.metadata.get("replaced", [])
    if not isinstance(raw_replaced, list):
        raise LiveryDockError("Managed native livery record has invalid backup metadata.")
    for item in raw_replaced:
        if not isinstance(item, dict) or str(item.get("livery_rel", "")) not in rels:
            raise LiveryDockError("Managed native livery record has invalid backup metadata.")
        subdir = str(item.get("backup_subdir", ""))
        if not backup_root or not re.fullmatch(r"livery-\d{3,}", subdir):
            raise LiveryDockError("Managed native livery record has an invalid backup path.")
        backup = safe_target_path(backup_root, subdir)
        if not backup.is_dir():
            raise LiveryDockError("A replaced livery backup is missing; the installed livery was left in place.")
        ensure_safe_tree(backup)
        replaced_lookup[str(item["livery_rel"])] = backup

    if target.exists():
        ensure_safe_tree(target)
    rollback_parent = app_data_root() / "Backups"
    rollback_parent.mkdir(parents=True, exist_ok=True)
    rollback = Path(tempfile.mkdtemp(prefix="uninstall-native-", dir=rollback_parent))
    snapshots: dict[str, Path] = {}
    try:
        # Capture the current installation before deleting anything, including layout metadata.
        for index, (rel_raw, dest) in enumerate(destinations.items()):
            if dest.exists():
                snapshot = rollback / f"payload-{index}"
                shutil.copytree(dest, snapshot)
                snapshots[rel_raw] = snapshot
        for filename in ("layout.json", "manifest.json"):
            if (target / filename).is_file():
                shutil.copy2(target / filename, rollback / filename)
        try:
            for rel_raw, dest in destinations.items():
                if dest.exists():
                    shutil.rmtree(dest)
                if rel_raw in replaced_lookup:
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copytree(replaced_lookup[rel_raw], dest)

            if target.exists():
                payload_remains = any(path.is_file() and path.relative_to(target).as_posix().lower()
                                      not in {"manifest.json", "layout.json"} for path in target.rglob("*"))
                other_records = any(item.id != record.id and str(Path(item.destination).resolve()).casefold()
                                    == str(target.resolve()).casefold() for item in current)
                if record.metadata.get("target_created") and not payload_remains and not other_records:
                    shutil.rmtree(target)
                else:
                    rebuild_layout_all(target)
            save_registry([item for item in current if item.id != record.id])
        except Exception:
            for rel_raw, dest in destinations.items():
                shutil.rmtree(dest, ignore_errors=True)
                if rel_raw in snapshots:
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copytree(snapshots[rel_raw], dest)
            for filename in ("layout.json", "manifest.json"):
                if (rollback / filename).is_file():
                    target.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(rollback / filename, target / filename)
            raise
    finally:
        shutil.rmtree(rollback, ignore_errors=True)
    if backup_root:
        shutil.rmtree(backup_root, ignore_errors=True)
    try:
        append_log(f"Uninstalled PMDG native managed source {record.title or record.package_name}")
    except OSError:
        pass
