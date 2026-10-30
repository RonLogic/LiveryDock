"""Native livery regressions built entirely from synthetic metadata and bytes."""
from __future__ import annotations

import json
import os
import shutil
import zipfile
from pathlib import Path

import pytest

from liverydock import pmdg_native as native
from liverydock.core import LiveryDockError, PackageValidationError, UnsafeArchiveError, load_registry, prepare_source


def native_zip(path: Path, *, livery_id: str = "TEST_NATIVE", product: str = "pmdg-aircraft-77er",
               prefix: str = "", extras: dict[str, bytes] | None = None) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(prefix + "livery.json", json.dumps({"productPackage": product, "liveryId": livery_id,
                                                           "title": "Synthetic test livery", "version": 1004}))
        archive.writestr(prefix + "livery.cfg", "[Selection]\nrequired_tags=b772_ext,engine_ge\n")
        archive.writestr(prefix + "texture/TEST.PNG.KTX2", b"synthetic-texture")
        archive.writestr(prefix + "model.airframe/livery.xml", "<ModelInfo/>")
        for name, value in (extras or {}).items():
            archive.writestr(prefix + name, value)
    return path


def bundle_zip(path: Path, archives: list[Path]) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for index, source in enumerate(archives):
            archive.write(source, f"pmdg-aircraft-77er-test-{index}.zip")
    return path


@pytest.fixture
def community(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    root = tmp_path / "Packages" / "Community2024"
    (root / "pmdg-aircraft-77er").mkdir(parents=True)
    return root


def install(archive: Path, community: Path):
    return native.install_pmdg_native(native.analyze_pmdg_native(archive), archive, community)


def livery_path(record, livery_id: str = "TEST_NATIVE") -> Path:
    return Path(record.destination) / "SimObjects" / "Airplanes" / "PMDG 777-200ER" / "liveries" / "pmdg" / livery_id


@pytest.mark.parametrize("product", ["pmdg-aircraft-77er/../../outside", "pmdg-aircraft-77er\\outside", "pmdg-aircraft-77er:stream"])
def test_native_product_cannot_supply_path(tmp_path: Path, product: str) -> None:
    source = native_zip(tmp_path / "bad.zip", product=product)
    with pytest.raises(PackageValidationError, match="productPackage"):
        native.analyze_pmdg_native(source)


@pytest.mark.parametrize("livery_id", ["../outside", "hidden:stream", "CON", "TRAILING.", " leading", "a" * 181])
def test_native_explicit_id_is_never_silently_renamed(tmp_path: Path, livery_id: str) -> None:
    source = native_zip(tmp_path / "bad.zip", livery_id=livery_id)
    with pytest.raises(PackageValidationError, match="liveryId"):
        native.analyze_pmdg_native(source)


def test_native_metadata_handles_case_and_windows_separators(tmp_path: Path, community: Path) -> None:
    source = native_zip(tmp_path / "source.zip")
    with zipfile.ZipFile(source) as archive:
        members = [(member.filename, archive.read(member)) for member in archive.infolist()]
    with zipfile.ZipFile(source, "w") as archive:
        for name, value in members:
            archive.writestr("Wrapper\\" + (name.upper() if name.startswith("livery.") else name), value)
    record = install(source, community)
    assert (livery_path(record) / "LIVERY.JSON").is_file()
    native.uninstall_pmdg_native_record(record)
    assert not Path(record.destination).exists()


def test_native_skips_helpers_and_alternate_texture(tmp_path: Path, community: Path) -> None:
    extras = {"MSFSLayoutGenerator.exe": b"helper", "texture/Dirty Version/TEST.PNG.KTX2": b"alternate",
              "helper.scr": b"script", "helper.ps1": b"script", "helper.dll": b"helper"}
    record = install(native_zip(tmp_path / "source.zip", extras=extras), community)
    root = livery_path(record)
    assert (root / "texture" / "TEST.PNG.KTX2").read_bytes() == b"synthetic-texture"
    assert all(not (root / name).exists() for name in extras)


def test_native_rejects_case_colliding_zip_members(tmp_path: Path) -> None:
    source = native_zip(tmp_path / "source.zip", extras={"LIVERY.JSON": b"{}"})
    with pytest.raises(UnsafeArchiveError, match="duplicate"):
        native.analyze_pmdg_native(source)


def test_complete_msfs_zip_keeps_all_embedded_liveries(tmp_path: Path) -> None:
    source = tmp_path / "ordinary-package.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("package/manifest.json", json.dumps({"title": "Synthetic", "content_type": "LIVERY"}))
        archive.writestr("package/layout.json", '{"content": []}')
        for name in ("FIRST", "SECOND"):
            prefix = f"package/SimObjects/Airplanes/Test/liveries/pmdg/{name}/"
            archive.writestr(prefix + "livery.json", "{}")
            archive.writestr(prefix + "livery.cfg", "[General]\n")
    prepared = prepare_source(source)
    try:
        assert prepared.source_kind == "package"
        assert len(prepared.package_roots) == 1
        assert len(list(prepared.root.rglob("livery.cfg"))) == 2
    finally:
        prepared.cleanup()


def test_native_zip_with_multiple_payload_roots_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "ambiguous.zip"
    with zipfile.ZipFile(source, "w") as archive:
        for name in ("FIRST", "SECOND"):
            archive.writestr(f"{name}/livery.json", "{}")
            archive.writestr(f"{name}/livery.cfg", "[General]\n")
    with pytest.raises(PackageValidationError, match="multiple native"):
        prepare_source(source)


def test_native_rejects_folder_junction(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    archive = native_zip(tmp_path / "source.zip")
    with zipfile.ZipFile(archive) as zf:
        zf.extractall(source)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "private.txt").write_text("must stay outside", encoding="utf-8")
    link = source / "linked"
    try:
        if os.name == "nt":
            import _winapi
            _winapi.CreateJunction(str(outside), str(link))
        else:
            link.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"Link creation unavailable: {exc}")
    with pytest.raises(LiveryDockError):
        native.analyze_pmdg_native(source)


def test_native_duplicate_bundle_restores_existing_livery(tmp_path: Path, community: Path) -> None:
    first = install(native_zip(tmp_path / "original.zip"), community)
    original = livery_path(first) / "texture" / "TEST.PNG.KTX2"
    original.write_bytes(b"original")
    layout_before = (Path(first.destination) / "layout.json").read_bytes()
    a = native_zip(tmp_path / "a.zip")
    b = native_zip(tmp_path / "b.zip", livery_id="test_native")
    with pytest.raises(PackageValidationError, match="duplicate liveryId"):
        install(bundle_zip(tmp_path / "bundle.zip", [a, b]), community)
    assert original.read_bytes() == b"original"
    assert (Path(first.destination) / "layout.json").read_bytes() == layout_before
    assert [record.id for record in load_registry()] == [first.id]


def test_native_bundle_failure_removes_partial_new_target(tmp_path: Path, community: Path) -> None:
    a = native_zip(tmp_path / "a.zip")
    b = native_zip(tmp_path / "b.zip", product="pmdg-aircraft-77w", livery_id="OTHER")
    with pytest.raises(LiveryDockError, match="targets"):
        install(bundle_zip(tmp_path / "bundle.zip", [a, b]), community)
    assert not (community / "pmdg-aircraft-77er-liveries").exists()
    assert load_registry() == []


def test_native_same_timestamp_replacement_must_uninstall_newest_first(tmp_path: Path, community: Path,
                                                                     monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native, "utc_now", lambda: "2026-10-30T00:00:00+00:00")
    first = install(native_zip(tmp_path / "first.zip"), community)
    second = install(native_zip(tmp_path / "second.zip", livery_id="test_native"), community)
    with pytest.raises(LiveryDockError, match="newer"):
        native.uninstall_pmdg_native_record(first)
    native.uninstall_pmdg_native_record(second)
    assert (livery_path(first) / "livery.json").is_file()
    native.uninstall_pmdg_native_record(first)
    assert not Path(first.destination).exists()


def test_native_missing_replacement_backup_leaves_installed_files(tmp_path: Path, community: Path) -> None:
    install(native_zip(tmp_path / "first.zip"), community)
    second = install(native_zip(tmp_path / "second.zip"), community)
    shutil.rmtree(Path(second.backup) / "livery-000")
    with pytest.raises(LiveryDockError, match="backup is missing"):
        native.uninstall_pmdg_native_record(second)
    assert (livery_path(second) / "livery.json").is_file()
    assert len(load_registry()) == 2


def test_native_uninstall_registry_failure_restores_current_install(tmp_path: Path, community: Path,
                                                                  monkeypatch: pytest.MonkeyPatch) -> None:
    record = install(native_zip(tmp_path / "source.zip"), community)
    target = Path(record.destination)
    original_layout = (target / "layout.json").read_bytes()

    def fail_save(_records):
        raise OSError("synthetic registry failure")

    monkeypatch.setattr(native, "save_registry", fail_save)
    with pytest.raises(OSError, match="registry failure"):
        native.uninstall_pmdg_native_record(record)
    assert (livery_path(record) / "livery.json").is_file()
    assert (target / "layout.json").read_bytes() == original_layout
    assert len(load_registry()) == 1


def test_native_uninstall_preserves_unmanaged_package_files(tmp_path: Path, community: Path) -> None:
    record = install(native_zip(tmp_path / "source.zip"), community)
    unrelated = Path(record.destination) / "another-owner.txt"
    unrelated.write_text("keep", encoding="utf-8")
    native.uninstall_pmdg_native_record(record)
    assert unrelated.read_text(encoding="utf-8") == "keep"
    assert not livery_path(record).exists()


def test_native_source_copy_failure_never_removes_existing_livery(tmp_path: Path, community: Path,
                                                                monkeypatch: pytest.MonkeyPatch) -> None:
    first = install(native_zip(tmp_path / "first.zip"), community)
    source = native_zip(tmp_path / "second.zip")
    original = livery_path(first) / "livery.json"
    original_bytes = original.read_bytes()

    def fail_extract(_source, destination):
        (destination / "partial.txt").write_text("partial", encoding="utf-8")
        raise OSError("synthetic source failure")

    monkeypatch.setattr(native, "_extract_direct_zip_to", fail_extract)
    with pytest.raises(OSError, match="source failure"):
        install(source, community)
    assert original.read_bytes() == original_bytes
    assert [record.id for record in load_registry()] == [first.id]


def test_native_swap_failure_restores_intact_previous_directory(tmp_path: Path, community: Path,
                                                              monkeypatch: pytest.MonkeyPatch) -> None:
    first = install(native_zip(tmp_path / "first.zip"), community)
    source = native_zip(tmp_path / "second.zip")
    original = livery_path(first) / "livery.json"
    original_bytes = original.read_bytes()
    actual_replace = Path.replace

    def fail_payload_swap(path: Path, destination):
        if path.name == "payload" and path.parent.name.startswith(".liverydock-native-"):
            raise OSError("synthetic swap failure")
        return actual_replace(path, destination)

    monkeypatch.setattr(Path, "replace", fail_payload_swap)
    with pytest.raises(OSError, match="swap failure"):
        install(source, community)
    assert original.read_bytes() == original_bytes
    assert [record.id for record in load_registry()] == [first.id]


def test_native_install_registry_failure_restores_existing_livery(tmp_path: Path, community: Path,
                                                                monkeypatch: pytest.MonkeyPatch) -> None:
    first = install(native_zip(tmp_path / "first.zip"), community)
    original = livery_path(first) / "texture" / "TEST.PNG.KTX2"
    original.write_bytes(b"original")

    def fail_save(_records):
        raise OSError("synthetic registry failure")

    monkeypatch.setattr(native, "save_registry", fail_save)
    with pytest.raises(OSError, match="registry failure"):
        install(native_zip(tmp_path / "second.zip"), community)
    assert original.read_bytes() == b"original"
    assert [record.id for record in load_registry()] == [first.id]
