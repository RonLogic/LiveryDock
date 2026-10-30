from __future__ import annotations

import json
import os
import shutil
import zipfile
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from liverydock import core


@pytest.fixture(autouse=True)
def isolated_app_data(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))


def package(root: Path, version: str = "1") -> Path:
    root.mkdir(parents=True)
    (root / "manifest.json").write_text(json.dumps({
        "package_name": "demo-livery", "title": "Synthetic livery",
        "content_type": "LIVERY", "package_version": version,
    }), encoding="utf-8")
    (root / "paint.txt").write_text(version, encoding="utf-8")
    (root / "layout.json").write_text('{"content": [{"path": "paint.txt"}]}', encoding="utf-8")
    return root


def install(root: Path, community: Path) -> core.InstallRecord:
    return core.install_package(core.analyze_package(root), root, community, "community2024")


def create_directory_link(link: Path, target: Path) -> None:
    try:
        if os.name == "nt":
            import _winapi
            _winapi.CreateJunction(str(target), str(link))
        else:
            link.symlink_to(target, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"Host does not permit creating directory links: {exc}")


def test_python311_windows_junction_tag_is_detected() -> None:
    class Junction:
        def is_symlink(self):
            return False

        def lstat(self):
            return SimpleNamespace(st_reparse_tag=0xA0000003)

    assert core._is_link(Junction())


def test_link_ancestor_guard_runs_before_extraction(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    destination = tmp_path / "extracted"
    linked = destination / "texture"
    linked.mkdir(parents=True)
    original = core._is_link
    monkeypatch.setattr(core, "_is_link", lambda path: path == linked or original(path))
    archive = tmp_path / "paint.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("texture/escape.txt", b"synthetic")
    with pytest.raises(core.LiveryDockError, match="link|junction"):
        core.safe_extract_zip(archive, destination)
    assert not (linked / "escape.txt").exists()


@pytest.mark.parametrize("name", [
    "../escape", "C:/escape", "/escape", "dir/../escape", "dir/file:stream",
    "dir/CON.txt", "dir/NUL", "dir/LPT9.bin", "dir/trailing. ", "dir/trailing.",
    "dir/wild?.txt", "dir/control\x01.txt", "\\\\server\\share\\file", "dir/COM¹.txt", "dir/NUL .txt",
])
def test_windows_archive_path_aliases_are_rejected(tmp_path: Path, name: str) -> None:
    archive = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr(name, b"synthetic")
    with pytest.raises(core.UnsafeArchiveError):
        core.safe_extract_zip(archive, tmp_path / "extracted")
    assert not (tmp_path / "escape").exists()


def test_zip_duplicates_are_rejected_before_extracting(tmp_path: Path) -> None:
    archive = tmp_path / "duplicates.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("Paint.KTX2", b"one")
        output.writestr("paint.ktx2", b"two")
    destination = tmp_path / "extracted"
    with pytest.raises(core.UnsafeArchiveError, match="duplicate"):
        core.safe_extract_zip(archive, destination)
    assert list(destination.iterdir()) == []


def test_zip_unix_symlink_is_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "links.zip"
    link = zipfile.ZipInfo("link")
    link.create_system = 3
    link.external_attr = 0o120777 << 16
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr(link, "../outside")
    with pytest.raises(core.UnsafeArchiveError, match="symbolic link"):
        core.safe_extract_zip(archive, tmp_path / "extracted")


def test_zip_backslashes_are_extracted_to_the_validated_path(tmp_path: Path) -> None:
    archive = tmp_path / "windows.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("texture\\paint.KTX2", b"synthetic")
    core.safe_extract_zip(archive, tmp_path / "extracted")
    assert (tmp_path / "extracted" / "texture" / "paint.KTX2").read_bytes() == b"synthetic"


def test_zip_does_not_follow_existing_directory_link(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    destination = tmp_path / "extracted"
    destination.mkdir()
    create_directory_link(destination / "texture", outside)
    archive = tmp_path / "paint.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("texture/escape.txt", b"synthetic")
    with pytest.raises(core.LiveryDockError, match="link|junction"):
        core.safe_extract_zip(archive, destination)
    assert not (outside / "escape.txt").exists()


def test_7zip_link_listing_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class Result:
        returncode = 0
        stdout = "----------\nPath = link\nSymbolic Link = ../outside\n"
        stderr = ""
    monkeypatch.setattr(core.subprocess, "run", lambda *args, **kwargs: Result())
    with pytest.raises(core.UnsafeArchiveError, match="link"):
        core._list_7zip_entries(Path("7z"), tmp_path / "paint.7z")


def test_install_copy_failure_preserves_previous_install(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    community = tmp_path / "Community2024"
    first = install(package(tmp_path / "v1", "1"), community)
    second = package(tmp_path / "v2", "2")
    original_copytree = core.shutil.copytree

    def failed_copy(source, destination, *args, **kwargs):
        result = original_copytree(source, destination, *args, **kwargs)
        if Path(source) == second:
            raise OSError("synthetic copy failure")
        return result

    monkeypatch.setattr(core.shutil, "copytree", failed_copy)
    with pytest.raises(OSError, match="synthetic copy failure"):
        install(second, community)
    assert (Path(first.destination) / "paint.txt").read_text() == "1"
    assert core.load_registry() == [first]
    assert not list(community.glob(".liverydock-staging-*"))


@pytest.mark.parametrize("existing", [False, True])
def test_install_registry_failure_rolls_back_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, existing: bool) -> None:
    community = tmp_path / "Community2024"
    first = install(package(tmp_path / "v1", "1"), community) if existing else None
    second = package(tmp_path / "v2", "2")

    def fail(_records):
        raise OSError("synthetic registry failure")

    monkeypatch.setattr(core, "save_registry", fail)
    with pytest.raises(OSError, match="synthetic registry failure"):
        install(second, community)
    destination = community / "demo-livery"
    if first:
        assert (destination / "paint.txt").read_text() == "1"
        assert core.load_registry() == [first]
    else:
        assert not destination.exists()
        assert core.load_registry() == []


def test_uninstall_registry_failure_restores_live_package(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    community = tmp_path / "Community2024"
    install(package(tmp_path / "v1", "1"), community)
    second = install(package(tmp_path / "v2", "2"), community)

    def fail(_records):
        raise OSError("synthetic registry failure")

    monkeypatch.setattr(core, "save_registry", fail)
    with pytest.raises(OSError, match="synthetic registry failure"):
        core.uninstall_record(second)
    assert (Path(second.destination) / "paint.txt").read_text() == "2"
    assert (Path(second.backup) / "paint.txt").read_text() == "1"
    assert core.load_registry() == [second]


def test_missing_backup_blocks_uninstall_before_removal(tmp_path: Path) -> None:
    community = tmp_path / "Community2024"
    install(package(tmp_path / "v1", "1"), community)
    second = install(package(tmp_path / "v2", "2"), community)
    shutil.rmtree(second.backup)
    with pytest.raises(core.LiveryDockError, match="backup is missing"):
        core.uninstall_record(second)
    assert (Path(second.destination) / "paint.txt").read_text() == "2"
    assert core.load_registry() == [second]


def test_stale_record_cannot_uninstall_replacement(tmp_path: Path) -> None:
    community = tmp_path / "Community2024"
    first = install(package(tmp_path / "v1", "1"), community)
    second = install(package(tmp_path / "v2", "2"), community)
    with pytest.raises(core.LiveryDockError, match="changed|no longer exists"):
        core.uninstall_record(first)
    assert (Path(second.destination) / "paint.txt").read_text() == "2"


def test_rapid_reinstalls_use_distinct_backups(tmp_path: Path) -> None:
    community = tmp_path / "Community2024"
    install(package(tmp_path / "v1", "1"), community)
    second = install(package(tmp_path / "v2", "2"), community)
    third = install(package(tmp_path / "v3", "3"), community)
    assert second.backup != third.backup
    assert (Path(second.backup) / "paint.txt").read_text() == "1"
    assert (Path(third.backup) / "paint.txt").read_text() == "2"


def test_corrupt_registry_is_not_overwritten(tmp_path: Path) -> None:
    registry = core.registry_path()
    registry.parent.mkdir(parents=True)
    registry.write_bytes(b"{corrupt")
    source = package(tmp_path / "source")
    with pytest.raises(core.LiveryDockError, match="registry"):
        install(source, tmp_path / "Community2024")
    assert registry.read_bytes() == b"{corrupt"
    assert not (tmp_path / "Community2024" / "demo-livery").exists()


def test_registry_cannot_restore_backup_outside_managed_storage(tmp_path: Path) -> None:
    record = install(package(tmp_path / "source"), tmp_path / "Community2024")
    outside = tmp_path / "outside"
    outside.mkdir()
    forged = replace(record, backup=str(outside))
    core.save_registry([forged])
    with pytest.raises(core.LiveryDockError, match="outside"):
        core.uninstall_record(forged)
    assert Path(record.destination).exists()
    assert outside.exists()


def test_registry_cannot_remove_official_package(tmp_path: Path) -> None:
    record = install(package(tmp_path / "source"), tmp_path / "Community2024")
    official = tmp_path / "Official2024" / "demo-livery"
    official.mkdir(parents=True)
    forged = replace(record, destination=str(official))
    core.save_registry([forged])
    with pytest.raises(core.LiveryDockError, match="Official"):
        core.uninstall_record(forged)
    assert official.exists()


def test_source_inside_destination_is_refused(tmp_path: Path) -> None:
    community = tmp_path / "Community2024"
    source = package(community / "demo-livery" / "nested-source")
    with pytest.raises(core.LiveryDockError, match="separate folders"):
        install(source, community)
    assert (source / "paint.txt").exists()


def test_package_with_junction_is_not_copied(tmp_path: Path) -> None:
    source = package(tmp_path / "source")
    outside = tmp_path / "outside"
    outside.mkdir()
    create_directory_link(source / "linked", outside)
    with pytest.raises(core.LiveryDockError, match="link|junction"):
        core.analyze_package(source)


def test_layout_merge_rejects_traversal(tmp_path: Path) -> None:
    source = package(tmp_path / "source")
    layout_before = (source / "layout.json").read_bytes()
    with pytest.raises(core.UnsafeArchiveError):
        core.merge_layout_entries(source, [Path("../outside")])
    assert (source / "layout.json").read_bytes() == layout_before


@pytest.mark.parametrize("name", ["CON", "NUL.txt", "LPT1", "COM9.cfg"])
def test_reserved_package_names_get_safe_prefix(name: str) -> None:
    result = core.sanitize_package_name(name)
    assert result.startswith("livery-")
    core._safe_member_path(result)


@pytest.fixture
def ptp_setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from liverydock import ptp as ptp_module

    community = tmp_path / "Packages" / "Community"
    template = community / "pmdg-aircraft-739" / "SimObjects" / "Airplanes" / "PMDG 737-900" / "liveries" / "pmdg" / "House"
    template.mkdir(parents=True)
    (template / "livery.cfg").write_text("[Selection]\nrequired_tags=b739er_ext,SSW_L,SSW_R\n", encoding="utf-8")
    (template / "livery.json").write_text("{}", encoding="utf-8")
    source = tmp_path / "PMDG739ER Synthetic.ptp"
    source.write_bytes(b"CRYP" + b"\x00" * 128)
    sdk = tmp_path / "SDK"
    sdk.mkdir()

    def extract(_source, destination):
        destination.mkdir(parents=True)
        (destination / "Config.cfg").write_text(
            "[fltsim.x]\ntitle=Synthetic\natc_airline=TEST\natc_id=TEST01\nmodel=ERSSW\nsim=B737-900ER\n",
            encoding="utf-8",
        )

    def build(_extracted, _template, destination, *_args, **_kwargs):
        destination.mkdir(parents=True)
        (destination / "livery.cfg").write_text("synthetic", encoding="utf-8")

    monkeypatch.setattr(ptp_module, "extract_pmdg_ptp", extract)
    monkeypatch.setattr(ptp_module, "build_native_livery_from_legacy", build)
    return source, community, sdk


def ptp_install(setup):
    source, community, sdk = setup
    return core.install_pmdg_ptp(core.analyze_ptp(source), source, community, sdk)


def test_ptp_registry_failure_removes_new_companion_package(ptp_setup, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(_records):
        raise OSError("synthetic registry failure")

    monkeypatch.setattr(core, "save_registry", fail)
    with pytest.raises(OSError, match="synthetic registry failure"):
        ptp_install(ptp_setup)
    _, community, _ = ptp_setup
    assert not (community / "pmdg-aircraft-739-liveries").exists()
    assert core.load_registry() == []


def test_ptp_replacement_registry_failure_restores_old_livery(ptp_setup, monkeypatch: pytest.MonkeyPatch) -> None:
    first = ptp_install(ptp_setup)
    target = Path(first.destination)
    livery = core.safe_target_path(target, first.metadata["livery_rel"])
    (livery / "original.txt").write_text("keep", encoding="utf-8")
    core.rebuild_layout_all(target)
    layout_before = (target / "layout.json").read_bytes()

    def fail(_records):
        raise OSError("synthetic registry failure")

    monkeypatch.setattr(core, "save_registry", fail)
    with pytest.raises(OSError, match="synthetic registry failure"):
        ptp_install(ptp_setup)
    assert (livery / "original.txt").read_text() == "keep"
    assert (target / "layout.json").read_bytes() == layout_before
    assert core.load_registry() == [first]


@pytest.mark.parametrize("metadata", [None, "layout.json", "manifest.json"])
def test_ptp_failure_restores_incomplete_companion_metadata(ptp_setup, monkeypatch: pytest.MonkeyPatch, metadata: str | None) -> None:
    _, community, _ = ptp_setup
    target = community / "pmdg-aircraft-739-liveries"
    target.mkdir()
    (target / "unmanaged.txt").write_text("keep", encoding="utf-8")
    if metadata:
        content = '{"content": []}' if metadata == "layout.json" else '{"total_package_size": "123"}'
        (target / metadata).write_text(content, encoding="utf-8")
    before = {path.relative_to(target): path.read_bytes() for path in target.rglob("*") if path.is_file()}

    def fail(_records):
        raise OSError("synthetic registry failure")

    monkeypatch.setattr(core, "save_registry", fail)
    with pytest.raises(OSError, match="synthetic registry failure"):
        ptp_install(ptp_setup)
    after = {path.relative_to(target): path.read_bytes() for path in target.rglob("*") if path.is_file()}
    assert after == before
    assert core.load_registry() == []


def test_ptp_backup_copy_failure_does_not_delete_original(ptp_setup, monkeypatch: pytest.MonkeyPatch) -> None:
    first = ptp_install(ptp_setup)
    target = Path(first.destination)
    livery = core.safe_target_path(target, first.metadata["livery_rel"])
    (livery / "original.txt").write_text("keep", encoding="utf-8")
    original_copytree = core.shutil.copytree

    def fail(source, destination, *args, **kwargs):
        if Path(source) == livery:
            Path(destination).mkdir()
            raise OSError("synthetic backup failure")
        return original_copytree(source, destination, *args, **kwargs)

    monkeypatch.setattr(core.shutil, "copytree", fail)
    with pytest.raises(OSError, match="synthetic backup failure"):
        ptp_install(ptp_setup)
    assert (livery / "original.txt").read_text() == "keep"
    assert core.load_registry() == [first]


def test_ptp_uninstall_registry_failure_restores_current_files(ptp_setup, monkeypatch: pytest.MonkeyPatch) -> None:
    record = ptp_install(ptp_setup)
    target = Path(record.destination)
    livery = core.safe_target_path(target, record.metadata["livery_rel"])
    before = (target / "layout.json").read_bytes()

    def fail(_records):
        raise OSError("synthetic registry failure")

    monkeypatch.setattr(core, "save_registry", fail)
    with pytest.raises(OSError, match="synthetic registry failure"):
        core.uninstall_record(record)
    assert (livery / "livery.cfg").read_text() == "synthetic"
    assert (target / "layout.json").read_bytes() == before
    assert core.load_registry() == [record]


def test_ptp_uninstall_preserves_unmanaged_payload(ptp_setup) -> None:
    record = ptp_install(ptp_setup)
    target = Path(record.destination)
    (target / "unmanaged.txt").write_text("keep", encoding="utf-8")
    core.uninstall_record(record)
    assert (target / "unmanaged.txt").read_text() == "keep"
    assert core.load_registry() == []


def test_ptp_uninstall_blocks_newer_native_overlap_with_equal_timestamp(ptp_setup) -> None:
    record = ptp_install(ptp_setup)
    rel = record.metadata["livery_rel"]
    native = replace(record, id="newer-native", install_kind="pmdg-native", metadata={"livery_rels": [rel.upper()]})
    core.save_registry([record, native])
    with pytest.raises(core.LiveryDockError, match="newer managed install"):
        core.uninstall_record(record)
    assert core.safe_target_path(Path(record.destination), rel).exists()


def test_ptp_uninstall_rejects_package_root_as_livery_path(ptp_setup) -> None:
    record = ptp_install(ptp_setup)
    malformed = replace(record, metadata={**record.metadata, "livery_rel": "."})
    core.save_registry([malformed])
    with pytest.raises(core.LiveryDockError, match="one PMDG livery"):
        core.uninstall_record(malformed)
    assert Path(record.destination).exists()


def test_unknown_ptp_target_never_selects_official_folder(tmp_path: Path) -> None:
    community = tmp_path / "Packages" / "Community"
    official = community.parent / "Official2024" / "pmdg-aircraft-739-liveries"
    official.mkdir(parents=True)
    (official / "layout.json").write_text('{"content": []}', encoding="utf-8")
    source = tmp_path / "unidentified.ptp"
    source.write_bytes(b"CRYP" + b"\x00" * 128)
    with pytest.raises(core.LiveryDockError, match="No installed"):
        core.resolve_pmdg_livery_target(community, core.analyze_ptp(source))
    assert official.exists()


def legacy_record(tmp_path: Path) -> core.InstallRecord:
    target = tmp_path / "Community" / "pmdg-aircraft-739-liveries"
    target.mkdir(parents=True)
    (target / "manifest.json").write_text("{}", encoding="utf-8")
    (target / "layout.json").write_text('{"content": []}', encoding="utf-8")
    (target / "paint.txt").write_text("new", encoding="utf-8")
    backup = core.app_data_root() / "Backups" / "legacy"
    (backup / "files").mkdir(parents=True)
    (backup / "files" / "paint.txt").write_text("old", encoding="utf-8")
    record = core.InstallRecord(
        id="legacy", package_name="legacy", title="Synthetic legacy", version="",
        package_format="pmdg-ptp", target_kind="community", destination=str(target),
        source="synthetic.ptp", backup=str(backup), installed_at=core.utc_now(), manifest_sha256="",
        install_kind="pmdg-ptp", metadata={"copied_files": ["paint.txt"], "overwritten_files": ["paint.txt"], "added_files": []},
    )
    core.save_registry([record])
    return record


def test_legacy_ptp_uninstall_registry_failure_restores_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    record = legacy_record(tmp_path)

    def fail(_records):
        raise OSError("synthetic registry failure")

    monkeypatch.setattr(core, "save_registry", fail)
    with pytest.raises(OSError, match="synthetic registry failure"):
        core.uninstall_record(record)
    assert (Path(record.destination) / "paint.txt").read_text() == "new"
    assert core.load_registry() == [record]


def test_legacy_ptp_unsafe_record_is_rejected_before_any_removal(tmp_path: Path) -> None:
    record = legacy_record(tmp_path)
    forged = replace(record, metadata={"copied_files": ["paint.txt", "../outside"], "added_files": ["paint.txt"], "overwritten_files": []})
    core.save_registry([forged])
    with pytest.raises(core.UnsafeArchiveError):
        core.uninstall_record(forged)
    assert (Path(record.destination) / "paint.txt").read_text() == "new"
