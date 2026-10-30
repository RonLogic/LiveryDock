from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from liverydock.core import (
    UnsafeArchiveError,
    analyze_package,
    discover_package_roots,
    parse_usercfg,
    safe_extract_zip,
    sanitize_package_name,
    install_package,
    load_registry,
    uninstall_record,
)


def write_package(
    root: Path,
    *,
    native: bool = False,
    legacy: bool = False,
    include_package_name: bool = True,
) -> Path:
    root.mkdir(parents=True)
    manifest = {"title": "Demo Livery", "content_type": "LIVERY"}
    if include_package_name:
        manifest["package_name"] = "demo-livery"
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    files: list[str] = []
    if native:
        path = root / "SimObjects" / "Airplanes" / "Demo" / "liveries" / "Blue" / "livery.cfg"
        path.parent.mkdir(parents=True)
        path.write_text("[Version]\nmajor=1\nminor=0\n[General]\nname=Blue\n", encoding="utf-8")
        files.append(path.relative_to(root).as_posix())
    if legacy:
        cfg = root / "SimObjects" / "Airplanes" / "DemoBlue" / "aircraft.cfg"
        cfg.parent.mkdir(parents=True)
        cfg.write_text("[LIVERY]\nbase_container=..\\Demo\n", encoding="utf-8")
        texture = cfg.parent / "texture.blue"
        texture.mkdir()
        files.extend([cfg.relative_to(root).as_posix()])
    (root / "layout.json").write_text(json.dumps({"content": [{"path": path} for path in files]}), encoding="utf-8")
    return root


def test_parse_usercfg(tmp_path: Path) -> None:
    cfg = tmp_path / "UserCfg.opt"
    cfg.write_text('InstalledPackagesPath "D:\\\\MSFS2024\\\\Packages"\n', encoding="utf-8")
    assert parse_usercfg(cfg) == Path(r"D:\MSFS2024\Packages")


def test_nested_package_discovery(tmp_path: Path) -> None:
    pkg = write_package(tmp_path / "wrapper" / "actual", native=True)
    assert discover_package_roots(tmp_path) == [pkg]


def test_native_livery_detection(tmp_path: Path) -> None:
    analysis = analyze_package(write_package(tmp_path / "native", native=True))
    assert analysis.is_livery
    assert analysis.package_format == "native-2024"
    assert analysis.target_hint == "community2024"


def test_legacy_livery_detection(tmp_path: Path) -> None:
    analysis = analyze_package(write_package(tmp_path / "legacy", legacy=True))
    assert analysis.is_livery
    assert analysis.package_format == "legacy-2020"
    assert analysis.target_hint == "community"


def test_zip_slip_is_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../escape.txt", "bad")
    with pytest.raises(UnsafeArchiveError):
        safe_extract_zip(archive, tmp_path / "out")


def test_sanitize_package_name() -> None:
    assert sanitize_package_name(" My Fancy Livery!!! ") == "My-Fancy-Livery"


def test_install_backup_and_restore(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    source_v1 = write_package(tmp_path / "source-v1", native=True)
    community = tmp_path / "Packages" / "Community2024"
    analysis_v1 = analyze_package(source_v1)
    first = install_package(analysis_v1, source_v1, community, "community2024")
    assert (community / "demo-livery" / "manifest.json").exists()
    assert len(load_registry()) == 1

    source_v2 = write_package(tmp_path / "source-v2", native=True)
    manifest = json.loads((source_v2 / "manifest.json").read_text(encoding="utf-8"))
    manifest["package_version"] = "2.0.0"
    (source_v2 / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    second = install_package(analyze_package(source_v2), source_v2, community, "community2024")
    assert second.backup is not None
    assert Path(second.backup).exists()
    assert len(load_registry()) == 1

    uninstall_record(second, restore_backup=True)
    restored_manifest = json.loads((community / "demo-livery" / "manifest.json").read_text(encoding="utf-8"))
    assert restored_manifest.get("package_version") is None
    assert load_registry() == []



def test_install_manifest_without_package_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: staging must preserve folder-derived package identity."""
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    source = write_package(
        tmp_path / "Ossim-VDG-El-Al-739-Fleet-Package-P2",
        native=True,
        include_package_name=False,
    )
    analysis = analyze_package(source)
    community = tmp_path / "Packages" / "Community2024"
    record = install_package(analysis, source, community, "community2024")
    destination = Path(record.destination)
    assert destination.name == analysis.package_name
    assert (destination / "manifest.json").exists()


def test_refuses_official_folder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    source = write_package(tmp_path / "source", native=True)
    with pytest.raises(Exception, match="Official"):
        install_package(analyze_package(source), source, tmp_path / "Official2024", "community2024")


def test_pmdg_ptp_detection_and_739_mapping(tmp_path: Path) -> None:
    from liverydock.core import analyze_ptp
    ptp = tmp_path / "PMDG739ER Ryanair EI-CSN.ptp"
    ptp.write_bytes(b"CRYP" + b"\x00" * 128)
    analysis = analyze_ptp(ptp)
    assert analysis.is_livery
    assert analysis.package_format == "pmdg-ptp"
    assert analysis.ptp_product_code == "739"
    assert analysis.ptp_target_package == "pmdg-aircraft-739-liveries"
    assert analysis.target_hint == "community"


def test_non_pmdg_ptp_header_rejected(tmp_path: Path) -> None:
    from liverydock.core import PackageValidationError, analyze_ptp
    ptp = tmp_path / "not-pmdg.ptp"
    ptp.write_bytes(b"NOPE" + b"\x00" * 128)
    with pytest.raises(PackageValidationError, match="CRYP"):
        analyze_ptp(ptp)


def test_pmdg_ptp_native_conversion_and_uninstall(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import shutil
    import liverydock.core as core
    import liverydock.ptp as ptpmod

    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    community = tmp_path / "Packages" / "Community"
    base = community / "pmdg-aircraft-739"
    template = base / "SimObjects" / "Airplanes" / "PMDG 737-900" / "liveries" / "pmdg" / "PMDG House"
    (template / "model").mkdir(parents=True)
    (template / "texture").mkdir()
    (template / "model" / "model.cfg").write_text("[models]\n", encoding="utf-8")
    (template / "texture" / "fallback.ktx2").write_bytes(b"KTX2")
    (template / "livery.cfg").write_text(
        "[Version]\nmajor=1\nminor=4\n[Selection]\nrequired_tags=b739er_ext,SSW_L,SSW_R\n", encoding="utf-8"
    )
    (template / "livery.json").write_text(json.dumps({"rev": 2, "productId": 999, "version": 1004}), encoding="utf-8")

    ptp = tmp_path / "PMDG739ER Ryanair EI-CSN.ptp"
    ptp.write_bytes(b"CRYP" + b"\x00" * 128)

    def fake_extract(_ptp: Path, out: Path):
        out.mkdir(parents=True, exist_ok=True)
        (out / "Config.cfg").write_text(
            "[fltsim.x]\ntitle=PMDG 737-900ER Ryanair EI-CSN\natc_airline=Ryanair\nicao_airline=RYR\natc_id=EI-CSN\nmodel=ERSSW\nsim=B737-900ER\ntexture=ERYR_CSN\nui_variation=Ryanair EI-CSN\n",
            encoding="utf-8",
        )
        (out / "Settings.dat").write_text("[Settings]\nAircraft=PMDG 737-900\nVariant=PMDG 737-900ER\nName=Ryanair EI-CSN\n", encoding="utf-8")
        tex = out / "Texture.ERYR_CSN"
        tex.mkdir()
        (tex / "PMDG_NG3_F1_ALBD.PNG.DDS").write_bytes(b"DDS")
        return [out / "Config.cfg", tex / "PMDG_NG3_F1_ALBD.PNG.DDS"]

    def fake_build(extracted: Path, template_path: Path, destination: Path, product_code: str, sdk_root: Path, steam: bool = False):
        shutil.copytree(template_path, destination)
        (destination / "converted.marker").write_text("ok", encoding="utf-8")
        return ({"title": "PMDG 737-900ER Ryanair EI-CSN", "atc_id": "EI-CSN"}, ["b739er_ext", "SSW_L", "SSW_R"])

    monkeypatch.setattr(ptpmod, "extract_pmdg_ptp", fake_extract)
    monkeypatch.setattr(ptpmod, "build_native_livery_from_legacy", fake_build)
    analysis = core.analyze_ptp(ptp)
    sdk = tmp_path / "MSFS 2024 SDK"
    sdk.mkdir()
    record = core.install_pmdg_ptp(analysis, ptp, community, sdk)

    target = community / "pmdg-aircraft-739-liveries"
    livery = target / "SimObjects" / "Airplanes" / "PMDG 737-900" / "liveries" / "pmdg" / "Ryanair_EI-CSN"
    assert (livery / "converted.marker").exists()
    assert record.metadata["native_conversion"] is True
    assert record.metadata["required_tags"] == ["b739er_ext", "SSW_L", "SSW_R"]
    layout = json.loads((target / "layout.json").read_text(encoding="utf-8"))
    assert any(item["path"].endswith("converted.marker") for item in layout["content"])

    core.uninstall_record(record)
    assert not target.exists()


def test_fspackagetool_project_path_is_first_and_unique(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: MSFS 2024 SDK requires project XML before all switches."""
    import liverydock.ptp as ptpmod

    sdk = tmp_path / "MSFS 2024 SDK"
    tool = sdk / "Tools" / "bin" / "fspackagetool.exe"
    tool.parent.mkdir(parents=True)
    tool.write_bytes(b"stub")

    dds = tmp_path / "PMDG_NG3_F1_ALBD.PNG.DDS"
    dds.write_bytes(b"DDS")
    output = tmp_path / "out"

    def fake_dds_to_source_image(_dds: Path, target: Path) -> Path:
        target.mkdir(parents=True, exist_ok=True)
        image = target / "PMDG_NG3_F1_ALBD.PNG"
        image.write_bytes(b"PNG")
        return image

    captured: dict[str, list[str]] = {}

    class Result:
        returncode = 1
        stderr = "stop-after-command-capture"
        stdout = ""

    def fake_run(args, **kwargs):
        captured["args"] = [str(x) for x in args]
        return Result()

    monkeypatch.setattr(ptpmod, "_dds_to_source_image", fake_dds_to_source_image)
    monkeypatch.setattr(ptpmod.subprocess, "run", fake_run)

    with pytest.raises(Exception, match="stop-after-command-capture"):
        ptpmod.convert_dds_to_ktx2([dds], sdk, output, steam=True)

    args = captured["args"]
    assert args[0].endswith("fspackagetool.exe")
    assert args[1].endswith("liverydock-textures.xml")
    assert args.count(args[1]) == 1
    assert args[2:] == ["-forcesteam", "-rebuild", "-nopause"]


def make_pmdg_native_zip(path: Path, *, product: str = "pmdg-aircraft-77er", livery_id: str = "TEST_LIVERY", title: str = "Test Livery", extra_texture_cfg: str | None = None) -> Path:
    livery_cfg = (
        "[Version]\nmajor = 1\nminor = 4\n\n"
        "[Selection]\nrequired_tags = b772_ext,engine_ge\n\n"
        f"[General]\nname = {title}\natc_id = TEST01\natc_airline = TEST\nicao_airline = TST\nui_variation = {title}\n"
    )
    livery_json = {
        "rev": 2,
        "productId": 205,
        "productPackage": product,
        "title": title,
        "airline": "TEST",
        "atcId": "TEST01",
        "liveryId": livery_id,
        "version": 1004,
    }
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("livery.cfg", livery_cfg)
        zf.writestr("livery.json", json.dumps(livery_json))
        zf.writestr("model.airframe/livery.xml", "<ModelInfo/>")
        zf.writestr("texture/TEST_ALBD.PNG.KTX2", b"KTX2DATA")
        zf.writestr("texture/TEST_ALBD.PNG.KTX2.json", "{}")
        zf.writestr("thumbnail/thumbnail.png", b"PNG")
        if extra_texture_cfg is not None:
            zf.writestr("texture/texture.CFG", extra_texture_cfg)
    return path


def test_pmdg_native_direct_zip_detection(tmp_path: Path) -> None:
    from liverydock.core import prepare_source
    from liverydock.pmdg_native import analyze_pmdg_native

    archive = make_pmdg_native_zip(tmp_path / "BAW_GVIIX_KT.zip", livery_id="BAW_GVIIX_KT", title="British Airways (G-VIIX)")
    prepared = prepare_source(archive)
    assert prepared.source_kind == "pmdg-native"
    analysis = analyze_pmdg_native(archive, prepared.source_kind)
    assert analysis.package_format == "pmdg-native-2024"
    assert analysis.pmdg_product_package == "pmdg-aircraft-77er"
    assert analysis.pmdg_airplane_folder == "PMDG 777-200ER"
    assert analysis.pmdg_livery_id == "BAW_GVIIX_KT"
    assert analysis.target_hint == "community2024"


def test_pmdg_native_direct_zip_install_and_uninstall(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from liverydock.pmdg_native import analyze_pmdg_native, install_pmdg_native
    from liverydock.core import uninstall_record

    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    archive = make_pmdg_native_zip(tmp_path / "BAW_GVIIX_KT.zip", livery_id="BAW_GVIIX_KT")
    community = tmp_path / "Packages" / "Community2024"
    (community / "pmdg-aircraft-77er").mkdir(parents=True)
    analysis = analyze_pmdg_native(archive, "pmdg-native")
    record = install_pmdg_native(analysis, archive, community)

    target = community / "pmdg-aircraft-77er-liveries"
    livery = target / "SimObjects" / "Airplanes" / "PMDG 777-200ER" / "liveries" / "pmdg" / "BAW_GVIIX_KT"
    assert (livery / "livery.cfg").exists()
    assert (livery / "texture" / "TEST_ALBD.PNG.KTX2").exists()
    layout = json.loads((target / "layout.json").read_text(encoding="utf-8"))
    assert any(item["path"].endswith("BAW_GVIIX_KT/livery.cfg") for item in layout["content"])

    uninstall_record(record)
    assert not target.exists()


def test_pmdg_nested_bundle_installs_all_liveries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from liverydock.core import prepare_source, uninstall_record
    from liverydock.pmdg_native import analyze_pmdg_native, install_pmdg_native

    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    common = make_pmdg_native_zip(tmp_path / "common.zip", livery_id="pw-kal-common", title="Korean Air Common")
    variant = make_pmdg_native_zip(
        tmp_path / "variant.zip",
        livery_id="pw-kal-hl7526",
        title="Korean Air HL7526",
        extra_texture_cfg="[fltsim]\nfallback.1=..\\..\\pw-kal-common\\texture\n",
    )
    bundle = tmp_path / "pmdg-aircraft-77er-kal-pack.zip"
    with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as outer:
        outer.write(common, "pmdg-aircraft-77er-kal-common.zip")
        outer.write(variant, "pmdg-aircraft-77er-kal-hl7526.zip")

    prepared = prepare_source(bundle)
    assert prepared.source_kind == "pmdg-native-bundle"
    analysis = analyze_pmdg_native(bundle, prepared.source_kind)
    assert len(analysis.pmdg_bundle_entries) == 2
    assert analysis.pmdg_product_package == "pmdg-aircraft-77er"

    community = tmp_path / "Packages" / "Community2024"
    (community / "pmdg-aircraft-77er").mkdir(parents=True)
    record = install_pmdg_native(analysis, bundle, community)
    root = community / "pmdg-aircraft-77er-liveries" / "SimObjects" / "Airplanes" / "PMDG 777-200ER" / "liveries" / "pmdg"
    assert (root / "pw-kal-common" / "livery.json").exists()
    assert (root / "pw-kal-hl7526" / "texture" / "texture.CFG").exists()
    assert "pw-kal-common" in (root / "pw-kal-hl7526" / "texture" / "texture.CFG").read_text(encoding="utf-8")

    uninstall_record(record)
    assert not (community / "pmdg-aircraft-77er-liveries").exists()
