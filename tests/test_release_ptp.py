"""PTP regressions use generated CAB bytes and textures, never PMDG assets."""
from __future__ import annotations

import json
import struct
import zlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from liverydock import ptp
from liverydock.core import LiveryDockError, UnsafeArchiveError


def make_cab(entries: list[tuple[str, bytes]], *, mszip: bool = False) -> bytes:
    payload = b"".join(data for _, data in entries)
    table = bytearray()
    offset = 0
    for name, data in entries:
        table.extend(struct.pack("<IIHHHH", len(data), offset, 0, 0, 0, 0))
        table.extend(name.encode("utf-8") + b"\0")
        offset += len(data)
    blocks = bytearray()
    history = b""
    block_count = 0
    for start in range(0, len(payload), 32768):
        plain = payload[start:start + 32768]
        if mszip:
            compressor = zlib.compressobj(wbits=-15, zdict=history) if history else zlib.compressobj(wbits=-15)
            packed = b"CK" + compressor.compress(plain) + compressor.flush()
            history = (history + plain)[-32768:]
        else:
            packed = plain
        blocks.extend(struct.pack("<IHH", 0, len(packed), len(plain)) + packed)
        block_count += 1
    data_offset = 44 + len(table)
    header = bytearray(36)
    header[:4] = b"MSCF"
    struct.pack_into("<I", header, 8, data_offset + len(blocks))
    struct.pack_into("<I", header, 16, 44)
    header[24:26] = b"\x03\x01"
    struct.pack_into("<HH", header, 26, 1, len(entries))
    return bytes(header) + struct.pack("<IHH", data_offset, block_count, int(mszip)) + table + blocks


def write_ptp(path: Path, cab: bytes) -> Path:
    assert len(cab) >= ptp.ENCRYPTION_START
    tail = cab[ptp.ENCRYPTION_START:]
    tail += b"\0" * (-len(tail) % 8)
    encryptor = ptp._blowfish_cipher().encryptor()
    encrypted = encryptor.update(ptp._swap_words_32(tail)) + encryptor.finalize()
    path.write_bytes(b"CRYP" + cab[4:ptp.ENCRYPTION_START] + ptp._swap_words_32(encrypted))
    return path


@pytest.mark.parametrize("mszip", [False, True])
def test_real_encrypted_ptp_roundtrip_across_blocks(tmp_path: Path, mszip: bool) -> None:
    # Exceeds both the CAB 32 KiB block and decryption 64 KiB read boundaries.
    textures = bytes(range(256)) * 400
    entries = [("Config.cfg", b"[fltsim.x]\ntitle=Synthetic Test\n"), ("Texture.TEST/TEST.PNG.DDS", textures)]
    cabinet = make_cab(entries, mszip=mszip)
    source = write_ptp(tmp_path / "synthetic.ptp", cabinet)
    decrypted = tmp_path / "decrypted.cab"
    assert ptp.decrypt_ptp_to_cab(source, decrypted) == len(cabinet)
    assert decrypted.read_bytes() == cabinet
    destination = tmp_path / "extracted"
    paths = ptp.extract_pmdg_ptp(source, destination)
    assert [path.relative_to(destination).as_posix() for path in paths] == [name for name, _ in entries]
    for name, data in entries:
        assert (destination / name).read_bytes() == data


@pytest.mark.parametrize("raw", [b"", b"CRYP", b"NOPE" + bytes(100)])
def test_invalid_ptp_header_is_rejected(tmp_path: Path, raw: bytes) -> None:
    source = tmp_path / "bad.ptp"
    source.write_bytes(raw)
    with pytest.raises(LiveryDockError, match="CRYP"):
        ptp.decrypt_ptp_to_cab(source, tmp_path / "out.cab")


def test_truncated_encrypted_payload_is_rejected(tmp_path: Path) -> None:
    source = write_ptp(tmp_path / "bad.ptp", make_cab([("Config.cfg", b"x" * 100)]))
    source.write_bytes(source.read_bytes()[:-1])
    with pytest.raises(LiveryDockError, match="PTP"):
        ptp.extract_pmdg_ptp(source, tmp_path / "out")


@pytest.mark.parametrize("unsafe", ["../escaped.txt", "C:/escaped.txt", "/escaped.txt"])
def test_unsafe_cab_paths_fail_before_writing_files(tmp_path: Path, unsafe: str) -> None:
    source = write_ptp(tmp_path / "unsafe.ptp", make_cab([("first.txt", b"good"), (unsafe, b"bad")]))
    output = tmp_path / "out"
    with pytest.raises(UnsafeArchiveError):
        ptp.extract_pmdg_ptp(source, output)
    assert list(output.rglob("*")) == []


def test_cab_rejects_case_insensitive_duplicate_destinations(tmp_path: Path) -> None:
    source = write_ptp(tmp_path / "duplicate.ptp", make_cab([("Texture/A.DDS", b"one"), ("texture/a.dds", b"two")]))
    output = tmp_path / "out"
    with pytest.raises(UnsafeArchiveError, match="duplicate"):
        ptp.extract_pmdg_ptp(source, output)
    assert list(output.rglob("*")) == []


def test_cab_file_range_is_checked_before_any_files_are_written(tmp_path: Path) -> None:
    cabinet = bytearray(make_cab([("first.txt", b"good"), ("bad.txt", b"bad")]))
    second_entry = 44 + 16 + len("first.txt") + 1
    struct.pack_into("<I", cabinet, second_entry + 4, 999999)
    source = write_ptp(tmp_path / "range.ptp", bytes(cabinet))
    output = tmp_path / "out"
    with pytest.raises(LiveryDockError, match="outside decompressed"):
        ptp.extract_pmdg_ptp(source, output)
    assert list(output.rglob("*")) == []


@pytest.mark.parametrize("field,value", [(8, 999999), (16, 999999), (36, 1)])
def test_corrupt_cab_structure_is_rejected(tmp_path: Path, field: int, value: int) -> None:
    cabinet = bytearray(make_cab([("Config.cfg", b"test")]))
    struct.pack_into("<I", cabinet, field, value)
    path = tmp_path / "bad.cab"
    path.write_bytes(cabinet)
    with pytest.raises(LiveryDockError, match="CAB"):
        ptp._parse_cab(path)


def test_mszip_expansion_is_bounded_before_allocating_a_bomb(tmp_path: Path) -> None:
    compressor = zlib.compressobj(wbits=-15)
    packed = b"CK" + compressor.compress(b"x" * 1024 * 1024) + compressor.flush()
    path = tmp_path / "bomb.cab"
    path.write_bytes(struct.pack("<IHH", 0, len(packed), 4) + packed)
    with pytest.raises(LiveryDockError, match="oversized|unexpected"):
        ptp._inflate_folder(path, ptp.CabFolder(0, 1, 1), 0)


@pytest.mark.parametrize("size", [0, 32769])
def test_cab_invalid_block_sizes_are_rejected(tmp_path: Path, size: int) -> None:
    path = tmp_path / "block.cab"
    path.write_bytes(struct.pack("<IHH", 0, 1, size) + b"x")
    with pytest.raises(LiveryDockError, match="block size"):
        ptp._inflate_folder(path, ptp.CabFolder(0, 1, 0), 0)


def test_mszip_requires_complete_deflate_stream(tmp_path: Path) -> None:
    compressor = zlib.compressobj(wbits=-15)
    packed = b"CK" + (compressor.compress(b"synthetic" * 100) + compressor.flush())[:-1]
    path = tmp_path / "block.cab"
    path.write_bytes(struct.pack("<IHH", 0, len(packed), 900) + packed)
    with pytest.raises(LiveryDockError, match="MSZIP"):
        ptp._inflate_folder(path, ptp.CabFolder(0, 1, 1), 0)


@pytest.mark.parametrize("code,model,expected", [
    ("736", "", ["b736_ext", "BW_L", "BW_R"]),
    ("737", "SSW", ["b737_ext", "SSW_L", "SSW_R"]),
    ("738", "", ["b738_ext", "BW_L", "BW_R"]),
    ("739", "ERSSW", ["b739er_ext", "SSW_L", "SSW_R"]),
    ("739", "", ["b739_ext", "BW_L", "BW_R"]),
])
def test_legacy_737_family_tags_remain_compatible(code: str, model: str, expected: list[str]) -> None:
    assert ptp.infer_737_tags({"model": model}, code) == expected


def fake_sdk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, generated: dict[str, bytes]):
    tool = tmp_path / "sdk" / "Tools" / "bin" / "fspackagetool.exe"
    tool.parent.mkdir(parents=True)
    tool.write_bytes(b"synthetic-tool-placeholder")
    captured = {}

    def fake_image(dds: Path, output: Path) -> Path:
        image = output / ptp._source_image_name(dds)
        image.write_bytes(b"synthetic-image-placeholder")
        return image

    def run(args, **kwargs):
        captured.update(args=args, **kwargs)
        root = Path(kwargs["cwd"])
        target = root / "Packages/liverydock-textures/SimObjects/Airplanes/liverydock-textures/common/texture"
        target.mkdir(parents=True)
        for name, data in generated.items():
            (target / name).write_bytes(data)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(ptp, "_dds_to_source_image", fake_image)
    monkeypatch.setattr(ptp.subprocess, "run", run)
    return tool.parents[2], captured


def test_sdk_conversion_copies_complete_output_and_cleans_work(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sdk, captured = fake_sdk(tmp_path, monkeypatch, {"TEST.PNG.KTX2": b"synthetic-ktx", "TEST.PNG.KTX2.json": b"{}"})
    source = tmp_path / "TEST.PNG.DDS"
    source.write_bytes(b"synthetic-dds")
    output = tmp_path / "out"
    results = ptp.convert_dds_to_ktx2([source], sdk, output, steam=True)
    assert {path.name for path in results} == {"TEST.PNG.KTX2", "TEST.PNG.KTX2.json"}
    assert captured["args"][2:] == ["-forcesteam", "-rebuild", "-nopause"]
    assert not Path(captured["cwd"]).exists()


@pytest.mark.parametrize("generated", [{"OTHER.PNG.KTX2": b"other"}, {"TEST.PNG.KTX2": b""}])
def test_sdk_partial_or_empty_output_cannot_replace_template_textures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, generated: dict[str, bytes]) -> None:
    sdk, _ = fake_sdk(tmp_path, monkeypatch, generated)
    source = tmp_path / "TEST.PNG.DDS"
    source.write_bytes(b"synthetic-dds")
    output = tmp_path / "out"
    output.mkdir()
    existing = output / "TEST.PNG.KTX2"
    existing.write_bytes(b"existing-template")
    with pytest.raises(LiveryDockError, match="all required"):
        ptp.convert_dds_to_ktx2([source], sdk, output)
    assert existing.read_bytes() == b"existing-template"


def test_flattened_texture_name_collisions_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(LiveryDockError, match="conflicting texture"):
        ptp.convert_dds_to_ktx2([tmp_path / "A/TEST.PNG.DDS", tmp_path / "B/test.png.dds"], tmp_path / "sdk", tmp_path / "out")


def test_pillow_dds_conversion_preserves_alpha_and_source_name(tmp_path: Path) -> None:
    from PIL import Image
    source = tmp_path / "TEST_ALBD.PNG.DDS"
    with Image.new("RGBA", (4, 4), (10, 20, 30, 40)) as image:
        image.save(source, format="DDS")
    output = ptp._dds_to_source_image(source, tmp_path / "images")
    assert output.name == "TEST_ALBD.PNG"
    with Image.open(output) as image:
        assert image.convert("RGBA").getpixel((0, 0)) == (10, 20, 30, 40)


def test_legacy_native_build_preserves_template_metadata_and_airframe_options(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    extracted = tmp_path / "extracted"
    texture = extracted / "Texture.TEST"
    texture.mkdir(parents=True)
    (texture / "TEST.PNG.DDS").write_bytes(b"synthetic-dds")
    (extracted / "Config.cfg").write_text("[fltsim.x]\ntitle=Synthetic 900ER\natc_airline=TEST\natc_id=T-0001\nmodel=ERSSW\nui_variation=Synthetic Test\n", encoding="utf-8")
    (extracted / "Aircraft.ini").write_text("[Options]\nTest=1\n", encoding="utf-8")
    template = tmp_path / "template"
    (template / "texture").mkdir(parents=True)
    (template / "texture/fallback.KTX2").write_bytes(b"synthetic-fallback")
    (template / "livery.cfg").write_text("[Version]\nmajor=1\nminor=4\n", encoding="utf-8")
    (template / "livery.json").write_text(json.dumps({"productId": 999, "productPackage": "pmdg-aircraft-739", "rev": 2, "version": 1004}), encoding="utf-8")
    captured = {}

    def convert(files, sdk, output, steam=False):
        captured.update(files=files, sdk=sdk, steam=steam)
        result = output / "TEST.PNG.KTX2"
        result.write_bytes(b"synthetic-converted")
        return [result]

    monkeypatch.setattr(ptp, "convert_dds_to_ktx2", convert)
    destination = tmp_path / "native/TEST_T-0001"
    meta, tags = ptp.build_native_livery_from_legacy(extracted, template, destination, "739", tmp_path / "sdk", steam=True)
    assert tags == ["b739er_ext", "SSW_L", "SSW_R"]
    assert meta["atc_id"] == "T-0001"
    assert captured["steam"] is True
    assert captured["files"] == [texture / "TEST.PNG.DDS"]
    assert (destination / "texture/fallback.KTX2").read_bytes() == b"synthetic-fallback"
    assert (destination / "texture/TEST.PNG.KTX2").read_bytes() == b"synthetic-converted"
    assert (destination / "options.ini").read_text(encoding="utf-8") == "[Options]\nTest=1\n"
    cfg = ptp.parse_ini_like(destination / "livery.cfg")
    assert cfg["version"] == {"major": "1", "minor": "4"}
    assert cfg["selection"]["required_tags"] == ",".join(tags)
    metadata = json.loads((destination / "livery.json").read_text(encoding="utf-8"))
    assert metadata["productId"] == 999
    assert metadata["productPackage"] == "pmdg-aircraft-739"
    assert metadata["liveryId"] == "TEST_T-0001"
    assert metadata["tags"] == ["SSW"]
