"""Generate harmless Office-shaped containers without downloading documents."""

from __future__ import annotations

import struct
import warnings
import zipfile
from pathlib import Path

from worker.analyzers.office_types import OfficeApplication

HARMLESS_AUTOEXEC_SOURCE = """Attribute VB_Name = "Module1"
Sub AutoOpen()
    Dim harmlessMessage As String
    harmlessMessage = "DOCGUARD_CONTROLLED_FIXTURE"
End Sub
"""
HARMLESS_EXECUTION_INDICATOR_SOURCE = """Attribute VB_Name = "Module1"
Sub InspectOnly()
    Dim fixtureObject As Object
    Set fixtureObject = CreateObject("WScript.Shell")
    fixtureObject.Run "cmd.exe /c echo DOCGUARD_CONTROLLED_FIXTURE"
End Sub
"""
VISIBLE_SHELL_TEXT = "This visible document text discusses Shell and CreateObject only."

_MAIN_PATHS = {
    OfficeApplication.WORD: "word/document.xml",
    OfficeApplication.EXCEL: "xl/workbook.xml",
    OfficeApplication.POWERPOINT: "ppt/presentation.xml",
}
_MAIN_CONTENT_TYPES = {
    OfficeApplication.WORD: (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
    ),
    OfficeApplication.EXCEL: (
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"
    ),
    OfficeApplication.POWERPOINT: (
        "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"
    ),
}
_MACRO_CONTENT_TYPES = {
    OfficeApplication.WORD: "application/vnd.ms-word.document.macroEnabled.main+xml",
    OfficeApplication.EXCEL: "application/vnd.ms-excel.sheet.macroEnabled.main+xml",
    OfficeApplication.POWERPOINT: (
        "application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml"
    ),
}
_VBA_PATHS = {
    OfficeApplication.WORD: "word/vbaProject.bin",
    OfficeApplication.EXCEL: "xl/vbaProject.bin",
    OfficeApplication.POWERPOINT: "ppt/vbaProject.bin",
}


def write_ooxml(
    path: Path,
    *,
    application: OfficeApplication,
    macro_source: str | None = None,
    visible_text: str = "DocGuard controlled fixture",
    external_relationship: bool = False,
    external_template: bool = False,
    embedded_object: bool = False,
    activex: bool = False,
    malformed_relationships: bool = False,
    hostile_relationship_xml: str | None = None,
    extra_relationships: int = 0,
    extra_entries: int = 0,
    oversized_member_bytes: int = 0,
    duplicate_content_types: bool = False,
) -> Path:
    main_path = _MAIN_PATHS[application]
    macro_enabled = macro_source is not None
    main_content_type = (
        _MACRO_CONTENT_TYPES[application] if macro_enabled else _MAIN_CONTENT_TYPES[application]
    )
    overrides = [f'<Override PartName="/{main_path}" ContentType="{main_content_type}"/>']
    if macro_enabled:
        overrides.append(
            f'<Override PartName="/{_VBA_PATHS[application]}" '
            'ContentType="application/vnd.ms-office.vbaProject"/>'
        )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" '
        'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>' + "".join(overrides) + "</Types>"
    )
    root_relationships = _relationships_xml(
        [
            (
                "rId1",
                "http://schemas.openxmlformats.org/officeDocument/2006/relationships/"
                "officeDocument",
                main_path,
                None,
            )
        ]
    )
    relationships: list[tuple[str, str, str, str | None]] = []
    if external_relationship:
        relationships.append(
            (
                "rIdExternal",
                "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink",
                "https://user:password@links.example.invalid/path?private=1#fragment",
                "External",
            )
        )
    if external_template:
        relationships.append(
            (
                "rIdTemplate",
                "http://schemas.openxmlformats.org/officeDocument/2006/relationships/"
                "attachedTemplate",
                "https://user:password@templates.example.invalid/template.dotm?private=1",
                "External",
            )
        )
    for index in range(extra_relationships):
        relationships.append(
            (
                f"rIdMany{index}",
                "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink",
                f"https://relationship-{index}.example.invalid/path",
                "External",
            )
        )
    if malformed_relationships:
        main_relationships = b"<Relationships><Relationship"
    elif hostile_relationship_xml is not None:
        main_relationships = hostile_relationship_xml.encode("utf-8")
    else:
        main_relationships = _relationships_xml(relationships).encode("utf-8")

    prefix = main_path.split("/", 1)[0]
    main_relationship_path = f"{prefix}/_rels/{_pure_name(main_path)}.rels"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(_fixed_info("[Content_Types].xml"), content_types)
        if duplicate_content_types:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                archive.writestr(_fixed_info("[Content_Types].xml"), content_types)
        archive.writestr(_fixed_info("_rels/.rels"), root_relationships)
        archive.writestr(
            _fixed_info(main_path),
            f'<?xml version="1.0"?><document><text>{visible_text}</text></document>',
        )
        archive.writestr(_fixed_info(main_relationship_path), main_relationships)
        if macro_source is not None:
            archive.writestr(
                _fixed_info(_VBA_PATHS[application]),
                build_compound_file({"MacroStream": _compressed_vba_stream(macro_source)}),
            )
        if embedded_object:
            archive.writestr(
                _fixed_info(f"{prefix}/embeddings/../../controlled-object.bin"),
                b"DOCGUARD_CONTROLLED_EMBEDDED_OBJECT",
            )
        if activex:
            archive.writestr(
                _fixed_info(f"{prefix}/activeX/activeX1.bin"),
                b"DOCGUARD_CONTROLLED_ACTIVEX_STRUCTURE",
            )
        for index in range(extra_entries):
            archive.writestr(_fixed_info(f"fixture/entry-{index}.txt"), b"bounded")
        if oversized_member_bytes:
            archive.writestr(
                _fixed_info(f"{prefix}/_rels/oversized.xml.rels"),
                b"A" * oversized_member_bytes,
            )
    return path


def write_generic_zip(path: Path) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(_fixed_info("random.txt"), b"not an Office package")
    return path


def write_inconsistent_ooxml(path: Path) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            _fixed_info("[Content_Types].xml"),
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="xml" ContentType="application/xml"/></Types>',
        )
        archive.writestr(_fixed_info("_rels/.rels"), _relationships_xml([]))
    return path


def write_classic_ole(path: Path, *, macro_source: str | None = None) -> Path:
    streams: dict[str, bytes] = {"WordDocument": b"DOCGUARD_CLASSIC_WORD_FIXTURE"}
    if macro_source is not None:
        streams["MacroStream"] = _compressed_vba_stream(macro_source)
    path.write_bytes(build_compound_file(streams))
    return path


def write_encrypted_office_ole(path: Path) -> Path:
    path.write_bytes(
        build_compound_file(
            {
                "EncryptionInfo": b"DOCGUARD_CONTROLLED_ENCRYPTION_INFO",
                "EncryptedPackage": b"DOCGUARD_CONTROLLED_ENCRYPTED_PACKAGE",
            }
        )
    )
    return path


def build_vba_compound(sources: list[str]) -> bytes:
    return build_compound_file(
        {
            f"MacroStream{index}": _compressed_vba_stream(source)
            for index, source in enumerate(sources)
        }
    )


def build_compound_file(streams: dict[str, bytes]) -> bytes:
    """Build a deterministic inert CFB v3 with regular (non-mini) root streams."""
    sector_size = 512
    free_sector = 0xFFFFFFFF
    end_of_chain = 0xFFFFFFFE
    fat_sector_marker = 0xFFFFFFFD
    padded_streams = {
        name: data + b"\x00" * (max(4_096, len(data)) - len(data)) for name, data in streams.items()
    }
    directory_sector_count = max(1, ((len(streams) + 1) * 128 + 511) // 512)
    data_sector_counts = {
        name: (len(data) + sector_size - 1) // sector_size for name, data in padded_streams.items()
    }
    data_sector_total = sum(data_sector_counts.values())
    fat_sector_count = 1
    while True:
        total = directory_sector_count + data_sector_total + fat_sector_count
        required = (total + 127) // 128
        if required == fat_sector_count:
            break
        fat_sector_count = required
    if fat_sector_count > 109:
        raise ValueError("fixture CFB exceeds header DIFAT capacity")

    first_data_sector = directory_sector_count
    stream_starts: dict[str, int] = {}
    cursor = first_data_sector
    for name in sorted(padded_streams):
        stream_starts[name] = cursor
        cursor += data_sector_counts[name]
    first_fat_sector = cursor
    total_sectors = directory_sector_count + data_sector_total + fat_sector_count

    fat = [free_sector] * (fat_sector_count * 128)
    for sector in range(directory_sector_count):
        fat[sector] = sector + 1 if sector + 1 < directory_sector_count else end_of_chain
    for name in sorted(padded_streams):
        start = stream_starts[name]
        count = data_sector_counts[name]
        for offset in range(count):
            fat[start + offset] = start + offset + 1 if offset + 1 < count else end_of_chain
    for sector in range(first_fat_sector, first_fat_sector + fat_sector_count):
        fat[sector] = fat_sector_marker

    header = bytearray(512)
    header[:8] = bytes.fromhex("D0CF11E0A1B11AE1")
    struct.pack_into("<HHHH", header, 24, 0x003E, 0x0003, 0xFFFE, 9)
    struct.pack_into("<H", header, 32, 6)
    struct.pack_into("<I", header, 40, 0)
    struct.pack_into("<I", header, 44, fat_sector_count)
    struct.pack_into("<I", header, 48, 0)
    struct.pack_into("<I", header, 52, 0)
    struct.pack_into("<I", header, 56, 4_096)
    struct.pack_into("<I", header, 60, end_of_chain)
    struct.pack_into("<I", header, 64, 0)
    struct.pack_into("<I", header, 68, end_of_chain)
    struct.pack_into("<I", header, 72, 0)
    for index in range(109):
        value = first_fat_sector + index if index < fat_sector_count else free_sector
        struct.pack_into("<I", header, 76 + index * 4, value)

    directory = bytearray(directory_sector_count * sector_size)
    child = 1 if streams else free_sector
    directory[:128] = _directory_entry(
        "Root Entry",
        entry_type=5,
        child=child,
        start=end_of_chain,
        size=0,
    )
    names = sorted(padded_streams)
    for index, name in enumerate(names, start=1):
        right = index + 1 if index < len(names) else free_sector
        directory[index * 128 : (index + 1) * 128] = _directory_entry(
            name,
            entry_type=2,
            right=right,
            start=stream_starts[name],
            size=len(padded_streams[name]),
        )

    body = bytearray(directory)
    for name in names:
        data = padded_streams[name]
        body.extend(data)
        body.extend(b"\x00" * ((-len(data)) % sector_size))
    for index in range(fat_sector_count):
        values = fat[index * 128 : (index + 1) * 128]
        body.extend(struct.pack("<128I", *values))
    if len(body) != total_sectors * sector_size:
        raise AssertionError("fixture CFB sector calculation mismatch")
    return bytes(header + body)


def _directory_entry(
    name: str,
    *,
    entry_type: int,
    left: int = 0xFFFFFFFF,
    right: int = 0xFFFFFFFF,
    child: int = 0xFFFFFFFF,
    start: int,
    size: int,
) -> bytes:
    encoded_name = (name + "\x00").encode("utf-16le")
    if len(encoded_name) > 64:
        raise ValueError("fixture CFB directory name is too long")
    entry = bytearray(128)
    entry[: len(encoded_name)] = encoded_name
    struct.pack_into("<H", entry, 64, len(encoded_name))
    entry[66] = entry_type
    entry[67] = 1
    struct.pack_into("<III", entry, 68, left, right, child)
    struct.pack_into("<I", entry, 116, start)
    struct.pack_into("<Q", entry, 120, size)
    return bytes(entry)


def _compressed_vba_stream(source: str) -> bytes:
    source_bytes = source.encode("cp1252")
    payload = bytearray()
    for offset in range(0, len(source_bytes), 8):
        payload.append(0)
        payload.extend(source_bytes[offset : offset + 8])
    if not payload or len(payload) > 4_095:
        raise ValueError("fixture VBA source exceeds one compressed chunk")
    compressed_header = 0xB000 | (len(payload) - 1)
    uncompressed_header = 0x3FFF
    return (
        b"\x01"
        + struct.pack("<H", compressed_header)
        + bytes(payload)
        + struct.pack("<H", uncompressed_header)
        + b"\x00" * 4_096
    )


def _relationships_xml(
    relationships: list[tuple[str, str, str, str | None]],
) -> str:
    items = []
    for relationship_id, relationship_type, target, mode in relationships:
        mode_attribute = f' TargetMode="{mode}"' if mode else ""
        items.append(
            f'<Relationship Id="{relationship_id}" Type="{relationship_type}" '
            f'Target="{target}"{mode_attribute}/>'
        )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<Relationships "
        'xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        + "".join(items)
        + "</Relationships>"
    )


def _fixed_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(2024, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o600 << 16
    return info


def _pure_name(path: str) -> str:
    return path.rsplit("/", 1)[-1]


__all__ = [
    "HARMLESS_AUTOEXEC_SOURCE",
    "HARMLESS_EXECUTION_INDICATOR_SOURCE",
    "VISIBLE_SHELL_TEXT",
    "build_compound_file",
    "build_vba_compound",
    "write_classic_ole",
    "write_encrypted_office_ole",
    "write_generic_zip",
    "write_inconsistent_ooxml",
    "write_ooxml",
]
