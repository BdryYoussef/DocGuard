"""Generate harmless structural PDFs without downloading sample documents."""

from __future__ import annotations

from itertools import pairwise
from pathlib import Path

import pikepdf
from pikepdf import Array, Dictionary, Encryption, Name, NameTree, String

HARMLESS_SCRIPT = "app.alert('DOCGUARD_HARMLESS_SCRIPT_FIXTURE')"
HARMLESS_URI = "https://example.invalid/document?id=private-fixture#fragment"


def write_benign_pdf(path: Path, *, pages: int = 1, keyword_text: bool = False) -> Path:
    with _new_pdf(pages) as pdf:
        if keyword_text:
            pdf.pages[0].obj.Contents = pdf.make_stream(
                b"BT (This document discusses /JavaScript syntax.) Tj ET"
            )
        _save(pdf, path)
    return path


def write_javascript_pdf(path: Path) -> Path:
    with _new_pdf() as pdf:
        pdf.Root.OpenAction = _javascript_action(pdf)
        _save(pdf, path)
    return path


def write_javascript_name_tree_pdf(path: Path) -> Path:
    with _new_pdf() as pdf:
        tree = NameTree.new(pdf)
        tree["harmless-script"] = _javascript_action(pdf)
        pdf.Root.Names = Dictionary(JavaScript=tree.obj)
        _save(pdf, path)
    return path


def write_open_action_pdf(path: Path) -> Path:
    with _new_pdf() as pdf:
        destination = Array([pdf.pages[0].obj, Name.Fit])
        pdf.Root.OpenAction = pdf.make_indirect(Dictionary(S=Name.GoTo, D=destination))
        _save(pdf, path)
    return path


def write_open_destination_pdf(path: Path) -> Path:
    with _new_pdf() as pdf:
        pdf.Root.OpenAction = Array([pdf.pages[0].obj, Name.Fit])
        _save(pdf, path)
    return path


def write_additional_action_pdf(path: Path) -> Path:
    with _new_pdf() as pdf:
        additional = Dictionary()
        additional[Name("/WC")] = pdf.make_indirect(Dictionary(S=Name.GoTo, D=String("fixture")))
        pdf.Root.AA = additional
        _save(pdf, path)
    return path


def write_launch_action_pdf(path: Path) -> Path:
    with _new_pdf() as pdf:
        pdf.Root.OpenAction = pdf.make_indirect(
            Dictionary(S=Name.Launch, F=String("harmless-dummy-resource.txt"))
        )
        _save(pdf, path)
    return path


def write_uri_action_pdf(path: Path, *, uri: str = HARMLESS_URI) -> Path:
    with _new_pdf() as pdf:
        action = pdf.make_indirect(Dictionary(S=Name.URI, URI=String(uri)))
        annotation = pdf.make_indirect(
            Dictionary(
                Type=Name.Annot,
                Subtype=Name.Link,
                Rect=Array([0, 0, 10, 10]),
                A=action,
            )
        )
        pdf.pages[0].obj.Annots = Array([annotation])
        _save(pdf, path)
    return path


def write_uri_action_chain_pdf(path: Path, *, action_count: int = 10) -> Path:
    if action_count <= 0:
        raise ValueError("action_count must be positive")
    with _new_pdf() as pdf:
        actions = [
            pdf.make_indirect(
                Dictionary(
                    S=Name.URI,
                    URI=String(f"https://host-{index}.example.invalid/path?discarded=true"),
                )
            )
            for index in range(action_count)
        ]
        for current, following in pairwise(actions):
            current.Next = following
        pdf.Root.OpenAction = actions[0]
        _save(pdf, path)
    return path


def write_embedded_file_pdf(path: Path) -> Path:
    with _new_pdf() as pdf:
        pdf.attachments["../../harmless-note.txt"] = b"harmless attachment fixture\n"
        _save(pdf, path)
    return path


def write_acroform_pdf(path: Path, *, xfa: bool = False) -> Path:
    with _new_pdf() as pdf:
        acroform = Dictionary(Fields=Array([]))
        if xfa:
            acroform.XFA = String("harmless-xfa-structure")
        pdf.Root.AcroForm = pdf.make_indirect(acroform)
        _save(pdf, path)
    return path


def write_encrypted_pdf(path: Path) -> Path:
    with _new_pdf() as pdf:
        pdf.save(
            path,
            encryption=Encryption(
                owner="docguard-owner-fixture",
                user="docguard-user-fixture",
                R=6,
            ),
            static_id=True,
        )
    return path


def write_malformed_pdf(path: Path) -> Path:
    path.write_bytes(b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R\n")
    return path


def write_multiple_actions_pdf(path: Path) -> Path:
    with _new_pdf() as pdf:
        javascript = _javascript_action(pdf)
        launch = pdf.make_indirect(
            Dictionary(S=Name.Launch, F=String("harmless-dummy-resource.txt"))
        )
        uri = pdf.make_indirect(Dictionary(S=Name.URI, URI=String(HARMLESS_URI)))
        javascript.Next = Array([launch, uri])
        pdf.Root.OpenAction = javascript
        additional = Dictionary()
        additional[Name("/WS")] = uri
        pdf.Root.AA = additional
        _save(pdf, path)
    return path


def write_action_chain_pdf(path: Path, *, action_count: int = 20) -> Path:
    if action_count <= 0:
        raise ValueError("action_count must be positive")
    with _new_pdf() as pdf:
        actions = [
            pdf.make_indirect(Dictionary(S=Name.GoTo, D=String(f"fixture-{index}")))
            for index in range(action_count)
        ]
        for current, following in pairwise(actions):
            current.Next = following
        pdf.Root.OpenAction = actions[0]
        _save(pdf, path)
    return path


def write_action_classes_pdf(path: Path) -> Path:
    with _new_pdf() as pdf:
        actions = [
            pdf.make_indirect(Dictionary(S=Name.GoTo, D=String("local-destination"))),
            pdf.make_indirect(
                Dictionary(S=Name.GoToR, F=String("harmless-remote.pdf"), D=String("page-1"))
            ),
            pdf.make_indirect(
                Dictionary(S=Name.SubmitForm, F=String("https://example.invalid/submit"))
            ),
            pdf.make_indirect(Dictionary(S=Name.ImportData, F=String("harmless-data.fdf"))),
            pdf.make_indirect(Dictionary(S=Name("/UnrecognizedFixtureAction"))),
        ]
        for current, following in pairwise(actions):
            current.Next = following
        pdf.Root.OpenAction = actions[0]
        _save(pdf, path)
    return path


def write_action_cycle_pdf(path: Path) -> Path:
    with _new_pdf() as pdf:
        action = pdf.make_indirect(Dictionary(S=Name.GoTo, D=String("cycle-fixture")))
        action.Next = action
        pdf.Root.OpenAction = action
        _save(pdf, path)
    return path


def _new_pdf(pages: int = 1) -> pikepdf.Pdf:
    if pages <= 0:
        raise ValueError("pages must be positive")
    pdf = pikepdf.Pdf.new()
    for _ in range(pages):
        pdf.add_blank_page(page_size=(612, 792))
    return pdf


def _javascript_action(pdf: pikepdf.Pdf) -> pikepdf.Object:
    return pdf.make_indirect(Dictionary(S=Name.JavaScript, JS=String(HARMLESS_SCRIPT)))


def _save(pdf: pikepdf.Pdf, path: Path) -> None:
    pdf.save(path, static_id=True, deterministic_id=True)


__all__ = [
    "HARMLESS_SCRIPT",
    "HARMLESS_URI",
    "write_acroform_pdf",
    "write_action_chain_pdf",
    "write_action_classes_pdf",
    "write_action_cycle_pdf",
    "write_additional_action_pdf",
    "write_benign_pdf",
    "write_embedded_file_pdf",
    "write_encrypted_pdf",
    "write_javascript_name_tree_pdf",
    "write_javascript_pdf",
    "write_launch_action_pdf",
    "write_malformed_pdf",
    "write_multiple_actions_pdf",
    "write_open_action_pdf",
    "write_open_destination_pdf",
    "write_uri_action_chain_pdf",
    "write_uri_action_pdf",
]
