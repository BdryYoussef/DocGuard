from __future__ import annotations

from pathlib import Path

from evaluation.corpus import CASES, materialize_case
from evaluation.models import CaseCategory, CaseClass


def test_case_ids_are_unique() -> None:
    ids = [case.case_id for case in CASES]
    assert len(ids) == len(set(ids))


def test_all_eight_categories_are_present() -> None:
    present = {case.category for case in CASES}
    assert present == set(CaseCategory)


def test_both_classes_are_present() -> None:
    present = {case.case_class for case in CASES}
    assert present == set(CaseClass)


def test_corpus_size_is_within_the_planned_range() -> None:
    assert 45 <= len(CASES) <= 60


def test_at_least_some_fail_secure_cases_exist() -> None:
    assert sum(1 for case in CASES if case.fail_secure) >= 3


def test_at_least_three_cdr_cases_are_prepared() -> None:
    cdr_cases = [case for case in CASES if case.cdr_case]
    assert 3 <= len(cdr_cases) <= 5
    assert all(
        case.category in {CaseCategory.BENIGN_PDF, CaseCategory.RISKY_PDF} for case in cdr_cases
    )


def test_all_cases_materialize_to_a_non_empty_file(tmp_path: Path) -> None:
    for case in CASES:
        path = materialize_case(case, tmp_path / case.case_id)
        assert path.exists()
        assert path.stat().st_size > 0
        assert path.name == case.filename


def test_materialization_is_deterministic(tmp_path: Path) -> None:
    case = next(case for case in CASES if case.case_id == "PDF-BEN-001")

    first = materialize_case(case, tmp_path / "first")
    second = materialize_case(case, tmp_path / "second")

    assert first.read_bytes() == second.read_bytes()
