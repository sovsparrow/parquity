from __future__ import annotations

from pathlib import Path

import pytest

from scripts import check_structure


def _write_module(root: Path, *parts: str) -> Path:
    path = root.joinpath(*parts)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("", encoding="utf-8")
    return path


def _production_modules(root: Path, *basenames: str) -> tuple[Path, ...]:
    return tuple(_write_module(root, "src", "parquity", basename) for basename in basenames)


def _production_package(root: Path, name: str) -> Path:
    return _write_module(root, "src", "parquity", name, "__init__.py")


def _inspect_modules(
    monkeypatch: pytest.MonkeyPatch, root: Path, *basenames: str
) -> tuple[check_structure.Violation, ...]:
    monkeypatch.setattr(check_structure, "ROOT", root)
    return check_structure.inspect_module_edges(_production_modules(root, *basenames))


def test_python_files_excludes_only_released_v0_1_0_fixture_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(check_structure, "ROOT", tmp_path)
    retained = {
        _write_module(tmp_path, "scripts", "check.py"),
        _write_module(tmp_path, "src", "parquity", "owner.py"),
        _write_module(tmp_path, "tests", "unit", "test_owner.py"),
        _write_module(tmp_path, "tests", "fixtures", "v0_2_0", "generated", "reproduce.py"),
    }
    excluded = {
        _write_module(tmp_path, "tests", "fixtures", "v0_1_0", "generated", "reproduce.py"),
        _write_module(tmp_path, "tests", "fixtures", "v0_1_0", "scan", "upstream_repro.py"),
    }

    discovered = set(check_structure.python_files())

    assert discovered == retained
    assert discovered.isdisjoint(excluded)


@pytest.mark.parametrize(
    ("basenames", "edge"),
    (
        (("shared_alpha.py", "shared_beta.py"), "prefix"),
        (("alpha_shared.py", "beta_shared.py"), "suffix"),
        (("_shared_alpha.py", "_shared_beta.py"), "prefix"),
        (("alpha_shared_.py", "beta_shared_.py"), "suffix"),
        (("shared.py", "shared_detail.py"), "prefix"),
    ),
)
def test_repeated_sibling_module_edges_are_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    basenames: tuple[str, str],
    edge: str,
) -> None:
    violations = _inspect_modules(monkeypatch, tmp_path, *basenames)

    assert len(violations) == 1
    assert f"normalized_{edge}='shared'" in violations[0].observed
    assert repr(tuple(sorted(basenames))) in violations[0].observed


@pytest.mark.parametrize(
    "basenames",
    (
        ("item_alpha.py", "items_beta.py"),
        ("items_beta.py", "item_alpha.py"),
    ),
)
def test_singular_and_plural_prefixes_share_one_normalized_edge_in_both_input_orders(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    basenames: tuple[str, str],
) -> None:
    violations = _inspect_modules(monkeypatch, tmp_path, *basenames)

    assert len(violations) == 1
    assert "normalized_prefix='item'" in violations[0].observed
    assert "item_alpha.py" in violations[0].observed
    assert "items_beta.py" in violations[0].observed


def test_singular_and_plural_compound_suffixes_share_one_normalized_edge(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    violations = _inspect_modules(monkeypatch, tmp_path, "alpha_item.py", "beta_items.py")

    assert len(violations) == 1
    assert "normalized_suffix='item'" in violations[0].observed
    assert "alpha_item.py" in violations[0].observed
    assert "beta_items.py" in violations[0].observed


def test_single_token_stem_does_not_participate_in_suffix_comparison(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert not _inspect_modules(monkeypatch, tmp_path, "record.py", "other_record.py")


def test_one_module_can_participate_in_independent_prefix_and_suffix_clusters(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    violations = _inspect_modules(
        monkeypatch,
        tmp_path,
        "shared_alpha.py",
        "shared_beta.py",
        "gamma_alpha.py",
    )
    observed = {violation.observed for violation in violations}

    assert len(observed) == 2
    assert any(
        "normalized_prefix='shared'" in value
        and "shared_alpha.py" in value
        and "shared_beta.py" in value
        for value in observed
    )
    assert any(
        "normalized_suffix='alpha'" in value
        and "gamma_alpha.py" in value
        and "shared_alpha.py" in value
        for value in observed
    )


@pytest.mark.parametrize(
    ("package", "module", "edge"),
    (
        ("shared", "shared_detail.py", "prefix"),
        ("alpha_shared", "beta_shared.py", "suffix"),
    ),
)
def test_package_names_participate_in_sibling_edge_clusters(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    package: str,
    module: str,
    edge: str,
) -> None:
    monkeypatch.setattr(check_structure, "ROOT", tmp_path)
    paths = (_production_package(tmp_path, package), *_production_modules(tmp_path, module))

    violations = check_structure.inspect_module_edges(paths)

    assert len(violations) == 1
    assert f"normalized_{edge}='shared'" in violations[0].observed
    assert f"{package}/" in violations[0].observed
    assert module in violations[0].observed


def test_edge_tokens_compare_case_insensitively_without_rewriting_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    violations = _inspect_modules(monkeypatch, tmp_path, "Shared_alpha.py", "shared_beta.py")

    assert len(violations) == 1
    assert "normalized_prefix='shared'" in violations[0].observed
    assert "Shared_alpha.py" in violations[0].observed
    assert "shared_beta.py" in violations[0].observed


def test_isolated_nested_and_nonproduction_module_edges_are_allowed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(check_structure, "ROOT", tmp_path)
    paths = (
        _write_module(tmp_path, "src", "parquity", "make_sense.py"),
        _write_module(tmp_path, "src", "parquity", "__init__.py"),
        _production_package(tmp_path, "unrelated"),
        _write_module(tmp_path, "src", "parquity", "first", "shared_alpha.py"),
        _write_module(tmp_path, "src", "parquity", "second", "shared_beta.py"),
        _write_module(tmp_path, "src", "parquity", "shared", "alpha.py"),
        _write_module(tmp_path, "src", "parquity", "shared", "beta.py"),
        _write_module(tmp_path, "tests", "unit", "shared_alpha.py"),
        _write_module(tmp_path, "tests", "unit", "shared_beta.py"),
        _write_module(tmp_path, "scripts", "alpha_shared.py"),
        _write_module(tmp_path, "scripts", "beta_shared.py"),
        _write_module(tmp_path, "src", "parquity", "__main__.py"),
    )

    assert not check_structure.inspect_module_edges(paths)


def test_main_reports_repeated_edges_and_accepts_nested_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(check_structure, "ROOT", tmp_path)
    monkeypatch.setattr(check_structure, "INDEPENDENT_MODULES", {})
    _production_modules(tmp_path, "shared_alpha.py", "shared_beta.py")

    assert check_structure.main() == 1
    output = capsys.readouterr().out
    assert "normalized_prefix='shared'" in output
    assert "shared_alpha.py" in output and "shared_beta.py" in output


def test_main_accepts_single_and_nested_module_owners(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(check_structure, "ROOT", tmp_path)
    monkeypatch.setattr(check_structure, "INDEPENDENT_MODULES", {})
    _write_module(tmp_path, "src", "parquity", "make_sense.py")
    _write_module(tmp_path, "src", "parquity", "shared", "alpha.py")
    _write_module(tmp_path, "src", "parquity", "shared", "beta.py")

    assert check_structure.main() == 0


def test_live_production_module_inventory_has_no_repeated_normalized_edges() -> None:
    assert not check_structure.inspect_module_edges(check_structure.python_files())


def test_configured_independent_module_owner_paths_must_exist(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(check_structure, "ROOT", tmp_path)
    model = _write_module(tmp_path, "src", "parquity", "model.py")

    violations = check_structure.inspect_independent_module_owners((model,))

    assert len(violations) == 1
    assert violations[0].path == tmp_path / "src" / "parquity" / "verdicts" / "model.py"
    assert violations[0].observed == "configured_owner='parquity.verdicts.model'; path_missing=True"
    assert violations[0].policy == "configured independent module owners must exist"


@pytest.mark.parametrize(
    "parts",
    (
        ("src", "parquity", "model.py"),
        ("src", "parquity", "verdicts", "model.py"),
    ),
)
def test_present_independent_module_owner_rejects_forbidden_capability_import(
    parts: tuple[str, ...],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(check_structure, "ROOT", tmp_path)
    path = _write_module(tmp_path, *parts)
    path.write_text("from parquity.engines import ENGINE_DESCRIPTORS\n", encoding="utf-8")

    violations = check_structure.inspect_file(path)

    assert len(violations) == 1
    assert violations[0].observed == "import='parquity.engines.ENGINE_DESCRIPTORS' at line 1"
    assert (
        violations[0].policy == "independent domain owners may not import engines, CLI, or matrix"
    )
