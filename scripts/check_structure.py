from __future__ import annotations

import ast
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

MODULE_LIMIT = 600
CALLABLE_LIMIT = 150
ROOT = Path(__file__).resolve().parents[1]
SEALED_FIXTURE_ROOT = Path("tests/fixtures/v0_1_0")
INDEPENDENT_MODULES = {
    Path("src/parquity/model.py"): "parquity.model",
    Path("src/parquity/verdicts/model.py"): "parquity.verdicts.model",
}
FORBIDDEN_IMPORTS = (
    "duckdb",
    "polars",
    "pyarrow",
    "parquity.cli",
    "parquity.engines",
    "parquity.matrix",
)


@dataclass(frozen=True, slots=True)
class Violation:
    path: Path
    symbol: str
    observed: str
    policy: str

    def render(self) -> str:
        relative = self.path.relative_to(ROOT)
        return f"{relative}: symbol={self.symbol!r}; observed={self.observed}; policy={self.policy}"


@dataclass(frozen=True, slots=True)
class CallableSpan:
    symbol: str
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class ModuleCandidate:
    path: Path
    directory: Path
    stem: str
    display_name: str


class CallableVisitor(ast.NodeVisitor):
    def __init__(self, path: Path) -> None:
        self.path = path
        self.scope: list[str] = []
        self.spans: list[CallableSpan] = []
        self.violations: list[Violation] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_callable(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_callable(node)

    def _visit_callable(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        symbol = ".".join((*self.scope, node.name))
        start = min((item.lineno for item in node.decorator_list), default=node.lineno)
        end = node.end_lineno if node.end_lineno is not None else node.lineno
        self.spans.append(CallableSpan(symbol, start, end))
        observed = end - start + 1
        if observed > CALLABLE_LIMIT:
            self.violations.append(
                Violation(
                    self.path,
                    symbol,
                    f"physical_lines={observed}",
                    f"callable physical-line limit={CALLABLE_LIMIT}",
                )
            )
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()


def python_files() -> tuple[Path, ...]:
    roots = (ROOT / "scripts", ROOT / "src", ROOT / "tests")
    sealed_root = ROOT / SEALED_FIXTURE_ROOT
    return tuple(
        sorted(
            path
            for root in roots
            for path in root.rglob("*.py")
            if not path.is_relative_to(sealed_root)
        )
    )


def inspect_file(path: Path) -> tuple[Violation, ...]:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    visitor = CallableVisitor(path)
    visitor.visit(tree)
    violations = list(visitor.violations)
    line_count = len(source.splitlines())
    if line_count > MODULE_LIMIT:
        violations.append(
            Violation(
                path,
                "<module>",
                f"physical_lines={line_count}",
                f"module physical-line limit={MODULE_LIMIT}",
            )
        )
    violations.extend(_import_violations(path, tree, visitor.spans))
    return tuple(violations)


def inspect_module_edges(paths: Iterable[Path]) -> tuple[Violation, ...]:
    groups: dict[tuple[Path, str, str], dict[Path, str]] = {}
    for path in paths:
        candidate = _module_candidate(path)
        if candidate is None:
            continue
        tokens = tuple(token for token in candidate.stem.split("_") if token)
        if not tokens:
            continue
        edges = [("prefix", _normalized_edge_token(tokens[0]))]
        if len(tokens) > 1:
            edges.append(("suffix", _normalized_edge_token(tokens[-1])))
        for edge, token in edges:
            groups.setdefault((candidate.directory, edge, token), {})[candidate.path] = (
                candidate.display_name
            )

    violations: list[Violation] = []
    for (_directory, edge, token), members in sorted(
        groups.items(),
        key=lambda item: (
            item[0][0].relative_to(ROOT).as_posix(),
            item[0][1],
            item[0][2],
        ),
    ):
        ordered = tuple(sorted(members.items(), key=lambda item: item[1].encode("utf-8")))
        if len(ordered) < 2:
            continue
        names = tuple(display_name for _path, display_name in ordered)
        violations.append(
            Violation(
                ordered[0][0],
                "<module-name>",
                f"normalized_{edge}={token!r}; siblings={names!r}",
                "repeated normalized sibling module edge tokens must be consolidated under "
                "one semantic owner; use a nested package only when it owns an independently "
                "changing policy, lifecycle, dependency, failure, or evidence contract",
            )
        )
    return tuple(violations)


def _normalized_edge_token(token: str) -> str:
    normalized = token.casefold()
    return normalized[:-1] if normalized.endswith("s") else normalized


def inspect_independent_module_owners(paths: Iterable[Path]) -> tuple[Violation, ...]:
    present = {path.relative_to(ROOT) for path in paths}
    return tuple(
        Violation(
            ROOT / relative,
            "<module>",
            f"configured_owner={module_name!r}; path_missing=True",
            "configured independent module owners must exist",
        )
        for relative, module_name in sorted(
            INDEPENDENT_MODULES.items(), key=lambda item: item[0].as_posix()
        )
        if relative not in present
    )


def _module_candidate(path: Path) -> ModuleCandidate | None:
    relative = path.relative_to(ROOT)
    if relative.parts[:2] != ("src", "parquity"):
        return None
    production_root = ROOT / "src" / "parquity"
    if path.name == "__init__.py":
        if path.parent == production_root:
            return None
        return ModuleCandidate(path, path.parent.parent, path.parent.name, f"{path.parent.name}/")
    if _is_dunder_module(path):
        return None
    return ModuleCandidate(path, path.parent, path.stem, path.name)


def _is_dunder_module(path: Path) -> bool:
    stem = path.stem
    return stem.startswith("__") and stem.endswith("__")


def _import_violations(
    path: Path,
    tree: ast.AST,
    spans: list[CallableSpan],
) -> tuple[Violation, ...]:
    relative = path.relative_to(ROOT)
    module_name = INDEPENDENT_MODULES.get(relative, _module_name(relative))
    violations: list[Violation] = []
    for line, target in _import_targets(tree, module_name):
        if relative in INDEPENDENT_MODULES and _is_forbidden_import(target):
            violations.append(
                Violation(
                    path,
                    _symbol_at(spans, line),
                    f"import={target!r} at line {line}",
                    "independent domain owners may not import engines, CLI, or matrix",
                )
            )
        if relative.parts[:1] == ("tests",) and _is_test_module_import(target):
            violations.append(
                Violation(
                    path,
                    _symbol_at(spans, line),
                    f"import={target!r} at line {line}",
                    "test modules may import tests.support, not other test modules",
                )
            )
    return tuple(violations)


def _module_name(relative: Path) -> str:
    parts = relative.with_suffix("").parts
    if parts[:1] == ("src",):
        parts = parts[1:]
    return ".".join(parts)


def _import_targets(tree: ast.AST, module_name: str) -> tuple[tuple[int, str], ...]:
    targets: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            targets.extend((node.lineno, alias.name) for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = _resolve_import_from(module_name, node)
            targets.extend(
                (
                    node.lineno,
                    base if alias.name == "*" else ".".join((base, alias.name)).strip("."),
                )
                for alias in node.names
            )
    return tuple(targets)


def _resolve_import_from(module_name: str, node: ast.ImportFrom) -> str:
    if node.level == 0:
        return node.module or ""
    package = module_name.split(".")[:-1]
    retained = package[: len(package) - node.level + 1]
    suffix = [] if node.module is None else node.module.split(".")
    return ".".join((*retained, *suffix))


def _is_forbidden_import(target: str) -> bool:
    return any(target == item or target.startswith(f"{item}.") for item in FORBIDDEN_IMPORTS)


def _is_test_module_import(target: str) -> bool:
    return target.startswith(("tests.unit.", "tests.acceptance."))


def _symbol_at(spans: list[CallableSpan], line: int) -> str:
    matches = [span for span in spans if span.start <= line <= span.end]
    if not matches:
        return "<module>"
    return min(matches, key=lambda span: span.end - span.start).symbol


def main() -> int:
    paths = python_files()
    violations = [violation for path in paths for violation in inspect_file(path)]
    violations.extend(inspect_independent_module_owners(paths))
    violations.extend(inspect_module_edges(paths))
    if not violations:
        return 0
    for violation in violations:
        print(violation.render())
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
