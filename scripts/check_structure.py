from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

MODULE_LIMIT = 350
CALLABLE_LIMIT = 100
ROOT = Path(__file__).resolve().parents[1]
INDEPENDENT_MODULES = {
    Path("src/parquity/model.py"): "parquity.model",
    Path("src/parquity/verdicts.py"): "parquity.verdicts",
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
    return tuple(sorted(path for root in roots for path in root.rglob("*.py")))


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


def _import_violations(
    path: Path,
    tree: ast.AST,
    spans: list[CallableSpan],
) -> tuple[Violation, ...]:
    module_name = INDEPENDENT_MODULES.get(path.relative_to(ROOT))
    if module_name is None:
        return ()
    violations: list[Violation] = []
    for line, target in _import_targets(tree, module_name):
        if _is_forbidden_import(target):
            violations.append(
                Violation(
                    path,
                    _symbol_at(spans, line),
                    f"import={target!r} at line {line}",
                    "model.py and verdicts.py may not import engines, CLI, or matrix",
                )
            )
    return tuple(violations)


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


def _symbol_at(spans: list[CallableSpan], line: int) -> str:
    matches = [span for span in spans if span.start <= line <= span.end]
    if not matches:
        return "<module>"
    return min(matches, key=lambda span: span.end - span.start).symbol


def main() -> int:
    violations = [violation for path in python_files() for violation in inspect_file(path)]
    if not violations:
        return 0
    for violation in violations:
        print(violation.render())
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
