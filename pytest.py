from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import traceback
from types import TracebackType
from typing import Any


sys.modules.setdefault("pytest", sys.modules[__name__])


class SkipTest(Exception):
    pass


def skip(reason: str = "") -> None:
    raise SkipTest(reason)


class raises:
    def __init__(self, expected: type[BaseException]) -> None:
        self.expected = expected

    def __enter__(self) -> "raises":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> bool:
        if exc_type is None:
            raise AssertionError(f"Expected {self.expected.__name__} to be raised")
        if not issubclass(exc_type, self.expected):
            return False
        return True


def main() -> int:
    root = Path.cwd()
    sys.path.insert(0, str(root / "src"))
    sys.path.insert(0, str(root / "tests"))
    failures = 0
    skipped = 0
    tests = 0
    for path in _iter_test_paths(root, sys.argv[1:]):
        module = _load_module(path)
        for name, value in sorted(vars(module).items()):
            if name.startswith("test_") and callable(value):
                tests += 1
                try:
                    _call(value)
                    print(f"PASS {path.name}::{name}")
                except SkipTest as exc:
                    skipped += 1
                    reason = f": {exc}" if str(exc) else ""
                    print(f"SKIP {path.name}::{name}{reason}")
                except Exception:
                    failures += 1
                    print(f"FAIL {path.name}::{name}")
                    traceback.print_exc()
    print(f"{tests - failures - skipped} passed, {failures} failed, {skipped} skipped")
    return 1 if failures else 0


def _iter_test_paths(root: Path, args: list[str]) -> list[Path]:
    selected = [arg for arg in args if arg and not arg.startswith("-")]
    if not selected:
        return sorted((root / "tests").rglob("test_*.py"))

    paths: list[Path] = []
    seen: set[Path] = set()
    for value in selected:
        candidate = (root / value).resolve() if not Path(value).is_absolute() else Path(value).resolve()
        if candidate.is_dir():
            matches = sorted(candidate.rglob("test_*.py"))
        elif candidate.is_file():
            matches = [candidate]
        else:
            continue
        for match in matches:
            if match not in seen:
                seen.add(match)
                paths.append(match)
    return paths


def _load_module(path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(path.stem, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[path.stem] = module
    spec.loader.exec_module(module)
    return module


def _call(func: Any) -> None:
    import tempfile

    if "tmp_path" in func.__code__.co_varnames[: func.__code__.co_argcount]:
        with tempfile.TemporaryDirectory() as tmp:
            func(Path(tmp))
    else:
        func()


if __name__ == "__main__":
    raise SystemExit(main())
