"""The core imports only the standard library (env-RUNTIME-000002)."""

import subprocess
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
INTEGRATIONS = {"fastapi_auth"}


def core_modules() -> list[str]:
    package = SRC / "catalyst_users"
    return sorted(f"catalyst_users.{p.stem}" for p in package.glob("*.py") if p.stem not in INTEGRATIONS)


def test_core_imports_with_the_standard_library_only():
    # -I: isolated mode; -S: no site-packages, so a third-party import fails.
    code = f"import sys; sys.path.insert(0, {str(SRC)!r}); " + "; ".join(f"import {m}" for m in core_modules())
    result = subprocess.run([sys.executable, "-I", "-S", "-c", code], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
