#!/usr/bin/env python3
"""Compile synthetic ELF fixtures and verify the Florida postprocessor fail-closed behavior."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


FORBIDDEN = [
    b"frida_agent_main",
    b"gum-js-loop",
    b"gmain",
    b"FridaScriptEngine",
    b"GLib-GIO",
    b"GDBusProxy",
    b"GumScript",
    b"gdbus",
]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compile_fixture(output: Path, include_gmain: bool = True) -> None:
    marker_gmain = 'USED static const char marker_gmain[] = "gmain";' if include_gmain else ""
    source = output.with_suffix(".c")
    source.write_text(
        f"""
#define USED __attribute__((used))
__attribute__((visibility("default"))) void frida_agent_main(void) {{}}
USED static const char marker_loop[] = "gum-js-loop";
{marker_gmain}
USED static const char marker_engine[] = "FridaScriptEngine";
USED static const char marker_gio[] = "GLib-GIO";
USED static const char marker_proxy[] = "GDBusProxy";
USED static const char marker_script[] = "GumScript";
USED static const char marker_dbus[] = "gdbus";
int florida_fixture(void) {{ return marker_loop[0] + marker_engine[0]; }}
""",
        encoding="utf-8",
    )
    subprocess.run(
        ["gcc", "-shared", "-fPIC", "-O0", "-o", str(output), str(source)],
        check=True,
    )


def dynamic_symbols(path: Path) -> set[str]:
    result = subprocess.run(
        ["nm", "-D", "--defined-only", str(path)],
        check=True,
        capture_output=True,
        text=True,
    )
    return {line.split()[-1] for line in result.stdout.splitlines() if line.split()}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--script", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    args = parser.parse_args()

    script = args.script.resolve()
    policy = args.policy.resolve()
    if shutil.which("gcc") is None or shutil.which("nm") is None:
        raise RuntimeError("gcc and nm are required for the postprocessor self-test")

    with tempfile.TemporaryDirectory(prefix="florida-selftest-") as temporary:
        root = Path(temporary)
        reports = root / "reports"
        env = dict(os.environ)
        env["FLORIDA_REPORT_DIR"] = str(reports)

        valid = root / "valid-agent.so"
        compile_fixture(valid, include_gmain=True)
        subprocess.run(
            [sys.executable, str(script), "--policy", str(policy), str(valid)],
            check=True,
            env=env,
        )

        symbols = dynamic_symbols(valid)
        if "frida_agent_main" in symbols or "main" not in symbols:
            raise RuntimeError(f"Entrypoint self-test failed; dynamic symbols={sorted(symbols)}")

        data = valid.read_bytes()
        remaining = [marker.decode("ascii") for marker in FORBIDDEN if marker in data]
        if remaining:
            raise RuntimeError(f"Residual marker self-test failed: {remaining}")

        report_files = list(reports.glob("*.florida.json"))
        if len(report_files) != 1:
            raise RuntimeError(f"Expected one verification report, found {len(report_files)}")
        report = json.loads(report_files[0].read_text(encoding="utf-8"))
        if report.get("status") != "verified":
            raise RuntimeError("Verification report did not contain status=verified")

        missing_required = root / "missing-required.so"
        compile_fixture(missing_required, include_gmain=False)
        before = digest(missing_required)
        failure = subprocess.run(
            [sys.executable, str(script), "--policy", str(policy), str(missing_required)],
            env=env,
        )
        if failure.returncode == 0:
            raise RuntimeError("A fixture missing required marker gmain unexpectedly succeeded")
        if digest(missing_required) != before:
            raise RuntimeError("Failed processing modified the original binary instead of remaining atomic")

    print("Florida postprocessor self-test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
