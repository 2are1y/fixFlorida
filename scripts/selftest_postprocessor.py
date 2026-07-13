#!/usr/bin/env python3
"""Compile synthetic ELF fixtures and verify fail-closed post-processing behavior."""

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


REQUIRED_MARKERS = [b"gum-js-loop", b"gmain"]
OPTIONAL_MARKERS = [
    b"FridaScriptEngine",
    b"GLib-GIO",
    b"GDBusProxy",
    b"GumScript",
    b"gdbus",
]
FORBIDDEN = [b"frida_agent_main", *REQUIRED_MARKERS, *OPTIONAL_MARKERS]
EXPECTED_MARKER_NAMES = {
    "FridaScriptEngine",
    "GLib-GIO",
    "GDBusProxy",
    "GumScript",
    "gum-js-loop",
    "gmain",
    "gdbus",
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compile_fixture(
    output: Path,
    *,
    include_gmain: bool = True,
    include_optional: bool = True,
) -> None:
    marker_gmain = 'USED static const char marker_gmain[] = "gmain";' if include_gmain else ""
    optional_source = ""
    if include_optional:
        optional_source = """
USED static const char marker_engine[] = "FridaScriptEngine";
USED static const char marker_gio[] = "GLib-GIO";
USED static const char marker_proxy[] = "GDBusProxy";
USED static const char marker_script[] = "GumScript";
USED static const char marker_dbus[] = "gdbus";
"""

    source = output.with_suffix(".c")
    source.write_text(
        f"""
#define USED __attribute__((used))
__attribute__((visibility("default"))) void frida_agent_main(void) {{}}
USED static const char marker_loop[] = "gum-js-loop";
{marker_gmain}
{optional_source}
int florida_fixture(void) {{ return marker_loop[0]; }}
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


def read_single_report(report_dir: Path) -> dict[str, object]:
    report_files = list(report_dir.glob("*.florida.json"))
    if len(report_files) != 1:
        raise RuntimeError(
            f"Expected one verification report in {report_dir}, found {len(report_files)}"
        )
    report = json.loads(report_files[0].read_text(encoding="utf-8"))
    if report.get("status") != "verified":
        raise RuntimeError("Verification report did not contain status=verified")
    if set(report.get("markers", {})) != EXPECTED_MARKER_NAMES:
        raise RuntimeError("Verification report contains an incomplete marker set")
    return report


def run_postprocessor(script: Path, policy: Path, target: Path, report_dir: Path) -> None:
    env = dict(os.environ)
    env["FLORIDA_REPORT_DIR"] = str(report_dir)
    subprocess.run(
        [sys.executable, str(script), "--policy", str(policy), str(target)],
        check=True,
        env=env,
    )


def assert_transformed_binary(path: Path) -> None:
    symbols = dynamic_symbols(path)
    if "frida_agent_main" in symbols or "main" not in symbols:
        raise RuntimeError(f"Entrypoint self-test failed; dynamic symbols={sorted(symbols)}")

    data = path.read_bytes()
    remaining = [marker.decode("ascii") for marker in FORBIDDEN if marker in data]
    if remaining:
        raise RuntimeError(f"Residual marker self-test failed: {remaining}")


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

        valid = root / "valid-agent.so"
        valid_reports = root / "valid-reports"
        compile_fixture(valid, include_gmain=True, include_optional=True)
        before_valid = digest(valid)
        run_postprocessor(script, policy, valid, valid_reports)
        assert_transformed_binary(valid)
        valid_report = read_single_report(valid_reports)
        if valid_report.get("original_sha256") == valid_report.get("transformed_sha256"):
            raise RuntimeError("Valid fixture report indicates no binary modification")
        if digest(valid) == before_valid:
            raise RuntimeError("Valid fixture was not modified")
        for name, marker in valid_report["markers"].items():
            if marker.get("hits", 0) < 1:
                raise RuntimeError(f"Present marker {name} was not transformed")

        optional_missing = root / "optional-missing-agent.so"
        optional_reports = root / "optional-reports"
        compile_fixture(optional_missing, include_gmain=True, include_optional=False)
        run_postprocessor(script, policy, optional_missing, optional_reports)
        assert_transformed_binary(optional_missing)
        optional_report = read_single_report(optional_reports)
        markers = optional_report["markers"]
        for name in ("gum-js-loop", "gmain"):
            if markers[name].get("policy") != "required" or markers[name].get("hits", 0) < 1:
                raise RuntimeError(f"Required marker {name} failed optional-missing self-test")
        for name in ("FridaScriptEngine", "GLib-GIO", "GDBusProxy", "GumScript", "gdbus"):
            if markers[name].get("policy") != "optional" or markers[name].get("hits") != 0:
                raise RuntimeError(f"Optional marker {name} did not report zero hits")

        missing_required = root / "missing-required.so"
        failure_reports = root / "failure-reports"
        compile_fixture(missing_required, include_gmain=False, include_optional=True)
        before_failure = digest(missing_required)
        env = dict(os.environ)
        env["FLORIDA_REPORT_DIR"] = str(failure_reports)
        failure = subprocess.run(
            [sys.executable, str(script), "--policy", str(policy), str(missing_required)],
            env=env,
        )
        if failure.returncode == 0:
            raise RuntimeError("A fixture missing required marker gmain unexpectedly succeeded")
        if digest(missing_required) != before_failure:
            raise RuntimeError("Failed processing modified the original binary")
        if list(failure_reports.glob("*.florida.json")):
            raise RuntimeError("Failed processing unexpectedly generated a verified report")

    print("Florida postprocessor self-test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
