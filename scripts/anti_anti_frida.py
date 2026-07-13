#!/usr/bin/env python3
"""Post-process an embedded Android frida-agent with fail-closed verification."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import string
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import lief


RNG = random.SystemRandom()
ALPHABET = string.ascii_letters
VALID_MARKER_POLICIES = {"required", "optional", "disabled"}
VALID_ENTRYPOINT_POLICIES = {
    "require-frida-agent-main",
    "allow-prepatched-main",
}


@dataclass(frozen=True)
class MarkerDefinition:
    name: str
    replacement_factory: Callable[[bytes, set[bytes]], bytes]

    @property
    def raw(self) -> bytes:
        return self.name.encode("ascii")


def token_bytes(length: int, original: bytes, data: bytes, used: set[bytes]) -> bytes:
    for _ in range(256):
        candidate = "".join(RNG.choice(ALPHABET) for _ in range(length)).encode("ascii")
        if candidate != original and candidate not in data and candidate not in used:
            return candidate
    raise RuntimeError(f"Unable to generate a collision-free {length}-byte token")


def fixed(value: bytes) -> Callable[[bytes, set[bytes]], bytes]:
    def make(_data: bytes, _used: set[bytes]) -> bytes:
        return value

    return make


def randomized(name: str) -> Callable[[bytes, set[bytes]], bytes]:
    original = name.encode("ascii")

    def make(data: bytes, used: set[bytes]) -> bytes:
        return token_bytes(len(original), original, data, used)

    return make


MARKERS: dict[str, MarkerDefinition] = {
    "FridaScriptEngine": MarkerDefinition("FridaScriptEngine", fixed(b"enignEtpircSadirF")),
    "GLib-GIO": MarkerDefinition("GLib-GIO", fixed(b"OIG-bilG")),
    "GDBusProxy": MarkerDefinition("GDBusProxy", fixed(b"yxorPsuBDG")),
    "GumScript": MarkerDefinition("GumScript", fixed(b"tpircSmuG")),
    "gum-js-loop": MarkerDefinition("gum-js-loop", randomized("gum-js-loop")),
    "gmain": MarkerDefinition("gmain", randomized("gmain")),
    "gdbus": MarkerDefinition("gdbus", randomized("gdbus")),
}


@dataclass(frozen=True)
class Policy:
    entrypoint: str
    markers: dict[str, str]


def load_policy(path: Path) -> Policy:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Unable to load policy {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise RuntimeError("Policy root must be a JSON object")

    entrypoint = raw.get("entrypoint")
    if entrypoint not in VALID_ENTRYPOINT_POLICIES:
        raise RuntimeError(
            f"Invalid entrypoint policy {entrypoint!r}; expected one of "
            f"{sorted(VALID_ENTRYPOINT_POLICIES)}"
        )

    marker_policies = raw.get("markers")
    if not isinstance(marker_policies, dict):
        raise RuntimeError("Policy field 'markers' must be an object")

    missing = set(MARKERS) - set(marker_policies)
    unknown = set(marker_policies) - set(MARKERS)
    if missing or unknown:
        raise RuntimeError(
            "Policy marker keys must exactly match the supported marker set; "
            f"missing={sorted(missing)}, unknown={sorted(unknown)}"
        )

    normalized: dict[str, str] = {}
    for name, value in marker_policies.items():
        if value not in VALID_MARKER_POLICIES:
            raise RuntimeError(
                f"Invalid policy {value!r} for marker {name!r}; expected one of "
                f"{sorted(VALID_MARKER_POLICIES)}"
            )
        normalized[name] = value

    return Policy(entrypoint=entrypoint, markers=normalized)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def symbol_names(binary: object) -> list[str]:
    return [symbol.name for symbol in binary.symbols]


def dynamic_symbol_names(binary: object) -> list[str]:
    symbols = getattr(binary, "dynamic_symbols", None)
    if symbols is None:
        return []
    return [symbol.name for symbol in symbols]


def count_name(names: list[str], name: str) -> int:
    return sum(1 for item in names if item == name)


def validate_entrypoint_before(policy: Policy, binary: object) -> dict[str, int]:
    names = symbol_names(binary)
    dynamic_names = dynamic_symbol_names(binary)
    state = {
        "old_before": count_name(names, "frida_agent_main"),
        "main_before": count_name(names, "main"),
        "dynamic_old_before": count_name(dynamic_names, "frida_agent_main"),
        "dynamic_main_before": count_name(dynamic_names, "main"),
    }

    if policy.entrypoint == "require-frida-agent-main":
        if state["old_before"] == 0:
            raise RuntimeError(
                "Required symbol frida_agent_main was not found. "
                "The upstream export layout may have changed; do not publish this build."
            )
        if state["dynamic_old_before"] == 0:
            raise RuntimeError(
                "The exported .dynsym entry frida_agent_main was not found. "
                "The binary is not a valid injectable agent for this policy."
            )
    else:
        if state["old_before"] == 0 and state["main_before"] == 0:
            raise RuntimeError(
                "Neither frida_agent_main nor main was found while using "
                "allow-prepatched-main policy"
            )
        if state["old_before"] > 0 and state["dynamic_old_before"] == 0:
            raise RuntimeError("frida_agent_main exists but is not dynamically exported")
        if state["old_before"] == 0 and state["dynamic_main_before"] == 0:
            raise RuntimeError("Prepatched main exists but is not dynamically exported")

    return state


def rename_symbols(binary: object, symbol_token: str) -> tuple[int, int]:
    entrypoints_renamed = 0
    other_symbols_renamed = 0

    for symbol in binary.symbols:
        name = symbol.name
        if name == "frida_agent_main":
            symbol.name = "main"
            entrypoints_renamed += 1
            continue

        updated = name.replace("frida", symbol_token).replace("FRIDA", symbol_token)
        if updated != name:
            symbol.name = updated
            other_symbols_renamed += 1

    return entrypoints_renamed, other_symbols_renamed


def validate_entrypoint_after(
    path: Path,
    policy: Policy,
    before: dict[str, int],
    renamed_count: int,
) -> dict[str, int]:
    binary = lief.parse(str(path))
    if binary is None:
        raise RuntimeError(f"LIEF could not re-parse transformed ELF: {path}")

    names = symbol_names(binary)
    dynamic_names = dynamic_symbol_names(binary)
    old_after = count_name(names, "frida_agent_main")
    main_after = count_name(names, "main")
    dynamic_old_after = count_name(dynamic_names, "frida_agent_main")
    dynamic_main_after = count_name(dynamic_names, "main")

    if old_after or dynamic_old_after:
        raise RuntimeError(
            "frida_agent_main is still present in an active ELF symbol table after rewriting"
        )

    if before["old_before"] > 0:
        if renamed_count != before["old_before"]:
            raise RuntimeError(
                f"Expected to rename {before['old_before']} frida_agent_main symbol(s), "
                f"renamed {renamed_count}"
            )

        expected_main = before["main_before"] + before["old_before"]
        if main_after < expected_main:
            raise RuntimeError(
                f"Expected at least {expected_main} main symbol(s) after rewriting, "
                f"found {main_after}"
            )

        if before["dynamic_old_before"] > 0:
            expected_dynamic_main = (
                before["dynamic_main_before"] + before["dynamic_old_before"]
            )
            if dynamic_main_after < expected_dynamic_main:
                raise RuntimeError(
                    "The rewritten dynamic main entrypoint count is lower than expected: "
                    f"expected at least {expected_dynamic_main}, found {dynamic_main_after}"
                )
    elif policy.entrypoint == "allow-prepatched-main":
        if main_after == 0:
            raise RuntimeError("Prepatched main entrypoint disappeared after ELF rewriting")
        if before["dynamic_main_before"] > 0 and dynamic_main_after < before["dynamic_main_before"]:
            raise RuntimeError(
                "The prepatched dynamic main entrypoint disappeared after ELF rewriting"
            )

    return {
        **before,
        "renamed": renamed_count,
        "old_after": old_after,
        "main_after": main_after,
        "dynamic_old_after": dynamic_old_after,
        "dynamic_main_after": dynamic_main_after,
    }


def replace_marker(
    data: bytes,
    definition: MarkerDefinition,
    policy: str,
    used_replacements: set[bytes],
) -> tuple[bytes, dict[str, object]]:
    old = definition.raw
    count = data.count(old)

    if policy == "disabled":
        print(f"[disabled] marker {definition.name!r}")
        return data, {"policy": policy, "hits": count, "replacement": None}

    if count == 0:
        if policy == "required":
            raise RuntimeError(
                f"Required marker {definition.name!r} was not found. "
                "The upstream binary layout may have changed; do not publish this build."
            )
        print(
            f"::warning::Optional marker {definition.name!r} was not found; "
            "the corresponding transformation was not needed or upstream changed"
        )
        return data, {"policy": policy, "hits": 0, "replacement": None}

    replacement = definition.replacement_factory(data, used_replacements)
    if len(old) != len(replacement):
        raise RuntimeError(
            f"Replacement length mismatch for {definition.name!r}: "
            f"{len(old)} != {len(replacement)}"
        )
    if replacement == old:
        raise RuntimeError(f"Replacement for {definition.name!r} is unchanged")

    used_replacements.add(replacement)
    print(
        f"[*] replacing {old!r} with {replacement!r} "
        f"({count} occurrence(s), policy={policy})"
    )
    return data.replace(old, replacement), {
        "policy": policy,
        "hits": count,
        "replacement": replacement.decode("ascii"),
    }


def sanitize_inactive_entrypoint_bytes(
    data: bytes, used_replacements: set[bytes]
) -> tuple[bytes, int]:
    marker = b"frida_agent_main"
    count = data.count(marker)
    if count == 0:
        return data, 0

    replacement = token_bytes(len(marker), marker, data, used_replacements)
    used_replacements.add(replacement)
    print(
        f"[*] sanitizing {count} inactive raw occurrence(s) of {marker!r} "
        f"with {replacement!r}"
    )
    return data.replace(marker, replacement), count


def verify_no_residuals(data: bytes, policy: Policy) -> list[str]:
    forbidden = [b"frida_agent_main"]
    forbidden.extend(
        MARKERS[name].raw
        for name, marker_policy in policy.markers.items()
        if marker_policy != "disabled"
    )
    remaining = [item.decode("ascii") for item in forbidden if item in data]
    if remaining:
        raise RuntimeError(f"Residual markers found after processing: {remaining}")
    return [item.decode("ascii") for item in forbidden]


def write_report(target: Path, payload: dict[str, object]) -> Path:
    configured = os.environ.get("FLORIDA_REPORT_DIR")
    report_dir = Path(configured).resolve() if configured else target.parent
    report_dir.mkdir(parents=True, exist_ok=True)

    identity = hashlib.sha256(str(target).encode("utf-8")).hexdigest()[:12]
    report = report_dir / f"{target.name}.{identity}.florida.json"
    temporary = report.with_suffix(report.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, report)
    return report


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("target", type=Path)
    return parser.parse_args(argv[1:])


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    target = args.target.resolve()
    policy_path = args.policy.resolve()
    policy = load_policy(policy_path)

    if not target.is_file() or target.stat().st_size == 0:
        raise RuntimeError(f"Invalid agent binary: {target}")

    original_mode = target.stat().st_mode
    original_sha256 = sha256(target)
    binary = lief.parse(str(target))
    if binary is None:
        raise RuntimeError(f"LIEF could not parse {target}")

    entrypoint_before = validate_entrypoint_before(policy, binary)

    original_data = target.read_bytes()
    symbol_token_bytes = token_bytes(5, b"frida", original_data, {b"FRIDA"})
    if symbol_token_bytes in {b"frida", b"FRIDA"}:
        raise RuntimeError("Generated ELF symbol token collides with an original marker")
    symbol_token = symbol_token_bytes.decode("ascii")
    entrypoints_renamed, other_symbols_renamed = rename_symbols(binary, symbol_token)

    temporary = target.with_name(target.name + ".florida.tmp")
    temporary.unlink(missing_ok=True)
    try:
        binary.write(str(temporary))
        if not temporary.is_file() or temporary.stat().st_size == 0:
            raise RuntimeError("LIEF did not produce a valid output file")

        first_symbol_validation = validate_entrypoint_after(
            temporary,
            policy,
            entrypoint_before,
            entrypoints_renamed,
        )

        data = temporary.read_bytes()
        used_replacements: set[bytes] = {symbol_token.encode("ascii")}
        data, inactive_entrypoint_hits = sanitize_inactive_entrypoint_bytes(
            data, used_replacements
        )

        marker_results: dict[str, dict[str, object]] = {}
        for name, definition in MARKERS.items():
            data, result = replace_marker(
                data,
                definition,
                policy.markers[name],
                used_replacements,
            )
            marker_results[name] = result

        forbidden_checked = verify_no_residuals(data, policy)
        temporary.write_bytes(data)
        os.chmod(temporary, original_mode)

        final_symbol_validation = validate_entrypoint_after(
            temporary,
            policy,
            entrypoint_before,
            entrypoints_renamed,
        )

        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)

    transformed_sha256 = sha256(target)
    if transformed_sha256 == original_sha256:
        raise RuntimeError("Post-processing completed without changing the agent binary")

    report_payload: dict[str, object] = {
        "status": "verified",
        "target": str(target),
        "policy": str(policy_path),
        "original_sha256": original_sha256,
        "transformed_sha256": transformed_sha256,
        "symbol_token": symbol_token,
        "entrypoint": final_symbol_validation,
        "entrypoint_first_pass": first_symbol_validation,
        "inactive_entrypoint_raw_hits": inactive_entrypoint_hits,
        "other_symbols_renamed": other_symbols_renamed,
        "markers": marker_results,
        "forbidden_markers_checked": forbidden_checked,
    }
    report = write_report(target, report_payload)

    print(f"[*] renamed {entrypoints_renamed} entrypoint symbol(s)")
    print(f"[*] renamed {other_symbols_renamed} additional ELF symbol(s)")
    print(f"[*] verification report: {report}")
    print(f"[*] Florida agent post-processing verified: {target}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except Exception as exc:
        print(f"[!] Florida agent post-processing failed: {exc}", file=sys.stderr)
        raise
