#!/usr/bin/env python3
"""Post-process an embedded Android frida-agent while preserving string lengths."""

from __future__ import annotations

import os
import random
import string
import sys
from pathlib import Path

import lief


RNG = random.SystemRandom()
ALPHABET = string.ascii_letters


def token(length: int) -> str:
    return "".join(RNG.choice(ALPHABET) for _ in range(length))


def replace_fixed(data: bytes, old: bytes, new: bytes) -> bytes:
    if len(old) != len(new):
        raise ValueError(f"Replacement length mismatch: {old!r} -> {new!r}")
    count = data.count(old)
    if count:
        print(f"[*] replacing {old!r} ({count} occurrence(s))")
        return data.replace(old, new)
    return data


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <frida-agent.so>", file=sys.stderr)
        return 2

    target = Path(argv[1]).resolve()
    if not target.is_file() or target.stat().st_size == 0:
        raise RuntimeError(f"Invalid agent binary: {target}")

    symbol_token = token(5)
    binary = lief.parse(str(target))
    if binary is None:
        raise RuntimeError(f"LIEF could not parse {target}")

    renamed = 0
    for symbol in binary.symbols:
        name = symbol.name
        if name == "frida_agent_main":
            symbol.name = "main"
            renamed += 1
            continue
        updated = name.replace("frida", symbol_token).replace("FRIDA", symbol_token)
        if updated != name:
            symbol.name = updated
            renamed += 1

    temporary = target.with_name(target.name + ".florida.tmp")
    binary.write(str(temporary))
    if not temporary.is_file() or temporary.stat().st_size == 0:
        raise RuntimeError("LIEF did not produce a valid output file")
    os.replace(temporary, target)
    print(f"[*] renamed {renamed} ELF symbol(s)")

    data = target.read_bytes()
    fixed_replacements = {
        b"FridaScriptEngine": b"enignEtpircSadirF",
        b"GLib-GIO": b"OIG-bilG",
        b"GDBusProxy": b"yxorPsuBDG",
        b"GumScript": b"tpircSmuG",
        b"gum-js-loop": token(11).encode("ascii"),
        b"gmain": token(5).encode("ascii"),
        b"gdbus": token(5).encode("ascii"),
    }
    for old, new in fixed_replacements.items():
        data = replace_fixed(data, old, new)
    target.write_bytes(data)

    print(f"[*] Florida agent post-processing finished: {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
