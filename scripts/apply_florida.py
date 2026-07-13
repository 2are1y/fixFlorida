#!/usr/bin/env python3
"""Apply Florida's Android source changes without fragile git-am patches."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path


class PatchError(RuntimeError):
    pass


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count == 0:
        if new in text:
            print(f"[already] {path}: replacement already present")
            return
        raise PatchError(f"Pattern not found in {path}:\n{old}")
    if count != 1:
        raise PatchError(f"Expected one match in {path}, found {count}:\n{old}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
    print(f"[patched] {path}")


def insert_before_once(path: Path, marker: str, insertion: str, sentinel: str) -> None:
    text = path.read_text(encoding="utf-8")
    if sentinel in text:
        print(f"[already] {path}: insertion already present")
        return
    index = text.find(marker)
    if index == -1:
        raise PatchError(f"Insertion marker not found in {path}:\n{marker}")
    path.write_text(text[:index] + insertion + text[index:], encoding="utf-8")
    print(f"[patched] {path}")


def patch_rpc(core: Path) -> None:
    path = core / "lib/base/rpc.vala"
    signature = (
        "\t\tpublic async Json.Node call (string method, Json.Node[] args, Bytes? data, "
        "Cancellable? cancellable) throws Error, IOError {"
    )
    helper = (
        "\t\tprivate static string get_rpc_marker (bool quoted = false) {\n"
        "\t\t\tstring marker = (string) Base64.decode ((string) Base64.decode "
        "(\"Wm5KcFpHRTZjbkJq\"));\n"
        "\t\t\treturn quoted ? \"\\\"\" + marker + \"\\\"\" : marker;\n"
        "\t\t}\n\n"
    )
    insert_before_once(path, signature, helper, "get_rpc_marker")
    replace_once(path, '.add_string_value ("frida:rpc")', ".add_string_value (get_rpc_marker ())")
    replace_once(
        path,
        'if (json.index_of ("\\\"frida:rpc\\\"") == -1)',
        "if (json.index_of (get_rpc_marker (true)) == -1)",
    )
    replace_once(
        path,
        'if (type == null || type != "frida:rpc")',
        "if (type == null || type != get_rpc_marker ())",
    )


def patch_linux_host_session(core: Path) -> None:
    path = core / "src/linux/linux-host-session.vala"
    replace_once(
        path,
        "\t\tprivate AgentDescriptor? agent;",
        "\t\tprivate AgentDescriptor? agent;\n\t\tprivate string agent_resource_prefix;",
    )
    replace_once(
        path,
        "\t\t\tinjector.uninjected.connect (on_uninjected);\n\n#if HAVE_EMBEDDED_ASSETS",
        "\t\t\tinjector.uninjected.connect (on_uninjected);\n\n"
        "\t\t\tagent_resource_prefix = Uuid.string_random ();\n\n#if HAVE_EMBEDDED_ASSETS",
    )
    replace_once(
        path,
        'agent = new AgentDescriptor (PathTemplate ("frida-agent-<arch>.so"),',
        'agent = new AgentDescriptor (PathTemplate (agent_resource_prefix + "-<arch>.so"),',
    )
    replace_once(
        path,
        'new AgentResource ("frida-agent-arm.so", new Bytes.static (emulated_arm.data), tempdir),',
        'new AgentResource (agent_resource_prefix + "-arm.so", new Bytes.static (emulated_arm.data), tempdir),',
    )
    replace_once(
        path,
        'new AgentResource ("frida-agent-arm64.so", new Bytes.static (emulated_arm64.data), tempdir),',
        'new AgentResource (agent_resource_prefix + "-arm64.so", new Bytes.static (emulated_arm64.data), tempdir),',
    )
    replace_once(path, 'string entrypoint = "frida_agent_main";', 'string entrypoint = "main";')
    replace_once(path, "\t\t\tunowned string name;", "\t\t\tstring name;")
    replace_once(path, 'name = "frida-agent-arm.so";', 'name = agent_resource_prefix + "-arm.so";')
    replace_once(path, 'name = "frida-agent-arm64.so";', 'name = agent_resource_prefix + "-arm64.so";')


def patch_agent_symbol_references(core: Path) -> None:
    replace_once(
        core / "src/agent-container.vala",
        'container.module.symbol ("frida_agent_main", out main_func_symbol)',
        'container.module.symbol ("main", out main_func_symbol)',
    )


def patch_droidy(core: Path) -> None:
    replace_once(
        core / "src/droidy/droidy-client.vala",
        'throw new Error.PROTOCOL ("Unexpected command");',
        'break; // Ignore an unexpected ADB command instead of terminating the transport.',
    )


def patch_process_name(core: Path, gum: Path) -> None:
    insert_before_once(
        core / "src/frida-glue.c",
        "    if (runtime == FRIDA_RUNTIME_OTHER)\n",
        '    g_set_prgname ("ggbond");\n\n',
        'g_set_prgname ("ggbond")',
    )
    replace_once(gum / "gum/gum.c", 'g_set_prgname ("frida");', 'g_set_prgname ("ggbond");')


def patch_memfd_name(core: Path) -> None:
    replace_once(
        core / "lib/base/linux.vala",
        "return Linux.syscall (LinuxSyscall.MEMFD_CREATE, name, flags);",
        'return Linux.syscall (LinuxSyscall.MEMFD_CREATE, "jit-cache", flags);',
    )


def install_agent_postprocessor(core: Path, anti_script: Path) -> None:
    destination = core / "src/anti-anti-frida.py"
    shutil.copy2(anti_script, destination)
    print(f"[copied] {destination}")

    path = core / "src/embed-agent.py"
    old = (
        "            if agent is not None:\n"
        "                shutil.copy(agent, embedded_agent)\n"
        "            else:\n"
        "                embedded_agent.write_bytes(b\"\")\n"
        "            embedded_assets += [embedded_agent]\n"
    )
    new = (
        "            if agent is not None:\n"
        "                shutil.copy(agent, embedded_agent)\n"
        "                postprocessor = Path(__file__).with_name(\"anti-anti-frida.py\")\n"
        "                subprocess.run([sys.executable, str(postprocessor), str(embedded_agent)], check=True)\n"
        "            else:\n"
        "                embedded_agent.write_bytes(b\"\")\n"
        "            embedded_assets += [embedded_agent]\n"
    )
    replace_once(path, old, new)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--frida-root", required=True, type=Path)
    parser.add_argument("--anti-script", required=True, type=Path)
    args = parser.parse_args()

    root = args.frida_root.resolve()
    core = root / "subprojects/frida-core"
    gum = root / "subprojects/frida-gum"

    for required in (core, gum, args.anti_script):
        if not required.exists():
            raise PatchError(f"Required path does not exist: {required}")

    patch_rpc(core)
    patch_linux_host_session(core)
    patch_agent_symbol_references(core)
    patch_droidy(core)
    patch_process_name(core, gum)
    patch_memfd_name(core)
    install_agent_postprocessor(core, args.anti_script.resolve())

    print("Florida source transformations completed successfully")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
