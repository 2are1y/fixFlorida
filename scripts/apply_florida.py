#!/usr/bin/env python3
"""Apply and verify Florida's Android source transformations without git-am."""

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


def assert_contains(path: Path, needle: str, expected: int | None = None) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(needle)
    if count == 0:
        raise PatchError(f"Verification failed: {needle!r} is absent from {path}")
    if expected is not None and count != expected:
        raise PatchError(
            f"Verification failed: expected {expected} occurrence(s) of {needle!r} "
            f"in {path}, found {count}"
        )


def assert_absent(path: Path, needle: str) -> None:
    text = path.read_text(encoding="utf-8")
    if needle in text:
        raise PatchError(f"Verification failed: residual {needle!r} remains in {path}")


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
        "#if HAVE_EMBEDDED_ASSETS\n\t\t\tvar blob32 = Frida.Data.Agent.get_frida_agent_32_so_blob ();",
        "#if HAVE_EMBEDDED_ASSETS\n"
        "\t\t\tvar random_prefix = Uuid.string_random ();\n"
        "\t\t\tvar blob32 = Frida.Data.Agent.get_frida_agent_32_so_blob ();",
    )
    replace_once(
        path,
        'agent = new AgentDescriptor (PathTemplate ("frida-agent-<arch>.so"),',
        'agent = new AgentDescriptor (PathTemplate (random_prefix + "-<arch>.so"),',
    )
    replace_once(
        path,
        'new AgentResource ("frida-agent-arm.so", new Bytes.static (emulated_arm.data), tempdir),',
        'new AgentResource (random_prefix + "-arm.so", new Bytes.static (emulated_arm.data), tempdir),',
    )
    replace_once(
        path,
        'new AgentResource ("frida-agent-arm64.so", new Bytes.static (emulated_arm64.data), tempdir),',
        'new AgentResource (random_prefix + "-arm64.so", new Bytes.static (emulated_arm64.data), tempdir),',
    )
    replace_once(path, 'string entrypoint = "frida_agent_main";', 'string entrypoint = "main";')

    replace_once(path, "\t\t\tunowned string name;", "\t\t\tunowned string suffix;")
    replace_once(path, 'name = "frida-agent-arm.so";', 'suffix = "-arm.so";')
    replace_once(path, 'name = "frida-agent-arm64.so";', 'suffix = "-arm64.so";')
    replace_once(
        path,
        "AgentResource? resource = agent.resources.first_match (r => r.name == name);",
        "AgentResource? resource = agent.resources.first_match (r => r.name.has_suffix (suffix));",
    )


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


def install_agent_postprocessor(core: Path, anti_script: Path, anti_policy: Path) -> None:
    script_destination = core / "src/anti-anti-frida.py"
    policy_destination = core / "src/anti-anti-frida-policy.json"
    shutil.copy2(anti_script, script_destination)
    shutil.copy2(anti_policy, policy_destination)
    print(f"[copied] {script_destination}")
    print(f"[copied] {policy_destination}")

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
        "                policy = Path(__file__).with_name(\"anti-anti-frida-policy.json\")\n"
        "                subprocess.run([\n"
        "                    sys.executable, str(postprocessor),\n"
        "                    \"--policy\", str(policy), str(embedded_agent),\n"
        "                ], check=True)\n"
        "            else:\n"
        "                embedded_agent.write_bytes(b\"\")\n"
        "            embedded_assets += [embedded_agent]\n"
    )
    replace_once(path, old, new)


def verify_source_transformations(core: Path, gum: Path) -> None:
    rpc = core / "lib/base/rpc.vala"
    linux = core / "src/linux/linux-host-session.vala"
    container = core / "src/agent-container.vala"
    droidy = core / "src/droidy/droidy-client.vala"
    glue = core / "src/frida-glue.c"
    linux_base = core / "lib/base/linux.vala"
    embed = core / "src/embed-agent.py"
    gum_c = gum / "gum/gum.c"

    assert_contains(rpc, "get_rpc_marker", expected=4)
    assert_absent(rpc, '.add_string_value ("frida:rpc")')
    assert_absent(rpc, 'json.index_of ("\\\"frida:rpc\\\"")')
    assert_absent(rpc, 'type != "frida:rpc"')

    assert_contains(linux, "var random_prefix = Uuid.string_random ();", expected=1)
    assert_contains(linux, 'PathTemplate (random_prefix + "-<arch>.so")', expected=1)
    assert_contains(linux, 'random_prefix + "-arm.so"', expected=1)
    assert_contains(linux, 'random_prefix + "-arm64.so"', expected=1)
    assert_contains(linux, 'r.name.has_suffix (suffix)', expected=1)
    assert_absent(linux, "agent_resource_prefix")
    assert_absent(linux, 'string entrypoint = "frida_agent_main";')

    assert_absent(container, 'container.module.symbol ("frida_agent_main"')
    assert_contains(container, 'container.module.symbol ("main"', expected=1)

    assert_absent(droidy, 'throw new Error.PROTOCOL ("Unexpected command");')
    assert_contains(glue, 'g_set_prgname ("ggbond");', expected=1)
    assert_contains(gum_c, 'g_set_prgname ("ggbond");', expected=1)
    assert_contains(linux_base, 'LinuxSyscall.MEMFD_CREATE, "jit-cache", flags', expected=1)

    assert_contains(embed, 'anti-anti-frida.py', expected=1)
    assert_contains(embed, 'anti-anti-frida-policy.json', expected=1)
    assert_contains(embed, 'subprocess.run([', expected=2)  # existing lipo call plus postprocessor call
    assert_contains(core / "src/anti-anti-frida.py", "Residual markers found after processing")
    assert_contains(core / "src/anti-anti-frida-policy.json", '"gum-js-loop": "required"')

    print("[verified] Florida source transformations")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--frida-root", required=True, type=Path)
    parser.add_argument("--anti-script", required=True, type=Path)
    parser.add_argument("--anti-policy", required=True, type=Path)
    args = parser.parse_args()

    root = args.frida_root.resolve()
    core = root / "subprojects/frida-core"
    gum = root / "subprojects/frida-gum"
    anti_script = args.anti_script.resolve()
    anti_policy = args.anti_policy.resolve()

    for required in (core, gum, anti_script, anti_policy):
        if not required.exists():
            raise PatchError(f"Required path does not exist: {required}")

    patch_rpc(core)
    patch_linux_host_session(core)
    patch_agent_symbol_references(core)
    patch_droidy(core)
    patch_process_name(core, gum)
    patch_memfd_name(core)
    install_agent_postprocessor(core, anti_script, anti_policy)
    verify_source_transformations(core, gum)

    print("Florida source transformations completed and verified successfully")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
