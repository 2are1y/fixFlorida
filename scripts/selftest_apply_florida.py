#!/usr/bin/env python3
"""Exercise source transformations and verify that applying them twice is safe."""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def make_fixture(root: Path) -> None:
    core = root / "subprojects/frida-core"
    gum = root / "subprojects/frida-gum"

    write(
        core / "lib/base/rpc.vala",
        '''namespace Frida {
\tpublic sealed class RpcClient : Object {
\t\tpublic async Json.Node call (string method, Json.Node[] args, Bytes? data, Cancellable? cancellable) throws Error, IOError {
\t\t\trequest.add_string_value ("frida:rpc");
\t\t\tif (json.index_of ("\\\"frida:rpc\\\"") == -1)
\t\t\t\treturn null;
\t\t\tif (type == null || type != "frida:rpc")
\t\t\t\treturn null;
\t\t}
\t}
}
''',
    )
    write(
        core / "src/linux/linux-host-session.vala",
        '''#if HAVE_EMBEDDED_ASSETS
\t\t\tvar blob32 = Frida.Data.Agent.get_frida_agent_32_so_blob ();
\t\t\tagent = new AgentDescriptor (PathTemplate ("frida-agent-<arch>.so"),
\t\t\t\tnew AgentResource ("frida-agent-arm.so", new Bytes.static (emulated_arm.data), tempdir),
\t\t\t\tnew AgentResource ("frida-agent-arm64.so", new Bytes.static (emulated_arm64.data), tempdir),
\t\t\t);
#endif
\t\t\tstring entrypoint = "frida_agent_main";
\t\t\tunowned string name;
\t\t\tname = "frida-agent-arm.so";
\t\t\tname = "frida-agent-arm64.so";
\t\t\tAgentResource? resource = agent.resources.first_match (r => r.name == name);
''',
    )
    write(
        core / "src/agent-container.vala",
        'container.module.symbol ("frida_agent_main", out main_func_symbol);\n',
    )
    write(
        core / "src/droidy/droidy-client.vala",
        'switch (command) {\ndefault:\n\tthrow new Error.PROTOCOL ("Unexpected command");\n}\n',
    )
    write(
        core / "src/frida-glue.c",
        "void x(void) {\n    if (runtime == FRIDA_RUNTIME_OTHER)\n      return;\n}\n",
    )
    write(
        core / "lib/base/linux.vala",
        "return Linux.syscall (LinuxSyscall.MEMFD_CREATE, name, flags);\n",
    )
    write(
        core / "src/embed-agent.py",
        '''from pathlib import Path
import shutil
import subprocess
import sys
subprocess.run(["existing"], check=True)
            if agent is not None:
                shutil.copy(agent, embedded_agent)
            else:
                embedded_agent.write_bytes(b"")
            embedded_assets += [embedded_agent]
''',
    )
    write(gum / "gum/gum.c", 'g_set_prgname ("frida");\n')


def run_apply(script: Path, source_root: Path, anti_script: Path, policy: Path) -> None:
    subprocess.run(
        [
            sys.executable,
            str(script),
            "--frida-root",
            str(source_root),
            "--anti-script",
            str(anti_script),
            "--anti-policy",
            str(policy),
        ],
        check=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--script", required=True, type=Path)
    parser.add_argument("--anti-script", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    args = parser.parse_args()

    script = args.script.resolve()
    anti_script = args.anti_script.resolve()
    policy = args.policy.resolve()

    with tempfile.TemporaryDirectory(prefix="florida-source-selftest-") as temporary:
        source_root = Path(temporary) / "frida"
        make_fixture(source_root)

        run_apply(script, source_root, anti_script, policy)
        first_rpc = (source_root / "subprojects/frida-core/lib/base/rpc.vala").read_text(
            encoding="utf-8"
        )
        run_apply(script, source_root, anti_script, policy)
        second_rpc = (source_root / "subprojects/frida-core/lib/base/rpc.vala").read_text(
            encoding="utf-8"
        )

        if first_rpc != second_rpc:
            raise RuntimeError("Second source transformation changed an already-patched tree")
        if first_rpc.count("private static string get_rpc_marker") != 1:
            raise RuntimeError("RPC helper was not inserted exactly once")

    print("Florida source transformation self-test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
