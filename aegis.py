#!/usr/bin/env python3
"""One entry point for Windows, Linux and macOS. Never downloads dependencies."""
import argparse
import os
from pathlib import Path
import subprocess
import sys

from scripts.runtime_support import environment_python, offline_environment

ROOT = Path(__file__).resolve().parent


def main(argv=None):
    parser = argparse.ArgumentParser(description="Aegis: local setup and one-command launch on Windows, Linux and macOS.",
                                     epilog="Start here: setup. Daily use: start (also the default). No environment activation is needed.")
    commands = parser.add_subparsers(dest="command")
    start = commands.add_parser("start", help="Start the local API and CLI; stop the API when the CLI exits")
    start.add_argument("--port", type=int, default=8000)
    start.add_argument("--plain", action="store_true")
    setup = commands.add_parser("setup", help="Guided installation from a reviewed local wheelhouse")
    setup.add_argument("wheelhouse", nargs="?")
    setup.add_argument("manifest", nargs="?")
    setup.add_argument("--profile", choices=["core", "media", "full"], default="core")
    cli = commands.add_parser("cli", help="Run any CLI command using the dedicated environment (does not start a server)")
    cli.add_argument("arguments", nargs=argparse.REMAINDER)
    arguments = list(sys.argv[1:] if argv is None else argv)
    # argparse REMAINDER does not consume leading unknown option flags. Forward
    # the entire CLI suffix so `cli --json doctor` and custom URLs work normally.
    args = (argparse.Namespace(command="cli", arguments=arguments[1:])
            if arguments and arguments[0] == "cli" else parser.parse_args(arguments))
    try:
        if sys.version_info < (3, 11):
            raise ValueError("Install a reviewed local Python 3.11+ runtime first; see QUICKSTART.md.")
        if args.command == "setup":
            if not args.wheelhouse or not args.manifest:
                if not sys.stdin.isatty():
                    raise ValueError("Supply setup <wheelhouse-directory> <hash-manifest>. See QUICKSTART.md.")
                print("Offline setup. Use a reviewed wheelhouse for this OS, CPU architecture and Python version.")
                print("The manifest must come from your trusted acquisition record; setup does not establish provenance.")
                args.wheelhouse = args.wheelhouse or input("Wheelhouse folder: ").strip().strip('"')
                args.manifest = args.manifest or input("Trusted SHA-256 manifest: ").strip().strip('"')
            if not args.wheelhouse or not args.manifest:
                raise ValueError("Setup cancelled: both local paths are required.")
            paths = [os.path.abspath(os.path.expanduser(path)) for path in (args.wheelhouse, args.manifest)]
            return subprocess.call([sys.executable, "-I", str(ROOT / "scripts" / "setup_offline.py"),
                                    *paths, "--profile", args.profile], cwd=ROOT, env=offline_environment())
        python = environment_python(ROOT)
        if not python.is_file():
            raise ValueError("First-time setup is needed. Run this launcher with 'setup' and supply your reviewed local wheelhouse. See QUICKSTART.md.")
        if args.command == "cli":
            command = [str(python), "-I", str(ROOT / "scripts" / "run_cli.py"), *args.arguments]
        else:
            port = getattr(args, "port", 8000)
            if not 1 <= port <= 65535:
                raise ValueError("Port must be between 1 and 65535.")
            command = [str(python), "-I", str(ROOT / "scripts" / "start_offline.py"), "--port", str(port)]
            if getattr(args, "plain", False):
                command.append("--plain")
        return subprocess.call(command, cwd=ROOT, env=offline_environment())
    except (OSError, ValueError) as error:
        print(f"Aegis: {error}", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\nLaunch interrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
