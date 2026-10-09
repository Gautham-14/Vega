"""Launch the CLI with an explicit source path from an isolated interpreter."""
from pathlib import Path
import sys

if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.runtime_support import require_environment


def main():
    try:
        require_environment(ROOT)
        from aegis.cli import main as cli_main
        return cli_main()
    except (RuntimeError, ImportError) as error:
        print(f"Aegis CLI: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
