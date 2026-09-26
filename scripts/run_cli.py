"""Launch the CLI with an explicit source path from an isolated interpreter."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.runtime_support import require_environment


def main():
    try:
        require_environment(ROOT)
        from aegis_cli import main as cli_main
        return cli_main()
    except (RuntimeError, ImportError) as error:
        print(f"Aegis CLI: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
