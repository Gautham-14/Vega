"""Run the installed VM host backend from an isolated source launcher."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.runtime_support import require_environment


def main():
    try:
        require_environment(ROOT)
        from aegis.vm.host import main as vm_main

        return vm_main()
    except (RuntimeError, ImportError) as error:
        print(f"Aegis VM: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
