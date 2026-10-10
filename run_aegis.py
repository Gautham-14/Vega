"""Compatibility launcher; installed users may run aegis-server."""

import uvicorn as uvicorn  # Retained for launch configuration tooling.

from aegis.server_entry import main

if __name__ == "__main__":
    main()
