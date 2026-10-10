"""
Aegis Sovereign AI Runtime - Launcher Entry Point
Usage: python run_aegis.py [--port 8000] [--host 127.0.0.1]
"""

import argparse
import ipaddress
import os

import uvicorn


def main():
    parser = argparse.ArgumentParser(description="Aegis Sovereign AI Runtime")
    parser.add_argument(
        "--host", type=str, default="127.0.0.1", help="Host interface (default: 127.0.0.1)"
    )
    parser.add_argument("--port", type=int, default=8000, help="Port (default: 8000)")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload for development")
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Enable the local sovereign control-plane simulation (no automatic seeding)",
    )
    parser.add_argument(
        "--quiet", action="store_true", help="Minimal output for the combined launcher"
    )
    args = parser.parse_args()
    try:
        address = ipaddress.ip_address(args.host)
    except ValueError:
        parser.error("Use a numeric loopback host")
    if not address.is_loopback or not 1 <= args.port <= 65535:
        parser.error("Aegis requires a numeric loopback host and port 1-65535")
    if args.demo:
        os.environ["AEGIS_ENABLE_DEMO_ENDPOINTS"] = "1"

    from aegis.ui_constants import AEGIS_ASCII_LOGO

    logo = AEGIS_ASCII_LOGO
    if not args.quiet:
        print(logo)
        display_host = f"[{args.host}]" if address.version == 6 else args.host
        print(f"Aegis | local server starting at http://{display_host}:{args.port}")
        print("Operate with: python aegis.py cli. First-time setup: QUICKSTART.md.")
        print("No demo records are loaded automatically.")

    from aegis.models.local_runtime import LocalRuntime

    try:
        runtime = LocalRuntime()
    except (OSError, ValueError) as error:
        parser.exit(
            1,
            f"Aegis local models: {error}\nSee LOCAL_MODELS.md to repair the pinned local configuration.\n",
        )
    if args.reload and runtime.settings is not None:
        parser.error("Managed local models require a stable server process; omit --reload")
    with runtime:
        uvicorn.run(
            "aegis.api.server:app",
            host=args.host,
            port=args.port,
            reload=args.reload,
            log_level="warning" if args.quiet else "info",
            access_log=False,
        )


if __name__ == "__main__":
    main()
