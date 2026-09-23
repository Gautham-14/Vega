"""
Aegis Sovereign AI Runtime - Launcher Entry Point
Usage: python run_aegis.py [--port 8000] [--host 127.0.0.1]
"""
import sys
import argparse
import os
import uvicorn
from pathlib import Path

# Ensure repo root is on python path
sys.path.insert(0, str(Path(__file__).resolve().parent))


def main():
    parser = argparse.ArgumentParser(description="Aegis Sovereign AI Runtime")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host interface (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port (default: 8000)")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload for development")
    parser.add_argument("--demo", action="store_true", help="Enable the local sovereign control-plane simulation (no automatic seeding)")
    args = parser.parse_args()
    if args.demo:
        os.environ["AEGIS_ENABLE_DEMO_ENDPOINTS"] = "1"

    logo = r"""
    ___    ____________ ________ 
   /   |  / ____/ ____//  _/ ___/
  / /| | / __/ / / __  / / \__ \ 
 / ___ |/ /___/ /_/ /_/ / ___/ / 
/_/  |_/_____/\____//___//____/  
                                 
 SOVEREIGN INDUSTRIAL AI RUNTIME
"""
    print("=" * 72)
    print(logo)
    print("=" * 72)
    print(" Local runtime ready. Storage initializes on startup.")
    print(f" Web Operations Console: http://{args.host}:{args.port}")
    print(f" REST API Specification: http://{args.host}:{args.port}/docs")
    print(" No demo records are loaded automatically.")
    print("=" * 72)

    uvicorn.run("aegis.api.server:app", host=args.host, port=args.port, reload=args.reload)

if __name__ == "__main__":
    main()
