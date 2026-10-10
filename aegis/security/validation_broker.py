"""Separate gVisor validation broker; the API never receives a Docker socket."""

import argparse
import os

from aegis.coding import sandbox, tools


def dispatch(request):
    if request == {"operation": "status"}:
        return sandbox.configuration()
    if set(request) != {"operation", "files", "command"} or request["operation"] != "execute":
        raise ValueError("Unsupported validation operation")
    if request["command"] not in sandbox.COMMANDS or not isinstance(request["files"], dict):
        raise ValueError("Only fixed validation commands are allowed")
    tools.validate_files(request["files"])
    return sandbox.execute(request["files"], request["command"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--runtime-uid", type=int, required=True)
    args = parser.parse_args()
    if os.environ.get("AEGIS_SANDBOX_BROKER_SOCKET"):
        raise ValueError(
            "Validator must use its own local backend, never recursively call a broker"
        )
    from aegis.control.store import init_control
    from aegis.storage.database import init_db

    init_db()
    init_control()
    from aegis.security.local_rpc import serve

    serve(args.socket, args.runtime_uid, dispatch)


if __name__ == "__main__":
    main()
