"""Explicit synthetic PUBLIC smoke check; never uses the operator's accounts/data."""

import argparse
import base64
import io
import json
import os
import platform
import secrets
import tempfile
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--live",
        action="store_true",
        required=True,
        help="Explicitly start the pinned local runtime and run inference",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--suite", type=Path, help="Explicit synthetic suite with routing and narrow answer checks"
    )
    parser.add_argument(
        "--diagnostic",
        action="store_true",
        help="Print bounded responses from these synthetic prompts only",
    )
    args = parser.parse_args()
    from scripts.local_model_evaluation import answer_check, load_suite

    cases = load_suite(args.suite) if args.suite else None
    with tempfile.TemporaryDirectory(
        prefix="aegis-public-chat-smoke-", dir=Path(tempfile.gettempdir()).resolve()
    ) as temporary:
        os.environ["AEGIS_DATA_DIR"] = str(Path(temporary) / "data")
        os.environ["AEGIS_SECURITY_PROFILE"] = "development"
        os.environ.pop("AEGIS_ENABLE_DEMO_ENDPOINTS", None)
        os.environ["AEGIS_ALLOWED_HOSTS"] = "localhost,127.0.0.1,testserver"
        from fastapi.testclient import TestClient
        from PIL import Image

        from aegis.api.server import app
        from aegis.models.local_runtime import LocalRuntime, configuration_hash
        from aegis.security import auth
        from aegis.version import __version__

        if args.diagnostic:
            from aegis.coding import providers

            original_request = providers.request_json

            def inspected(*positional, **keywords):
                value = original_request(*positional, **keywords)
                if positional[0] == "/v1/chat/completions":
                    print(
                        json.dumps({"model": value.get("model"), "choices": value.get("choices")})[
                            :1600
                        ],
                        flush=True,
                    )
                return value

            providers.request_json = inspected

        password = secrets.token_urlsafe(24)
        reports = []
        with LocalRuntime() as runtime, TestClient(app) as client:
            inventory_hash = configuration_hash(runtime.settings)
            auth.provision("operator", password)
            login = client.post(
                "/api/auth/login", json={"username": "operator", "password": password}
            )
            login.raise_for_status()
            headers = {"Authorization": "Bearer " + login.json()["access_token"]}
            image = io.BytesIO()
            Image.new("RGB", (64, 64), "red").save(image, format="PNG")
            requests = [
                ("text", {"prompt": "Explain what a heat exchanger does in two sentences."}),
                (
                    "code",
                    {
                        "prompt": "Write a Python function returning the square of a number. Explain it briefly."
                    },
                ),
                (
                    "vision",
                    {
                        "prompt": "What is the main color of this image?",
                        "images": [base64.b64encode(image.getvalue()).decode("ascii")],
                    },
                ),
                (
                    "code",
                    {"prompt": "Help me implement a loop that adds all integers from 1 to n."},
                ),
            ]
            if cases is not None:
                requests = []
                for case in cases:
                    body = {"prompt": case["prompt"]}
                    if case["color"] is not None:
                        colored = io.BytesIO()
                        Image.new("RGB", (64, 64), case["color"]).save(colored, format="PNG")
                        body["images"] = [base64.b64encode(colored.getvalue()).decode("ascii")]
                    requests.append((case["role"], body))
            for index, (expected, body) in enumerate(requests):
                started = time.monotonic()
                response = client.post(
                    "/api/chat", json={"classification": "PUBLIC", **body}, headers=headers
                )
                if response.status_code != 200:
                    if cases is not None:
                        reports.append(
                            {
                                "id": cases[index]["id"],
                                "expected_role": expected,
                                "http_status": response.status_code,
                                "routing_pass": False,
                                "answer_check_pass": False,
                                "error": "Bounded request rejected; no weaker fallback",
                                "request_latency_ms": round((time.monotonic() - started) * 1000),
                            }
                        )
                        print(json.dumps(reports[-1]), flush=True)
                        continue
                    raise RuntimeError(
                        f"{expected} smoke request failed: {response.status_code} {response.text[:1000]}"
                    )
                result = response.json()
                routing_pass = (
                    result["routing"]["role"] == expected
                    and result["is_simulation"] is False
                    and bool(result["answer"].strip())
                )
                if cases is None and (
                    result["routing"]["role"] != expected
                    or result["is_simulation"] is not False
                    or not result["answer"].strip()
                ):
                    raise RuntimeError("Live routing did not select the expected role")
                reports.append(
                    {
                        "role": expected,
                        "model": result["routing"]["model"],
                        "latency_ms": result["latency_ms"],
                        "routing_model_calls": result["routing_model_calls"],
                        "nonempty_answer": True,
                        "request_latency_ms": round((time.monotonic() - started) * 1000),
                    }
                )
                if cases is not None:
                    reports[-1].update(
                        id=cases[index]["id"],
                        expected_role=expected,
                        routing_pass=routing_pass,
                        answer_check_pass=answer_check(result["answer"], cases[index]["check"]),
                    )
                print(json.dumps(reports[-1]), flush=True)
        passing = sum(
            bool(item.get("routing_pass") and item.get("answer_check_pass")) for item in reports
        )
        result = {
            "status": "PASS" if cases is None or passing == len(reports) else "NEEDS_REVIEW",
            "scope": "Synthetic PUBLIC inference and model routing, not quality/security certification",
            "checks": reports,
            "operator_data_used": False,
            "python": platform.python_version(),
            "platform": platform.platform(),
            "application_version": __version__,
            "local_inventory_sha256": inventory_hash,
            "created_at": time.time(),
        }
        if cases is not None:
            import hashlib

            result.update(
                suite_sha256=hashlib.sha256(args.suite.read_bytes()).hexdigest(),
                total=len(reports),
                routing_passed=sum(bool(item["routing_pass"]) for item in reports),
                answer_checks_passed=sum(bool(item["answer_check_pass"]) for item in reports),
                combined_passed=passing,
                limitations="Narrow fact/AST heuristics, not domain review or executed code tests",
            )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
