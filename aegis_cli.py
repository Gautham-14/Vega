#!/usr/bin/env python3
"""
Aegis Command Line Interface
Interact with the Aegis sovereign operations runtime.
"""
import argparse
import json
import urllib.request
import urllib.error
import sys

BASE_URL = "http://127.0.0.1:8000/api"

def api_call(endpoint, method="GET", data=None, persona="operator"):
    url = f"{BASE_URL}{endpoint}"
    headers = {"X-Aegis-Actor": persona, "Content-Type": "application/json"}
    
    payload = None
    if data is not None:
        payload = json.dumps(data).encode("utf-8")
        
    req = urllib.request.Request(url, data=payload, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        print(f"Error [{e.code}]: {e.reason}")
        try:
            print(json.dumps(json.loads(e.read().decode()), indent=2))
        except:
            print(e.read().decode())
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"Connection error: Make sure Aegis is running at {BASE_URL}")
        sys.exit(1)


def cmd_state(args):
    print(f"--- Workspace State (Persona: {args.persona}) ---")
    state = api_call("/coding/state", persona=args.persona)
    print(json.dumps(state, indent=2))


def cmd_demo_prepare(args):
    res = api_call("/control/demo/prepare", method="POST", persona=args.persona)
    print("Demo prepared:", json.dumps(res, indent=2))


def cmd_demo_activate(args):
    res = api_call("/control/demo/activate", method="POST", persona=args.persona)
    print("Demo activated:", json.dumps(res, indent=2))


def cmd_approve(args):
    data = {"decision": args.decision.upper()}
    res = api_call(f"/control/approvals/{args.approval_id}/decide", method="POST", data=data, persona=args.persona)
    print("Approval decision recorded:", json.dumps(res, indent=2))


def cmd_coding_fixture(args):
    res = api_call("/coding/demo/repository", method="POST", persona=args.persona)
    print("Coding fixture imported:", json.dumps(res, indent=2))


def cmd_coding_capsule(args):
    data = {"provider": args.provider}
    res = api_call("/coding/capsules", method="POST", data=data, persona=args.persona)
    print("Coding capsule requested:", json.dumps(res, indent=2))


def cmd_coding_lease(args):
    data = {
        "repository_id": args.repo,
        "capsule_id": args.capsule,
        "mode": args.mode.upper(),
        "minutes": args.minutes,
        "allow_export": args.export,
        "user": args.recipient
    }
    res = api_call("/coding/leases", method="POST", data=data, persona=args.persona)
    print("Coding lease issued:", json.dumps(res, indent=2))


def cmd_coding_run(args):
    data = {
        "lease_id": args.lease,
        "prompt": args.prompt,
        "purpose": args.purpose
    }
    res = api_call("/coding/tasks", method="POST", data=data, persona=args.persona)
    print("Coding task executed:", json.dumps(res, indent=2))


def main():
    parser = argparse.ArgumentParser(description="Aegis CLI - Operate Aegis from the terminal")
    parser.add_argument("--persona", default="operator", help="Active persona (e.g., operator, model-custodian, security-officer, data-owner)")
    
    subparsers = parser.add_subparsers(dest="command", required=True)

    # State
    subparsers.add_parser("state", help="Get current coding workspace state")

    # Control Plane (Industrial)
    parser_demo_prep = subparsers.add_parser("demo-prepare", help="Prepare control plane demo")
    parser_demo_act = subparsers.add_parser("demo-activate", help="Activate control plane demo")
    
    parser_approve = subparsers.add_parser("approve", help="Approve or reject a request")
    parser_approve.add_argument("approval_id", help="The ID of the approval")
    parser_approve.add_argument("decision", choices=["approve", "reject"], help="Decision")

    # Coding Workbench
    parser_fixture = subparsers.add_parser("coding-fixture", help="Import coding demo fixture")
    
    parser_capsule = subparsers.add_parser("coding-capsule", help="Request coding capsule")
    parser_capsule.add_argument("--provider", default="reference", choices=["reference", "ollama"], help="Provider")
    
    parser_lease = subparsers.add_parser("coding-lease", help="Issue a coding lease")
    parser_lease.add_argument("--repo", required=True, help="Repository ID")
    parser_lease.add_argument("--capsule", required=True, help="Capsule ID")
    parser_lease.add_argument("--mode", default="PLAN", choices=["ASK", "PLAN", "EXECUTE"], help="Execution mode")
    parser_lease.add_argument("--recipient", default="operator", help="Recipient persona")
    parser_lease.add_argument("--minutes", type=int, default=15, help="Duration in minutes")
    parser_lease.add_argument("--export", action="store_true", help="Allow patch export")

    parser_run = subparsers.add_parser("coding-run", help="Run a coding task")
    parser_run.add_argument("--lease", required=True, help="Lease ID")
    parser_run.add_argument("--prompt", required=True, help="Task prompt")
    parser_run.add_argument("--purpose", required=True, help="Task purpose")

    args = parser.parse_args()

    # Call the appropriate function
    globals()[f"cmd_{args.command.replace('-', '_')}"](args)

if __name__ == "__main__":
    main()
