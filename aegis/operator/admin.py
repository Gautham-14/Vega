from __future__ import annotations

from getpass import getpass

from aegis.cli_support import terminal_text

from .common import (
    CLIError,
)


def provision_user(args, *, password_reader=getpass):
    from aegis.control import policy, store

    if args.user_command == "roles":
        return policy.ACTORS
    if args.user_command in {"list", "sessions", "disable", "revoke-sessions", "mfa-enroll"}:
        from aegis.security import auth
        from aegis.storage.database import init_db

        init_db()
        store.init_control()
        if args.user_command == "mfa-enroll":
            result = auth.enroll_mfa(args.actor)
            print("Authenticator seed (save now): " + terminal_text(result["secret"]))
            return {"actor": args.actor, "mfa_enrolled": True, "sessions_revoked": True}
        if args.user_command == "list":
            return auth.account_inventory()
        if args.user_command == "sessions":
            return auth.session_inventory(args.actor)
        return auth.revoke_account(args.actor, disable=args.user_command == "disable")
    password = password_reader("New Aegis password (12-256 characters): ")
    if password != password_reader("Confirm password: "):
        raise CLIError("Passwords do not match")
    if not 12 <= len(password) <= 256:
        raise CLIError("Use a password of 12-256 characters")
    from aegis.security.auth import provision
    from aegis.storage.database import init_db

    init_db()
    store.init_control()
    return provision(args.actor, password, template=args.template)


def backup_command(args, *, password_reader=getpass):
    from aegis.security import recovery

    if args.backup_command == "create":
        password = password_reader("New backup passphrase (16-256 characters): ")
        if password != password_reader("Confirm backup passphrase: "):
            raise CLIError("Backup passphrases do not match")
        return recovery.create_backup(args.file, password)
    password = password_reader("Backup passphrase: ")
    if args.backup_command == "verify":
        return recovery.verify_backup(args.file, password)
    if args.backup_command == "drill":
        return recovery.drill_backup(args.file, args.directory, password)
    return recovery.restore_backup(args.file, args.directory, password)
