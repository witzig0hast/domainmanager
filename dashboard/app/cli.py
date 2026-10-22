"""Helpers, run inside the image:
    python -m app.cli hash-password [OUTFILE]
    python -m app.cli totp-secret [OUTFILE] [USER]
With OUTFILE the result is written there instead of stdout (prompts would otherwise end up in a redirect)."""
from __future__ import annotations

import getpass
import os
import sys

import pyotp

from .auth import hash_password


def _emit(value: str, path: str | None) -> None:
    if not path:
        print(value)
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(value)
    print(f"Gespeichert in {path}")


def main() -> None:
    args = sys.argv[1:]
    cmd = args[0] if args else ""
    out = args[1] if len(args) > 1 else None
    if cmd == "hash-password":
        pw = getpass.getpass("Neues Passwort (min. 12 Zeichen): ")
        if len(pw) < 12:
            sys.exit("Zu kurz.")
        if pw != getpass.getpass("Wiederholen: "):
            sys.exit("Stimmt nicht überein.")
        _emit(hash_password(pw), out)
    elif cmd == "totp-secret":
        user = args[2] if len(args) > 2 else os.environ.get("ADMIN_USER", "admin")
        secret = pyotp.random_base32()
        print("In die Authenticator-App eintragen – Secret (manuell):", secret, file=sys.stderr)
        print("oder diese URI als QR-Code (z.B. `qrencode -t ansiutf8 '<URI>'`):", file=sys.stderr)
        print(pyotp.TOTP(secret).provisioning_uri(name=user, issuer_name="DomainManager"), file=sys.stderr)
        _emit(secret, out)
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
