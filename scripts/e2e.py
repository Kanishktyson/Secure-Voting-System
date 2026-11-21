#!/usr/bin/env python3
"""Full end-to-end lifecycle smoke test, runnable with no third-party packages.

    python3 scripts/e2e.py

Starts the real HTTP server in a background thread on an ephemeral port, then
drives sign-in -> vote -> receipt -> verify -> close -> results -> JSON exports
over real sockets. Exits non-zero on the first failed check, so it can gate CI.
"""

from __future__ import annotations

import html as html_lib
import http.client
import json
import re
import sys
import tempfile
import threading
from pathlib import Path
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from secure_vote.app import make_server  # noqa: E402
from secure_vote.config import Config  # noqa: E402
from secure_vote.db import initialize, open_db  # noqa: E402
from secure_vote.service import register_voter  # noqa: E402

CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')
HIDDEN_RE = re.compile(r'<input type="hidden" name="([^"]+)" value="([^"]*)"')


class Client:
    def __init__(self, port: int):
        self.port = port
        self.cookies: dict[str, str] = {}

    def request(self, method: str, path: str, form: dict[str, str] | None = None):
        headers: dict[str, str] = {}
        body = None
        if form is not None:
            body = urlencode(form).encode("ascii")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            headers["Content-Length"] = str(len(body))
        if self.cookies:
            headers["Cookie"] = "; ".join(
                f"{key}={value}" for key, value in self.cookies.items()
            )
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(method, path, body=body, headers=headers)
            response = conn.getresponse()
            payload = response.read().decode("utf-8")
            raw_headers = response.getheaders()
            status = response.status
        finally:
            conn.close()
        for key, value in raw_headers:
            if key.lower() == "set-cookie":
                name, cookie_value = value.split(";", 1)[0].split("=", 1)
                self.cookies[name.strip()] = cookie_value.strip()
        return status, payload

    @staticmethod
    def csrf(body: str) -> str:
        match = CSRF_RE.search(body)
        assert match, "no CSRF token in page"
        return html_lib.unescape(match.group(1))

    def sign_in(self, username: str, password: str) -> None:
        _, page = self.request("GET", "/login")
        status, _ = self.request(
            "POST",
            "/login",
            {"csrf_token": self.csrf(page), "username": username, "password": password},
        )
        assert status == 303, f"sign in failed for {username}: HTTP {status}"


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        config = Config(
            db_path=root / "election.db",
            key_path=root / "server.key",
            secret_key=b"e2e-smoke-key-0123456789-abcdef",
            pbkdf2_iterations=1_000,
            host="127.0.0.1",
            port=0,
            samesite="strict",
        )
        initialize(
            config,
            admin_username="admin",
            admin_password="E2eAdminPass123!",
            initial_state="open",
        )
        with open_db(config) as conn:
            register_voter(conn, config, "e2e_voter", "E2eVoterPass123!")

        server = make_server(config, "127.0.0.1", 0)
        port = server.server_address[1]
        thread = threading.Thread(
            target=server.serve_forever,
            kwargs={"poll_interval": 0.05},
            daemon=True,
        )
        thread.start()
        print(f"[e2e] server on 127.0.0.1:{port}", flush=True)

        try:
            voter = Client(port)
            voter.sign_in("e2e_voter", "E2eVoterPass123!")
            print("[e2e] ✓ sign in", flush=True)

            status, page = voter.request("GET", "/vote")
            assert status == 200 and 'name="choice"' in page
            status, body = voter.request(
                "POST", "/vote", {"csrf_token": voter.csrf(page), "choice": "aurora"}
            )
            assert status == 200 and "Ballot recorded" in body
            fields = {
                html_lib.unescape(k): html_lib.unescape(v)
                for k, v in HIDDEN_RE.findall(body)
            }
            print("[e2e] ✓ ballot cast + receipt issued", flush=True)

            status, body = voter.request("POST", "/verify", fields)
            assert status == 200 and "Verified" in body
            status, board = Client(port).request("GET", "/verify")
            assert fields["tracking_code"] in board and fields["ballot_hash"] in board
            print("[e2e] ✓ receipt verified against public bulletin board", flush=True)

            status, sealed = Client(port).request("GET", "/results")
            assert status == 200 and "Results are sealed" in sealed
            status, sealed_export = Client(port).request(
                "GET", "/export/results.json"
            )
            assert status == 409 and "sealed" in json.loads(sealed_export)["error"].lower()
            print("[e2e] ✓ results and JSON export sealed while open", flush=True)

            admin = Client(port)
            admin.sign_in("admin", "E2eAdminPass123!")
            _, panel = admin.request("GET", "/admin")
            status, _ = admin.request(
                "POST",
                "/admin/transition",
                {"csrf_token": admin.csrf(panel), "target": "closed"},
            )
            assert status == 303
            status, results = Client(port).request("GET", "/results")
            assert status == 200 and "Certified count" in results and "OK" in results
            print("[e2e] ✓ election closed, certified results published", flush=True)

            status, audit_json = Client(port).request("GET", "/export/audit.json")
            audit = json.loads(audit_json)
            assert status == 200 and audit["format"] == "securevote/audit-v1"
            assert audit["count"] > 0
            status, results_json = Client(port).request("GET", "/export/results.json")
            bundle = json.loads(results_json)
            assert status == 200 and bundle["format"] == "securevote/results-v1"
            assert bundle["results"]["total"] == 1
            assert bundle["integrity"]["ok"] and "signature" in bundle["checkpoint"]
            print("[e2e] ✓ results and audit exports validated", flush=True)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    print("[e2e] OK — full lifecycle passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(f"[e2e] FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
