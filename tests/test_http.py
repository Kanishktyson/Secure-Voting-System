import html as html_lib
import json
import re
import tempfile
import threading
import unittest
from collections import namedtuple
from http.client import HTTPConnection
from pathlib import Path
from urllib.parse import urlencode

from secure_vote import views
from secure_vote.app import Handler, _security_headers, make_server
from secure_vote.config import Candidate
from secure_vote.db import open_db, set_meta
from secure_vote.demo import seed_demo
from secure_vote.service import set_state

from support import ADMIN_PASSWORD, TEST_PASSWORD, seed, test_config

HttpResult = namedtuple("HttpResult", "status headers body")
CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')
HIDDEN_RE = re.compile(r'<input type="hidden" name="([^"]+)" value="([^"]*)"')


def setUpModule():
    # Keep unittest output readable; request lines are not part of assertions.
    Handler.log_request = lambda self, code="-", size="-": None


def headers_named(result: HttpResult, name: str) -> list[str]:
    return [value for key, value in result.headers if key.lower() == name.lower()]


def csrf(body: str) -> str:
    match = CSRF_RE.search(body)
    assert match, "no CSRF token found in page"
    return html_lib.unescape(match.group(1))


def hidden(body: str) -> dict[str, str]:
    return {
        html_lib.unescape(key): html_lib.unescape(value)
        for key, value in HIDDEN_RE.findall(body)
    }


class Client:
    """Tiny cookie-aware HTTP/1.1 client (no redirects, no external deps)."""

    def __init__(self, port: int):
        self.port = port
        self.cookies: dict[str, str] = {}

    def request(
        self,
        method: str,
        path: str,
        form: dict[str, str] | None = None,
        *,
        raw_body: str | None = None,
        headers: dict[str, str] | None = None,
        content_type: str | None = None,
    ) -> HttpResult:
        request_headers: dict[str, str] = {}
        body = None
        if raw_body is not None:
            body = raw_body.encode("utf-8")
            request_headers["Content-Length"] = str(len(body))
            request_headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif form is not None:
            body = urlencode(form).encode("ascii")
            request_headers["Content-Length"] = str(len(body))
            request_headers["Content-Type"] = "application/x-www-form-urlencoded"
        if self.cookies:
            request_headers["Cookie"] = "; ".join(
                f"{key}={value}" for key, value in self.cookies.items()
            )
        if content_type:
            request_headers["Content-Type"] = content_type
        if headers:
            request_headers.update(headers)

        connection = HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            connection.request(method, path, body=body, headers=request_headers)
            response = connection.getresponse()
            payload = response.read().decode("utf-8")
            raw_headers = response.getheaders()
            status = response.status
        finally:
            connection.close()

        for key, value in raw_headers:
            if key.lower() != "set-cookie":
                continue
            pair = value.split(";", 1)[0]
            if "=" not in pair:
                continue
            name, cookie_value = pair.split("=", 1)
            name, cookie_value = name.strip(), cookie_value.strip()
            if "Max-Age=0" in value:
                self.cookies.pop(name, None)
            else:
                self.cookies[name] = cookie_value
        return HttpResult(status, raw_headers, payload)

    def sign_in(self, username: str, password: str) -> None:
        page = self.request("GET", "/login")
        result = self.request(
            "POST",
            "/login",
            {
                "csrf_token": csrf(page.body),
                "username": username,
                "password": password,
            },
        )
        assert result.status == 303, f"sign in failed: {result.status}"


def start_server(config):
    server = make_server(config, "127.0.0.1", 0)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
    )
    thread.start()
    return server, thread, server.server_address[1]


def stop_server(server, thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


class HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.config = test_config(Path(cls.tmp.name), demo=True)
        seed(cls.config, voters=("seed_voter",))
        cls.server, cls.thread, cls.port = start_server(cls.config)

    @classmethod
    def tearDownClass(cls):
        stop_server(cls.server, cls.thread)
        cls.tmp.cleanup()

    def client(self) -> Client:
        return Client(self.port)

    # -- baseline ----------------------------------------------------------

    def test_home_page_and_security_headers(self):
        result = self.client().request("GET", "/")
        self.assertEqual(result.status, 200)
        self.assertIn("SecureVote", result.body)
        self.assertIn("default-src 'self'", headers_named(result, "Content-Security-Policy")[0])
        self.assertEqual(headers_named(result, "X-Content-Type-Options"), ["nosniff"])
        self.assertIn("no-store", headers_named(result, "Cache-Control")[0])
        self.assertEqual(headers_named(result, "X-Frame-Options"), [])
        self.assertTrue(int(headers_named(result, "Content-Length")[0]) > 0)

    def test_healthz_404_and_method_not_allowed(self):
        client = self.client()
        self.assertEqual(client.request("GET", "/healthz").status, 200)
        self.assertEqual(client.request("GET", "/does-not-exist").status, 404)
        page = client.request("GET", "/login")
        not_allowed = client.request("POST", "/", {"csrf_token": csrf(page.body)})
        self.assertEqual(not_allowed.status, 405)

    def test_accessibility_markers_and_unique_ids(self):
        client = self.client()
        home = client.request("GET", "/")
        self.assertIn('class="skip-link"', home.body)
        self.assertIn('id="main-content"', home.body)
        self.assertIn('aria-current="page"', home.body)
        self.assertIn('name="description"', home.body)

        verify = client.request("GET", "/verify")
        self.assertIn('for="vr-nonce"', verify.body)
        self.assertIn('id="vr-nonce"', verify.body)
        ids = re.findall(r' id="([^"]+)"', verify.body)
        self.assertEqual(len(ids), len(set(ids)), "duplicate HTML ids found")

    def test_head_mirrors_get_without_body(self):
        client = self.client()
        head = client.request("HEAD", "/")
        get = client.request("GET", "/")
        self.assertEqual(head.status, 200)
        self.assertEqual(head.body, "")
        self.assertEqual(
            headers_named(head, "Content-Length"),
            headers_named(get, "Content-Length"),
        )

    def test_static_stylesheet(self):
        result = self.client().request("GET", "/static/style.css")
        self.assertEqual(result.status, 200)
        self.assertIn("text/css", headers_named(result, "Content-Type")[0])
        self.assertIn("--accent", result.body)

    def test_csrf_is_required_on_every_post(self):
        client = self.client()
        client.request("GET", "/login")
        result = client.request(
            "POST", "/login", {"username": "admin", "password": ADMIN_PASSWORD}
        )
        self.assertEqual(result.status, 403)

    def test_bad_content_type_and_oversized_body(self):
        client = self.client()
        client.request("GET", "/login")
        wrong = client.request(
            "POST", "/login", raw_body="hello", content_type="text/plain"
        )
        self.assertEqual(wrong.status, 400)
        huge = client.request(
            "POST", "/login", raw_body="x" * (self.config.max_body_bytes + 100)
        )
        self.assertEqual(huge.status, 400)

    def test_login_rate_limiting(self):
        client = self.client()
        page = client.request("GET", "/login")
        token = csrf(page.body)
        statuses = []
        for _ in range(self.config.login_max_failures + 2):
            result = client.request(
                "POST",
                "/login",
                {
                    "csrf_token": token,
                    "username": "bruteforce_target",
                    "password": "WrongPass123!",
                },
            )
            statuses.append(result.status)
        self.assertEqual(statuses[:5], [401] * 5)
        self.assertIn(429, statuses[5:])

    # -- sessions ----------------------------------------------------------

    def test_login_sets_hardened_cookie_and_hashed_session(self):
        client = self.client()
        page = client.request("GET", "/login")
        result = client.request(
            "POST",
            "/login",
            {
                "csrf_token": csrf(page.body),
                "username": "admin",
                "password": ADMIN_PASSWORD,
            },
        )
        self.assertEqual(result.status, 303)
        self.assertEqual(headers_named(result, "Location"), ["/vote"])
        session_cookie = next(
            v for v in headers_named(result, "Set-Cookie") if v.startswith("svs_session=")
        )
        self.assertIn("HttpOnly", session_cookie)
        self.assertIn("SameSite=Strict", session_cookie)
        self.assertNotIn("Secure", session_cookie)
        raw = session_cookie.split(";", 1)[0].split("=", 1)[1]
        with open_db(self.config) as conn:
            stored = [r["token_hash"] for r in conn.execute("SELECT token_hash FROM sessions")]
            self.assertNotIn(raw, stored)

    def test_logout_revokes_session(self):
        client = self.client()
        client.sign_in("admin", ADMIN_PASSWORD)
        vote_page = client.request("GET", "/vote")
        self.assertEqual(vote_page.status, 200)
        result = client.request("POST", "/logout", {"csrf_token": csrf(vote_page.body)})
        self.assertEqual(result.status, 303)
        self.assertNotIn("svs_session", client.cookies)
        self.assertEqual(client.request("GET", "/vote").status, 303)

    # -- registration, voting, verification --------------------------------

    def test_register_cast_verify_flow(self):
        client = self.client()
        page = client.request("GET", "/register")
        result = client.request(
            "POST",
            "/register",
            {
                "csrf_token": csrf(page.body),
                "username": "flow_voter",
                "password": TEST_PASSWORD,
            },
        )
        self.assertEqual(result.status, 303)

        ballot_page = client.request("GET", "/vote")
        self.assertIn("Aurora Alliance", ballot_page.body)
        self.assertIn('name="choice"', ballot_page.body)

        invalid = client.request(
            "POST",
            "/vote",
            {"csrf_token": csrf(ballot_page.body), "choice": "not-an-option"},
        )
        self.assertEqual(invalid.status, 400)

        cast = client.request(
            "POST",
            "/vote",
            {"csrf_token": csrf(ballot_page.body), "choice": "aurora"},
        )
        self.assertEqual(cast.status, 200)
        self.assertIn("Ballot recorded", cast.body)
        fields = hidden(cast.body)
        self.assertIn("tracking_code", fields)
        self.assertEqual(fields["mode"], "receipt")
        self.assertEqual(fields["choice"], "aurora")

        verified = client.request("POST", "/verify", fields)
        self.assertEqual(verified.status, 200)
        self.assertIn("Verified", verified.body)

        board = client.request("GET", "/verify")
        self.assertIn(fields["tracking_code"], board.body)
        self.assertIn(fields["ballot_hash"], board.body)

        # A second ballot is rejected, and /vote explains why.
        again = client.request(
            "POST", "/vote", {"csrf_token": csrf(cast.body), "choice": "cascade"}
        )
        self.assertEqual(again.status, 409)
        self.assertIn("already", client.request("GET", "/vote").body.lower())

    def test_registration_rejects_weak_password_and_duplicates(self):
        client = self.client()
        page = client.request("GET", "/register")
        weak = client.request(
            "POST",
            "/register",
            {"csrf_token": csrf(page.body), "username": "weak_user", "password": "short"},
        )
        self.assertEqual(weak.status, 400)
        self.assertIn("notice-danger", weak.body)
        self.assertIn("12", weak.body)

        duplicate = client.request(
            "POST",
            "/register",
            {"csrf_token": csrf(page.body), "username": "admin", "password": TEST_PASSWORD},
        )
        self.assertEqual(duplicate.status, 400)
        self.assertIn("already registered", duplicate.body.lower())

    def test_verify_rejects_bogus_receipt(self):
        client = self.client()
        page = client.request("GET", "/verify")
        result = client.request(
            "POST",
            "/verify",
            {
                "csrf_token": csrf(page.body),
                "mode": "lookup",
                "tracking_code": "definitely-not-present",
            },
        )
        self.assertEqual(result.status, 200)
        self.assertIn("No ballot", result.body)

    def test_audit_log_is_public(self):
        result = self.client().request("GET", "/audit")
        self.assertEqual(result.status, 200)
        self.assertIn("voter_registered", result.body)
        self.assertIn("intact", result.body.lower())

    def test_admin_pages_require_admin_role(self):
        voter = self.client()
        page = voter.request("GET", "/register")
        voter.request(
            "POST",
            "/register",
            {"csrf_token": csrf(page.body), "username": "plain_voter", "password": TEST_PASSWORD},
        )
        self.assertEqual(voter.request("GET", "/admin").status, 403)
        self.assertEqual(self.client().request("GET", "/admin").status, 303)

        admin = self.client()
        admin.sign_in("admin", ADMIN_PASSWORD)
        self.assertEqual(admin.request("GET", "/admin").status, 200)

    def test_results_sealed_before_close(self):
        result = self.client().request("GET", "/results")
        self.assertIn("Results are sealed", result.body)

    # -- view-level escaping ----------------------------------------------

    def test_candidate_labels_are_html_escaped(self):
        malicious = (Candidate("x", "<script>alert(1)</script>", "<img src=x>"),)
        config = test_config(Path(self.tmp.name) / "escaping", candidates=malicious)
        ctx = views.ViewContext(session=None, csrf_token="token", demo=False)
        rendered = views.ballot(ctx, malicious)
        self.assertNotIn("<script>", rendered)
        self.assertNotIn("<img src=x>", rendered)
        self.assertIn("&lt;script&gt;", rendered)
        self.assertIn("&lt;img src=x&gt;", rendered)

    def test_embed_safe_cookies_for_iframe_previews(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        config = test_config(Path(tmp.name) / "embedded", samesite="none")
        seed(config, voters=())
        server, thread, port = start_server(config)
        try:
            result = Client(port).request("GET", "/login")
            cookie = headers_named(result, "Set-Cookie")[0]
            self.assertIn("SameSite=None", cookie)
            self.assertIn("Secure", cookie)
            self.assertIn("Partitioned", cookie)
            self.assertIn("HttpOnly", cookie)
        finally:
            stop_server(server, thread)

    def test_strict_frame_policy_is_opt_in(self):
        strict = test_config(Path(self.tmp.name) / "strict", strict_frame_policy=True)
        headers = _security_headers(strict)
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertNotIn("X-Frame-Options", _security_headers(self.config))


class ElectionClosingTests(unittest.TestCase):
    """Isolated server so closing the election cannot affect other tests."""

    def test_close_publishes_verified_results(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        config = test_config(Path(tmp.name) / "closing")
        seed(config, voters=())
        server = None
        try:
            server, thread, port = start_server(config)
            voter = Client(port)
            page = voter.request("GET", "/register")
            voter.request(
                "POST",
                "/register",
                {"csrf_token": csrf(page.body), "username": "first_voter", "password": TEST_PASSWORD},
            )
            ballot = voter.request("GET", "/vote")
            voter.request(
                "POST",
                "/vote",
                {"csrf_token": csrf(ballot.body), "choice": "borealis"},
            )

            sealed = voter.request("GET", "/results")
            self.assertIn("Results are sealed", sealed.body)

            admin = Client(port)
            admin.sign_in("admin", ADMIN_PASSWORD)
            panel = admin.request("GET", "/admin")
            self.assertIn("Voting open", panel.body)
            transition = admin.request(
                "POST",
                "/admin/transition",
                {"csrf_token": csrf(panel.body), "target": "closed"},
            )
            self.assertEqual(transition.status, 303)

            results = voter.request("GET", "/results")
            self.assertEqual(results.status, 200)
            self.assertIn("Borealis Coalition", results.body)
            self.assertIn("Integrity checks", results.body)
            self.assertIn("OK", results.body)
            self.assertIn('aria-label="Votes for', results.body)
        finally:
            if server is not None:
                stop_server(server, thread)


class ExportHttpTests(unittest.TestCase):
    """Browser-facing, dependency-free JSON exports on an isolated server."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = test_config(Path(self.tmp.name))
        seed(self.config, voters=("alice",))
        self.server, self.thread, self.port = start_server(self.config)
        self.addCleanup(stop_server, self.server, self.thread)
        self.client = Client(self.port)

    def get(self, path):
        result = self.client.request("GET", path)
        return result.body, result.status, dict(result.headers)

    def close_election(self):
        with open_db(self.config) as conn:
            set_state(conn, self.config, "admin", "closed")

    def test_civic_ledger_design_is_local_and_accessible(self):
        body, status, _ = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn('class="status-strip"', body)
        self.assertIn("The civic ledger", body)
        self.assertNotIn("<script", body.lower())
        self.assertNotIn(" style=", body)
        self.assertIn('href="/static/style.css"', body)

        login, status, _ = self.get("/login")
        self.assertEqual(status, 200)
        self.assertIn('class="journey"', login)
        self.assertIn('aria-current="step"', login)

        css, status, _ = self.get("/static/style.css")
        self.assertEqual(status, 200)
        self.assertIn("--accent", css)
        self.assertIn("Georgia", css)
        self.assertIn("repeating-linear-gradient", css)
        self.assertIn("@media print", css)

    def test_json_exports_are_public_and_well_formed(self):
        body, status, headers = self.get("/export/audit.json")
        self.assertEqual(status, 200)
        self.assertIn("application/json", headers["Content-Type"])
        self.assertIn('attachment; filename="audit.json"', headers["Content-Disposition"])
        audit = json.loads(body)
        self.assertEqual(audit["format"], "securevote/audit-v1")
        self.assertGreater(audit["count"], 0)

        # Results are sealed until close; then the full signed bundle appears.
        body, status, _ = self.get("/export/results.json")
        self.assertEqual(status, 409)
        self.assertIn("sealed", json.loads(body)["error"].lower())

        self.close_election()
        body, status, headers = self.get("/export/results.json")
        self.assertEqual(status, 200)
        self.assertIn(
            'attachment; filename="results.json"',
            headers["Content-Disposition"],
        )
        payload = json.loads(body)
        self.assertEqual(payload["format"], "securevote/results-v1")
        self.assertEqual(payload["election"]["state"], "closed")
        self.assertTrue(payload["integrity"]["ok"])

    def test_custom_election_title_is_rendered(self):
        with open_db(self.config) as conn:
            set_meta(conn, "election_title", "Campus Council 2026")
        body, status, _ = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn("Campus Council 2026", body)
        body, status, _ = self.get("/export/results.json")
        self.assertEqual(status, 409)

    def test_export_links_are_rendered(self):
        body, status, _ = self.get("/audit")
        self.assertEqual(status, 200)
        self.assertIn('href="/export/audit.json" download', body)
        self.close_election()
        body, status, _ = self.get("/results")
        self.assertEqual(status, 200)
        self.assertIn('href="/export/results.json" download', body)
