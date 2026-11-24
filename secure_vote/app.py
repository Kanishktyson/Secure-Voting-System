"""HTTP layer: routing, sessions, CSRF, rate limiting and security headers.

Built on ``http.server`` from the standard library so the whole request path is
visible in one file. Requests get their own SQLite connection (SQLite objects
are not shared between threads) and every response carries a strict baseline of
security headers.
"""

from __future__ import annotations

import json
import sys
import threading
import time
import traceback
from collections import deque
from dataclasses import dataclass, field
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, NoReturn
from urllib.parse import parse_qs, urlsplit

from . import views
from .audit import read_audit_log, verify_audit_chain
from .config import Config
from .crypto import random_token, safe_equals
from .db import connect, get_state
from .service import (
    AlreadyVoted,
    ElectionNotOpen,
    InvalidTransition,
    PermissionDenied,
    ValidationError,
    VotingError,
    authenticate,
    bulletin_board,
    candidates_from_db,
    cast_ballot,
    end_session,
    export_audit,
    export_results,
    get_election_info,
    get_session,
    get_stats,
    integrity_summary,
    register_voter,
    set_state,
    start_session,
    tally,
    verify_receipt,
)

SESSION_COOKIE = "svs_session"
ANON_CSRF_COOKIE = "svs_anon"
KNOWN_PATHS = frozenset(
    {
        "/",
        "/login",
        "/register",
        "/logout",
        "/vote",
        "/verify",
        "/results",
        "/audit",
        "/admin",
        "/admin/transition",
        "/static/style.css",
        "/healthz",
        "/export/results.json",
        "/export/audit.json",
    }
)

_STYLE_PATH = Path(__file__).parent / "static" / "style.css"
try:
    STYLE_CSS = _STYLE_PATH.read_text(encoding="utf-8")
except OSError:  # pragma: no cover - only when the package is incomplete
    STYLE_CSS = "/* stylesheet unavailable */"


class RateLimiter:
    """Small in-memory sliding-window limiter for failed sign-in attempts.

    Per-process only. A multi-instance deployment needs a shared store (Redis,
    etc.); see README "Limitations".
    """

    def __init__(self, max_failures: int, window_seconds: int) -> None:
        self.max_failures = max_failures
        self.window = window_seconds
        self._failures: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> deque[float]:
        bucket = self._failures.setdefault(key, deque())
        while bucket and now - bucket[0] > self.window:
            bucket.popleft()
        return bucket

    def allowed(self, key: str) -> bool:
        with self._lock:
            return len(self._prune(key, time.monotonic())) < self.max_failures

    def record_failure(self, key: str) -> None:
        with self._lock:
            self._prune(key, time.monotonic()).append(time.monotonic())

    def reset(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)


@dataclass
class Response:
    status: int = 200
    body: str = ""
    content_type: str = "text/html; charset=utf-8"
    headers: dict[str, str] = field(default_factory=dict)
    set_cookies: list[str] = field(default_factory=list)


def _security_headers(config: Config) -> dict[str, str]:
    directives = [
        "default-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "form-action 'self'",
        "base-uri 'self'",
        "object-src 'none'",
        "script-src 'none'",
    ]
    headers = {
        "Content-Security-Policy": "; ".join(directives),
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Cache-Control": "no-store, max-age=0",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    }
    # The Arena/browser preview embeds the app in an iframe. Strict framing and
    # cross-origin isolation rules are therefore opt-in for real deployments.
    if config.strict_frame_policy:
        headers["Content-Security-Policy"] += "; frame-ancestors 'none'"
        headers["X-Frame-Options"] = "DENY"
        headers["Cross-Origin-Resource-Policy"] = "same-origin"
    return headers


class VotingServer(ThreadingHTTPServer):
    """Threaded HTTP server carrying the immutable app config."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], config: Config) -> None:
        self.config = config
        self.rate_limiter = RateLimiter(
            config.login_max_failures, config.login_window_seconds
        )
        super().__init__(address, Handler)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "SecureVote/1.0"
    sys_version = ""

    # -- cookie helpers ----------------------------------------------------

    def _cookie(self, name: str, value: str, max_age: int) -> str:
        config: Config = self.server.config  # type: ignore[attr-defined]
        mode = config.samesite.lower()
        parts = [f"{name}={value}", "Path=/", f"Max-Age={max_age}", "HttpOnly"]
        if mode == "none":
            # Cross-site embedded previews are third-party contexts: Strict/Lax
            # cookies are not sent at all. None requires Secure; Partitioned
            # (CHIPS) keeps the cookie usable where 3P cookies are blocked.
            parts.extend(["SameSite=None", "Secure", "Partitioned"])
        else:
            parts.append("SameSite=Lax" if mode == "lax" else "SameSite=Strict")
            if config.secure_cookies:
                parts.append("Secure")
        return "; ".join(parts)

    def _session_cookie(self, raw: str) -> str:
        config: Config = self.server.config  # type: ignore[attr-defined]
        max_age = config.session_ttl_seconds if raw else 0
        return self._cookie(SESSION_COOKIE, raw, max_age)

    def _read_cookies(self) -> dict[str, str]:
        jar = SimpleCookie()
        try:
            jar.load(self.headers.get("Cookie", ""))
        except (CookieError, ValueError):
            return {}
        return {name: morsel.value for name, morsel in jar.items()}

    # -- request parsing ---------------------------------------------------

    def _reject_form(self, message: str) -> NoReturn:
        """Reject a form and make sure no unread bytes survive the connection.

        If a body is refused before it is consumed, HTTP/1.1 keep-alive would
        otherwise try to parse those leftover bytes as the next request line.
        Closing the connection is the safe, bounded response (we never drain an
        attacker-declared multi-megabyte body just to be polite).
        """
        self.close_connection = True
        raise ValidationError(message)

    def _read_form(self) -> dict[str, str]:
        config: Config = self.server.config  # type: ignore[attr-defined]
        raw_length = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_length)
        except ValueError:
            self._reject_form("Invalid request length.")
        if length < 0 or length > config.max_body_bytes:
            self._reject_form("Request body is too large.")
        content_type = (
            self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        )
        if content_type != "application/x-www-form-urlencoded":
            self._reject_form("Unsupported form content type.")
        try:
            body = self.rfile.read(length).decode("utf-8")
        except UnicodeDecodeError:
            self._reject_form("Request body must be UTF-8.")
        parsed = parse_qs(body, keep_blank_values=True, max_num_fields=40)
        return {key: values[0] for key, values in parsed.items() if values}

    # -- response ----------------------------------------------------------

    def _send(self, response: Response, extra_cookies: list[str]) -> None:
        config: Config = self.server.config  # type: ignore[attr-defined]
        body = response.body.encode("utf-8")
        self.send_response(response.status)
        self.send_header("Content-Type", response.content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in _security_headers(config).items():
            self.send_header(name, value)
        for name, value in response.headers.items():
            self.send_header(name, value)
        if self.close_connection:
            self.send_header("Connection", "close")
        for header in [*extra_cookies, *response.set_cookies]:
            self.send_header("Set-Cookie", header)
        self.end_headers()
        # HEAD keeps the headers (including Content-Length) of the equivalent
        # GET but never sends a body.
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def log_request(self, code: int | str = "-", size: int | str = "-") -> None:
        """Log method/path/status only — never query strings or form values."""
        path = urlsplit(self.path).path
        sys.stderr.write(f"{self.address_string()} {self.command} {path} {code}\n")

    # -- entry points ------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        self._handle("GET")

    def do_POST(self) -> None:  # noqa: N802 (stdlib naming)
        self._handle("POST")

    def do_HEAD(self) -> None:  # noqa: N802
        self._handle("HEAD")

    def _handle(self, method: str) -> None:
        config: Config = self.server.config  # type: ignore[attr-defined]
        parsed = urlsplit(self.path)
        path = parsed.path.rstrip("/") or "/"
        jar = self._read_cookies()
        raw_session = jar.get(SESSION_COOKIE) or None
        anon = jar.get(ANON_CSRF_COOKIE)
        extra_cookies: list[str] = []
        if not anon:
            anon = random_token(24)
            extra_cookies.append(
                self._cookie(ANON_CSRF_COOKIE, anon, config.session_ttl_seconds)
            )

        conn = None
        ctx = views.ViewContext(session=None, csrf_token=anon, demo=config.demo)
        try:
            conn = connect(config)
            election = get_election_info(conn, config)
            ctx = views.ViewContext(
                session=get_session(conn, config, raw_session),
                csrf_token=anon,
                demo=config.demo,
                election=election,
            )
            if ctx.session:
                # Authenticated forms are bound to the server-side session token.
                ctx = views.ViewContext(
                    session=ctx.session,
                    csrf_token=ctx.session.csrf_token,
                    demo=config.demo,
                    election=election,
                )

            form: dict[str, str] = {}
            if method == "POST":
                form = self._read_form()
                if not safe_equals(form.get("csrf_token", ""), ctx.csrf_token):
                    raise PermissionDenied(
                        "Missing or invalid CSRF token. Reload the page and try again."
                    )

            response = self._route(
                "GET" if method == "HEAD" else method,
                path,
                conn,
                ctx,
                form,
                raw_session,
                anon,
            )
        except PermissionDenied as exc:
            response = Response(403, views.error_page(ctx, 403, str(exc)))
        except ValidationError as exc:
            response = Response(400, views.error_page(ctx, 400, str(exc)))
        except (AlreadyVoted, ElectionNotOpen, InvalidTransition) as exc:
            response = Response(409, views.error_page(ctx, 409, str(exc)))
        except VotingError as exc:
            response = Response(400, views.error_page(ctx, 400, str(exc)))
        except Exception:  # noqa: BLE001 - never leak a traceback to the client
            traceback.print_exc(file=sys.stderr)
            response = Response(
                500,
                views.error_page(ctx, 500, "An unexpected error occurred."),
            )
        finally:
            if conn is not None:
                conn.close()

        self._send(response, extra_cookies)

    # -- routing -----------------------------------------------------------

    def _route(
        self,
        method: str,
        path: str,
        conn: Any,
        ctx: views.ViewContext,
        form: dict[str, str],
        raw_session: str | None,
        anon: str,
    ) -> Response:
        config: Config = self.server.config  # type: ignore[attr-defined]

        if method == "GET" and path == "/static/style.css":
            return Response(body=STYLE_CSS, content_type="text/css; charset=utf-8")

        if method == "GET" and path == "/healthz":
            return Response(
                body='{"status":"ok"}', content_type="application/json"
            )

        if method == "GET" and path in ("/export/results.json", "/export/audit.json"):
            json_type = "application/json; charset=utf-8"
            filename = path.rsplit("/", 1)[-1]
            if path == "/export/results.json":
                try:
                    payload = export_results(conn, config)
                except ElectionNotOpen as exc:
                    return Response(
                        409,
                        json.dumps({"error": str(exc)}),
                        content_type=json_type,
                    )
            else:
                payload = export_audit(conn)
            return Response(
                body=json.dumps(payload, indent=2),
                content_type=json_type,
                headers={"Content-Disposition": f'attachment; filename="{filename}"'},
            )

        if method == "GET" and path == "/":
            return Response(
                body=views.home(ctx, get_stats(conn), integrity_summary(conn, config))
            )

        if path == "/login":
            if method == "GET":
                return Response(body=views.login(ctx))
            if method == "POST":
                return self._post_login(conn, ctx, form, raw_session)

        if path == "/register":
            if method == "GET":
                return Response(body=views.register(ctx))
            if method == "POST":
                return self._post_register(conn, ctx, form, raw_session)

        if path == "/logout" and method == "POST":
            if ctx.session is None:
                return Response(303, "", headers={"Location": "/login"})
            end_session(conn, config, raw_session, ctx.session.username)
            response = Response(303, "", headers={"Location": "/"})
            response.set_cookies.append(self._session_cookie(""))
            return response

        if path == "/vote":
            if ctx.session is None:
                return Response(303, "", headers={"Location": "/login"})
            if method == "GET":
                if ctx.session.has_voted:
                    return Response(body=views.already_voted(ctx))
                return Response(
                    body=views.ballot(ctx, candidates_from_db(conn, config))
                )
            if method == "POST":
                return self._post_vote(conn, ctx, form)

        if path == "/verify":
            if method == "GET":
                return Response(
                    body=views.verify(ctx, bulletin_board(conn, config))
                )
            if method == "POST":
                return self._post_verify(conn, ctx, form)

        if path == "/results" and method == "GET":
            data = tally(conn, config) if get_state(conn) == "closed" else None
            return Response(body=views.results(ctx, data))

        if path == "/audit" and method == "GET":
            ok, _ = verify_audit_chain(conn, config)
            return Response(body=views.audit(ctx, read_audit_log(conn), ok=ok))

        if path == "/admin" and method == "GET":
            if ctx.session is None:
                return Response(303, "", headers={"Location": "/login"})
            _require_admin(ctx)
            return Response(
                body=views.admin(
                    ctx,
                    get_stats(conn),
                    integrity_summary(conn, config),
                    candidates_from_db(conn, config),
                )
            )

        if path == "/admin/transition" and method == "POST":
            if ctx.session is None:
                return Response(303, "", headers={"Location": "/login"})
            _require_admin(ctx)
            return self._post_transition(conn, ctx, form)

        if path in KNOWN_PATHS:
            return Response(405, views.error_page(ctx, 405, "Method not allowed."))
        return Response(404, views.error_page(ctx, 404, "That page does not exist."))

    # -- POST handlers -----------------------------------------------------

    def _post_login(
        self,
        conn: Any,
        ctx: views.ViewContext,
        form: dict[str, str],
        raw_session: str | None,
    ) -> Response:
        config: Config = self.server.config  # type: ignore[attr-defined]
        username = (form.get("username") or "").strip()
        password = form.get("password") or ""
        key = f"{self.client_address[0]}:{username.lower()}"
        limiter: RateLimiter = self.server.rate_limiter  # type: ignore[attr-defined]

        if not limiter.allowed(key):
            return Response(
                429,
                views.error_page(
                    ctx, 429, "Too many failed sign-in attempts. Try again shortly."
                ),
            )
        row = authenticate(conn, config, username, password)
        if row is None:
            limiter.record_failure(key)
            return Response(
                401,
                views.login(
                    ctx,
                    error="Invalid username or password.",
                    username=username,
                ),
            )
        limiter.reset(key)
        raw, _ = start_session(
            conn, config, row["id"], previous_token=raw_session
        )
        response = Response(303, "", headers={"Location": "/vote"})
        response.set_cookies.append(self._session_cookie(raw))
        return response

    def _post_register(
        self,
        conn: Any,
        ctx: views.ViewContext,
        form: dict[str, str],
        raw_session: str | None,
    ) -> Response:
        config: Config = self.server.config  # type: ignore[attr-defined]
        username = form.get("username") or ""
        password = form.get("password") or ""
        try:
            voter_id = register_voter(conn, config, username, password)
        except ValidationError as exc:
            return Response(
                400, views.register(ctx, error=str(exc), username=username)
            )
        raw, _ = start_session(
            conn, config, voter_id, previous_token=raw_session
        )
        response = Response(303, "", headers={"Location": "/vote"})
        response.set_cookies.append(self._session_cookie(raw))
        return response

    def _post_vote(
        self, conn: Any, ctx: views.ViewContext, form: dict[str, str]
    ) -> Response:
        config: Config = self.server.config  # type: ignore[attr-defined]
        try:
            receipt = cast_ballot(conn, config, ctx.session, form.get("choice", ""))
        except AlreadyVoted:
            return Response(409, views.already_voted(ctx))
        except ElectionNotOpen as exc:
            return Response(409, views.error_page(ctx, 409, str(exc)))
        except ValidationError as exc:
            return Response(
                400,
                views.ballot(
                    ctx, candidates_from_db(conn, config), error=str(exc)
                ),
            )
        return Response(body=views.receipt(ctx, receipt))

    def _post_verify(
        self, conn: Any, ctx: views.ViewContext, form: dict[str, str]
    ) -> Response:
        config: Config = self.server.config  # type: ignore[attr-defined]
        mode = form.get("mode", "")
        board = bulletin_board(conn, config)
        if mode == "lookup":
            tracking = (form.get("tracking_code") or "").strip()
            match = next(
                (item for item in board if item["tracking_code"] == tracking), None
            )
            lookup = (
                {
                    "found": True,
                    "published_hash": match["ballot_hash"],
                    "chain_ok": match["chain_ok"],
                }
                if match
                else {"found": False, "verdict": "No ballot with that tracking code was found."}
            )
            return Response(
                body=views.verify(
                    ctx,
                    board,
                    lookup=lookup,
                    form_values={"tracking_code": tracking},
                )
            )
        if mode == "receipt":
            result = verify_receipt(conn, config, form)
            return Response(
                body=views.verify(
                    ctx, board, receipt_result=result, form_values=form
                )
            )
        return Response(400, views.error_page(ctx, 400, "Unknown verification mode."))

    def _post_transition(
        self, conn: Any, ctx: views.ViewContext, form: dict[str, str]
    ) -> Response:
        config: Config = self.server.config  # type: ignore[attr-defined]
        target = form.get("target", "")
        if target not in ("open", "closed"):
            raise ValidationError("Invalid election state.")
        try:
            set_state(conn, config, ctx.session.username, target)
        except InvalidTransition as exc:
            return Response(
                409,
                views.admin(
                    ctx,
                    get_stats(conn),
                    integrity_summary(conn, config),
                    candidates_from_db(conn, config),
                    error=str(exc),
                ),
            )
        return Response(303, "", headers={"Location": "/admin"})


def _require_admin(ctx: views.ViewContext) -> None:
    if ctx.session is None or not ctx.session.is_admin:
        raise PermissionDenied("Administrator access is required.")


def make_server(config: Config, host: str | None = None, port: int | None = None) -> VotingServer:
    """Construct (but do not start) the HTTP server."""
    return VotingServer((host or config.host, port or config.port), config)
