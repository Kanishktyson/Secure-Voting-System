"""HTML rendering.

Every dynamic value passes through :func:`esc` before interpolation. There is
no JavaScript in the application and the CSP forbids inline scripts, so the
output is safe by construction rather than by convention.
"""

from __future__ import annotations

from dataclasses import dataclass
from html import escape
from typing import Any, Iterable

from .config import Candidate, DEMO_ADMIN, DEMO_VOTERS
from .service import SessionContext


def esc(value: Any) -> str:
    """Escape a value for HTML text or a quoted attribute."""
    return escape("" if value is None else str(value), quote=True)


@dataclass(frozen=True)
class ViewContext:
    session: SessionContext | None
    csrf_token: str
    demo: bool = False
    election: dict[str, Any] | None = None


def _election(ctx: ViewContext) -> dict[str, Any]:
    """Always returns a safe dictionary, even for hand-built test contexts."""
    return ctx.election or {
        "title": "General Election",
        "description": "",
        "state": "open",
        "candidates": [],
    }


def csrf_input(ctx: ViewContext) -> str:
    return f'<input type="hidden" name="csrf_token" value="{esc(ctx.csrf_token)}">'


def _badge(label: str, tone: str = "neutral") -> str:
    return f'<span class="badge badge-{esc(tone)}">{esc(label)}</span>'


def state_badge(state: str) -> str:
    tones = {"setup": "neutral", "open": "ok", "closed": "muted"}
    labels = {"setup": "Not open yet", "open": "Voting open", "closed": "Voting closed"}
    return _badge(labels.get(state, state), tones.get(state, "neutral"))


def _nav(ctx: ViewContext, active: str) -> str:
    links = [
        ("", "/", "Overview"),
        ("vote", "/vote", "Vote"),
        ("verify", "/verify", "Verify"),
        ("results", "/results", "Results"),
        ("audit", "/audit", "Audit log"),
    ]
    if ctx.session and ctx.session.is_admin:
        links.append(("admin", "/admin", "Admin"))
    items = "".join(
        f'<a class="nav-link{" active" if key == active else ""}" href="{href}"'
        + (' aria-current="page"' if key == active else "")
        + f'>{esc(label)}</a>'
        for key, href, label in links
    )

    if ctx.session:
        who = esc(ctx.session.username)
        role = "admin" if ctx.session.is_admin else "voter"
        account = (
            f'<span class="account"><span class="account-name">{who}</span>'
            f'<span class="account-role">{role}</span></span>'
            '<form method="post" action="/logout" class="inline-form">'
            f'{csrf_input(ctx)}<button class="btn btn-ghost btn-sm" type="submit">Sign out</button>'
            "</form>"
        )
    else:
        account = (
            '<a class="btn btn-ghost btn-sm" href="/login">Sign in</a>'
            '<a class="btn btn-primary btn-sm" href="/register">Register</a>'
        )
    return (
        '<header class="topbar"><div class="shell topbar-inner">'
        '<a class="brand" href="/"><span class="brand-mark">◆</span>'
        '<span>Secure<span class="brand-accent">Vote</span></span></a>'
        f'<nav class="nav" aria-label="Main navigation">{items}</nav>'
        f'<div class="account-area">{account}</div>'
        "</div></header>"
    )


def page(
    title: str,
    content: str,
    ctx: ViewContext,
    *,
    active: str = "",
    subtitle: str = "",
) -> str:
    head = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{esc(title)} · {esc(_election(ctx)['title'])} · SecureVote</title>"
        '<meta name="description" content="A verifiable, anonymous electronic voting prototype.">'
        '<link rel="stylesheet" href="/static/style.css">'
        '<meta name="color-scheme" content="light">'
        "</head><body>"
        '<a class="skip-link" href="#main-content">Skip to main content</a>'
    )
    hero = ""
    if subtitle:
        hero = (
            '<section class="page-head"><div class="shell">'
            f'<div class="page-eyebrow">{esc(_election(ctx)["title"])}</div>'
            f'<h1>{esc(title)}</h1><p>{esc(subtitle)}</p>'
            "</div></section>"
        )
    footer = (
        '<footer class="footer"><div class="shell footer-inner">'
        "<span>SecureVote · an educational, verifiable voting prototype</span>"
        '<span>Standard library only · <a href="/audit">public audit log</a></span>'
        "</div></footer>"
    )
    return (
        head
        + _nav(ctx, active)
        + hero
        + f'<main id="main-content" class="shell main" tabindex="-1">{content}</main>'
        + footer
        + "</body></html>"
    )


def _card(title: str, body: str, *, extra_class: str = "") -> str:
    return (
        f'<section class="card {extra_class}">'
        f"<h2>{esc(title)}</h2>{body}</section>"
    )


def _stat(label: str, value: Any, hint: str = "") -> str:
    hint_html = f'<span class="stat-hint">{esc(hint)}</span>' if hint else ""
    return (
        '<div class="stat">'
        f'<span class="stat-value">{esc(value)}</span>'
        f'<span class="stat-label">{esc(label)}</span>{hint_html}</div>'
    )


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------


def home(
    ctx: ViewContext, stats: dict[str, Any], integrity: dict[str, Any]
) -> str:
    state = str(stats["state"])
    if state == "open":
        cta = '<a class="btn btn-primary" href="/vote">Cast your ballot</a>'
    elif state == "closed":
        cta = '<a class="btn btn-primary" href="/results">View results</a>'
    else:
        cta = '<a class="btn btn-primary" href="/login">Sign in</a>'

    integrity_badge = (
        _badge("Integrity verified", "ok")
        if integrity["ok"]
        else _badge("Integrity alert", "danger")
    )
    problems = ""
    if not integrity["ok"]:
        all_problems = integrity["ballot_problems"] + integrity["audit_problems"]
        problems = (
            '<div class="notice notice-danger"><strong>Integrity check failed.</strong>'
            "<ul>" + "".join(f"<li>{esc(p)}</li>" for p in all_problems) + "</ul></div>"
        )

    election = _election(ctx)
    election_line = (
        f'<div class="election-name">{esc(election["title"])}</div>'
        if election.get("title")
        else ""
    )
    election_copy = esc(election.get("description") or "")

    stats_grid = (
        '<div class="stats">'
        + _stat("Registered voters", stats["eligible"], "excluding the election admin")
        + _stat("Ballots cast", stats["ballots"], "anonymous, unlinkable records")
        + _stat("Election state", state, "setup / open / closed")
        + "</div>"
    )

    body = (
        '<section class="hero"><div class="shell hero-inner">'
        '<div class="hero-copy">'
        '<div class="eyebrow">Verifiable · Anonymous · Auditable</div>'
        + election_line
        + "<h1>A voting system you can actually check.</h1>"
        + (f"<p>{election_copy}</p>" if election_copy else "")
        + "<p>Every ballot is anonymous, cryptographically committed, and linked "
        "into a tamper-evident chain. You get a private receipt and can confirm "
        "your vote was recorded without revealing how you voted.</p>"
        f'<div class="hero-actions">{cta}<a class="btn btn-outline" href="/verify">Verify a ballot</a></div>'
        "</div>"
        '<div class="hero-panel">'
        f'<div class="panel-row"><span>Election status</span>{state_badge(state)}</div>'
        f'<div class="panel-row"><span>Ballot chain</span>{_badge("OK" if integrity["ballot_chain_ok"] else "FAILED", "ok" if integrity["ballot_chain_ok"] else "danger")}</div>'
        f'<div class="panel-row"><span>Audit chain</span>{_badge("OK" if integrity["audit_chain_ok"] else "FAILED", "ok" if integrity["audit_chain_ok"] else "danger")}</div>'
        f'<div class="panel-row"><span>Ballot options</span><span class="mono">{len(election.get("candidates", []))}</span></div>'
        '<div class="panel-row"><span>Runtime dependencies</span><span class="mono">0</span></div>'
        f'<div class="panel-foot">{integrity_badge}</div>'
        "</div></div></section>"
        f'<div class="shell">{problems}{stats_grid}</div>'
        '<section class="shell steps">'
        + _card(
            "1 · Register & sign in",
            "<p>Salted PBKDF2 password hashes, opaque server-side sessions and "
            "CSRF tokens on every state change.</p>",
        )
        + _card(
            "2 · Cast one secret ballot",
            "<p>Ballots are stored with no voter identifier. A conditional update "
            "inside a serialisable transaction makes double voting impossible, "
            "even under concurrent requests.</p>",
        )
        + _card(
            "3 · Verify the count",
            "<p>Your receipt lets you recompute your ballot's public commitment. "
            "The bulletin board, hash chain and audit log let anyone check the "
            "election after it closes.</p>",
        )
        + "</section>"
        '<section class="shell"><div class="notice notice-info">'
        "<strong>Scope note.</strong> This is an educational prototype, not "
        "production election software. It guarantees integrity and ballot "
        "secrecy against database readers, but the server is still trusted with "
        "vote contents. See the README for the full threat model."
        "</div></section>"
    )
    return page("Overview", body, ctx, active="")


def login(
    ctx: ViewContext, *, error: str = "", username: str = ""
) -> str:
    error_html = (
        f'<div class="notice notice-danger">{esc(error)}</div>' if error else ""
    )
    demo_html = ""
    if ctx.demo:
        voters = ", ".join(name for name, _ in DEMO_VOTERS)
        demo_html = (
            '<div class="notice notice-info demo-credentials">'
            "<strong>Demo accounts</strong>"
            f"<p>Voters: <span class='mono'>{esc(voters)}</span> · password "
            f"<span class='mono'>{esc(DEMO_VOTERS[0][1])}</span></p>"
            f"<p>Admin: <span class='mono'>{esc(DEMO_ADMIN[0])}</span> · password "
            f"<span class='mono'>{esc(DEMO_ADMIN[1])}</span></p>"
            "</div>"
        )
    form = (
        f'<form method="post" action="/login" class="form">{csrf_input(ctx)}'
        '<label for="username">Username</label>'
        f'<input id="username" name="username" autocomplete="username" required '
        f'value="{esc(username)}" maxlength="32">'
        '<label for="password">Password</label>'
        '<input id="password" name="password" type="password" '
        'autocomplete="current-password" required maxlength="128">'
        '<button class="btn btn-primary btn-block" type="submit">Sign in</button>'
        "</form>"
        '<p class="muted">No account yet? <a href="/register">Register as a voter</a>.</p>'
    )
    return page(
        "Sign in",
        f'<div class="narrow">{error_html}{_card("Welcome back", form)}{demo_html}</div>',
        ctx,
        active="login",
        subtitle="Authenticate to cast a ballot or administer the election.",
    )


def register(ctx: ViewContext, *, error: str = "", username: str = "") -> str:
    error_html = (
        f'<div class="notice notice-danger">{esc(error)}</div>' if error else ""
    )
    form = (
        f'<form method="post" action="/register" class="form">{csrf_input(ctx)}'
        '<label for="username">Username</label>'
        f'<input id="username" name="username" autocomplete="username" required '
        f'value="{esc(username)}" maxlength="32" '
        'pattern="[a-z0-9_]{3,32}" title="3-32 lowercase letters, digits or underscore">'
        '<label for="password">Password</label>'
        '<input id="password" name="password" type="password" '
        'autocomplete="new-password" required minlength="12" maxlength="128">'
        '<p class="field-hint">At least 12 characters, including a letter and a digit.</p>'
        '<button class="btn btn-primary btn-block" type="submit">Create account</button>'
        "</form>"
        '<p class="muted">Already registered? <a href="/login">Sign in</a>.</p>'
    )
    return page(
        "Register",
        f'<div class="narrow">{error_html}{_card("Create a voter account", form)}</div>',
        ctx,
        active="register",
        subtitle="One account, one ballot. Registration is open while the election is open.",
    )


def ballot(
    ctx: ViewContext,
    candidates: Iterable[Candidate],
    *,
    error: str = "",
) -> str:
    error_html = (
        f'<div class="notice notice-danger">{esc(error)}</div>' if error else ""
    )
    options = "".join(
        '<label class="option">'
        f'<input type="radio" name="choice" value="{esc(c.key)}" required>'
        '<span class="option-body">'
        f'<span class="option-label">{esc(c.label)}</span>'
        f'<span class="option-desc">{esc(c.description)}</span>'
        "</span></label>"
        for c in candidates
    )
    form = (
        f'<form method="post" action="/vote" class="form">{csrf_input(ctx)}'
        f'<fieldset class="options"><legend>Choose one option</legend>{options}</fieldset>'
        '<div class="notice notice-warning">Your choice is final. Once cast, a '
        "ballot cannot be changed or withdrawn, and the server deliberately "
        "forgets the link between you and your ballot.</div>"
        '<button class="btn btn-primary btn-block" type="submit">Cast ballot</button>'
        "</form>"
    )
    return page(
        "Ballot",
        f'<div class="narrow">{error_html}{_card("Official ballot", form)}</div>',
        ctx,
        active="vote",
        subtitle="Mark one option. Your selection is never written alongside your identity.",
    )


def already_voted(ctx: ViewContext) -> str:
    body = (
        '<div class="notice notice-info">'
        "<strong>Your ballot has already been recorded.</strong> Each account may "
        "vote exactly once. If you saved your receipt you can still confirm it "
        "appears on the public bulletin board."
        "</div>"
        '<div class="btn-row"><a class="btn btn-primary" href="/verify">Verify my receipt</a>'
        '<a class="btn btn-outline" href="/results">Results</a></div>'
    )
    return page(
        "Already voted",
        f'<div class="narrow">{_card("One person, one vote", body)}</div>',
        ctx,
        active="vote",
        subtitle="This account has already participated.",
    )


def receipt(ctx: ViewContext, receipt: dict[str, str]) -> str:
    fields = [
        ("Tracking code", "tracking_code"),
        ("Option", "choice_label"),
        ("Nonce (secret)", "nonce"),
        ("Timestamp (UTC)", "created_at"),
        ("Ballot commitment", "ballot_hash"),
        ("Ballot ID", "ballot_id"),
    ]
    rows = "".join(
        f'<div class="receipt-row"><dt>{esc(label)}</dt>'
        f'<dd class="mono">{esc(receipt.get(key, ""))}</dd></div>'
        for label, key in fields
    )
    hidden = "".join(
        f'<input type="hidden" name="{esc(key)}" value="{esc(receipt.get(key, ""))}">'
        for key in (
            "tracking_code",
            "choice",
            "nonce",
            "created_at",
            "ballot_hash",
        )
    )
    body = (
        '<div class="notice notice-success"><strong>Ballot recorded.</strong> '
        "Save this receipt now — it is shown only once and is never stored by "
        "the server. It proves your vote was counted without revealing your "
        "identity to anyone else.</div>"
        f'<dl class="receipt">{rows}</dl>'
        '<form method="post" action="/verify" class="form">'
        f'{csrf_input(ctx)}<input type="hidden" name="mode" value="receipt">{hidden}'
        '<button class="btn btn-primary" type="submit">Verify this ballot now</button>'
        "</form>"
        '<p class="muted"><a href="/verify">Open the public bulletin board</a> '
        "to see that your tracking code and commitment are published.</p>"
    )
    return page(
        "Your receipt",
        f'<div class="narrow">{_card("Keep this somewhere safe", body)}</div>',
        ctx,
        active="vote",
        subtitle="Your private proof that the ballot was recorded as cast.",
    )


def verify(
    ctx: ViewContext,
    board: list[dict[str, Any]],
    *,
    lookup: dict[str, Any] | None = None,
    receipt_result: dict[str, Any] | None = None,
    form_values: dict[str, str] | None = None,
) -> str:
    values = form_values or {}
    lookup_html = ""
    if lookup is not None:
        if lookup.get("found"):
            lookup_html = (
                '<div class="notice notice-success">Tracking code found. Published '
                f'commitment: <span class="mono wrap">{esc(lookup["published_hash"])}</span>'
                f' · chain status {_badge("OK" if lookup["chain_ok"] else "FAILED", "ok" if lookup["chain_ok"] else "danger")}</div>'
            )
        else:
            lookup_html = (
                f'<div class="notice notice-danger">{esc(lookup.get("verdict", "Not found."))}</div>'
            )

    receipt_html = ""
    if receipt_result is not None:
        tone = "success" if receipt_result.get("commitment_ok") else "danger"
        receipt_html = (
            f'<div class="notice notice-{tone}"><strong>{esc(receipt_result["verdict"])}</strong></div>'
        )

    lookup_form = (
        f'<form method="post" action="/verify" class="form">{csrf_input(ctx)}'
        '<input type="hidden" name="mode" value="lookup">'
        '<label for="tracking_code">Tracking code</label>'
        '<input id="tracking_code" name="tracking_code" required '
        f'value="{esc(values.get("tracking_code", ""))}" maxlength="64">'
        '<button class="btn btn-outline" type="submit">Look up</button></form>'
    )
    # Every control has an explicit <label for>, with ids distinct from the
    # lookup form above so the page has no duplicate ids.
    receipt_fields = (
        ("vr-tracking_code", "tracking_code", "Tracking code", True),
        ("vr-nonce", "nonce", "Nonce from your receipt", True),
        ("vr-created_at", "created_at", "Timestamp", True),
        ("vr-choice", "choice", "Option key", True),
        ("vr-ballot_hash", "ballot_hash", "Ballot commitment (optional)", False),
    )
    receipt_controls = "".join(
        f'<label for="{field_id}">{esc(label)}</label>'
        f'<input id="{field_id}" name="{name}" '
        f'{"required " if required else ""}maxlength="64" '
        f'value="{esc(values.get(name, ""))}">'
        for field_id, name, label, required in receipt_fields
    )
    receipt_form = (
        f'<form method="post" action="/verify" class="form">{csrf_input(ctx)}'
        '<input type="hidden" name="mode" value="receipt">'
        + receipt_controls
        + '<button class="btn btn-outline" type="submit">Verify receipt</button></form>'
    )

    if board:
        table_rows = "".join(
            '<tr>'
            f'<td class="mono wrap">{esc(item["tracking_code"])}</td>'
            f'<td class="mono wrap">{esc(item["ballot_hash"])}</td>'
            f'<td>{_badge("OK" if item["chain_ok"] else "FAILED", "ok" if item["chain_ok"] else "danger")}</td>'
            "</tr>"
            for item in board
        )
        board_html = (
            '<div class="table-wrap"><table><thead><tr>'
            "<th>Tracking code</th><th>Ballot commitment (SHA-256)</th><th>Chain</th>"
            f"</tr></thead><tbody>{table_rows}</tbody></table></div>"
        )
    else:
        board_html = '<p class="muted">No ballots have been cast yet.</p>'

    body = (
        '<div class="two-col">'
        + _card(
            "Look up a tracking code",
            "<p class='muted'>Anyone can check that a tracking code is published.</p>"
            + lookup_html
            + lookup_form,
        )
        + _card(
            "Verify a full receipt",
            "<p class='muted'>Only the voter holds the nonce. Recomputing the "
            "commitment proves the ballot was recorded as cast; an outsider "
            "cannot brute-force the choice without that nonce.</p>"
            + receipt_html
            + receipt_form,
        )
        + "</div>"
        + _card(
            f"Public bulletin board · {len(board)} ballot(s)",
            "<p class='muted'>Sorted by tracking code, not by insertion order, so "
            "the board does not reveal when each person voted.</p>" + board_html,
            extra_class="wide-card",
        )
    )
    return page(
        "Verify",
        body,
        ctx,
        active="verify",
        subtitle="Check that ballots are present, intact and counted.",
    )


def results(ctx: ViewContext, data: dict[str, Any] | None) -> str:
    if data is None:
        body = (
            '<div class="notice notice-info"><strong>Results are sealed.</strong> '
            "Vote totals are only published after an administrator closes the "
            "election, so partial counts cannot influence remaining voters.</div>"
            '<p><a class="btn btn-outline" href="/verify">Verify ballots meanwhile</a></p>'
        )
        return page(
            "Results",
            f'<div class="narrow">{_card("Not yet published", body)}</div>',
            ctx,
            active="results",
            subtitle="Certified totals appear here once voting closes.",
        )

    max_votes = max(data["counts"].values(), default=0) or 1
    # <progress> keeps all presentation in CSS: the CSP forbids inline styles.
    bars = "".join(
        '<div class="result-row">'
        f'<div class="result-head"><span>{esc(data["labels"].get(key, key))}</span>'
        f'<strong>{esc(count)}</strong></div>'
        f'<progress class="bar" value="{esc(count)}" max="{esc(max_votes)}" '
        f'aria-label="Votes for {esc(data["labels"].get(key, key))}"></progress>'
        "</div>"
        for key, count in data["counts"].items()
    )
    checks = [
        ("Ballot hash chain", data["ballot_chain_ok"], data["ballot_chain_problems"]),
        ("Audit hash chain", data["audit_chain_ok"], data["audit_chain_problems"]),
        ("Ballot / voter counts agree", data["consistent"], []),
    ]
    checks_html = "".join(
        f'<div class="panel-row"><span>{esc(label)}</span>'
        f'{_badge("OK" if ok else "FAILED", "ok" if ok else "danger")}</div>'
        + (
            "<ul class='problems'>"
            + "".join(f"<li>{esc(p)}</li>" for p in problems)
            + "</ul>"
            if problems
            else ""
        )
        for label, ok, problems in checks
    )
    body = (
        '<div class="two-col">'
        + _card("Certified count", bars, extra_class="wide-card")
        + _card(
            "Summary",
            '<div class="stats small">'
            + _stat("Ballots", data["total"])
            + _stat("Turnout", f'{data["turnout"]:.1f}%')
            + _stat("Eligible", data["registered"])
            + "</div>"
            f'<p class="digest">Results digest<br><span class="mono wrap">{esc(data["results_digest"])}</span></p>',
        )
        + "</div>"
        + _card(
            "Integrity checks",
            checks_html
            + '<p><a class="btn btn-outline btn-sm" href="/export/results.json" download>'
            "Download certified results (JSON)</a></p>",
            extra_class="wide-card",
        )
    )
    return page(
        "Results",
        body,
        ctx,
        active="results",
        subtitle="Final tally, published only after the election is closed.",
    )


def audit(ctx: ViewContext, rows: Iterable[Any], *, ok: bool) -> str:
    items = list(rows)
    if items:
        table_rows = "".join(
            "<tr>"
            f'<td class="mono">{esc(row["seq"])}</td>'
            f'<td class="mono wrap">{esc(row["ts"])}</td>'
            f"<td>{esc(row['actor'])}</td>"
            f"<td>{esc(row['action'])}</td>"
            f'<td class="wrap">{esc(row["detail"])}</td>'
            "</tr>"
            for row in items
        )
        table = (
            '<div class="table-wrap"><table><thead><tr><th>#</th><th>Timestamp (UTC)</th>'
            "<th>Actor</th><th>Action</th><th>Detail</th></tr></thead>"
            f"<tbody>{table_rows}</tbody></table></div>"
        )
    else:
        table = '<p class="muted">No events recorded yet.</p>'

    body = (
        f'<div class="notice {"notice-success" if ok else "notice-danger"}">'
        + (
            "The HMAC audit chain is intact."
            if ok
            else "The audit chain failed verification — investigate immediately."
        )
        + "</div>"
        + _card(
            f"Recent events · {len(items)} shown",
            "<p class='muted'>Append-only and hash-chained. Ballot choices, "
            "passwords and receipt secrets are never logged.</p>" + table
            + '<p><a class="btn btn-outline btn-sm" href="/export/audit.json" download>'
            "Download full audit log (JSON)</a></p>",
            extra_class="wide-card",
        )
    )
    return page(
        "Audit log",
        body,
        ctx,
        active="audit",
        subtitle="A public, tamper-evident record of election events.",
    )


def admin(
    ctx: ViewContext,
    stats: dict[str, Any],
    integrity: dict[str, Any],
    candidates: Iterable[Candidate],
    *,
    error: str = "",
    notice: str = "",
) -> str:
    state = str(stats["state"])
    error_html = (
        f'<div class="notice notice-danger">{esc(error)}</div>' if error else ""
    )
    notice_html = (
        f'<div class="notice notice-success">{esc(notice)}</div>' if notice else ""
    )

    if state == "setup":
        control = (
            f'<form method="post" action="/admin/transition">{csrf_input(ctx)}'
            '<input type="hidden" name="target" value="open">'
            '<button class="btn btn-primary" type="submit">Open voting</button></form>'
        )
    elif state == "open":
        control = (
            f'<form method="post" action="/admin/transition">{csrf_input(ctx)}'
            '<input type="hidden" name="target" value="closed">'
            '<button class="btn btn-danger" type="submit">Close election & publish results</button></form>'
            '<p class="field-hint">This is irreversible. New ballots will be '
            "rejected and the tally becomes public.</p>"
        )
    else:
        control = (
            '<p class="muted">The election is closed. Results are final and '
            "the state cannot be reopened.</p>"
            '<a class="btn btn-outline" href="/results">View published results</a>'
        )

    option_list = "".join(
        f'<li><span class="mono">{esc(c.key)}</span> — {esc(c.label)}</li>'
        for c in candidates
    )
    body = (
        error_html
        + notice_html
        + '<div class="two-col">'
        + _card(
            "Election control",
            f'<div class="panel-row"><span>Current state</span>{state_badge(state)}</div>'
            + control,
        )
        + _card(
            "Live statistics",
            '<div class="stats small">'
            + _stat("Eligible", stats["eligible"])
            + _stat("Voted", stats["voted"])
            + _stat("Ballots", stats["ballots"])
            + "</div>",
        )
        + "</div>"
        + _card(
            "Integrity status",
            f'<div class="panel-row"><span>Ballot chain</span>{_badge("OK" if integrity["ballot_chain_ok"] else "FAILED", "ok" if integrity["ballot_chain_ok"] else "danger")}</div>'
            f'<div class="panel-row"><span>Audit chain</span>{_badge("OK" if integrity["audit_chain_ok"] else "FAILED", "ok" if integrity["audit_chain_ok"] else "danger")}</div>'
            '<p><a class="btn btn-outline btn-sm" href="/audit">Open audit log</a></p>',
            extra_class="wide-card",
        )
        + _card(
            "Ballot options",
            f"<ul class='option-list'>{option_list}</ul>",
            extra_class="wide-card",
        )
    )
    return page(
        "Administration",
        body,
        ctx,
        active="admin",
        subtitle="Election state and integrity controls (admin only).",
    )


def error_page(ctx: ViewContext, status: int, message: str) -> str:
    titles = {
        400: "Bad request",
        401: "Sign in required",
        403: "Forbidden",
        404: "Not found",
        405: "Method not allowed",
        409: "Conflict",
        413: "Request too large",
        429: "Too many attempts",
        500: "Server error",
    }
    body = (
        f'<div class="notice notice-danger"><strong>{esc(titles.get(status, "Error"))}</strong> '
        f"{esc(message)}</div>"
        '<p><a class="btn btn-outline" href="/">Back to overview</a></p>'
    )
    return page(
        titles.get(status, "Error"),
        f'<div class="narrow">{_card(f"HTTP {status}", body)}</div>',
        ctx,
    )
