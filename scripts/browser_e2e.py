#!/usr/bin/env python3
"""Real Chromium end-to-end test for the rendered UI and JSON downloads.

CI installs Playwright separately (see ``requirements-browser.txt`` and the
``browser-e2e`` job in ``.github/workflows/ci.yml``):

    python -m playwright install --with-deps chromium
    python scripts/browser_e2e.py

Set ``SVS_CHROME_PATH`` to use an existing Chromium binary instead of the
Playwright-managed download, or ``SVS_SCREENSHOT_PATH`` to additionally save a
full-page capture of the rendered custom-election home page.

The script starts the real stdlib HTTP server on an ephemeral port and drives
a custom election through Chromium: register, vote, verify a receipt, inspect
the public board, confirm sealed results, close as admin, then download and
validate certified results / audit exports. There is no JavaScript in the app,
so every assertion below exercises actual HTML form navigation and CSS.
"""

from __future__ import annotations

import os
import sys
import tempfile
import threading
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from playwright.sync_api import expect, sync_playwright  # noqa: E402

from secure_vote.app import Handler, make_server  # noqa: E402
from secure_vote.config import (  # noqa: E402
    DEMO_ADMIN,
    Config,
    load_election_file,
)
from secure_vote.demo import seed_demo  # noqa: E402

PASSWORD = "BrowserPass123!"
TIMEOUT = 20_000


def start_server(config: Config):
    server = make_server(config, "127.0.0.1", 0)
    thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.05},
        daemon=True,
    )
    thread.start()
    return server, thread, f"http://127.0.0.1:{server.server_address[1]}"


def stop_server(server, thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def launch(p):
    """Use Playwright's managed Chromium, or ``SVS_CHROME_PATH`` when supplied."""
    return p.chromium.launch(
        headless=True,
        executable_path=os.environ.get("SVS_CHROME_PATH") or None,
        args=["--no-sandbox", "--disable-dev-shm-usage"],
    )


def run(base: str, title: str) -> None:
    expect.set_options(timeout=TIMEOUT)

    with sync_playwright() as p:
        browser = launch(p)
        context = browser.new_context(
            viewport={"width": 1440, "height": 1000},
            accept_downloads=True,
        )
        page = context.new_page()
        page.set_default_timeout(TIMEOUT)

        response = page.goto(base + "/")
        assert response is not None and response.status == 200
        assert "script-src 'none'" in response.headers["content-security-policy"]
        expect(page).to_have_title(f"Overview · {title} · SecureVote")
        expect(page.locator("h1")).to_contain_text(
            "A voting system you can actually check."
        )
        expect(page.locator(".election-name")).to_have_text(title)
        hero_css = page.locator(".hero").evaluate(
            "el => getComputedStyle(el).backgroundImage"
        )
        assert "linear-gradient" in hero_css, f"CSS did not render: {hero_css}"
        assert page.locator("script").count() == 0, "unexpected JavaScript"
        screenshot = os.environ.get("SVS_SCREENSHOT_PATH")
        if screenshot:
            Path(screenshot).parent.mkdir(parents=True, exist_ok=True)
            page.screenshot(path=screenshot, full_page=True)
        page.keyboard.press("Tab")
        expect(page.locator(".skip-link")).to_be_focused()
        print(f"[browser] ✓ rendered HTML/CSS with no JS ({hero_css[:48]}…)", flush=True)

        page.goto(base + "/register")
        page.locator('form[action="/register"] input[name="username"]').fill(
            "browser_voter"
        )
        page.locator('form[action="/register"] input[name="password"]').fill(PASSWORD)
        page.locator('form[action="/register"] button[type="submit"]').click()
        expect(page).to_have_url(base + "/vote")
        options = page.locator('form[action="/vote"] input[name="choice"]')
        expect(options).to_have_count(4)
        expect(page.locator('form[action="/vote"]')).to_contain_text("Atlas Ticket")
        print("[browser] ✓ custom four-option ballot rendered", flush=True)

        page.locator('input[name="choice"][value="atlas"]').check()
        page.locator('form[action="/vote"] button[type="submit"]').click()
        expect(page.locator("body")).to_contain_text("Ballot recorded")
        receipt = page.locator("dl.receipt")
        expect(receipt).to_contain_text("Atlas Ticket")
        tracking_code = receipt.locator("dd.mono").first.inner_text().strip()
        assert len(tracking_code) >= 16, f"bad tracking code: {tracking_code!r}"
        page.locator('form[action="/verify"] button[type="submit"]').click()
        expect(page.locator(".notice-success")).to_contain_text(
            "Verified: your ballot is recorded as cast and intact."
        )
        print("[browser] ✓ ballot cast, one-time receipt verified", flush=True)

        page.goto(base + "/verify")
        expect(page.locator("body")).to_contain_text(tracking_code)
        page.goto(base + "/results")
        expect(page.locator("body")).to_contain_text("Results are sealed")
        sealed = context.request.get(base + "/export/results.json")
        assert sealed.status == 409, f"expected sealed results, got {sealed.status}"
        assert "sealed" in sealed.json()["error"].lower()
        print("[browser] ✓ public bulletin board; results sealed while open", flush=True)

        audit_response = context.request.get(base + "/export/audit.json")
        assert audit_response.status == 200
        assert "attachment" in audit_response.headers.get("content-disposition", "")
        audit = audit_response.json()
        assert audit["format"] == "securevote/audit-v1"
        assert audit["count"] > 0
        assert len(audit["entries"][0]["entry_hash"]) == 64
        page.goto(base + "/audit")
        with page.expect_download() as download_info:
            page.locator('a[href="/export/audit.json"]').click()
        assert download_info.value.suggested_filename == "audit.json"
        print("[browser] ✓ hash-chained audit trail downloaded as JSON", flush=True)

        admin_context = browser.new_context(
            viewport={"width": 1440, "height": 1000},
            accept_downloads=True,
        )
        admin = admin_context.new_page()
        admin.set_default_timeout(TIMEOUT)
        admin.goto(base + "/login")
        admin.locator('form[action="/login"] input[name="username"]').fill(
            DEMO_ADMIN[0]
        )
        admin.locator('form[action="/login"] input[name="password"]').fill(
            DEMO_ADMIN[1]
        )
        admin.locator('form[action="/login"] button[type="submit"]').click()
        expect(admin).to_have_url(base + "/vote")
        admin.goto(base + "/admin")
        admin.locator(
            'form[action="/admin/transition"] button[type="submit"]'
        ).click()
        expect(admin).to_have_url(base + "/admin")
        expect(admin.locator("body")).to_contain_text("election is closed")
        print("[browser] ✓ administrator closed the election through the UI", flush=True)

        page.goto(base + "/results")
        expect(page.locator("body")).to_contain_text("Certified count")
        expect(page.locator("body")).to_contain_text("Atlas Ticket")
        expect(
            page.locator('a[href="/export/results.json"]')
        ).to_be_visible()
        with page.expect_download() as download_info:
            page.locator('a[href="/export/results.json"]').click()
        assert download_info.value.suggested_filename == "results.json"

        bundle_response = context.request.get(base + "/export/results.json")
        assert bundle_response.status == 200
        bundle = bundle_response.json()
        assert bundle["format"] == "securevote/results-v1"
        assert bundle["election"]["title"] == title
        assert bundle["election"]["state"] == "closed"
        assert bundle["results"]["total"] == 1
        assert bundle["results"]["counts"]["atlas"] == 1
        assert bundle["integrity"]["ok"] is True
        assert "signature" in bundle["checkpoint"]
        print(
            "[browser] ✓ certified results and signed checkpoint exported",
            flush=True,
        )

        admin_context.close()
        context.close()
        browser.close()


def main() -> int:
    # Keep the CI log focused on assertions rather than one line per request.
    Handler.log_request = lambda self, code="-", size="-": None
    election_file = ROOT / "examples" / "election.json"
    title, description, candidates = load_election_file(election_file)
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        config = Config(
            db_path=root / "election.db",
            key_path=root / "server.key",
            secret_key=b"browser-e2e-key-0123456789-abcdef",
            candidates=candidates,
            election_title=title,
            election_description=description,
            pbkdf2_iterations=1_000,
            host="127.0.0.1",
            port=0,
            samesite="strict",
        )
        seed_demo(config)
        server, thread, base = start_server(config)
        print(f"[browser] server on {base}", flush=True)
        try:
            run(base, title)
        finally:
            stop_server(server, thread)
    print("[browser] OK — real Chromium lifecycle passed", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        traceback.print_exc()
        raise SystemExit(1)
