from playwright.sync_api import sync_playwright
import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
OUT_DIR = BASE_DIR / "static" / "screenshots"
OUT_DIR.mkdir(parents=True, exist_ok=True)

def safe_filename(url: str) -> str:
    return re.sub(r'[^a-zA-Z0-9]', '_', url)[:80]

def analyze_and_screenshot(url: str, html_content: str | None = None) -> dict:
    """Takes screenshot of URL OR raw HTML. Always returns screenshot path."""
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--ignore-certificate-errors",
                    "--disable-blink-features=AutomationControlled",
                    "--disable-web-security",
                    "--allow-running-insecure-content",
                ],
            )

            page = browser.new_page(ignore_https_errors=True)

            # ── LOAD PAGE ─────────────────────────
            if html_content:
                print("[SCREENSHOT] Loading raw HTML")
                page.set_content(html_content, wait_until="load")
            else:
                print("[SCREENSHOT] Opening URL:", url)
                page.goto(url, wait_until="load", timeout=60000)

            filename = safe_filename(url) + ".png"
            path = OUT_DIR / filename

            page.screenshot(path=str(path), full_page=True)
            browser.close()

            print("[SCREENSHOT] Saved:", path)

            return {"screenshot": f"screenshots/{filename}"}

    except Exception as e:
        print("[SCREENSHOT ERROR]", e)
        return {"screenshot": ""}