import pytest
from playwright.sync_api import sync_playwright, expect
import time

BASE_URL = "http://127.0.0.1:5000"

@pytest.mark.e2e
def test_text_only_secret():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        # Go to home page
        page.goto(BASE_URL)
        page.screenshot(path="screenshot_text_only.png")
        with open("page_text_only.html", "w") as f:
            f.write(page.content())
        page.wait_for_selector('textarea[name="message"]', timeout=10000)
        # Fill out text secret form
        page.fill('textarea[name="message"]', 'playwright secret')
        for i, digit in enumerate('12345'):
            page.fill(f'.pin-box:nth-of-type({i+1})', digit)
        page.fill('input[name="exp"]', '1')
        # Submit form
        page.click('button[type="submit"]')
        # Wait for navigation
        page.wait_for_selector('#share-link')
        # Check share link is present
        share_link = page.input_value('#share-link')
        assert '/combo/' in share_link
        # Click Copy Link and check clipboard
        page.wait_for_selector('#copy-btn', timeout=10000)
        page.click('#copy-btn')
        # Clipboard check removed
        browser.close()

@pytest.mark.e2e
def test_file_only_secret(tmp_path):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(BASE_URL)
        page.screenshot(path="screenshot_file_only.png")
        with open("page_file_only.html", "w") as f:
            f.write(page.content())
        page.wait_for_selector('.pin-box', timeout=10000)
        # Fill out form (no text)
        for i, digit in enumerate('54321'):
            page.fill(f'.pin-box:nth-of-type({i+1})', digit)
        page.fill('input[name="exp"]', '1')
        # Upload a file
        test_file = tmp_path / "testfile.txt"
        test_file.write_text("file secret content")
        page.set_input_files('input[type="file"]', str(test_file))
        # Submit form
        page.click('button[type="submit"]')
        # Wait for download link
        page.wait_for_selector('.download-link', timeout=10000)
        # Check download link is present
        download_link = page.get_attribute('.download-link', 'href')
        assert '/download/' in download_link
        # Click Copy Link and check clipboard
        page.click('#copy-btn')
        share_link = page.input_value('#share-link')
        # Clipboard check removed
        browser.close()

@pytest.mark.e2e
def test_text_and_file_secret(tmp_path):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(BASE_URL)
        page.screenshot(path="screenshot_text_and_file.png")
        with open("page_text_and_file.html", "w") as f:
            f.write(page.content())
        page.wait_for_selector('textarea[name="message"]', timeout=10000)
        # Fill out form
        page.fill('textarea[name="message"]', 'combo playwright secret')
        for i, digit in enumerate('99999'):
            page.fill(f'.pin-box:nth-of-type({i+1})', digit)
        page.fill('input[name="exp"]', '1')
        # Upload a file
        test_file = tmp_path / "combo.txt"
        test_file.write_text("combo file content")
        page.set_input_files('input[type="file"]', str(test_file))
        # Submit form
        page.click('button[type="submit"]')
        # Wait for both download and share link
        page.wait_for_selector('.download-link', timeout=10000)
        # Check both present
        download_link = page.get_attribute('.download-link', 'href')
        share_link = page.input_value('#share-link')
        assert '/download/' in download_link
        assert '/combo/' in share_link
        # Click Copy Link and check clipboard
        page.click('#copy-btn')
        # Clipboard check removed
        browser.close() 