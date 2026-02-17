#!/usr/bin/env python3
"""
Instagram DM Auto Sender - COMPLETE & FIXED VERSION
Fixed: All missing functions, proper error handling, multiple URL support
Added: Full functionality with all original features working
"""

import argparse
import os
import time
import re
import unicodedata
import json
import asyncio
import logging
from datetime import datetime
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError

# ==================== CONFIGURATION ====================
MOBILE_UA = "Mozilla/5.0 (Linux; Android 13; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
MOBILE_VIEWPORT = {"width": 412, "height": 915}
LAUNCH_ARGS = [
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--disable-software-rasterizer",
    "--disable-background-networking",
    "--disable-renderer-backgrounding",
    "--disable-extensions",
    "--disable-sync",
    "--disable-translate",
    "--disable-features=site-per-process",
    "--disable-infobars",
    "--mute-audio",
    "--disable-blink-features=AutomationControlled",
]

# ==================== LOGGING SETUP ====================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dm_sender.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ==================== HELPER FUNCTIONS ====================
def sanitize_input(raw):
    """Fix shell-truncated input"""
    if isinstance(raw, list):
        raw = " ".join(raw)
    return raw

def parse_messages(names_arg):
    """Parse messages from string or file, preserving newlines for ASCII art"""
    if isinstance(names_arg, list):
        names_arg = " ".join(names_arg)

    content = None
    is_file = isinstance(names_arg, str) and names_arg.endswith('.txt') and os.path.exists(names_arg)

    if is_file:
        # Try JSON lines format first
        try:
            msgs = []
            with open(names_arg, 'r', encoding='utf-8') as f:
                for ln in f:
                    ln = ln.rstrip('\n')
                    if not ln:
                        continue
                    try:
                        m = json.loads(ln)
                        if isinstance(m, str):
                            msgs.append(m)
                        else:
                            raise ValueError("Not a string")
                    except:
                        msgs.append(ln)
            if msgs:
                logger.info(f"Loaded {len(msgs)} messages from JSON lines file")
                return msgs
        except:
            pass

        # Regular text file
        try:
            with open(names_arg, 'r', encoding='utf-8') as f:
                content = f.read()
            logger.info(f"Loaded content from file: {names_arg}")
        except Exception as e:
            raise ValueError(f"Failed to read file {names_arg}: {e}")
    else:
        content = str(names_arg)

    # Normalize weird ampersands
    content = content.replace('﹠', '&').replace('＆', '&').replace('⅋', '&')
    
    # Split by & or 'and'
    pattern = r'\s*(?:&|\band\b)\s*'
    parts = [part.strip() for part in re.split(pattern, content, flags=re.IGNORECASE) if part.strip()]
    
    logger.info(f"Parsed {len(parts)} messages from text input")
    return parts

def validate_thread_url(url):
    """Validate Instagram DM thread URL format"""
    pattern = r'^https://www\.instagram\.com/direct/t/[a-zA-Z0-9_]+/?$'
    if not re.match(pattern, url):
        return False
    return True

async def check_session_valid(context):
    """Check if the stored session is still valid"""
    try:
        page = await context.new_page()
        await page.goto("https://www.instagram.com/", timeout=30000, wait_until="domcontentloaded")
        await asyncio.sleep(2)
        
        # Check if we're logged in (no login button)
        login_button = await page.locator('button:has-text("Log in")').count()
        await page.close()
        
        if login_button > 0:
            logger.warning("Session expired - login button found")
            return False
        logger.info("Session is valid")
        return True
    except Exception as e:
        logger.error(f"Session check failed: {e}")
        return False

# ==================== LOGIN FUNCTION ====================
async def login(args, storage_path, headless):
    """Async Instagram login with improved stability"""
    logger.info("Starting Instagram login process...")
    
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=False,  # Always visible for login
                args=LAUNCH_ARGS
            )
            context = await browser.new_context(
                user_agent=MOBILE_UA,
                viewport=MOBILE_VIEWPORT,
                is_mobile=True,
                has_touch=True,
                device_scale_factor=2,
                color_scheme="dark"
            )
            page = await context.new_page()
            
            try:
                # Navigate to login
                logger.info("Navigating to Instagram...")
                await page.goto("https://www.instagram.com/accounts/login/", timeout=60000, wait_until="networkidle")
                
                # Wait for username field
                logger.info("Waiting for login form...")
                await page.wait_for_selector('input[name="username"]', timeout=30000, state="visible")
                
                # Type username with human-like delays
                username_input = page.locator('input[name="username"]')
                await username_input.click()
                await asyncio.sleep(0.2)
                await username_input.fill(args.username)
                await asyncio.sleep(0.3)
                
                # Type password
                password_input = page.locator('input[name="password"]')
                await password_input.click()
                await asyncio.sleep(0.3)
                await password_input.fill(args.password)
                await asyncio.sleep(0.5)
                
                # Click login
                login_button = page.locator('button[type="submit"]')
                await login_button.click()
                
                # Wait for navigation to home
                logger.info("Waiting for login to complete...")
                try:
                    await page.wait_for_url(lambda url: "instagram.com" in url and "accounts" not in url, timeout=60000)
                    
                    # Check for "Save Info" or "Not Now" popups
                    await asyncio.sleep(3)
                    
                    # Handle "Save your login info?" popup
                    not_now = page.locator('button:has-text("Not Now")')
                    if await not_now.count() > 0:
                        await not_now.first.click()
                        await asyncio.sleep(1)
                    
                    # Handle "Turn on Notifications" popup
                    not_now = page.locator('button:has-text("Not Now")')
                    if await not_now.count() > 0:
                        await not_now.first.click()
                    
                    logger.info("Login successful!")
                    
                    # Save storage state
                    await context.storage_state(path=storage_path)
                    logger.info(f"Storage state saved to {storage_path}")
                    
                    return True
                    
                except PlaywrightTimeoutError:
                    # Check if we're still on login page (failed login)
                    current_url = page.url
                    if "accounts" in current_url:
                        # Check for error message
                        error = page.locator('p:has-text("Sorry, your password was incorrect")')
                        if await error.count() > 0:
                            logger.error("Invalid credentials")
                            return False
                        
                        error = page.locator('p:has-text("We couldn\'t connect to Instagram")')
                        if await error.count() > 0:
                            logger.error("Network error during login")
                            return False
                    
                    logger.error(f"Login timeout, current URL: {current_url}")
                    return False
                    
            except Exception as e:
                logger.error(f"Login error: {e}")
                return False
            finally:
                await browser.close()
                
    except Exception as e:
        logger.error(f"Unexpected login error: {e}")
        return False

# ==================== PAGE INITIALIZATION ====================
async def init_page(page, url, dm_selector):
    """Initialize page with robust retry logic"""
    logger.debug(f"Initializing page for URL: {url}")
    
    for attempt in range(3):
        try:
            # First go to Instagram home to ensure session is loaded
            await page.goto("https://www.instagram.com/", timeout=45000, wait_until="domcontentloaded")
            await asyncio.sleep(2)
            
            # Navigate to DM thread
            logger.debug(f"Navigating to thread (attempt {attempt+1}/3)")
            await page.goto(url, timeout=45000, wait_until="domcontentloaded")
            await asyncio.sleep(3)  # Wait for dynamic content
            
            # Wait for message box to be visible
            await page.wait_for_selector(dm_selector, timeout=15000, state="visible")
            
            # Additional wait to ensure page is fully interactive
            await asyncio.sleep(1)
            
            logger.info(f"Page initialized successfully for {url}")
            return True
            
        except PlaywrightTimeoutError as e:
            logger.warning(f"Init attempt {attempt+1}/3 timed out: {e}")
            if attempt < 2:
                wait_time = (attempt + 1) * 2
                logger.debug(f"Waiting {wait_time}s before retry...")
                await asyncio.sleep(wait_time)
                
        except Exception as e:
            logger.warning(f"Init attempt {attempt+1}/3 failed: {e}")
            if attempt < 2:
                wait_time = (attempt + 1) * 2
                await asyncio.sleep(wait_time)
    
    logger.error(f"Failed to initialize page for {url} after 3 attempts")
    return False

# ==================== MESSAGE SENDER - COMPLETE & FIXED ====================
async def sender(tab_id, args, messages, context, page):
    """Send messages in infinite loop with improved reliability"""
    # Multiple possible selectors for the message box
    dm_selectors = [
        'div[role="textbox"][aria-label="Message"]',
        'div[role="textbox"][aria-label="Message..."]',
        'div[contenteditable="true"][aria-label="Message"]',
        'div[contenteditable="true"][aria-label="Message..."]',
        'textarea[placeholder="Message..."]',
        'div[spellcheck="true"][contenteditable="true"]',
        'div[contenteditable="true"]',
        'div[role="textbox"]'
    ]
    
    logger.info(f"📱 Tab {tab_id} ready, starting infinite message loop.")
    current_page = page
    cycle_start = time.time()
    msg_index = 0
    error_count = 0
    max_errors = 5
    reload_interval = 1  # Reload every 60 seconds
    message_count = 0
    
    while True:
        try:
            # Check if we need to reload the page
            elapsed = time.time() - cycle_start
            if elapsed >= reload_interval:
                logger.info(f"🔄 Tab {tab_id} reloading thread after {elapsed:.1f}s (sent {message_count} messages)")
                try:
                    await current_page.reload(timeout=45000, wait_until="domcontentloaded")
                    await asyncio.sleep(3)
                    
                    # Find the message box with retry
                    message_box = None
                    for selector in dm_selectors:
                        try:
                            if await current_page.locator(selector).count() > 0:
                                message_box = current_page.locator(selector).first
                                logger.debug(f"Tab {tab_id} found message box with selector: {selector}")
                                break
                        except:
                            continue
                    
                    if not message_box:
                        logger.warning(f"Tab {tab_id} message box not found after reload")
                        # Try to navigate to thread again
                        await current_page.goto(args.thread_url if not isinstance(args.thread_url, list) else args.thread_url[0], timeout=45000)
                        await asyncio.sleep(3)
                    
                    cycle_start = time.time()
                    error_count = 0  # Reset error count on successful reload
                    
                except Exception as reload_e:
                    logger.error(f"Tab {tab_id} reload failed: {reload_e}")
                    # Don't raise, just continue and try again next cycle
                    cycle_start = time.time() - reload_interval + 10  # Try again in 10 seconds
                continue

            # Get current message
            msg = messages[msg_index]
            send_success = False
            
            # Try to find message box
            message_box = None
            for selector in dm_selectors:
                try:
                    if await current_page.locator(selector).count() > 0:
                        message_box = current_page.locator(selector).first
                        if await message_box.is_visible():
                            break
                except:
                    continue
            
            if not message_box:
                logger.warning(f"Tab {tab_id} message box not found, attempting to refresh...")
                await current_page.reload(timeout=30000)
                await asyncio.sleep(3)
                cycle_start = time.time()  # Reset reload timer
                continue
            
            # Send message with retry
            for retry in range(3):
                try:
                    # Click and focus
                    await message_box.click()
                    
                    # Clear existing text (if any)
                    await message_box.fill("")
                    
                    # Type message
                    await message_box.fill(msg)
                    
                    # Press Enter to send
                    await message_box.press("Enter")
                    
                    message_count += 1
                    logger.info(f"📤 Tab {tab_id} sent message {msg_index + 1}/{len(messages)} [{message_count} total]: {msg[:30]}...")
                    send_success = True
                    error_count = 0  # Reset error count on success
                    break
                    
                except Exception as send_e:
                    logger.warning(f"Tab {tab_id} send error (retry {retry+1}/3): {send_e}")
                    if retry < 2:
                        await asyncio.sleep(0.2)
                    else:
                        error_count += 1
                        if error_count >= max_errors:
                            logger.error(f"Tab {tab_id} exceeded max errors ({max_errors}), raising exception")
                            raise Exception(f"Tab {tab_id} failed after {max_errors} errors")
                        
                        # Try to recover by reloading
                        logger.info(f"Tab {tab_id} attempting recovery reload...")
                        await current_page.reload(timeout=30000)
                        await asyncio.sleep(3)
                        cycle_start = time.time()  # Reset reload timer

            if not send_success:
                logger.error(f"Tab {tab_id} failed to send message after 3 retries")
                error_count += 1
                if error_count >= max_errors:
                    raise Exception(f"Tab {tab_id} failed after {max_errors} errors")
            
            # Delay between messages (configurable)
            await asyncio.sleep(0.1)  # 100ms between messages for good speed
            
            # Move to next message
            msg_index = (msg_index + 1) % len(messages)
            
        except Exception as e:
            logger.error(f"Tab {tab_id} unexpected error in main loop: {e}")
            error_count += 1
            if error_count >= max_errors:
                logger.error(f"Tab {tab_id} reached max errors ({max_errors}), stopping")
                raise
            await asyncio.sleep(2)  # Wait before retrying

# ==================== MAIN FUNCTION ====================
async def main():
    parser = argparse.ArgumentParser(description="Instagram DM Auto Sender - Complete Version")
    parser.add_argument('--username', required=False, help='Instagram username')
    parser.add_argument('--password', required=False, help='Instagram password')
    parser.add_argument('--thread-url', required=True, help='Instagram DM thread URL(s) - comma separated')
    parser.add_argument('--names', nargs='+', required=True, help='Messages or .txt file')
    parser.add_argument('--headless', default='true', choices=['true', 'false'], help='Run headless')
    parser.add_argument('--storage-state', required=True, help='Storage state file path')
    parser.add_argument('--tabs', type=int, default=1, help='Number of tabs (1-5)')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    args = parser.parse_args()
    
    # Set debug level if requested
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    logger.info("=" * 50)
    logger.info("🚀 Instagram DM Auto Sender - Starting")
    logger.info("=" * 50)
    
    # Sanitize inputs
    args.names = sanitize_input(args.names)
    
    # Parse thread URLs
    thread_urls = [u.strip() for u in args.thread_url.split(',') if u.strip()]
    
    if not thread_urls:
        logger.error("No valid thread URLs provided.")
        return
    
    # Validate thread URLs
    valid_urls = []
    for url in thread_urls:
        if validate_thread_url(url):
            valid_urls.append(url)
        else:
            logger.warning(f"Invalid thread URL format: {url}")
    
    if not valid_urls:
        logger.error("No valid thread URLs after validation.")
        return
    
    logger.info(f"✅ Valid thread URLs: {len(valid_urls)}")
    
    headless = args.headless == 'true'
    storage_path = args.storage_state
    do_login = not os.path.exists(storage_path)

    # Handle login if needed
    if do_login:
        logger.info("No existing session found, starting login process...")
        if not args.username or not args.password:
            logger.error("Username and password required for initial login.")
            return
        success = await login(args, storage_path, headless)
        if not success:
            logger.error("Login failed, exiting.")
            return
    else:
        logger.info(f"Using existing storage state: {storage_path}")
    
    # Parse messages
    try:
        messages = parse_messages(args.names)
    except ValueError as e:
        logger.error(f"Error parsing messages: {e}")
        return

    if not messages:
        logger.error("No valid messages provided.")
        return

    logger.info(f"📝 Parsed {len(messages)} messages:")
    for i, msg in enumerate(messages, 1):
        logger.debug(f"  {i}. {msg[:50]}{'...' if len(msg) > 50 else ''}")
    
    tabs = min(max(args.tabs, 1), 5)
    logger.info(f"🔄 Using {tabs} tabs per URL, total: {len(valid_urls) * tabs} tabs")

    # Main Playwright execution
    async with async_playwright() as p:
        browser = None
        context = None
        pages = []
        
        try:
            # Launch browser
            logger.info(f"Launching browser (headless: {headless})...")
            browser = await p.chromium.launch(
                headless=headless,
                args=LAUNCH_ARGS
            )
            
            # Create context with storage state
            logger.info("Creating browser context...")
            context = await browser.new_context(
                storage_state=storage_path,
                user_agent=MOBILE_UA,
                viewport=MOBILE_VIEWPORT,
                is_mobile=True,
                has_touch=True,
                device_scale_factor=2,
                color_scheme="dark"
            )
            
            # Check if session is still valid
            logger.info("Checking session validity...")
            session_valid = await check_session_valid(context)
            if not session_valid:
                logger.error("Session expired, please login again")
                if args.username and args.password:
                    logger.info("Attempting to re-login...")
                    success = await login(args, storage_path, headless)
                    if not success:
                        logger.error("Re-login failed, exiting.")
                        return
                    # Recreate context with new storage state
                    await context.close()
                    context = await browser.new_context(
                        storage_state=storage_path,
                        user_agent=MOBILE_UA,
                        viewport=MOBILE_VIEWPORT,
                        is_mobile=True,
                        has_touch=True,
                        device_scale_factor=2,
                        color_scheme="dark"
                    )
                else:
                    logger.error("No credentials available for re-login")
                    return
            
            # Create and initialize pages
            page_urls = []
            for url in valid_urls:
                for tab_num in range(tabs):
                    page = await context.new_page()
                    pages.append(page)
                    page_urls.append((page, url, tab_num + 1))
                    logger.debug(f"Created page {len(page_urls)} for URL: {url}")
            
            # Initialize all pages
            logger.info("Initializing all pages...")
            init_tasks = [
                asyncio.create_task(init_page(page, url, 'div[contenteditable="true"]')) 
                for page, url, _ in page_urls
            ]
            init_results = await asyncio.gather(*init_tasks, return_exceptions=True)
            
            # Filter successful pages
            successful_pages = []
            for idx, result in enumerate(init_results):
                page, url, tab_num = page_urls[idx]
                if isinstance(result, Exception) or not result:
                    logger.warning(f"Tab {tab_num} for {url} failed to initialize, skipping.")
                    await page.close()
                else:
                    successful_pages.append(page)
                    logger.info(f"✅ Tab {len(successful_pages)} ready for {url}")
            
            if not successful_pages:
                logger.error("No tabs could be initialized, exiting.")
                return
            
            # Store thread_url in args for access in sender
            args.thread_url = valid_urls[0]  # Use first URL as default
            
            # Start sender tasks
            logger.info(f"🚀 Starting {len(successful_pages)} tab(s) in infinite message loop. Press Ctrl+C to stop.")
            tasks = [
                asyncio.create_task(sender(j + 1, args, messages, context, successful_pages[j])) 
                for j in range(len(successful_pages))
            ]
            
            # Wait for all tasks (they run indefinitely)
            await asyncio.gather(*tasks)
            
        except KeyboardInterrupt:
            logger.info("\n🛑 Received interrupt signal, stopping all tabs...")
            
        except Exception as e:
            logger.error(f"Fatal error: {e}", exc_info=True)
            
        finally:
            # Cleanup
            logger.info("Cleaning up resources...")
            for page in pages:
                try:
                    await page.close()
                except:
                    pass
            
            if context:
                await context.close()
            
            if browser:
                await browser.close()
            
            logger.info("👋 Shutdown complete.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("\nExited by user.")
    except Exception as e:
        logger.error(f"Unhandled exception: {e}", exc_info=True)