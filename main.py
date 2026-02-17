import argparse
import json
import os
import time
import random
import logging
import unicodedata
import sqlite3
import re
import urllib.parse
import subprocess
import pty
import errno
import sys
import threading
import uuid
import signal
import asyncio
import psutil
from typing import Dict, List
from queue import Queue, Empty
from instagrapi.exceptions import LoginRequired, PleaseWaitFewMinutes, RateLimitError

# Playwright imports
from playwright.sync_api import sync_playwright
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError
from playwright_stealth import stealth_sync

# Telegram imports - FIXED with CallbackQueryHandler
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, 
    CommandHandler, 
    MessageHandler, 
    filters, 
    ConversationHandler, 
    ContextTypes,
    CallbackQueryHandler  # ✅ CRITICAL: This was missing!
)

# Instagrapi imports
from instagrapi.exceptions import (
    ChallengeRequired,
    TwoFactorRequired,
    PleaseWaitFewMinutes,
    RateLimitError,
    LoginRequired,
)


logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('instagram_bot.log'),
        logging.StreamHandler()
    ]
)

user_fetching = set()
user_cancel_fetch = set()  # new set
AUTHORIZED_FILE = 'authorized_users.json'
TASKS_FILE = 'tasks.json'
OWNER_TG_ID = 8305984975
BOT_TOKEN = "8591799796:AAGCzpFduqawhtkeH6a5uFmckRJG1O1VQ5g"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"

authorized_users = []  # list of {'id': int, 'username': str}
users_data: Dict[int, Dict] = {}  # unlocked data {'accounts': list, 'default': int, 'pairs': dict or None, 'switch_minutes': int, 'threads': int}
users_pending: Dict[int, Dict] = {}  # pending challenges
users_tasks: Dict[int, List[Dict]] = {}  # tasks per user
persistent_tasks = []
running_processes: Dict[int, subprocess.Popen] = {}
waiting_for_otp = {}
user_queues = {}

# Ensure sessions directory exists
os.makedirs('sessions', exist_ok=True)

# === PATCH: Fix instagrapi invalid timestamp bug ===
def _sanitize_timestamps(obj):
    """Fix invalid *_timestamp_us fields in Instagram data"""
    if isinstance(obj, dict):
        new_obj = {}
        for k, v in obj.items():
            if isinstance(v, int) and k.endswith("_timestamp_us"):
                try:
                    secs = int(v) // 1_000_000  # convert microseconds → seconds
                except Exception:
                    secs = None
                # skip impossible years (>2100 or negative)
                if secs is None or secs < 0 or secs > 4102444800:
                    new_obj[k] = None
                else:
                    new_obj[k] = secs
            else:
                new_obj[k] = _sanitize_timestamps(v)
        return new_obj
    elif isinstance(obj, list):
        return [_sanitize_timestamps(i) for i in obj]
    else:
        return obj


async def playwright_login_and_save_state(username: str, password: str, user_id: int) -> str:
    """
    Async Playwright login (STABLE VERSION)
    - Instagram me login karta hai
    - storage_state ko sessions/<user>_<username>_state.json me save karta hai
    - file path return karta hai
    """

    import random, logging, asyncio
    from playwright.async_api import async_playwright

    COOKIE_FILE = f"sessions/{user_id}_{username}_state.json"

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=[
                "--disable-gpu",
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
            ],
        )

        context = await browser.new_context(
            user_agent=USER_AGENT,
            viewport={"width": 1280, "height": 720},
        )

        page = await context.new_page()

        login_url = "https://www.instagram.com/accounts/login/?__coig_login=1"
        logging.info("[PLOGIN] Opening login page...")

        await page.goto(login_url, wait_until="domcontentloaded", timeout=60000)
        await asyncio.sleep(random.uniform(3, 5))

        # ================= FIX 1: ENSURE LOGIN FORM LOADED =================
        if await page.locator('input[name="username"]').count() == 0:
            logging.warning("[PLOGIN] Login form not visible, reloading page...")
            await page.reload()
            await asyncio.sleep(random.uniform(4, 6))

        username_inputs = await page.locator('input[name="username"]').count()

        if username_inputs == 0:
            html_snippet = (await page.content())[:800].replace("\n", " ")
            logging.error(f"[PLOGIN] Login form still missing. URL={page.url}")
            await browser.close()
            raise ValueError("ERROR_010: Login form not loaded (Instagram intro/splash page)")

        # ================= HUMAN TYPE =================
        username_input = page.locator('input[name="username"]')
        password_input = page.locator('input[name="password"]')
        login_button = page.locator('button[type="submit"]').first

        # username typing
        await username_input.click()
        await asyncio.sleep(random.uniform(0.3, 0.8))
        await username_input.fill("")
        await username_input.type(username, delay=random.randint(60, 120))

        # password typing
        await asyncio.sleep(random.uniform(0.4, 1.0))
        await password_input.click()
        await asyncio.sleep(random.uniform(0.3, 0.8))
        await password_input.fill("")
        await password_input.type(password, delay=random.randint(60, 120))

        # click login
        await asyncio.sleep(random.uniform(1.0, 2.0))
        await login_button.click()

        logging.info("[PLOGIN] Submitted login form")

        # ================= WAIT AFTER LOGIN =================
        await asyncio.sleep(5)

        current_url = page.url
        logging.info(f"[PLOGIN] After login URL = {current_url}")

        # ================= FIX 2: OTP DETECTION =================
        otp_locator = page.locator('input[name="verificationCode"]')
        otp_count = await otp_locator.count()

        if otp_count > 0 or "challenge" in current_url or "two_factor" in current_url:
            await browser.close()
            raise ValueError("ERROR_OTP: OTP / Challenge required")

        # ================= FIX 3: LOGIN FAILED DETECTION =================
        if "accounts/login" in current_url:
            await browser.close()
            raise ValueError("ERROR_LOGIN_FAILED: Wrong username/password or blocked")

        # ================= FIX 4: SUCCESS VALIDATION =================
        if "instagram.com" not in current_url:
            await browser.close()
            raise ValueError("ERROR_UNKNOWN: Unexpected redirect after login")

        logging.info("[PLOGIN] Login successful, saving session...")

        # ================= SAVE STORAGE STATE =================
        await asyncio.sleep(3)
        await context.storage_state(path=COOKIE_FILE)

        logging.info(f"[PLOGIN] Storage state saved -> {COOKIE_FILE}")

        await browser.close()
        logging.info("[PLOGIN] Browser closed")

    return COOKIE_FILE


# 🧩 Monkeypatch instagrapi to fix validation crash
try:
    import instagrapi.extractors as extractors
    _orig_extract_reply_message = extractors.extract_reply_message

    def patched_extract_reply_message(data):
        data = _sanitize_timestamps(data)
        return _orig_extract_reply_message(data)

    extractors.extract_reply_message = patched_extract_reply_message
    print("[Patch] Applied timestamp sanitizer to instagrapi extractors ✅")
except Exception as e:
    print(f"[Patch Warning] Could not patch instagrapi: {e}")
# === END PATCH ===

# --- Playwright sync helper: run sync_playwright() inside a fresh thread ---
def run_with_sync_playwright(fn, *args, **kwargs):
    """
    Runs `fn(p, *args, **kwargs)` where p is the object returned by sync_playwright()
    inside a new thread and returns fn's return value (or raises exception).
    """
    result = {"value": None, "exc": None}

    def target():
        try:
            with sync_playwright() as p:
                result["value"] = fn(p, *args, **kwargs)
        except Exception as e:
            result["exc"] = e

    t = threading.Thread(target=target)
    t.start()
    t.join()
    if result["exc"]:
        raise result["exc"]
    return result["value"]

def load_authorized():
    global authorized_users
    if os.path.exists(AUTHORIZED_FILE):
        with open(AUTHORIZED_FILE, 'r') as f:
            authorized_users = json.load(f)
    # Ensure owner is authorized
    if not any(u['id'] == OWNER_TG_ID for u in authorized_users):
        authorized_users.append({'id': OWNER_TG_ID, 'username': 'owner'})

load_authorized()

def load_users_data():
    global users_data
    users_data = {}
    for file in os.listdir('.'):
        if file.startswith('user_') and file.endswith('.json'):
            user_id_str = file[5:-5]
            if user_id_str.isdigit():
                user_id = int(user_id_str)
                with open(file, 'r') as f:
                    data = json.load(f)
                # Defaults
                if 'pairs' not in data:
                    data['pairs'] = None
                if 'switch_minutes' not in data:
                    data['switch_minutes'] = 10
                if 'threads' not in data:
                    data['threads'] = 1
                users_data[user_id] = data

load_users_data()

def save_authorized():
    with open(AUTHORIZED_FILE, 'w') as f:
        json.dump(authorized_users, f)

def save_user_data(user_id: int, data: Dict):
    with open(f'user_{user_id}.json', 'w') as f:
        json.dump(data, f)

def is_authorized(user_id: int) -> bool:
    return any(u['id'] == user_id for u in authorized_users)

def is_owner(user_id: int) -> bool:
    return user_id == OWNER_TG_ID

def future_expiry(days=365):
    return int(time.time()) + days*24*3600

def convert_for_playwright(insta_file, playwright_file):
    try:
        with open(insta_file, "r") as f:
            data = json.load(f)
    except Exception as e:
        return

    cookies = []
    auth = data.get("authorization_data", {})
    for name, value in auth.items():
        cookies.append({
            "name": name,
            "value": urllib.parse.unquote(value),
            "domain": ".instagram.com",
            "path": "/",
            "expires": future_expiry(),
            "httpOnly": True,
            "secure": True,
            "sameSite": "Lax"
        })

    playwright_state = {
        "cookies": cookies,
        "origins": [{"origin": "https://www.instagram.com", "localStorage": []}]
    }

    with open(playwright_file, "w") as f:
        json.dump(playwright_state, f, indent=4)

def get_storage_state_from_instagrapi(settings: Dict):
    cl = Client()
    cl.set_settings(settings)

    # Collect cookies from instagrapi structures (compatible with multiple instagrapi versions)
    cookies_dict = {}
    if hasattr(cl, "session") and cl.session:
        try:
            cookies_dict = cl.session.cookies.get_dict()
        except Exception:
            cookies_dict = {}
    elif hasattr(cl, "private") and hasattr(cl.private, "cookies"):
        try:
            cookies_dict = cl.private.cookies.get_dict()
        except Exception:
            cookies_dict = {}
    elif hasattr(cl, "_http") and hasattr(cl._http, "cookies"):
        try:
            cookies_dict = cl._http.cookies.get_dict()
        except Exception:
            cookies_dict = {}

    cookies = []
    for name, value in cookies_dict.items():
        cookies.append({
            "name": name,
            "value": value,
            "domain": ".instagram.com",
            "path": "/",
            "expires": int(time.time()) + 365*24*3600,
            "httpOnly": True,
            "secure": True,
            "sameSite": "Lax"
        })

    storage_state = {
        "cookies": cookies,
        "origins": [{"origin": "https://www.instagram.com", "localStorage": []}]
    }
    return storage_state

def instagrapi_login(username, password):
    """
    🔥 FINAL STABLE INSTAGRAPI LOGIN FUNCTION
    ✔ session reuse
    ✔ auto relogin
    ✔ latest device spoof
    ✔ challenge + 2FA handling
    ✔ rate-limit protection
    ✔ playwright state conversion
    """

    import os, json, time, random
    from instagrapi import Client
    from instagrapi.exceptions import (
        ChallengeRequired,
        TwoFactorRequired,
        PleaseWaitFewMinutes,
        RateLimitError,
        LoginRequired,
    )

    username = username.strip().lower()

    # ================= INIT CLIENT =================
    cl = Client()

    # ================= 🔥 BEST DEVICE PROFILE =================
    cl.set_device({
        "app_version": "312.0.0.32.111",
        "android_version": 31,
        "android_release": "12.0",
        "dpi": "420dpi",
        "resolution": "1080x2400",
        "manufacturer": "Samsung",
        "device": "SM-G991B",
        "model": "Galaxy S21",
        "cpu": "arm64-v8a",
    })

    # human delay settings
    cl.delay_range = [1, 3]

    # ================= FILE PATHS =================
    os.makedirs("sessions", exist_ok=True)
    session_file = f"sessions/{username}_session.json"
    playwright_file = f"sessions/{username}_state.json"

    # small human delay
    def human_delay(a=2.0, b=4.5):
        time.sleep(random.uniform(a, b))

    try:
        # ======================================================
        # 🔁 STEP 1: LOAD EXISTING SESSION
        # ======================================================
        if os.path.exists(session_file):
            try:
                cl.load_settings(session_file)

                # verify session
                try:
                    cl.get_timeline_feed()
                    print(f"[LOGIN] ♻️ Session reused for {username}")
                except LoginRequired:
                    print(f"[LOGIN] ⚠️ Session expired → relogin {username}")
                    cl.login(username, password)
                    human_delay()

            except Exception as e:
                print(f"[LOGIN] ⚠️ Corrupt session → fresh login: {e}")
                cl.login(username, password)
                human_delay()

        else:
            # no session → fresh login
            print(f"[LOGIN] 🔐 Fresh login for {username}")
            cl.login(username, password)
            human_delay()

        # ======================================================
        # 🔐 STEP 2: FINAL SESSION VALIDATION
        # ======================================================
        try:
            cl.get_timeline_feed()
        except LoginRequired:
            print(f"[LOGIN] ❌ Session invalid, retry login once more: {username}")
            cl.login(username, password)
            human_delay()
            cl.get_timeline_feed()

        # ======================================================
        # 💾 STEP 3: SAVE SESSION
        # ======================================================
        cl.dump_settings(session_file)

        # ======================================================
        # 🔄 STEP 4: CONVERT TO PLAYWRIGHT STORAGE
        # ======================================================
        convert_for_playwright(session_file, playwright_file)

        # ======================================================
        # 📦 STEP 5: LOAD & RETURN STATE
        # ======================================================
        with open(playwright_file, "r") as f:
            state = json.load(f)

        print(f"[LOGIN] ✅ SUCCESS → {username}")
        return state

    # ================= ERROR HANDLING =================

    except TwoFactorRequired:
        raise ValueError("ERROR_004: 2FA required")

    except ChallengeRequired:
        try:
            # try auto resolve
            cl.challenge_resolve(cl.last_json)
            cl.get_timeline_feed()
            cl.dump_settings(session_file)
            convert_for_playwright(session_file, playwright_file)
            return json.load(open(playwright_file))
        except Exception:
            raise ValueError("ERROR_004: Challenge required")

    except PleaseWaitFewMinutes:
        raise ValueError("ERROR_002: Please wait a few minutes (rate limit)")

    except RateLimitError:
        raise ValueError("ERROR_002: Rate limit exceeded")

    except Exception as e:
        raise ValueError(f"ERROR_007: Login failed - {str(e)}")

def list_group_chats(user_id, storage_state, username, password, max_groups=10, amount=10):
    """
    Fetch Instagram group chats safely with auto re-login & session sync.
    COMPLETELY FIXED VERSION - 100% Working
    Returns:
        groups: list of {display, url}
        new_state: updated playwright storage_state
    """
    username = username.strip().lower()
    norm_username = username

    session_file = f"sessions/{user_id}_{norm_username}_session.json"
    playwright_file = f"sessions/{user_id}_{norm_username}_state.json"

    cl = Client()
    updated = False
    new_state = None
    
    print(f"[DEBUG] Starting list_group_chats for {username}")

    # -----------------------------
    # 🔐 LOAD EXISTING SESSION
    # -----------------------------
    if os.path.exists(session_file):
        try:
            cl.load_settings(session_file)
            print(f"[DEBUG] Loaded session from {session_file}")

            # Verify session is valid with multiple methods
            session_valid = False
            
            # Method 1: Try to get user_id
            try:
                test_id = cl.user_id
                if test_id:
                    session_valid = True
                    print(f"[DEBUG] Session validated via user_id: {test_id}")
            except:
                pass
            
            # Method 2: Try a simple API call
            if not session_valid:
                try:
                    cl.get_timeline_feed()
                    session_valid = True
                    print("[DEBUG] Session validated via timeline feed")
                except Exception as e:
                    print(f"[DEBUG] Timeline feed validation failed: {e}")
            
            if not session_valid:
                raise Exception("Session expired")

        except Exception as e:
            print(f"[DEBUG] Session invalid, relogging: {e}")
            try:
                print(f"[DEBUG] Attempting re-login for {username}")
                cl.login(username, password)
                cl.dump_settings(session_file)
                convert_for_playwright(session_file, playwright_file)
                updated = True
                print(f"[DEBUG] Re-login successful for {username}")
            except Exception as e:
                print(f"[ERROR] Re-login failed: {e}")
                return [], storage_state
    else:
        print(f"[DEBUG] No session file, logging in fresh for {username}")
        try:
            cl.login(username, password)
            cl.dump_settings(session_file)
            convert_for_playwright(session_file, playwright_file)
            updated = True
            print(f"[DEBUG] Fresh login successful for {username}")
        except Exception as e:
            print(f"[ERROR] Login failed: {e}")
            return [], storage_state

    # -----------------------------
    # 📥 FETCH THREADS - MULTIPLE METHODS
    # -----------------------------
    all_threads = []
    
    try:
        # Method 1: direct_threads (primary method)
        print(f"[DEBUG] Fetching direct_threads (amount={amount})...")
        threads = cl.direct_threads(amount=amount)
        if threads:
            all_threads.extend(threads)
            print(f"[DEBUG] Found {len(threads)} threads via direct_threads")
        
        # Method 2: direct_inbox (alternative method)
        print("[DEBUG] Trying direct_inbox...")
        inbox = cl.direct_inbox(amount=amount)
        if inbox and hasattr(inbox, 'threads'):
            inbox_threads = inbox.threads
            # Avoid duplicates by checking thread IDs
            existing_ids = {getattr(t, 'id', None) or getattr(t, 'thread_id', None) for t in all_threads if t}
            for t in inbox_threads:
                t_id = getattr(t, 'id', None) or getattr(t, 'thread_id', None)
                if t_id not in existing_ids:
                    all_threads.append(t)
                    existing_ids.add(t_id)
            print(f"[DEBUG] Added {len(inbox_threads)} threads via direct_inbox")
        
        # Method 3: direct_pending_inbox
        print("[DEBUG] Trying direct_pending_inbox...")
        pending = cl.direct_pending_inbox(amount=amount)
        if pending:
            pending_ids = {getattr(t, 'id', None) or getattr(t, 'thread_id', None) for t in all_threads if t}
            for t in pending:
                t_id = getattr(t, 'id', None) or getattr(t, 'thread_id', None)
                if t_id not in pending_ids:
                    all_threads.append(t)
                    pending_ids.add(t_id)
            print(f"[DEBUG] Added {len(pending)} threads via pending inbox")
            
    except Exception as e:
        print(f"[DEBUG] Error fetching threads: {e}")
    
    # Remove None values and duplicates
    all_threads = [t for t in all_threads if t is not None]
    
    # If still no threads, try one more time with larger amount
    if not all_threads:
        try:
            print("[DEBUG] Final attempt - fetching with amount=30...")
            threads = cl.direct_threads(amount=30)
            all_threads = threads
            print(f"[DEBUG] Found {len(threads)} threads in final attempt")
        except Exception as e:
            print(f"[DEBUG] Final attempt failed: {e}")
            return [], storage_state

    time.sleep(random.uniform(1.0, 2.5))

    # -----------------------------
    # 🎯 FILTER GROUPS - COMPLETE DETECTION
    # -----------------------------
    groups = []
    processed_ids = set()
    
    print(f"[DEBUG] Processing {len(all_threads)} threads for groups...")
    
    for idx, thread in enumerate(all_threads):
        if len(groups) >= max_groups:
            break

        try:
            # Get thread data safely
            thread_dict = {}
            if hasattr(thread, 'dict'):
                try:
                    thread_dict = thread.dict()
                except:
                    pass
            elif hasattr(thread, '__dict__'):
                thread_dict = thread.__dict__
            
            # Extract thread properties with multiple fallbacks
            thread_id = None
            for id_attr in ['thread_id', 'id', 'pk', 'cid']:
                if hasattr(thread, id_attr):
                    thread_id = getattr(thread, id_attr)
                    break
                elif thread_dict.get(id_attr):
                    thread_id = thread_dict.get(id_attr)
                    break
            
            if not thread_id or thread_id in processed_ids:
                continue
            processed_ids.add(thread_id)
            
            # Get thread type
            thread_type = None
            if hasattr(thread, 'thread_type'):
                thread_type = thread.thread_type
            elif thread_dict.get('thread_type'):
                thread_type = thread_dict.get('thread_type')
            
            # Get thread title
            thread_title = None
            for title_attr in ['thread_title', 'title', 'name', 'custom_name']:
                if hasattr(thread, title_attr):
                    thread_title = getattr(thread, title_attr)
                    break
                elif thread_dict.get(title_attr):
                    thread_title = thread_dict.get(title_attr)
                    break
            
            # Get users list
            users = []
            if hasattr(thread, 'users'):
                users = thread.users
            elif thread_dict.get('users'):
                users = thread_dict.get('users')
            
            # Get inviter
            inviter = None
            if hasattr(thread, 'inviter'):
                inviter = thread.inviter
            elif thread_dict.get('inviter'):
                inviter = thread_dict.get('inviter')
            
            print(f"[DEBUG] Thread {idx+1}: ID={thread_id}, Type={thread_type}, Title={thread_title}, Users={len(users)}")
            
            # ============= GROUP DETECTION CRITERIA =============
            is_group = False
            reasons = []
            
            # CRITERION 1: Check thread_type
            # Instagram thread types: 1 = one-to-one, 2 = group
            if thread_type in [2, '2', 'GROUP', 'group']:
                is_group = True
                reasons.append(f"type={thread_type}")
            
            # CRITERION 2: Check is_group attribute
            if hasattr(thread, 'is_group') and thread.is_group:
                is_group = True
                reasons.append("is_group=True")
            elif thread_dict.get('is_group') is True:
                is_group = True
                reasons.append("dict_is_group=True")
            
            # CRITERION 3: Check users count (groups have 2+ other users)
            if len(users) >= 2:
                is_group = True
                reasons.append(f"users_count={len(users)}")
            
            # CRITERION 4: Check for thread title (groups usually have titles)
            if thread_title and thread_title.strip() and len(thread_title.strip()) > 0:
                is_group = True
                reasons.append("has_title")
            
            # CRITERION 5: Check if it's a one-to-one chat (exclude these)
            if len(users) == 1 and not thread_title:
                print(f"[DEBUG] Thread {idx+1}: Skipping - one-to-one DM")
                continue
            
            # CRITERION 6: Check for group-specific fields
            if thread_dict.get('is_group') is not None:
                is_group = is_group or thread_dict.get('is_group')
            
            # If still not identified as group, skip
            if not is_group:
                continue
            
            print(f"[DEBUG] Thread {idx+1}: ✓ IDENTIFIED AS GROUP - {', '.join(reasons)}")
            
            # ============= BUILD GROUP DISPLAY NAME =============
            display_name = ""
            
            # Try to use thread title first
            if thread_title and thread_title.strip():
                display_name = thread_title.strip()
            else:
                # Generate name from participants
                participant_names = []
                for u in users[:3]:  # First 3 participants
                    if hasattr(u, 'username') and u.username:
                        participant_names.append(f"@{u.username}")
                    elif hasattr(u, 'full_name') and u.full_name:
                        participant_names.append(u.full_name)
                    elif isinstance(u, dict):
                        if u.get('username'):
                            participant_names.append(f"@{u['username']}")
                        elif u.get('full_name'):
                            participant_names.append(u['full_name'])
                
                if participant_names:
                    display_name = ", ".join(participant_names)
                    if len(users) > 3:
                        display_name += f" +{len(users)-3} more"
                else:
                    display_name = "Group Chat"
            
            # Calculate member count (including self)
            member_count = len(users) + 1  # +1 for self
            if inviter:
                member_count = max(member_count, len(users) + 1)
            
            # Add member count to display
            if member_count > 0:
                display_name = f"{display_name} ({member_count})"
            
            # Build URL
            url = f"https://www.instagram.com/direct/t/{thread_id}/"
            
            groups.append({
                "display": display_name,
                "url": url,
                "member_count": member_count,
                "thread_id": thread_id
            })
            
            print(f"[DEBUG] ✓ Added group {len(groups)}: {display_name}")

        except Exception as e:
            print(f"[DEBUG] Error processing thread {idx}: {e}")
            continue

    # Sort groups by member count (largest first) for better UX
    groups.sort(key=lambda x: x['member_count'], reverse=True)
    
    print(f"[DEBUG] 🎯 FINAL: Found {len(groups)} group chats")

    # -----------------------------
    # 🔁 SYNC PLAYWRIGHT STATE
    # -----------------------------
    try:
        if updated:
            settings = cl.get_settings()
            new_state = get_storage_state_from_instagrapi(settings)
            with open(playwright_file, "w") as f:
                json.dump(new_state, f, indent=2)
            print(f"[DEBUG] ✓ Updated playwright state saved to {playwright_file}")
        elif os.path.exists(playwright_file):
            with open(playwright_file, "r") as f:
                new_state = json.load(f)
            print(f"[DEBUG] ✓ Loaded existing playwright state from {playwright_file}")
        else:
            new_state = storage_state
            print(f"[DEBUG] Using provided storage state")
    except Exception as e:
        print(f"[WARN] Failed to update storage state: {e}")
        new_state = storage_state

    return groups, new_state

def get_dm_thread_url(user_id, username, password, target_username):
    """
    Get DM thread URL for a single user (non-group).
    Auto-fixes expired session + syncs Playwright state.
    """

    username = username.strip().lower()
    target_username = target_username.strip().lower()

    session_file = f"sessions/{user_id}_{username}_session.json"
    playwright_file = f"sessions/{user_id}_{username}_state.json"

    cl = Client()
    updated = False

    # -----------------------------
    # 🔐 LOAD / FIX SESSION
    # -----------------------------
    if os.path.exists(session_file):
        try:
            cl.load_settings(session_file)

            # validate session
            try:
                cl.get_timeline_feed()
            except LoginRequired:
                raise Exception("Session expired")

        except Exception:
            try:
                cl.login(username, password)
                cl.dump_settings(session_file)
                convert_for_playwright(session_file, playwright_file)
                updated = True
            except Exception as e:
                print(f"[ERROR] Login failed: {e}")
                return None
    else:
        # no session → login fresh
        try:
            cl.login(username, password)
            cl.dump_settings(session_file)
            convert_for_playwright(session_file, playwright_file)
            updated = True
        except Exception as e:
            print(f"[ERROR] Login failed: {e}")
            return None

    # -----------------------------
    # 📥 FETCH THREADS
    # -----------------------------
    try:
        threads = cl.direct_threads(amount=15)
        time.sleep(random.uniform(0.8, 1.8))

    except LoginRequired:
        # retry login once more
        try:
            print("[AUTO FIX] Session expired again, relogging...")
            cl.login(username, password)
            cl.dump_settings(session_file)
            convert_for_playwright(session_file, playwright_file)
            updated = True

            threads = cl.direct_threads(amount=15)
            time.sleep(random.uniform(0.8, 1.8))

        except Exception as e:
            print(f"[ERROR] Failed after relogin: {e}")
            return None

    except Exception as e:
        print(f"[ERROR] Thread fetch failed: {e}")
        return None

    # -----------------------------
    # 🔎 FIND TARGET DM THREAD
    # -----------------------------
    for thread in threads:
        try:
            # skip groups
            if getattr(thread, "is_group", True):
                continue

            users = getattr(thread, "users", [])
            if len(users) != 1:
                continue

            user = users[0]
            if user.username.lower() != target_username:
                continue

            thread_id = getattr(thread, "thread_id", None) or getattr(thread, "id", None)
            if not thread_id:
                continue

            url = f"https://www.instagram.com/direct/t/{thread_id}/"

            # -----------------------------
            # 🔁 UPDATE PLAYWRIGHT STATE
            # -----------------------------
            if updated:
                try:
                    settings = cl.get_settings()
                    new_state = get_storage_state_from_instagrapi(settings)
                    with open(playwright_file, "w") as f:
                        json.dump(new_state, f)
                except Exception as e:
                    print(f"[WARN] Failed to update playwright state: {e}")

            return url

        except Exception:
            continue

    # -----------------------------
    # ❌ NOT FOUND
    # -----------------------------
    return None

def perform_login(page, username, password):
    try:
        page.evaluate("""() => {
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
            Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
            Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
            window.chrome = { app: {}, runtime: {} };
            const originalQuery = window.navigator.permissions.query;
            window.navigator.permissions.query = (parameters) => (
                parameters.name === 'notifications' ?
                Promise.resolve({ state: 'denied' }) :
                originalQuery(parameters)
            );
            const getParameter = WebGLRenderingContext.prototype.getParameter;
            WebGLRenderingContext.prototype.getParameter = function(parameter) {
                if (parameter === 37445) return 'Google Inc. (Intel)';
                if (parameter === 37446) return 'ANGLE (Intel, Intel(R) UHD Graphics 630 (0x00003E9B) Direct3D11 vs_5_0 ps_5_0, D3D11)';
                return getParameter.call(this, parameter);
            };
        }""")

        username_locator = page.locator('input[name="username"]')
        username_locator.wait_for(state='visible', timeout=10000)
        username_locator.focus()
        time.sleep(random.uniform(0.5, 1.5))
        for char in username:
            username_locator.press(char)
            time.sleep(random.uniform(0.05, 0.15))

        password_locator = page.locator('input[name="password"]')
        password_locator.wait_for(state='visible', timeout=10000)
        time.sleep(random.uniform(0.5, 1.5))
        password_locator.focus()
        time.sleep(random.uniform(0.3, 0.8))
        for char in password:
            password_locator.press(char)
            time.sleep(random.uniform(0.05, 0.15))

        time.sleep(random.uniform(1.0, 2.5))

        submit_locator = page.locator('button[type="submit"]')
        submit_locator.wait_for(state='visible', timeout=10000)
        if not submit_locator.is_enabled():
            raise Exception("Submit button not enabled")
        submit_locator.click()

        try:
            page.wait_for_url(lambda url: 'accounts/login' not in url and 'challenge' not in url and 'two_factor' not in url, timeout=60000)
            
            if page.locator('[role="alert"]').count() > 0:
                error_text = page.locator('[role="alert"]').inner_text().lower()
                if 'incorrect' in error_text or 'wrong' in error_text:
                    raise ValueError("ERROR_001: Invalid credentials")
                elif 'wait' in error_text or 'few minutes' in error_text or 'too many' in error_text:
                    raise ValueError("ERROR_002: Rate limit exceeded")
                else:
                    raise ValueError(f"ERROR_003: Login error - {error_text}")
        except TimeoutError:
            current_url = page.url
            page_content = page.content().lower()
            if 'challenge' in current_url:
                raise ValueError("ERROR_004: Login challenge required")
            elif 'two_factor' in current_url or 'verify' in current_url:
                raise ValueError("ERROR_005: 2FA verification required")
            elif '429' in page_content or 'rate limit' in page_content or 'too many requests' in page_content:
                raise ValueError("ERROR_002: Rate limit exceeded")
            elif page.locator('[role="alert"]').count() > 0:
                error_text = page.locator('[role="alert"]').inner_text().lower()
                raise ValueError(f"ERROR_006: Login failed - {error_text}")
            else:
                raise ValueError("ERROR_007: Login timeout or unknown error")

        logging.info("Login successful")
    except Exception as e:
        logging.error(f"Login failed: {str(e)}")
        raise

# ---------------- Globals for PTY ----------------
APP = None
LOOP = None
SESSIONS = {}
SESSIONS_LOCK = threading.Lock()

# ---------------- Child PTY login ----------------
def child_login(user_id: int, username: str, password: str):
    from instagrapi import Client
    from instagrapi.exceptions import (
        TwoFactorRequired,
        ChallengeRequired,
        PleaseWaitFewMinutes,
        RateLimitError,
        LoginRequired,
    )
    import time, sys

    cl = Client()
    username = username.strip().lower()

    session_file = f"sessions/{user_id}_{username}_session.json"
    playwright_file = f"sessions/{user_id}_{username}_state.json"

    try:
        print(f"[{username}] ⚙️ Attempting login... If stuck, check email/SMS for OTP and enter here (e.g. 192122)")

        # -------- PRIMARY LOGIN --------
        cl.login(username, password)

        # -------- VERIFY SESSION (IMPORTANT FIX) --------
        try:
            cl.get_timeline_feed()
        except LoginRequired:
            raise Exception("Session not valid after login")

        # -------- SAVE SESSION --------
        cl.dump_settings(session_file)
        convert_for_playwright(session_file, playwright_file)

        print(f"[{username}] ✅ Logged in successfully. Session saved: {session_file}")

    # ========================= 2FA =========================
    except TwoFactorRequired:
        print(f"[{username}] 🔐 2FA required")
        print(f" Enter code (6 digits) for {username} (2FA): ", end="", flush=True)

        otp = input().strip()

        try:
            cl.login(username, password, verification_code=otp)

            # verify again
            cl.get_timeline_feed()

            cl.dump_settings(session_file)
            convert_for_playwright(session_file, playwright_file)

            print(f"[{username}] ✅ OTP resolved. Logged in. Session saved: {session_file}")

        except Exception as e:
            print(f"[{username}] ❌ OTP failed: {str(e)}")

    # ========================= CHALLENGE =========================
    except ChallengeRequired:
        print(f"[{username}] 🔐 Challenge verification required")
        print(f" Enter code (6 digits) for {username} (Challenge): ", end="", flush=True)

        otp = input().strip()

        try:
            cl.challenge_resolve(cl.last_json, security_code=otp)

            # verify session
            cl.get_timeline_feed()

            cl.dump_settings(session_file)
            convert_for_playwright(session_file, playwright_file)

            print(f"[{username}] ✅ Challenge resolved. Logged in. Session saved: {session_file}")

        except Exception as e:
            print(f"[{username}] ❌ Challenge OTP failed: {str(e)}")

    # ========================= RATE LIMIT =========================
    except (PleaseWaitFewMinutes, RateLimitError):
        print(f"[{username}] ⏳ Rate limited by Instagram. Please wait 20–30 minutes before retrying.")

    # ========================= GENERIC ERROR =========================
    except Exception as e:
        print(f"[{username}] ❌ Login failed: {str(e)}")

    # ========================= EXIT CLEANLY =========================
    finally:
        time.sleep(0.5)
        sys.exit(0)

# ---------------- PTY reader thread ----------------
def reader_thread(user_id: int, chat_id: int, master_fd: int, username: str, password: str):
    global APP, LOOP
    buf = b""
    while True:
        try:
            data = os.read(master_fd, 1024)
            if not data:
                break
            buf += data
            while b"\n" in buf or len(buf) > 2048:
                if b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    text = line.decode(errors="ignore").strip()
                else:
                    text = buf.decode(errors="ignore")
                    buf = b""
                if not text:
                    continue
                if text.startswith("Code entered"):
                    continue
                lower = text.lower()
                if (
                    len(text) > 300
                    or "cdninstagram.com" in lower
                    or "http" in lower
                    or "{" in text
                    or "}" in text
                    or "debug" in lower
                    or "info" in lower
                    or "urllib3" in lower
                    or "connection" in lower
                    or "starting new https" in lower
                    or "instagrapi" in lower
                ):
                    continue
                try:
                    if APP and LOOP:
                        asyncio.run_coroutine_threadsafe(
                            APP.bot.send_message(chat_id=chat_id, text=f"🔥{text}"), LOOP
                        )
                except Exception:
                    logging.error("[THREAD] send_message failed")
        except OSError as e:
            if e.errno == errno.EIO:
                break
            else:
                logging.error("[THREAD] PTY read error: %s", e)
                break
        except Exception as e:
            logging.error("[THREAD] Unexpected error: %s", e)
            break
    try:
        playwright_file = f"sessions/{user_id}_{username}_state.json"
        if os.path.exists(playwright_file):
            with open(playwright_file, 'r') as f:
                state = json.load(f)
            if user_id in users_data:
                data = users_data[user_id]
            else:
                data = {'accounts': [], 'default': None, 'pairs': None, 'switch_minutes': 10, 'threads': 1}
            # normalize incoming username
            norm_username = username.strip().lower()

            for i, acc in enumerate(data['accounts']):
                if acc.get('ig_username', '').strip().lower() == norm_username:
                    # overwrite existing entry for exact same username (normalized)
                    data['accounts'][i] = {'ig_username': norm_username, 'password': password, 'storage_state': state}
                    data['default'] = i
                    break
            else:
                # not found -> append new normalized account
                data['accounts'].append({'ig_username': norm_username, 'password': password, 'storage_state': state})
                data['default'] = len(data['accounts']) - 1
            save_user_data(user_id, data)
            users_data[user_id] = data
            if APP and LOOP:
                asyncio.run_coroutine_threadsafe(APP.bot.send_message(chat_id=chat_id, text="✅ Login successful and saved securely! 🎉"), LOOP)
        else:
            if APP and LOOP:
                asyncio.run_coroutine_threadsafe(APP.bot.send_message(chat_id=chat_id, text="⚠️ Login failed. No session saved."), LOOP)
    except Exception as e:
        logging.error("Failed to save user data: %s", e)
        if APP and LOOP:
            asyncio.run_coroutine_threadsafe(APP.bot.send_message(chat_id=chat_id, text=f"⚠️ Error saving data: {str(e)}"), LOOP)
    finally:
        with SESSIONS_LOCK:
            if user_id in SESSIONS:
                try:
                    os.close(SESSIONS[user_id]["master_fd"])
                except Exception:
                    pass
                SESSIONS.pop(user_id, None)

# ---------------- Relay input ----------------
async def relay_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    text = update.message.text
    with SESSIONS_LOCK:
        info = SESSIONS.get(user_id)
    if not info:
        return
    master_fd = info["master_fd"]
    try:
        os.write(master_fd, (text + "\n").encode())
    except OSError as e:
        await update.message.reply_text(f"Failed to write to PTY stdin: {e}")
    except Exception as e:
        logging.error("Relay input error: %s", e)

async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    text = update.message.text.strip()
    if user_id in waiting_for_otp:
        if len(text) == 6 and text.isdigit():
            user_queues[user_id].put(text)
            del waiting_for_otp[user_id]
            await update.message.reply_text("✅ Code submitted to browser! 🔄")
            return
        else:
            await update.message.reply_text("❌ Invalid code. Please enter 6-digit code.")
            return
    # Fallback to relay
    await relay_input(update, context)

# ---------------- Kill command ----------------
async def cmd_kill(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    with SESSIONS_LOCK:
        info = SESSIONS.get(user_id)
    if not info:
        await update.message.reply_text("No active PTY session.")
        return
    pid = info["pid"]
    master_fd = info["master_fd"]
    try:
        os.kill(pid, 15)
    except Exception:
        pass
    try:
        os.close(master_fd)
    except Exception:
        pass
    with SESSIONS_LOCK:
        SESSIONS.pop(user_id, None)
    await update.message.reply_text(f"🛑 Stopped login terminal (pid={pid}) successfully.")

# ---------------- Flush command ----------------
async def flush(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not is_owner(user_id):
        await update.message.reply_text("⚠️ you are not an admin ⚠️")
        return
    global users_tasks, persistent_tasks
    for uid, tasks in users_tasks.items():
        for task in tasks[:]:
            proc = task['proc']
            proc.terminate()
            await asyncio.sleep(3)
            if proc.poll() is None:
                proc.kill()
            # remove from runtime map if present
            pid = task.get('pid')
            if pid in running_processes:
                running_processes.pop(pid, None)
            if task.get('type') == 'message_attack' and 'names_file' in task:
                names_file = task['names_file']
                if os.path.exists(names_file):
                    os.remove(names_file)
            logging.info(f"{time.strftime('%Y-%m-%d %H:%M:%S')} Task stop user={uid} task={task['id']} by flush")
            mark_task_stopped_persistent(task['id'])
            tasks.remove(task)
        users_tasks[uid] = tasks
    await update.message.reply_text("🛑 All tasks globally stopped! 🛑")

PSID_SESSION, PSID_USERNAME = range(2)
USERNAME, PASSWORD = range(2)
PLO_USERNAME, PLO_PASSWORD = range(2)
SLOG_SESSION, SLOG_USERNAME = range(2)

# ================= ꜰʟᴀꜱʜ ʙᴏᴛ =================
# ⚡ ᴍᴀᴅᴇ ᴡɪᴛʜ ❤️ ʙʏ @Why_NoT_Zarko

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import ContextTypes

# ================= ᴄᴏɴꜰɪɢᴜʀᴀᴛɪᴏɴ =================
CHANNEL_LINK = "https://t.me/+Vcpn1Nt8D0gwMjFl"
SUPPORT_LINK = "https://t.me/+Vcpn1Nt8D0gwMjFl"
PHOTO_URL = "https://i.ibb.co/W41tzvys/x.jpg"

# ================= ʙᴜᴛᴛᴏɴꜱ =================
START_BUTTON = InlineKeyboardMarkup([
    [
        InlineKeyboardButton("• ᴄʜᴀɴɴᴇʟ •", url=CHANNEL_LINK),
        InlineKeyboardButton("• ꜱᴜᴘᴘᴏʀᴛ •", url=SUPPORT_LINK)
    ]
])

# ================= ʜᴇʟᴘᴇʀ ꜰᴜɴᴄᴛɪᴏɴꜱ =================
def create_start_text(user_name: str, user_id: int, bot_name: str, bot_id: int) -> str:
    """Generate formatted start message"""
    return (
        "┏━━━━━━━━━━━━━━━━━━━━━┓\n"
        "┃     ⚡ ꜰʟᴀꜱʜ ʙᴏᴛ ⚡     ┃\n"
        "┣━━━━━━━━━━━━━━━━━━━━━┫\n"
        "┃                     ┃\n"
        f"┃  ʜᴇʏ » {user_name}\n"
        f"┃  ɪᴅ  » {user_id}\n"
        "┃                     ┃\n"
        f"┃  ʙᴏᴛ » {bot_name}\n"
        f"┃  ɪᴅ  » {bot_id}\n"
        "┣━━━━━━━━━━━━━━━━━━━━━┫\n"
        "┃  ᴅᴇᴠ » @Why_NoT_ZarKo ┃\n"
        "┣━━━━━━━━━━━━━━━━━━━━━┫\n"
        "┃  📊 ʙᴏᴛ ɪɴꜰᴏʀᴍᴀᴛɪᴏɴ  ┃\n"
        "┣━━━━━━━━━━━━━━━━━━━━━┫\n"
        "┃ /help     ⚡ ʜᴇʟᴘ       ┃\n"
        "┃ /psid     🗝️ ʙʀᴏᴡꜱᴇʀ ꜱᴇꜱꜱɪᴏɴ    ┃\n"
        "┃  /pattack  💥 ᴍᴀɴᴜᴀʟ ꜱᴇɴᴅɪɴɢ     ┃\n"
        "┗━━━━━━━━━━━━━━━━━━━━━┛"
    )

# ================= /ꜱᴛᴀʀᴛ ᴄᴏᴍᴍᴀɴᴅ =================
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /start command with style"""
    
    # ꜰɪʟᴛᴇʀ ɢʀᴏᴜᴘ ᴄʜᴀᴛꜱ
    if update.effective_chat.type != "private":
        return

    try:
        # ɢᴇᴛ ʙᴏᴛ ɪɴꜰᴏ
        bot = await context.bot.get_me()
        bot_name = bot.first_name
        bot_id = bot.id

        # ɢᴇᴛ ᴜꜱᴇʀ ɪɴꜰᴏ
        user = update.effective_user
        user_name = user.first_name or "ᴜꜱᴇʀ"
        user_id = user.id

        # ɢᴇɴᴇʀᴀᴛᴇ ᴍᴇꜱꜱᴀɢᴇ
        text = create_start_text(user_name, user_id, bot_name, bot_id)

        # ꜱᴇɴᴅ ᴘʜᴏᴛᴏ ᴡɪᴛʜ ᴄᴀᴘᴛɪᴏɴ
        await update.message.reply_photo(
            photo=PHOTO_URL,
            caption=text,
            reply_markup=START_BUTTON,
            parse_mode='HTML'
        )

    except Exception as e:
        # ᴄʟᴇᴀɴ ᴇʀʀᴏʀ ʜᴀɴᴅʟɪɴɢ
        error_msg = f"❌ **ᴇʀʀᴏʀ:** `{str(e)}`"
        await update.message.reply_text(
            error_msg,
            parse_mode='MARKDOWN'
        )

    
async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not is_authorized(user_id):
        await update.message.reply_text("⚠️ ʏᴏᴜ ᴀʀᴇ ɴᴏᴛ ᴀᴜᴛʜᴏʀɪꜱᴇᴅ ᴛᴏ ᴜꜱᴇ, ᴅᴍ ᴏᴡɴᴇʀ ᴛᴏ ɢᴀɪɴ ᴀᴄᴄᴇꜱꜱ! @Why_not_ZarKo ⚠️")
        return
    
    help_text = """
╔══════════════════════════════════╗
║      ᴀᴠᴀɪʟᴀʙʟᴇ ᴄᴏᴍᴍᴀɴᴅꜱ 🌟       ║
╠══════════════════════════════════╣
║ /help     ⚡ ʜᴇʟᴘ                 ║
║ /login    📱 ʟᴏɢɪɴ               ║
║ /plogin   🔐 ʙʀᴏᴡꜱᴇʀ ʟᴏɢɪɴ       ║
║ /slogin   🔑 ꜱᴇꜱꜱɪᴏɴ ʟᴏɢɪɴ       ║
║ /psid     🗝️ ʙʀᴏᴡꜱᴇʀ ꜱᴇꜱꜱɪᴏɴ    ║
║ /viewmyac 👀 ᴠɪᴇᴡ ꜱᴀᴠᴇᴅ ᴀᴄᴄᴏᴜɴᴛꜱ ║
║ /setig    🔄 ꜱᴇᴛ ᴅᴇꜰᴀᴜʟᴛ ᴀᴄᴄ    ║
║ /pair     📦 ᴄʀᴇᴀᴛᴇ ᴘᴀɪʀ        ║
║ /unpair   ✨ ᴜɴᴘᴀɪʀ ᴀᴄᴄᴏᴜɴᴛꜱ    ║
║ /switch   ⏱️ ꜱᴇᴛ ɪɴᴛᴇʀᴠᴀʟ       ║
║ /threads  🔢 ꜱᴇᴛ ᴛʜʀᴇᴀᴅꜱ        ║
║ /viewpref ⚙️ ᴠɪᴇᴡ ᴘʀᴇꜰᴇʀᴇɴᴄᴇꜱ   ║
║ /attack   💥 ꜱᴛᴀʀᴛ ꜱᴇɴᴅɪɴɢ      ║
║ /pattack  💥 ᴍᴀɴᴜᴀʟ ꜱᴇɴᴅɪɴɢ    ║
║ /stop     🛑 ꜱᴛᴏᴘ ᴛᴀꜱᴋꜱ        ║
║ /task     📋 ᴠɪᴇᴡ ᴏɴɢᴏɪɴɢ ᴛᴀꜱᴋꜱ ║
║ /logout   🚪 ʟᴏɢᴏᴜᴛ ᴀᴄᴄᴏᴜɴᴛ     ║
║ /kill     🛑 ᴋɪʟʟ ꜱᴇꜱꜱɪᴏɴ       ║
║ /usg      📊 ꜱʏꜱᴛᴇᴍ ᴜꜱᴀɢᴇ       ║
╚══════════════════════════════════╝"""

    if is_owner(user_id):
        help_text += """
╔══════════════════════════════════╗
║        ᴀᴅᴍɪɴ ᴄᴏᴍᴍᴀɴᴅꜱ 👑         ║
╠══════════════════════════════════╣
║ /add    ➕ ᴀᴅᴅ ᴀᴜᴛʜᴏʀɪᴢᴇᴅ ᴜꜱᴇʀ   ║
║ /remove ➖ ʀᴇᴍᴏᴠᴇ ᴀᴜᴛʜᴏʀɪᴢᴇᴅ ᴜꜱᴇʀ ║
║ /users  📜 ʟɪꜱᴛ ᴀᴜᴛʜᴏʀɪᴢᴇᴅ ᴜꜱᴇʀꜱ ║
║ /flush  🧹 ꜱᴛᴏᴘ ᴀʟʟ ᴛᴀꜱᴋꜱ ɢʟᴏʙᴀʟʟʏ ║
╚══════════════════════════════════╝"""
    
    await update.message.reply_text(help_text)

async def psid_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    if not is_authorized(user_id):
        await update.message.reply_text("╔════════════════════╗\n║  ⚠️ ɴᴏᴛ ᴀᴜᴛʜᴏʀɪᴢᴇᴅ ║\n╚════════════════════╝")
        return ConversationHandler.END

    await update.message.reply_text("╔════════════════════╗\n║ 🔑 ᴇɴᴛᴇʀ ʏᴏᴜʀ     ║\n║ ɪɴꜱᴛᴀɢʀᴀᴍ         ║\n║ ꜱᴇꜱꜱɪᴏɴɪᴅ:         ║\n╚════════════════════╝")
    return PSID_SESSION

def playwright_test_session(sessionid: str):
    """
    Test Instagram sessionid using Playwright
    Returns: (success: bool, storage_state: dict or None)
    """

    def run(p):
        try:
            browser = p.chromium.launch(headless=True)

            context = browser.new_context()

            # add session cookie
            context.add_cookies([{
                "name": "sessionid",
                "value": sessionid,
                "domain": ".instagram.com",
                "path": "/",
                "httpOnly": True,
                "secure": True,
                "sameSite": "Lax"
            }])

            page = context.new_page()

            # open instagram
            page.goto("https://www.instagram.com/", timeout=60000)
            page.wait_for_timeout(8000)

            current_url = page.url.lower()
            page_content = page.content().lower()

            # ================= INVALID / LOGIN PAGE =================
            if "accounts/login" in current_url or "log in" in page_content:
                browser.close()
                return False, None

            # ================= CHECKPOINT / CHALLENGE =================
            if "challenge" in current_url or "checkpoint" in current_url:
                browser.close()
                return False, None

            # ================= RATE LIMIT / BLOCK =================
            if "try again later" in page_content or "rate limit" in page_content:
                browser.close()
                return False, None

            # ================= SUCCESS CHECK =================
            # if no login button visible, assume logged in
            success = page.locator("text=Log in").count() == 0

            if not success:
                browser.close()
                return False, None

            # ================= SAVE STORAGE =================
            state = context.storage_state()

            browser.close()
            return True, state

        except Exception as e:
            try:
                browser.close()
            except:
                pass
            return False, None

    return run_with_sync_playwright(run)

async def psid_get_session(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    sessionid = update.message.text.strip()
    user_id = update.effective_user.id

    await update.message.reply_text("╔════════════════════╗\n║  🔄 ᴛᴇꜱᴛɪɴɢ      ║\n║  ᴘʟᴀʏᴡʀɪɢʜᴛ...    ║\n╚════════════════════╝")

    try:
        success, state = await asyncio.to_thread(playwright_test_session, sessionid)
        if not success:
            await update.message.reply_text("╔════════════════════╗\n║ ❌ ʟᴏɢɪɴ ꜰᴀɪʟᴇᴅ  ║\n║ ɪɴᴠᴀʟɪᴅ/ᴄʜᴇᴄᴋᴘᴏɪɴᴛ ║\n╚════════════════════╝")
            return ConversationHandler.END

        context.user_data['psid_state'] = state
        context.user_data['psid_sessionid'] = sessionid
        await update.message.reply_text("╔════════════════════╗\n║ ✅ ʟᴏɢɪɴ ꜱᴜᴄᴄᴇꜱꜱ ║\n║ ᴇɴᴛᴇʀ ᴜꜱᴇʀɴᴀᴍᴇ:   ║\n╚════════════════════╝")
        return PSID_USERNAME
    except Exception as e:
        await update.message.reply_text(f"╔════════════════════╗\n║ ❌ ᴇʀʀᴏʀ:        ║\n║ {str(e)[:15]}... ║\n╚════════════════════╝")
        return ConversationHandler.END

async def psid_get_username(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    username = update.message.text.strip().lower()
    user_id = update.effective_user.id

    state = context.user_data['psid_state']
    sessionid = context.user_data['psid_sessionid']

    os.makedirs("sessions", exist_ok=True)

    # Save Playwright
    pw_file = f"sessions/{user_id}_{username}_state.json"
    with open(pw_file, "w") as f:
        json.dump(state, f, indent=2)

    # Save in bot memory
    if user_id not in users_data:
        users_data[user_id] = {'accounts': [], 'default': None, 'pairs': None, 'switch_minutes': 10, 'threads': 1}

    users_data[user_id]['accounts'].append({
        "ig_username": username,
        "password": "",
        "storage_state": state
    })
    users_data[user_id]['default'] = len(users_data[user_id]['accounts']) - 1
    save_user_data(user_id, users_data[user_id])

    await update.message.reply_text(f"╔════════════════════╗\n║ 🎉 ꜱᴇꜱꜱɪᴏɴ ꜱᴀᴠᴇᴅ ║\n║ ᴜꜱᴇʀ: {username[:10]}...  ║\n║ ᴘʟᴀʏᴡʀɪɢʜᴛ ʀᴇᴀᴅʏ ║\n╚════════════════════╝")
    return ConversationHandler.END    

async def login_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    if not is_authorized(user_id):
        await update.message.reply_text("╔════════════════════╗\n║ ⚠️ ɴᴏᴛ ᴀᴜᴛʜᴏʀɪᴢᴇᴅ ║\n║ @Why_not_ZarKo     ║\n╚════════════════════╝")
        return ConversationHandler.END
    await update.message.reply_text("╔════════════════════╗\n║ 📱 ᴇɴᴛᴇʀ ɪɴꜱᴛᴀ   ║\n║ ᴜꜱᴇʀɴᴀᴍᴇ:         ║\n╚════════════════════╝")
    return USERNAME

async def get_username(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data['ig_username'] = update.message.text.strip().lower()
    await update.message.reply_text("╔════════════════════╗\n║ 🔒 ᴇɴᴛᴇʀ ᴘᴀꜱꜱᴡᴏʀᴅ ║\n╚════════════════════╝")
    return PASSWORD

async def get_password(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    username = context.user_data['ig_username']
    password = update.message.text.strip()
    
    with SESSIONS_LOCK:
        if user_id in SESSIONS:
            await update.message.reply_text("╔════════════════════╗\n║ ⚠️ ᴘᴛʏ ꜱᴇꜱꜱɪᴏɴ   ║\n║ ᴀʟʀᴇᴀᴅʏ ʀᴜɴɴɪɴɢ  ║\n║ ᴜꜱᴇ /ᴋɪʟʟ ꜰɪʀꜱᴛ  ║\n╚════════════════════╝")
            return ConversationHandler.END

    pid, master_fd = pty.fork()
    if pid == 0:
        try:
            child_login(user_id, username, password)
        except SystemExit:
            os._exit(0)
        except Exception as e:
            print(f"[CHILD] Unexpected error: {e}")
            os._exit(1)
    else:
        t = threading.Thread(target=reader_thread, args=(user_id, chat_id, master_fd, username, password), daemon=True)
        t.start()
        with SESSIONS_LOCK:
            SESSIONS[user_id] = {"pid": pid, "master_fd": master_fd, "thread": t, "username": username, "password": password, "chat_id": chat_id}
        
    return ConversationHandler.END

# --- /plogin handlers (ASYNC, NO THREAD) ---
async def plogin_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    if not is_authorized(user_id):
        await update.message.reply_text("╔════════════════════╗\n║ ⚠️ ɴᴏᴛ ᴀᴜᴛʜᴏʀɪᴢᴇᴅ ║\n║ @Why_not_ZarKo     ║\n╚════════════════════╝")
        return ConversationHandler.END

    await update.message.reply_text("╔════════════════════╗\n║ 🔐 ᴇɴᴛᴇʀ ɪɴꜱᴛᴀ   ║\n║ ᴜꜱᴇʀɴᴀᴍᴇ ꜰᴏʀ     ║\n║ ᴘʟᴀʏᴡʀɪɢʜᴛ:      ║\n╚════════════════════╝")
    return PLO_USERNAME

async def plogin_get_username(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data['pl_username'] = update.message.text.strip().lower()
    await update.message.reply_text("╔════════════════════╗\n║ 🔒 ᴇɴᴛᴇʀ ᴘᴀꜱꜱᴡᴏʀᴅ ║\n╚════════════════════╝")
    return PLO_PASSWORD

async def plogin_get_password(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    username = context.user_data['pl_username']
    password = update.message.text.strip()

    await update.message.reply_text("╔════════════════════╗\n║ 🔄 ꜱᴛᴀʀᴛɪɴɢ      ║\n║ ᴘʟᴀʏᴡʀɪɢʜᴛ ʟᴏɢɪɴ ║\n║ (ᴀꜱʏɴᴄ, ɴᴏ ᴛʜʀᴇᴀᴅ)║\n╚════════════════════╝")

    try:
        state_file = await playwright_login_and_save_state(username, password, user_id)

        logging.info("[PLOGIN] Loading storage_state from %s", state_file)
        state = json.load(open(state_file))

        cookies = [c for c in state.get('cookies', []) if c.get('domain') == '.instagram.com']
        logging.info("[PLOGIN] cookies for .instagram.com = %s", len(cookies))

        sessionid = None
        for c in cookies:
            if c.get("name") == "sessionid":
                sessionid = c.get("value")
                break

        if not sessionid:
            logging.error("[PLOGIN] sessionid cookie not found in storage_state")
            raise ValueError("ERROR_011: sessionid cookie not found – cannot init Instagrapi client")

        cl = Client()
        logging.info("[PLOGIN] Logging into Instagrapi using sessionid (len=%s)", len(sessionid))

        cl.login_by_sessionid(sessionid)

        session_file = f"sessions/{user_id}_{username}_session.json"
        logging.info("[PLOGIN] Dumping Instagrapi settings to %s", session_file)
        cl.dump_settings(session_file)

        logging.info("[PLOGIN] Updating users_data for user_id=%s", user_id)
        if user_id not in users_data:
            users_data[user_id] = {
                'accounts': [],
                'default': None,
                'pairs': None,
                'switch_minutes': 10,
                'threads': 1,
            }
            save_user_data(user_id, users_data[user_id])

        data = users_data[user_id]
        found = False
        for i, acc in enumerate(data['accounts']):
            if acc.get('ig_username', '').strip().lower() == username:
                acc['password'] = password
                acc['storage_state'] = state
                data['default'] = i
                found = True
                logging.info("[PLOGIN] Updated existing account index=%s", i)
                break

        if not found:
            data['accounts'].append({
                'ig_username': username,
                'password': password,
                'storage_state': state,
            })
            data['default'] = len(data['accounts']) - 1
            logging.info("[PLOGIN] Added new account, total=%s", len(data['accounts']))

        save_user_data(user_id, data)

        await update.message.reply_text("╔════════════════════╗\n║ ✅ ᴘʟᴀʏᴡʀɪɢʜᴛ    ║\n║ ʟᴏɢɪɴ ꜱᴜᴄᴄᴇꜱꜱꜰᴜʟ ║\n║ 🎉 ꜱᴇꜱꜱɪᴏɴꜱ ꜱᴀᴠᴇᴅ ║\n╚════════════════════╝")

    except ValueError as ve:
        err_msg = str(ve)
        logging.error("[PLOGIN] ValueError: %s", err_msg)
        await update.message.reply_text(f"╔════════════════════╗\n║ ❌ ʟᴏɢɪɴ ꜰᴀɪʟᴇᴅ ║\n║ {err_msg[:15]}...    ║\n╚════════════════════╝")

    except Exception as e:
        logging.exception("[PLOGIN] Unexpected exception in plogin_get_password")
        await update.message.reply_text(f"╔════════════════════╗\n║ ❌ ᴜɴᴇxᴘᴇᴄᴛᴇᴅ    ║\n║ ᴇʀʀᴏʀ: {str(e)[:15]}... ║\n╚════════════════════╝")

    return ConversationHandler.END

# --- / handlers ---

async def slogin_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id

    if not is_authorized(user_id):
        await update.message.reply_text(
            "╔════════════════════╗\n"
            "║ ⚠️ ɴᴏᴛ ᴀᴜᴛʜᴏʀɪᴢᴇᴅ ║\n"
            "║ @Why_not_ZarKo     ║\n"
            "╚════════════════════╝"
        )
        return ConversationHandler.END

    # clean any previous temp file
    context.user_data.pop("temp_session_file", None)

    await update.message.reply_text(
        "╔════════════════════╗\n"
        "║ 🔑 ᴇɴᴛᴇʀ ꜱᴇꜱꜱɪᴏɴ  ║\n"
        "║ ɪᴅ:                ║\n"
        "╚════════════════════╝"
    )
    return SLOG_SESSION


# =======================================================
# STEP 1 — GET SESSION ID
# =======================================================

async def slogin_get_session(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    import os, time
    from instagrapi.exceptions import LoginRequired, PleaseWaitFewMinutes, RateLimitError
    from instagrapi import Client

    sessionid = (update.message.text or "").strip()
    user_id = update.effective_user.id

    if not sessionid or len(sessionid) < 10:
        await update.message.reply_text("❌ Invalid session id format")
        return ConversationHandler.END

    temp_file = f"temp_session_{user_id}_{int(time.time())}.json"

    cl = Client()

    # 🔥 device spoof
    cl.set_device({
        "app_version": "312.0.0.32.111",
        "android_version": 31,
        "android_release": "12.0",
        "dpi": "420dpi",
        "resolution": "1080x2400",
        "manufacturer": "Samsung",
        "device": "SM-G991B",
        "model": "Galaxy S21",
        "cpu": "arm64-v8a",
    })

    try:
        # 🔐 login via sessionid
        cl.login_by_sessionid(sessionid)

        # 🔥 verify session
        cl.get_timeline_feed()

        # save temp session
        cl.dump_settings(temp_file)

        context.user_data["temp_session_file"] = temp_file

        await update.message.reply_text(
            "╔════════════════════╗\n"
            "║ ✅ ᴠᴀʟɪᴅ ꜱᴇꜱꜱɪᴏɴ ║\n"
            "║ 📝 ᴇɴᴛᴇʀ ᴜꜱᴇʀɴᴀᴍᴇ ║\n"
            "╚════════════════════╝"
        )
        return SLOG_USERNAME

    except LoginRequired:
        await update.message.reply_text("❌ Session expired or invalid")
        return ConversationHandler.END

    except (PleaseWaitFewMinutes, RateLimitError):
        await update.message.reply_text("⏳ Instagram rate limit, try later")
        return ConversationHandler.END

    except Exception as e:
        await update.message.reply_text(f"❌ Error: {str(e)[:30]}")

    # cleanup on fail
    if os.path.exists(temp_file):
        os.remove(temp_file)

    await update.message.reply_text(
        "╔════════════════════╗\n"
        "║ ❌ ɪɴᴠᴀʟɪᴅ       ║\n"
        "║ ꜱᴇꜱꜱɪᴏɴ ɪᴅ       ║\n"
        "╚════════════════════╝"
    )
    return ConversationHandler.END


# =======================================================
# STEP 2 — SAVE USERNAME + FINALIZE ACCOUNT
# =======================================================

async def slogin_get_username(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    import os, json

    username = (update.message.text or "").strip().lower()
    user_id = update.effective_user.id

    if not username or " " in username:
        await update.message.reply_text("❌ Invalid username")
        return SLOG_USERNAME

    temp_file = context.user_data.get("temp_session_file")

    if not temp_file or not os.path.exists(temp_file):
        await update.message.reply_text("❌ Session file missing, restart /slogin")
        return ConversationHandler.END

    session_file = f"sessions/{user_id}_{username}_session.json"
    playwright_file = f"sessions/{user_id}_{username}_state.json"

    os.makedirs("sessions", exist_ok=True)

    try:
        # move temp → final
        os.replace(temp_file, session_file)

        # load settings
        with open(session_file, "r") as f:
            settings = json.load(f)

        # convert → playwright state
        state = get_storage_state_from_instagrapi(settings)

        with open(playwright_file, "w") as f:
            json.dump(state, f, indent=2)

    except Exception as e:
        await update.message.reply_text(f"❌ Storage build failed: {str(e)[:30]}")
        return ConversationHandler.END

    # ================= SAVE USER DATA =================
    if user_id not in users_data:
        users_data[user_id] = {
            "accounts": [],
            "default": None,
            "pairs": None,
            "switch_minutes": 10,
            "threads": 1
        }

    data = users_data[user_id]

    found = False
    for i, acc in enumerate(data["accounts"]):
        if acc.get("ig_username", "").lower() == username:
            data["accounts"][i] = {
                "ig_username": username,
                "password": "",
                "storage_state": state
            }
            data["default"] = i
            found = True
            break

    if not found:
        data["accounts"].append({
            "ig_username": username,
            "password": "",
            "storage_state": state
        })
        data["default"] = len(data["accounts"]) - 1

    save_user_data(user_id, data)

    # cleanup temp reference
    context.user_data.pop("temp_session_file", None)

    await update.message.reply_text(
        f"╔════════════════════╗\n"
        f"║ ✅ ꜱᴇꜱꜱɪᴏɴ ꜱᴀᴠᴇᴅ ║\n"
        f"║ ᴜꜱᴇʀ: {username[:10]}... ║\n"
        f"║ 🎉 ʀᴇᴀᴅʏ ᴛᴏ ᴜꜱᴇ ║\n"
        f"╚════════════════════╝"
    )

    return ConversationHandler.END

async def viewmyac(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not is_authorized(user_id):
        await update.message.reply_text("╔════════════════════╗\n║ ⚠️ ɴᴏᴛ ᴀᴜᴛʜᴏʀɪᴢᴇᴅ ║\n║ @Why_not_ZarKo     ║\n╚════════════════════╝")
        return
    if user_id not in users_data:
        await update.message.reply_text("╔════════════════════╗\n║ ❌ ɴᴏ ꜱᴀᴠᴇᴅ      ║\n║ ᴀᴄᴄᴏᴜɴᴛꜱ         ║\n║ ᴜꜱᴇ /ʟᴏɢɪɴ       ║\n╚════════════════════╝")
        return
    data = users_data[user_id]
    
    msg = "╔════════════════════╗\n║  👀 ʏᴏᴜʀ ᴀᴄᴄᴏᴜɴᴛꜱ  ║\n╠════════════════════╣\n"
    for i, acc in enumerate(data['accounts']):
        default = " ⭐" if data['default'] == i else ""
        num = f"{i+1}."
        username = acc['ig_username'][:15] + "..." if len(acc['ig_username']) > 15 else acc['ig_username']
        msg += f"║ {num:<3} {username:<14}{default} ║\n"
    msg += "╚════════════════════╝"
    
    await update.message.reply_text(msg)

async def setig(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not is_authorized(user_id):
        await update.message.reply_text("╔════════════════════╗\n║ ⚠️ ɴᴏᴛ ᴀᴜᴛʜᴏʀɪᴢᴇᴅ ║\n║ @Why_not_ZarKo     ║\n╚════════════════════╝")
        return
    if not context.args or not context.args[0].isdigit():
        await update.message.reply_text("╔════════════════════╗\n║ ❗ ᴜꜱᴀɢᴇ:        ║\n║    /ꜱᴇᴛɪɢ <ɴᴜᴍʙᴇʀ> ║\n╚════════════════════╝")
        return
    num = int(context.args[0]) - 1
    if user_id not in users_data:
        await update.message.reply_text("╔════════════════════╗\n║ ❌ ɴᴏ ᴀᴄᴄᴏᴜɴᴛꜱ   ║\n║    ꜱᴀᴠᴇᴅ         ║\n╚════════════════════╝")
        return
    data = users_data[user_id]
    if num < 0 or num >= len(data['accounts']):
        await update.message.reply_text("╔════════════════════╗\n║ ⚠️ ɪɴᴠᴀʟɪᴅ      ║\n║    ɴᴜᴍʙᴇʀ        ║\n╚════════════════════╝")
        return
    data['default'] = num
    save_user_data(user_id, data)
    acc = data['accounts'][num]['ig_username']
    await update.message.reply_text(f"╔════════════════════╗\n║ ✅ {num+1}. {acc[:10]}...  ║\n║  ɴᴏᴡ ᴅᴇꜰᴀᴜʟᴛ    ║\n║        ᴀᴄᴄᴏᴜɴᴛ ⭐  ║\n╚════════════════════╝")

async def logout_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not is_authorized(user_id):
        await update.message.reply_text("╔════════════════════╗\n║ ⚠️ ɴᴏᴛ ᴀᴜᴛʜᴏʀɪᴢᴇᴅ ║\n║ @Why_not_ZarKo     ║\n╚════════════════════╝")
        return
    if not context.args:
        await update.message.reply_text("╔════════════════════╗\n║ ❗ ᴜꜱᴀɢᴇ:        ║\n║ /ʟᴏɢᴏᴜᴛ <ᴜꜱᴇʀɴᴀᴍᴇ> ║\n╚════════════════════╝")
        return
    username = context.args[0].strip()
    if user_id not in users_data:
        await update.message.reply_text("╔════════════════════╗\n║ ❌ ɴᴏ ᴀᴄᴄᴏᴜɴᴛꜱ   ║\n║    ꜱᴀᴠᴇᴅ         ║\n╚════════════════════╝")
        return
    data = users_data[user_id]
    for i, acc in enumerate(data['accounts']):
        if acc['ig_username'] == username:
            del data['accounts'][i]
            if data['default'] == i:
                data['default'] = 0 if data['accounts'] else None
            elif data['default'] > i:
                data['default'] -= 1
            if data['pairs']:
                pl = data['pairs']['list']
                if username in pl:
                    pl.remove(username)
                    if not pl:
                        data['pairs'] = None
                    else:
                        data['pairs']['default_index'] = 0
            break
    else:
        await update.message.reply_text("╔════════════════════╗\n║ ⚠️ ᴀᴄᴄᴏᴜɴᴛ      ║\n║  ɴᴏᴛ ꜰᴏᴜɴᴅ       ║\n╚════════════════════╝")
        return
    save_user_data(user_id, data)
    session_file = f"sessions/{user_id}_{username}_session.json"
    state_file = f"sessions/{user_id}_{username}_state.json"
    if os.path.exists(session_file):
        os.remove(session_file)
    if os.path.exists(state_file):
        os.remove(state_file)
    await update.message.reply_text(f"╔════════════════════╗\n║ ✅ ʟᴏɢɢᴇᴅ ᴏᴜᴛ   ║\n║ ʀᴇᴍᴏᴠᴇᴅ {username[:10]}... ║\n║ ꜰɪʟᴇꜱ ᴅᴇʟᴇᴛᴇᴅ   ║\n╚════════════════════╝")

# New commands
async def pair_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not is_authorized(user_id):
        await update.message.reply_text("╔════════════════════╗\n║ ⚠️ ɴᴏᴛ ᴀᴜᴛʜᴏʀɪᴢᴇᴅ ║\n║ @Why_not_ZarKo     ║\n╚════════════════════╝")
        return
    if not context.args:
        await update.message.reply_text("╔════════════════════╗\n║ ❗ ᴜꜱᴀɢᴇ:        ║\n║ /ᴘᴀɪʀ ɪɢ1-ɪɢ2-ɪɢ3 ║\n╚════════════════════╝")
        return
    arg_str = '-'.join(context.args)
    us = [u.strip() for u in arg_str.split('-') if u.strip()]
    if len(us) < 2:
        await update.message.reply_text("╔════════════════════╗\n║ ❗ ᴘʀᴏᴠɪᴅᴇ ᴀᴛ    ║\n║ ʟᴇᴀꜱᴛ ᴛᴡᴏ ᴀᴄᴄꜱ  ║\n╚════════════════════╝")
        return
    if user_id not in users_data or not users_data[user_id]['accounts']:
        await update.message.reply_text("╔════════════════════╗\n║ ❌ ɴᴏ ᴀᴄᴄᴏᴜɴᴛꜱ   ║\n║ ᴜꜱᴇ /ʟᴏɢɪɴ ꜰɪʀꜱᴛ ║\n╚════════════════════╝")
        return
    data = users_data[user_id]
    accounts_set = {acc['ig_username'] for acc in data['accounts']}
    missing = [u for u in us if u not in accounts_set]
    if missing:
        await update.message.reply_text(f"╔════════════════════╗\n║ ⚠️ ᴍɪꜱꜱɪɴɢ:      ║\n║ {missing[0][:10]}...      ║\n║ ꜱᴀᴠᴇ ᴡɪᴛʜ /ʟᴏɢɪɴ ║\n╚════════════════════╝")
        return
    data['pairs'] = {'list': us, 'default_index': 0}
    first_u = us[0]
    for i, acc in enumerate(data['accounts']):
        if acc['ig_username'] == first_u:
            data['default'] = i
            break
    save_user_data(user_id, data)
    await update.message.reply_text(f"╔════════════════════╗\n║ ✅ ᴘᴀɪʀ ᴄʀᴇᴀᴛᴇᴅ  ║\n║ {len(us)} ᴀᴄᴄᴏᴜɴᴛꜱ     ║\n║ ᴅᴇꜰᴀᴜʟᴛ: {first_u[:10]}... ⭐ ║\n║ ᴜꜱᴇ /ᴀᴛᴛᴀᴄᴋ ᴛᴏ   ║\n║ ꜱᴛᴀʀᴛ ᴘᴀɪʀɪɴɢ   ║\n╚════════════════════╝")

async def unpair_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not is_authorized(user_id):
        await update.message.reply_text("╔════════════════════╗\n║ ⚠️ ɴᴏᴛ ᴀᴜᴛʜᴏʀɪᴢᴇᴅ ║\n║ @Why_not_ZarKo     ║\n╚════════════════════╝")
        return

    if user_id not in users_data or not users_data[user_id].get('pairs'):
        await update.message.reply_text("╔════════════════════╗\n║ ❌ ɴᴏ ᴀᴄᴛɪᴠᴇ     ║\n║ ᴘᴀɪʀ ꜰᴏᴜɴᴅ      ║\n║ ᴜꜱᴇ /ᴘᴀɪʀ ꜰɪʀꜱᴛ  ║\n╚════════════════════╝")
        return

    data = users_data[user_id]
    pair_info = data['pairs']
    pair_list = pair_info['list']

    if not context.args:
        msg = "╔════════════════════╗\n║ 👥 ᴄᴜʀʀᴇɴᴛ ᴘᴀɪʀꜱ  ║\n╠════════════════════╣\n"
        for i, u in enumerate(pair_list, 1):
            mark = " ⭐" if i - 1 == pair_info.get('default_index', 0) else ""
            msg += f"║ {i}. {u[:15]}{'...' if len(u)>15 else ''}{mark} ║\n"
        msg += "╠════════════════════╣\n║ /ᴜɴᴘᴀɪʀ ᴀʟʟ      ║\n║ /ᴜɴᴘᴀɪʀ <ᴜꜱᴇʀ>    ║\n╚════════════════════╝"
        await update.message.reply_text(msg)
        return

    arg = context.args[0].strip().lower()

    if arg == "all":
        data['pairs'] = None
        save_user_data(user_id, data)
        await update.message.reply_text("╔════════════════════╗\n║ 🧹 ᴀʟʟ ᴘᴀɪʀꜱ     ║\n║ ʀᴇᴍᴏᴠᴇᴅ          ║\n╚════════════════════╝")
        return

    target = arg
    if target not in pair_list:
        await update.message.reply_text(f"╔════════════════════╗\n║ ⚠️ {target[:10]}...    ║\n║ ɴᴏᴛ ɪɴ ᴘᴀɪʀ     ║\n║ ʟɪꜱᴛ             ║\n╚════════════════════╝")
        return

    pair_list.remove(target)
    if not pair_list:
        data['pairs'] = None
        msg = f"╔════════════════════╗\n║ ✅ ʀᴇᴍᴏᴠᴇᴅ {target[:10]}... ║\n║ ɴᴏ ᴘᴀɪʀꜱ ʟᴇꜰᴛ   ║\n╚════════════════════╝"
    else:
        if pair_info.get('default_index', 0) >= len(pair_list):
            pair_info['default_index'] = 0
        msg = f"╔════════════════════╗\n║ ✅ ʀᴇᴍᴏᴠᴇᴅ {target[:10]}... ║\n║ ʟᴇꜰᴛ: {len(pair_list)} ᴘᴀɪʀꜱ   ║\n╚════════════════════╝"

    save_user_data(user_id, data)
    await update.message.reply_text(msg)

async def switch_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not is_authorized(user_id):
        await update.message.reply_text("╔════════════════════╗\n║ ⚠️ ɴᴏᴛ ᴀᴜᴛʜᴏʀɪᴢᴇᴅ ║\n║ @Why_not_ZarKo     ║\n╚════════════════════╝")
        return
    if not context.args or not context.args[0].isdigit():
        await update.message.reply_text("╔════════════════════╗\n║ ❗ ᴜꜱᴀɢᴇ:        ║\n║ /ꜱᴡɪᴛᴄʜ <ᴍɪɴ>    ║\n╚════════════════════╝")
        return
    min_ = int(context.args[0])
    data = users_data[user_id]
    if not data.get('pairs') or len(data['pairs']['list']) < 2:
        await update.message.reply_text("╔════════════════════╗\n║ ⚠️ ɴᴏ ᴘᴀɪʀ      ║\n║ ꜰᴏᴜɴᴅ           ║\n║ ᴜꜱᴇ /ᴘᴀɪʀ ꜰɪʀꜱᴛ ║\n╚════════════════════╝")
        return
    if min_ < 5:
        await update.message.reply_text("╔════════════════════╗\n║ ⚠️ ᴍɪɴɪᴍᴜᴍ      ║\n║ ɪɴᴛᴇʀᴠᴀʟ ɪꜱ     ║\n║ 5 ᴍɪɴᴜᴛᴇꜱ        ║\n╚════════════════════╝")
        return
    data['switch_minutes'] = min_
    save_user_data(user_id, data)
    await update.message.reply_text(f"╔════════════════════╗\n║ ⏱️ ꜱᴡɪᴛᴄʜ      ║\n║ ɪɴᴛᴇʀᴠᴀʟ ꜱᴇᴛ   ║\n║ ᴛᴏ {min_} ᴍɪɴᴜᴛᴇꜱ  ║\n╚════════════════════╝")

async def threads_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not is_authorized(user_id):
        await update.message.reply_text("╔════════════════════╗\n║ ⚠️ ɴᴏᴛ ᴀᴜᴛʜᴏʀɪᴢᴇᴅ ║\n║ @Why_not_ZarKo     ║\n╚════════════════════╝")
        return
    if not context.args or not context.args[0].isdigit():
        await update.message.reply_text("╔════════════════════╗\n║ ❗ ᴜꜱᴀɢᴇ:        ║\n║ /ᴛʜʀᴇᴀᴅꜱ <1-5>   ║\n╚════════════════════╝")
        return
    n = int(context.args[0])
    if n < 1 or n > 5:
        await update.message.reply_text("╔════════════════════╗\n║ ⚠️ ᴛʜʀᴇᴀᴅꜱ ᴍᴜꜱᴛ ║\n║ ʙᴇ ʙᴇᴛᴡᴇᴇɴ      ║\n║ 1 ᴀɴᴅ 5          ║\n╚════════════════════╝")
        return
    if user_id not in users_data:
        users_data[user_id] = {'accounts': [], 'default': None, 'pairs': None, 'switch_minutes': 10, 'threads': 1}
        save_user_data(user_id, users_data[user_id])
    data = users_data[user_id]
    data['threads'] = n
    save_user_data(user_id, data)
    await update.message.reply_text(f"╔════════════════════╗\n║ 🔁 ᴛʜʀᴇᴀᴅꜱ ꜱᴇᴛ   ║\n║ ᴛᴏ {n}             ║\n╚════════════════════╝")

async def viewpref(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not is_authorized(user_id):
        await update.message.reply_text("╔════════════════════╗\n║ ⚠️ ɴᴏᴛ ᴀᴜᴛʜᴏʀɪᴢᴇᴅ ║\n║ @Why_not_ZarKo     ║\n╚════════════════════╝")
        return
    if user_id not in users_data:
        await update.message.reply_text("╔════════════════════╗\n║ ❌ ɴᴏ ᴅᴀᴛᴀ      ║\n║ ᴜꜱᴇ /ʟᴏɢɪɴ      ║\n╚════════════════════╝")
        return
    data = users_data[user_id]
    saved_accounts = ', '.join([acc['ig_username'] for acc in data['accounts']])
    
    msg = "╔════════════════════╗\n║  🔧 ʙᴏᴛ ᴘʀᴇꜰꜱ  🔧  ║\n╠════════════════════╣\n"
    
    if data.get('pairs'):
        pl = data['pairs']['list']
        default_idx = data['pairs']['default_index']
        default_u = pl[default_idx]
        msg += f"║ ᴘᴀɪʀꜱ: ʏᴇꜱ         ║\n║ {len(pl)} ᴀᴄᴄᴏᴜɴᴛꜱ      ║\n║ ᴅᴇꜰᴀᴜʟᴛ: {default_u[:15]}{'...' if len(default_u)>15 else ''} ⭐ ║\n"
    else:
        msg += "║ ᴘᴀɪʀꜱ: ɴᴏ           ║\n"
    
    switch_min = data.get('switch_minutes', 10)
    threads = data.get('threads', 1)
    msg += f"║ ⏱️ ꜱᴡɪᴛᴄʜ: {switch_min} ᴍɪɴ    ║\n"
    msg += f"║ 🧵 ᴛʜʀᴇᴀᴅꜱ: {threads}        ║\n"
    msg += f"║ 👤 ꜱᴀᴠᴇᴅ: {len(data['accounts'])} ᴀᴄᴄᴏᴜɴᴛꜱ  ║\n"
    
    tasks = users_tasks.get(user_id, [])
    running_attacks = [t for t in tasks if t.get('type') == 'message_attack' and t['status'] == 'running' and t['proc'].poll() is None]
    if running_attacks:
        task = running_attacks[0]
        pid = task['pid']
        ttype = task['target_type']
        tdisplay = task['target_display']
        disp = f"@{tdisplay}" if ttype == 'dm' else tdisplay
        msg += f"╠════════════════════╣\n║ ⚡ ᴀᴄᴛɪᴠᴇ ᴀᴛᴛᴀᴄᴋ ⚡  ║\n║ ᴘɪᴅ: {pid}            ║\n║ ᴛᴀʀɢᴇᴛ: {disp[:15]}    ║\n╠════════════════════╣\n"
        pair_list = task['pair_list']
        curr_idx = task['pair_index']
        curr_u = pair_list[curr_idx]
        for u in pair_list:
            if u == curr_u:
                msg += f"║ ▶️ {u[:15]}... ║\n"
            else:
                msg += f"║ ⏸️ {u[:15]}... ║\n"
    else:
        msg += "║ ɴᴏ ᴀᴄᴛɪᴠᴇ ᴀᴛᴛᴀᴄᴋ   ║\n"
    
    msg += "╚════════════════════╝"
    await update.message.reply_text(msg)

MODE, SELECT_GC, TARGET, MESSAGES = range(4)
P_MODE, P_TARGET_DISPLAY, P_THREAD_URL, P_MESSAGES = range(4)
MODE, SELECT_GC, TARGET, MESSAGES = range(4)
# ================= FIXED ATTACK FLOW =================

async def attack_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    🎯 Attack configuration start - COMPLETE & FIXED
    """
    user_id = update.effective_user.id

    # -----------------------------
    # 1️⃣ Authorization check
    # -----------------------------
    if not is_authorized(user_id):
        await update.message.reply_text(
            "╔══════════════════════╗\n"
            "║  ⛔ ᴀᴄᴄᴇꜱꜱ ᴅᴇɴɪᴇᴅ   ║\n"
            "╚══════════════════════╝"
        )
        return ConversationHandler.END

    # -----------------------------
    # 2️⃣ Account verification
    # -----------------------------
    data = users_data.get(user_id)
    if not data or not data.get('accounts'):
        await update.message.reply_text(
            "┌────────────────────┐\n"
            "│  ⚠️ ʟᴏɢɪɴ ʀᴇQᴜɪʀᴇᴅ  │\n"
            "├────────────────────┤\n"
            "│ ᴘʟᴇᴀꜱᴇ /ʟᴏɢɪɴ     │\n"
            "│ ᴛᴏ ᴄᴏɴᴛɪɴᴜᴇ        │\n"
            "└────────────────────┘"
        )
        return ConversationHandler.END

    # -----------------------------
    # 3️⃣ Default account setup
    # -----------------------------
    if data.get('default') is None:
        data['default'] = 0
        save_user_data(user_id, data)
    
    # Verify default account index is valid
    if data['default'] >= len(data['accounts']):
        data['default'] = 0
        save_user_data(user_id, data)

    # -----------------------------
    # 4️⃣ Reset previous flow data
    # -----------------------------
    context.user_data.clear()
    context.user_data['user_id'] = user_id
    context.user_data['attack_start_time'] = time.time()

    # -----------------------------
    # 5️⃣ Inline buttons (DM / GC)
    # -----------------------------
    keyboard = InlineKeyboardMarkup([
        [
            InlineKeyboardButton("📩 ᴅᴍ", callback_data="mode_dm"),
            InlineKeyboardButton("👥 ɢᴄ", callback_data="mode_gc")
        ]
    ])

    # -----------------------------
    # 6️⃣ Send UI message with account info
    # -----------------------------
    default_username = data['accounts'][data['default']]['ig_username']
    display_username = default_username[:15] + "..." if len(default_username) > 15 else default_username
    
    await update.message.reply_text(
        f"╔══════════════════════╗\n"
        f"║   🎯 ꜱᴇʟᴇᴄᴛ ᴍᴏᴅᴇ    ║\n"
        f"╠══════════════════════╣\n"
        f"║ ᴅᴇꜰᴀᴜʟᴛ: {display_username:<12} ║\n"
        f"╠══════════════════════╣\n"
        f"║ • 📩 ᴅᴍ → ᴅɪʀᴇᴄᴛ ᴍꜱɢ ║\n"
        f"║ • 👥 ɢᴄ → ɢʀᴏᴜᴘ ᴄʜᴀᴛ║\n"
        f"╚══════════════════════╝",
        reply_markup=keyboard
    )

    return MODE


async def mode_button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    📱 Mode selection handler (DM / GC) - CALLBACK QUERY HANDLER
    """
    query = update.callback_query
    await query.answer()

    user_id = query.from_user.id
    callback_data = query.data

    # -----------------------------
    # 🔐 Safety: get user data safely
    # -----------------------------
    user_data = users_data.get(user_id)
    if not user_data or not user_data.get("accounts"):
        await query.message.edit_text("❌ Account not found. Please /login again")
        return ConversationHandler.END

    # Store user_id in context
    context.user_data['user_id'] = user_id

    # =============================
    # 📩 DM MODE
    # =============================
    if callback_data == "mode_dm":
        context.user_data['mode'] = 'dm'

        keyboard = InlineKeyboardMarkup([
            [InlineKeyboardButton("🔗 Use Thread URL", callback_data="dm_thread")]
        ])

        await query.message.edit_text(
            "╔══════════════════════╗\n"
            "║     📩 DM MODE       ║\n"
            "╠══════════════════════╣\n"
            "║ • Enter username     ║\n"
            "║ • OR use thread URL  ║\n"
            "╚══════════════════════╝",
            reply_markup=keyboard
        )
        return TARGET

    # =============================
    # 👥 GC MODE
    # =============================
    elif callback_data == "mode_gc":
        context.user_data['mode'] = 'gc'

        acc = user_data['accounts'][user_data['default']]

        # loading message
        loading_msg = await query.message.edit_text(
            "🔍 Fetching group chats..."
        )

        try:
            groups, new_state = await asyncio.to_thread(
                list_group_chats,
                user_id,
                acc['storage_state'],
                acc['ig_username'],
                acc['password'],
                max_groups=10,
                amount=10
            )
        except Exception as e:
            await loading_msg.edit_text(f"❌ Failed to fetch groups:\n{e}")
            return ConversationHandler.END

        # update session state
        if new_state != acc['storage_state']:
            acc['storage_state'] = new_state
            save_user_data(user_id, user_data)

        # no groups
        if not groups:
            await loading_msg.edit_text("❌ No group chats found")
            return ConversationHandler.END

        # build inline buttons
        buttons = []
        for idx, g in enumerate(groups, 1):
            display_name = g['display'][:20]
            buttons.append([
                InlineKeyboardButton(
                    f"{idx}. {display_name}",
                    callback_data=f"gc_{g['url']}"
                )
            ])

        # manual thread option
        buttons.append([
            InlineKeyboardButton("🔗 Use Thread URL", callback_data="gc_thread")
        ])

        # header message
        header = (
            "╔══════════════════════╗\n"
            "║   👥 GROUP CHATS     ║\n"
            "╠══════════════════════╣\n"
            f"║ Total: {len(groups):2d}/10        ║\n"
            "╚══════════════════════╝"
        )

        await loading_msg.edit_text(
            header,
            reply_markup=InlineKeyboardMarkup(buttons)
        )

        return SELECT_GC

    # =============================
    # ❌ Unknown callback
    # =============================
    else:
        await query.message.edit_text("❌ Invalid selection")
        return ConversationHandler.END


async def gc_button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    📱 Group selection handler - CALLBACK QUERY HANDLER
    Complete & fixed version with proper error handling and user feedback
    """
    query = update.callback_query
    await query.answer()
    
    callback_data = query.data
    user_id = query.from_user.id
    
    # -----------------------------
    # 🛡️ Safety check - Mode exists
    # -----------------------------
    if 'mode' not in context.user_data:
        await query.message.edit_text(
            "╔══════════════════════╗\n"
            "║     ❌ ᴇʀʀᴏʀ         ║\n"
            "╠══════════════════════╣\n"
            "║ ꜱᴇꜱꜱɪᴏɴ ᴇxᴘɪʀᴇᴅ    ║\n"
            "║ ʀᴇꜱᴛᴀʀᴛ /ᴀᴛᴛᴀᴄᴋ   ║\n"
            "╚══════════════════════╝"
        )
        return ConversationHandler.END
    
    # -----------------------------
    # 🛡️ Safety check - User data exists
    # -----------------------------
    if user_id not in users_data or not users_data[user_id].get('accounts'):
        await query.message.edit_text(
            "╔══════════════════════╗\n"
            "║     ❌ ᴀᴄᴄᴏᴜɴᴛ      ║\n"
            "╠══════════════════════╣\n"
            "║ ɴᴏ ꜱᴀᴠᴇᴅ ᴀᴄᴄᴏᴜɴᴛꜱ  ║\n"
            "║ ᴘʟᴇᴀꜱᴇ /ʟᴏɢɪɴ     ║\n"
            "║ ꜰɪʀꜱᴛ              ║\n"
            "╚══════════════════════╝"
        )
        return ConversationHandler.END
    
    # =============================
    # 📌 Group selected from list
    # =============================
    if callback_data.startswith("gc_"):
        # Extract thread URL from callback data
        thread_url = callback_data.replace("gc_", "")
        
        # 🔍 URL validation
        if not thread_url.startswith("https://www.instagram.com/direct/t/"):
            await query.message.edit_text(
                "╔══════════════════════╗\n"
                "║     ❌ ɪɴᴠᴀʟɪᴅ     ║\n"
                "╠══════════════════════╣\n"
                "║ ɪɴᴠᴀʟɪᴅ ᴛʜʀᴇᴀᴅ   ║\n"
                "║ ᴜʀʟ ꜰᴏʀᴍᴀᴛ       ║\n"
                "╚══════════════════════╝"
            )
            return ConversationHandler.END
        
        # Store in context
        context.user_data['thread_url'] = thread_url
        context.user_data['target_display'] = "ꜱᴇʟᴇᴄᴛᴇᴅ ɢʀᴏᴜᴘ"
        context.user_data['mode'] = 'gc'
        
        # ✅ Success - Ask for messages
        await query.message.edit_text(
            "╔══════════════════════╗\n"
            "║     ✅ ɢᴄ ꜱᴇʟᴇᴄᴛᴇᴅ ║\n"
            "╠══════════════════════╣\n"
            "║ 📤 ꜱᴇɴᴅ ʏᴏᴜʀ       ║\n"
            "║ ᴍᴇꜱꜱᴀɢᴇꜱ          ║\n"
            "╠══════════════════════╣\n"
            "║ ꜰᴏʀᴍᴀᴛ:           ║\n"
            "║ ᴍꜱɢ1 & ᴍꜱɢ2 & ... ║\n"
            "║ ᴏʀ ᴜᴘʟᴏᴀᴅ .ᴛxᴛ    ║\n"
            "╚══════════════════════╝"
        )
        return MESSAGES
    
    # =============================
    # 🔗 Manual thread URL mode
    # =============================
    elif callback_data == "gc_thread":
        context.user_data['mode'] = 'gc'
        
        await query.message.edit_text(
            "╔══════════════════════╗\n"
            "║     🔗 ᴍᴀɴᴜᴀʟ ᴜʀʟ  ║\n"
            "╠══════════════════════╣\n"
            "║ ᴘʟᴇᴀꜱᴇ ꜱᴇɴᴅ ᴛʜᴇ   ║\n"
            "║ ɢʀᴏᴜᴘ ᴛʜʀᴇᴀᴅ ᴜʀʟ: ║\n"
            "║                    ║\n"
            "║ https://www.       ║\n"
            "║ instagram.com/     ║\n"
            "║ direct/t/...       ║\n"
            "╚══════════════════════╝"
        )
        return TARGET
    
    # =============================
    # 🔄 Refresh groups
    # =============================
    elif callback_data == "gc_refresh":
        await query.message.edit_text(
            "╔══════════════════════╗\n"
            "║     🔄 ʀᴇꜰʀᴇꜱʜɪɴɢ ║\n"
            "╠══════════════════════╣\n"
            "║ ꜰᴇᴛᴄʜɪɴɢ ɢʀᴏᴜᴘꜱ   ║\n"
            "║ ᴀɢᴀɪɴ...           ║\n"
            "╚══════════════════════╝"
        )
        
        # Get user data
        data = users_data[user_id]
        acc = data['accounts'][data['default']]
        
        try:
            # Fetch groups again
            groups, new_state = await asyncio.to_thread(
                list_group_chats,
                user_id,
                acc['storage_state'],
                acc['ig_username'],
                acc['password'],
                max_groups=10,
                amount=10
            )
            
            # Update session state if changed
            if new_state != acc['storage_state']:
                acc['storage_state'] = new_state
                save_user_data(user_id, data)
            
            if not groups:
                await query.message.edit_text(
                    "╔══════════════════════╗\n"
                    "║     ❌ ɴᴏ ɢʀᴏᴜᴘꜱ    ║\n"
                    "╠══════════════════════╣\n"
                    "║ ɴᴏ ɢʀᴏᴜᴘ ᴄʜᴀᴛꜱ     ║\n"
                    "║ ꜰᴏᴜɴᴅ                ║\n"
                    "╚══════════════════════╝"
                )
                return ConversationHandler.END
            
            # Build inline buttons
            buttons = []
            for idx, g in enumerate(groups, 1):
                display_name = g['display'][:25] + "..." if len(g['display']) > 25 else g['display']
                member_count = g.get('member_count', '?')
                buttons.append([
                    InlineKeyboardButton(
                        f"{idx}. {display_name} [{member_count}]",
                        callback_data=f"gc_{g['url']}"
                    )
                ])
            
            # Add manual thread option and refresh button
            buttons.append([
                InlineKeyboardButton("🔗 ᴜ꜇ᴇ ᴛʜʀᴇᴀᴅ ᴜʀʟ", callback_data="gc_thread"),
                InlineKeyboardButton("🔄 ʀᴇꜰʀᴇꜱʜ", callback_data="gc_refresh")
            ])
            
            # Header with count
            header = (
                "╔══════════════════════╗\n"
                "║   👥 ɢʀᴏᴜᴘ ᴄʜᴀᴛꜱ   ║\n"
                "╠══════════════════════╣\n"
                f"║ ᴛᴏᴛᴀʟ: {len(groups):2d}/10        ║\n"
                "╚══════════════════════╝"
            )
            
            await query.message.edit_text(
                header,
                reply_markup=InlineKeyboardMarkup(buttons)
            )
            return SELECT_GC
            
        except Exception as e:
            await query.message.edit_text(
                f"╔══════════════════════╗\n"
                f"║     ❌ ᴇʀʀᴏʀ        ║\n"
                f"╠══════════════════════╣\n"
                f"║ {str(e)[:20]:<20} ║\n"
                f"╚══════════════════════╝"
            )
            return ConversationHandler.END
    
    # =============================
    # ❌ Cancel operation
    # =============================
    elif callback_data == "gc_cancel":
        await query.message.edit_text(
            "╔══════════════════════╗\n"
            "║     ❌ ᴄᴀɴᴄᴇʟʟᴇᴅ   ║\n"
            "╠══════════════════════╣\n"
            "║ ᴏᴘᴇʀᴀᴛɪᴏɴ ᴄᴀɴᴄᴇʟʟᴇᴅ ║\n"
            "║ ᴜꜱᴇ /ᴀᴛᴛᴀᴄᴋ ᴛᴏ     ║\n"
            "║ ꜱᴛᴀʀᴛ ᴀɢᴀɪɴ        ║\n"
            "╚══════════════════════╝"
        )
        return ConversationHandler.END
    
    # =============================
    # ❌ Unknown callback
    # =============================
    else:
        await query.message.edit_text(
            "╔══════════════════════╗\n"
            "║     ❌ ɪɴᴠᴀʟɪᴅ      ║\n"
            "╠══════════════════════╣\n"
            "║ ɪɴᴠᴀʟɪᴅ ꜱᴇʟᴇᴄᴛɪᴏɴ  ║\n"
            "║ ᴘʟᴇᴀꜱᴇ ᴛʀʏ ᴀɢᴀɪɴ  ║\n"
            "╚══════════════════════╝"
        )
        return ConversationHandler.END


async def dm_button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    📩 DM thread URL button handler
    """
    query = update.callback_query
    await query.answer()
    
    if query.data == "dm_thread":
        context.user_data['mode'] = 'dm'
        
        await query.message.edit_text(
            "╔══════════════════════╗\n"
            "║     🔗 DM ᴛʜʀᴇᴀᴅ   ║\n"
            "╠══════════════════════╣\n"
            "║ ꜱᴇɴᴅ ᴅᴍ ᴛʜʀᴇᴀᴅ    ║\n"
            "║ ᴜʀʟ:                ║\n"
            "║ https://www.instagram║\n"
            "║ .com/direct/t/...    ║\n"
            "╚══════════════════════╝"
        )
        return TARGET
    
    return ConversationHandler.END


async def get_target_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    🎯 Handle target input (username or thread URL)
    """
    user_id = update.effective_user.id
    text = (update.message.text or "").strip()

    # -----------------------------
    # 🛡️ Safety: ensure mode exists
    # -----------------------------
    mode = context.user_data.get("mode")
    if not mode:
        await update.message.reply_text("❌ Session expired. Please run /attack again")
        return ConversationHandler.END

    # -----------------------------
    # 1️⃣ If user pasted THREAD URL
    # -----------------------------
    if text.startswith("https://www.instagram.com/direct/t/"):
        # validate properly
        if "/direct/t/" not in text:
            await update.message.reply_text("❌ Invalid Instagram thread URL")
            return TARGET

        context.user_data['thread_url'] = text
        context.user_data['target_display'] = "Thread URL"

        await update.message.reply_text(
            "╔════════════════════╗\n"
            "║ 📤 ꜱᴇɴᴅ ᴍᴇꜱꜱᴀɢᴇꜱ  ║\n"
            "║ ᴍꜱɢ1 & ᴍꜱɢ2 &... ║\n"
            "║ ᴏʀ ᴜᴘʟᴏᴀᴅ .ᴛxᴛ   ║\n"
            "╚════════════════════╝"
        )
        return MESSAGES

    # -----------------------------
    # 2️⃣ Otherwise treat as USERNAME (DM)
    # -----------------------------
    target_u = text.lstrip('@').strip().lower()

    if not target_u or " " in target_u:
        await update.message.reply_text(
            "╔════════════════════╗\n"
            "║ ⚠️ ɪɴᴠᴀʟɪᴅ      ║\n"
            "║ ᴜꜱᴇʀɴᴀᴍᴇ        ║\n"
            "╚════════════════════╝"
        )
        return TARGET

    context.user_data['target_display'] = target_u

    # -----------------------------
    # 🔐 Safe account access
    # -----------------------------
    data = users_data.get(user_id)
    if not data or not data.get('accounts'):
        await update.message.reply_text("❌ Account not found. Please /login again")
        return ConversationHandler.END

    acc = data['accounts'][data['default']]

    # -----------------------------
    # 3️⃣ Get DM thread URL safely
    # -----------------------------
    try:
        thread_url = await asyncio.to_thread(
            get_dm_thread_url,
            user_id,
            acc['ig_username'],
            acc['password'],
            target_u
        )
    except Exception as e:
        await update.message.reply_text(f"❌ Error fetching DM thread:\n{e}")
        return ConversationHandler.END

    # validate thread
    if not thread_url or not thread_url.startswith("https://www.instagram.com/direct/t/"):
        await update.message.reply_text(
            "╔════════════════════╗\n"
            "║ ❌ ᴄᴏᴜʟᴅ ɴᴏᴛ     ║\n"
            "║ ʟᴏᴄᴋ ᴛʜʀᴇᴀᴅ ɪᴅ  ║\n"
            "║ ᴡɪᴛʜ ᴅᴇꜰᴀᴜʟᴛ   ║\n"
            "║ ᴀᴄᴄᴏᴜɴᴛ        ║\n"
            "╚════════════════════╝"
        )
        return ConversationHandler.END

    context.user_data['thread_url'] = thread_url

    # -----------------------------
    # 4️⃣ Ask for messages
    # -----------------------------
    await update.message.reply_text(
        "╔════════════════════╗\n"
        "║ 📤 ꜱᴇɴᴅ ᴍᴇꜱꜱᴀɢᴇꜱ  ║\n"
        "║ ᴍꜱɢ1 & ᴍꜱɢ2 &... ║\n"
        "║ ᴏʀ ᴜᴘʟᴏᴀᴅ .ᴛxᴛ   ║\n"
        "╚════════════════════╝"
    )

    return MESSAGES


async def get_messages_file(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    📄 Handle uploaded .txt file
    """
    user_id = update.effective_user.id
    document = update.message.document

    # -------------------------
    # 1️⃣ Check file uploaded
    # -------------------------
    if not document:
        await update.message.reply_text(
            "╔════════════════════╗\n"
            "║ ❌ ᴘʟᴇᴀꜱᴇ       ║\n"
            "║ ᴜᴘʟᴏᴀᴅ ᴀ .ᴛxᴛ   ║\n"
            "║ ꜰɪʟᴇ            ║\n"
            "╚════════════════════╝"
        )
        return ConversationHandler.END

    # -------------------------
    # 2️⃣ File type validation
    # -------------------------
    if not document.file_name.lower().endswith(".txt"):
        await update.message.reply_text("❌ Only .txt file allowed")
        return ConversationHandler.END

    # -------------------------
    # 3️⃣ File size limit (max 1MB)
    # -------------------------
    if document.file_size and document.file_size > 1_000_000:
        await update.message.reply_text("❌ File too large (max 1MB)")
        return ConversationHandler.END

    try:
        file = await document.get_file()

        # -------------------------
        # 4️⃣ Unique file name
        # -------------------------
        import uuid, os
        randomid = str(uuid.uuid4())[:8]
        names_file = f"{user_id}_{randomid}.txt"

        # -------------------------
        # 5️⃣ Download file
        # -------------------------
        await file.download_to_drive(names_file)

        # -------------------------
        # 6️⃣ Check file empty
        # -------------------------
        if not os.path.exists(names_file) or os.path.getsize(names_file) == 0:
            await update.message.reply_text("❌ File is empty")
            return ConversationHandler.END

        # -------------------------
        # 7️⃣ Save in context
        # -------------------------
        context.user_data['uploaded_names_file'] = names_file

        # -------------------------
        # 8️⃣ Continue to message handler
        # -------------------------
        return await get_messages(update, context)

    except Exception as e:
        await update.message.reply_text(f"❌ Error downloading file: {e}")
        return ConversationHandler.END


async def get_messages(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    📝 Process messages and start attack
    """
    user_id = update.effective_user.id
    
    import uuid, os, json, time, subprocess, unicodedata, logging
    
    # -----------------------------
    # 1️⃣ Thread verification
    # -----------------------------
    thread_url = context.user_data.get('thread_url')
    target_display = context.user_data.get('target_display')
    target_mode = context.user_data.get('mode')
    
    if not thread_url:
        await update.message.reply_text(
            "╔══════════════════════╗\n"
            "║     ❌ ᴇʀʀᴏʀ        ║\n"
            "╠══════════════════════╣\n"
            "║ ᴛʜʀᴇᴀᴅ ɴᴏᴛ ꜱᴇᴛ    ║\n"
            "║ ʀᴇꜱᴛᴀʀᴛ /ᴀᴛᴛᴀᴄᴋ   ║\n"
            "╚══════════════════════╝"
        )
        return ConversationHandler.END
    
    # -----------------------------
    # 2️⃣ Message file handling
    # -----------------------------
    uploaded_file = context.user_data.pop('uploaded_names_file', None)
    
    if uploaded_file and os.path.exists(uploaded_file):
        names_file = uploaded_file
        logging.debug("Using uploaded file: %s", uploaded_file)
        
        if os.path.getsize(names_file) == 0:
            await update.message.reply_text(
                "╔══════════════════════╗\n"
                "║     ❌ ᴇʀʀᴏʀ        ║\n"
                "╠══════════════════════╣\n"
                "║ ᴜᴘʟᴏᴀᴅᴇᴅ ꜰɪʟᴇ     ║\n"
                "║ ɪꜱ ᴇᴍᴘᴛʏ          ║\n"
                "╚══════════════════════╝"
            )
            return ConversationHandler.END
    
    else:
        raw_text = (update.message.text or "").strip()
        
        if not raw_text:
            await update.message.reply_text(
                "╔══════════════════════╗\n"
                "║     ❌ ᴇʀʀᴏʀ        ║\n"
                "╠══════════════════════╣\n"
                "║ ᴇᴍᴘᴛʏ ᴍᴇꜱꜱᴀɢᴇ    ║\n"
                "║ ᴛᴇxᴛ               ║\n"
                "╚══════════════════════╝"
            )
            return ConversationHandler.END
        
        text = unicodedata.normalize("NFKC", raw_text)
        
        randomid = str(uuid.uuid4())[:8]
        names_file = f"{user_id}_{randomid}.txt"
        
        try:
            with open(names_file, 'w', encoding='utf-8') as f:
                f.write(text)
        except Exception as e:
            await update.message.reply_text(
                f"╔══════════════════════╗\n"
                f"║     ❌ ᴇʀʀᴏʀ        ║\n"
                f"╠══════════════════════╣\n"
                f"║ {str(e)[:18]:<18} ║\n"
                f"╚══════════════════════╝"
            )
            return ConversationHandler.END
    
    # -----------------------------
    # 3️⃣ Account + rotation
    # -----------------------------
    data = users_data.get(user_id)
    if not data or not data.get('accounts'):
        await update.message.reply_text(
            "╔══════════════════════╗\n"
            "║     ❌ ᴇʀʀᴏʀ        ║\n"
            "╠══════════════════════╣\n"
            "║ ᴀᴄᴄᴏᴜɴᴛ ᴍɪꜱꜱɪɴɢ   ║\n"
            "║ ᴘʟᴇᴀꜱᴇ /ʟᴏɢɪɴ     ║\n"
            "╚══════════════════════╝"
        )
        return ConversationHandler.END
    
    pairs = data.get('pairs')
    pair_list = pairs['list'] if pairs else [data['accounts'][data['default']]['ig_username']]
    
    if len(pair_list) == 1:
        warning = "⚠️ ᴡᴀʀɴɪɴɢ: ꜱɪɴɢʟᴇ ᴀᴄᴄᴏᴜɴᴛ ᴍᴀʏ ʟᴇᴀᴅ ᴛᴏ ᴄʜᴀᴛ ʙᴀɴ. ᴜꜱᴇ /ᴘᴀɪʀ ꜰᴏʀ ʀᴏᴛᴀᴛɪᴏɴ.\n\n"
    else:
        warning = ""
    
    switch_minutes = data.get('switch_minutes', 10)
    threads_n = data.get('threads', 1)
    
    # -----------------------------
    # 4️⃣ Running tasks limit
    # -----------------------------
    tasks = users_tasks.get(user_id, [])
    
    running_msg = [
        t for t in tasks
        if t.get('type') == 'message_attack'
        and t['status'] == 'running'
        and t['proc'].poll() is None
    ]
    
    if len(running_msg) >= 5:
        await update.message.reply_text(
            "╔══════════════════════╗\n"
            "║     ⚠ ʟɪᴍɪᴛ        ║\n"
            "╠══════════════════════╣\n"
            "║ ᴍᴀx 5 ᴀᴛᴛᴀᴄᴋꜱ     ║\n"
            "║ ꜱᴛᴏᴘ ᴏɴᴇ ꜰɪʀꜱᴛ    ║\n"
            "╚══════════════════════╝"
        )
        if os.path.exists(names_file):
            os.remove(names_file)
        return ConversationHandler.END
    
    # -----------------------------
    # 5️⃣ Duplicate protection
    # -----------------------------
    for t in tasks:
        if t.get("target_thread_url") == thread_url and t.get("status") == "running":
            await update.message.reply_text(
                "╔══════════════════════╗\n"
                "║     ⚠ ᴅᴜᴘʟɪᴄᴀᴛᴇ   ║\n"
                "╠══════════════════════╣\n"
                "║ ᴀʟʀᴇᴀᴅʏ ᴀᴛᴛᴀᴄᴋɪɴɢ ║\n"
                "║ ᴛʜɪꜱ ᴛᴀʀɢᴇᴛ       ║\n"
                "╚══════════════════════╝"
            )
            return ConversationHandler.END
    
    # -----------------------------
    # 6️⃣ Starting account
    # -----------------------------
    start_idx = pairs['default_index'] if pairs else 0
    start_u = pair_list[start_idx]
    
    start_acc = next(acc for acc in data['accounts'] if acc['ig_username'] == start_u)
    start_pass = start_acc['password']
    start_u = start_u.strip().lower()
    
    # -----------------------------
    # 7️⃣ Session state
    # -----------------------------
    state_file = f"sessions/{user_id}_{start_u}_state.json"
    
    if not os.path.exists(state_file):
        with open(state_file, 'w') as f:
            json.dump(start_acc['storage_state'], f)
    
    # -----------------------------
    # 8️⃣ Build command
    # -----------------------------
    cmd = [
        "python3", "msg.py",
        "--username", start_u,
        "--password", start_pass,
        "--thread-url", thread_url,
        "--names", names_file,
        "--tabs", str(threads_n),
        "--headless", "true",
        "--storage-state", state_file
    ]
    
    # -----------------------------
    # 9️⃣ Start process
    # -----------------------------
    try:
        proc = subprocess.Popen(cmd)
    except Exception as e:
        await update.message.reply_text(
            f"╔══════════════════════╗\n"
            f"║     ❌ ꜰᴀɪʟᴇᴅ      ║\n"
            f"╠══════════════════════╣\n"
            f"║ {str(e)[:18]:<18} ║\n"
            f"╚══════════════════════╝"
        )
        return ConversationHandler.END
    
    running_processes[proc.pid] = proc
    pid = proc.pid
    
    # -----------------------------
    # 🔟 Save task
    # -----------------------------
    task_id = str(uuid.uuid4())
    
    task = {
        "id": task_id,
        "user_id": user_id,
        "type": "message_attack",
        "pair_list": pair_list,
        "pair_index": start_idx,
        "switch_minutes": switch_minutes,
        "threads": threads_n,
        "names_file": names_file,
        "target_thread_url": thread_url,
        "target_type": target_mode,
        "target_display": target_display,
        "last_switch_time": time.time(),
        "status": "running",
        "cmd": cmd,
        "pid": pid,
        "display_pid": pid,
        "proc_list": [pid],
        "proc": proc,
        "start_time": time.time()
    }
    
    persistent_tasks.append(task)
    save_persistent_tasks()
    
    tasks.append(task)
    users_tasks[user_id] = tasks
    
    logging.info(f"{time.strftime('%Y-%m-%d %H:%M:%S')} Attack started user={user_id} target={target_display} pid={pid}")
    
    # -----------------------------
    # 1️⃣1️⃣ Status message
    # -----------------------------
    status_lines = []
    curr_u = pair_list[start_idx]
    for u in pair_list:
        if u == curr_u:
            status_lines.append(f"⚡ ᴜꜱɪɴɢ: {u}")
        else:
            status_lines.append(f"⏳ ᴄᴏᴏʟᴅᴏᴡɴ: {u}")
    
    status = "\n".join(status_lines)
    
    status_msg = (
        "╔══════════════════════╗\n"
        "║  🚀 ꜱᴘᴀᴍ ꜱᴛᴀʀᴛᴇᴅ  ║\n"
        "╠══════════════════════╣\n"
        f"{status}\n"
        "╠══════════════════════╣\n"
        f"║ ꜱᴛᴏᴘ: /stop {pid:<6} ║\n"
        f"║ ᴏʀ: /stop all      ║\n"
        "╚══════════════════════╝"
    )
    
    sent_msg = await update.message.reply_text(warning + status_msg)
    
    task['status_chat_id'] = update.message.chat_id
    task['status_msg_id'] = sent_msg.message_id
    
    return ConversationHandler.END

async def pattack_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    if not is_authorized(user_id):
        await update.message.reply_text("╔════════════════════╗\n║ ⚠️ ɴᴏᴛ ᴀᴜᴛʜᴏʀɪᴢᴇᴅ ║\n║ @Why_not_ZarKo     ║\n╚════════════════════╝")
        return ConversationHandler.END
    if user_id not in users_data or not users_data[user_id]['accounts']:
        await update.message.reply_text("╔════════════════════╗\n║ ❗ ᴘʟᴇᴀꜱᴇ        ║\n║ /ʟᴏɢɪɴ ꜰɪʀꜱᴛ    ║\n╚════════════════════╝")
        return ConversationHandler.END
    data = users_data[user_id]
    if data['default'] is None:
        data['default'] = 0
        save_user_data(user_id, data)
    await update.message.reply_text("╔════════════════════╗\n║ 🎯 ᴡʜᴇʀᴇ ᴛᴏ      ║\n║ ꜱᴇɴᴅ ᴍꜱɢꜱ?      ║\n║                   ║\n║ ᴅᴍ ᴏʀ ɢᴄ        ║\n╚════════════════════╝")
    return P_MODE

async def p_get_mode(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    💥 Choose sending mode (DM / GC)
    Stores mode in user_data and moves to next step
    """
    try:
        # Safety check
        if not update.message or not update.message.text:
            await update.message.reply_text("❌ Invalid input. Please type 'dm' or 'gc'.")
            return P_MODE

        text = update.message.text.strip().lower()

        # ---------------- DM MODE ----------------
        if text in ["dm", "d", "direct", "inbox"]:
            context.user_data['mode'] = 'dm'

            await update.message.reply_text(
                "╔════════════════════╗\n"
                "║     📩 DM MODE     ║\n"
                "╠════════════════════╣\n"
                "║ ᴇɴᴛᴇʀ ᴛᴀʀɢᴇᴛ       ║\n"
                "║ ᴜꜱᴇʀɴᴀᴍᴇ (ᴅɪꜱᴘʟᴀʏ) ║\n"
                "╚════════════════════╝"
            )
            return P_TARGET_DISPLAY

        # ---------------- GROUP MODE ----------------
        elif text in ["gc", "group", "groupchat", "g"]:
            context.user_data['mode'] = 'gc'

            await update.message.reply_text(
                "╔════════════════════╗\n"
                "║    👥 GC MODE      ║\n"
                "╠════════════════════╣\n"
                "║ ᴇɴᴛᴇʀ ɢʀᴏᴜᴘ ɴᴀᴍᴇ  ║\n"
                "║ (ᴅɪꜱᴘʟᴀʏ ᴏɴʟʏ)     ║\n"
                "╚════════════════════╝"
            )
            return P_TARGET_DISPLAY

        # ---------------- INVALID INPUT ----------------
        else:
            await update.message.reply_text(
                "╔════════════════════╗\n"
                "║     ❌ ɪɴᴠᴀʟɪᴅ     ║\n"
                "╠════════════════════╣\n"
                "║ ᴛʏᴘᴇ: dm ᴏʀ gc     ║\n"
                "╚════════════════════╝"
            )
            return P_MODE

    except Exception as e:
        # crash protection
        await update.message.reply_text(f"❌ Error: {str(e)[:30]}")
        return P_MODE

async def p_get_target_display(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    target_display = update.message.text.strip()
    if not target_display:
        await update.message.reply_text("⚠️ Invalid input. ⚠️")
        return P_TARGET_DISPLAY
    context.user_data['target_display'] = target_display
    if context.user_data['mode'] == 'dm':
        await update.message.reply_text("Enter username thread url:")
    else:
        await update.message.reply_text("Enter gc thread url:")
    return P_THREAD_URL

async def p_get_thread_url(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    thread_url = update.message.text.strip()
    if not thread_url.startswith("https://www.instagram.com/direct/t/"):
        await update.message.reply_text("⚠️ Invalid thread URL. It should be like https://www.instagram.com/direct/t/{id}/ ⚠️")
        return P_THREAD_URL
    context.user_data['thread_url'] = thread_url
    await update.message.reply_text("Send messages like: msg1 & msg2 & msg3 or upload .txt file")
    return P_MESSAGES

async def p_get_messages_file(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    document = update.message.document

    if not document:
        await update.message.reply_text("❌ Please upload a .txt file.")
        return ConversationHandler.END

    file = await document.get_file()

    import uuid, os
    randomid = str(uuid.uuid4())[:8]
    names_file = f"{user_id}_{randomid}.txt"

    # Save uploaded .txt file
    await file.download_to_drive(names_file)

    # store file path in context so p_get_messages can use it
    context.user_data['uploaded_names_file'] = names_file

    # Reuse same logic as text handler
    return await p_get_messages(update, context)

async def p_get_messages(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id

    import uuid, os, json, time, random

    # Check if we came from file upload handler
    uploaded_file = context.user_data.pop('uploaded_names_file', None)

    if uploaded_file and os.path.exists(uploaded_file):
        # Use already saved .txt file from upload
        names_file = uploaded_file
        raw_text = f"[USING_UPLOADED_FILE:{os.path.basename(uploaded_file)}]"
        logging.debug("USING UPLOADED FILE: %r", uploaded_file)
    else:
        # Normal text input flow
        raw_text = (update.message.text or "").strip()
        logging.debug("RAW MESSAGES INPUT: %r", raw_text)

        # Normalize to handle fullwidth & etc.
        text = unicodedata.normalize("NFKC", raw_text)

        # Always make a temp file
        randomid = str(uuid.uuid4())[:8]
        names_file = f"{user_id}_{randomid}.txt"

        # ✅ Write raw text directly so msgb.py handles splitting correctly
        try:
            with open(names_file, 'w', encoding='utf-8') as f:
                f.write(text)
        except Exception as e:
            await update.message.reply_text(f"❌ Error creating file: {e}")
            return ConversationHandler.END

    data = users_data[user_id]
    pairs = data.get('pairs') or {}
    pair_list = pairs.get('list') or [
    data['accounts'][data['default']]['ig_username']]
    start_idx = pairs.get('default_index', 0)
    if len(pair_list) == 1:
        warning = "⚠️ Warning: You may get chat ban if you use a single account too long. Use /pair to make multi-account rotation.\n\n"
    else:
        warning = ""
    switch_minutes = data.get('switch_minutes', 10)
    threads_n = data.get('threads', 1)
    tasks = users_tasks.get(user_id, [])
    running_msg = [t for t in tasks if t.get('type') == 'message_attack' and t['status'] == 'running' and t['proc'].poll() is None]
    if len(running_msg) >= 5:
        await update.message.reply_text("⚠️ Max 5 message attacks running. Stop one first. ⚠️")
        if os.path.exists(names_file):
            os.remove(names_file)
        return ConversationHandler.END

    thread_url = context.user_data['thread_url']
    target_display = context.user_data['target_display']
    target_mode = context.user_data['mode']
    start_idx = pairs['default_index'] if pairs else 0
    start_u = pair_list[start_idx]
    start_acc = next(acc for acc in data['accounts'] if acc['ig_username'] == start_u)
    start_pass = start_acc['password']
    start_u = start_u.strip().lower()
    state_file = f"sessions/{user_id}_{start_u}_state.json"
    if not os.path.exists(state_file):
        with open(state_file, 'w') as f:
            json.dump(start_acc['storage_state'], f)

    cmd = [
        "python3", "msg.py",
        "--username", start_u,
        "--password", start_pass,
        "--thread-url", thread_url,
        "--names", names_file,
        "--tabs", str(threads_n),
        "--headless", "true",
        "--storage-state", state_file
    ]
    proc = subprocess.Popen(cmd)
    running_processes[proc.pid] = proc
    pid = proc.pid
    task_id = str(uuid.uuid4())
    task = {
        "id": task_id,
        "user_id": user_id,
        "type": "message_attack",
        "pair_list": pair_list,
        "pair_index": start_idx,
        "switch_minutes": switch_minutes,
        "threads": threads_n,
        "names_file": names_file,
        "target_thread_url": thread_url,
        "target_type": target_mode,
        "target_display": target_display,
        "last_switch_time": time.time(),
        "status": "running",
        "cmd": cmd,
        "pid": pid,
        "display_pid": pid,
        "proc_list": [pid],
        "proc": proc,
        "start_time": time.time()
    }
    persistent_tasks.append(task)
    save_persistent_tasks()
    tasks.append(task)
    users_tasks[user_id] = tasks
    logging.info(f"{time.strftime('%Y-%m-%d %H:%M:%S')} Message attack start user={user_id} task={task_id} target={target_display} pid={pid}")

    status = "Spamming...!\n"
    curr_u = pair_list[task['pair_index']]
    for u in pair_list:
        if u == curr_u:
            status += f"using - {u}\n"
        else:
            status += f"cooldown - {u}\n"
    status += f"To stop 🛑 type /stop {task['display_pid']} or /stop all to stop all processes."

    sent_msg = await update.message.reply_text(warning + status)
    task['status_chat_id'] = update.message.chat_id
    task['status_msg_id'] = sent_msg.message_id
    return ConversationHandler.END

def load_persistent_tasks():
    global persistent_tasks
    if os.path.exists(TASKS_FILE):
        with open(TASKS_FILE, 'r') as f:
            persistent_tasks = json.load(f)
    else:
        persistent_tasks = []

def save_persistent_tasks():
    """
    Safely write persistent_tasks to TASKS_FILE.
    Removes runtime-only values (like 'proc') and ensures JSON-safe data.
    """
    safe_list = []
    for t in persistent_tasks:
        cleaned = {}
        for k, v in t.items():
            if k == 'proc':
                continue
            if isinstance(v, (int, float, str, bool, dict, list, type(None))):
                cleaned[k] = v
            else:
                try:
                    json.dumps(v)
                    cleaned[k] = v
                except Exception:
                    cleaned[k] = str(v)
        safe_list.append(cleaned)

    temp_file = TASKS_FILE + '.tmp'
    with open(temp_file, 'w') as f:
        json.dump(safe_list, f, indent=2)
    os.replace(temp_file, TASKS_FILE)

def mark_task_stopped_persistent(task_id: str):
    global persistent_tasks
    for task in persistent_tasks:
        if task['id'] == task_id:
            task['status'] = 'stopped'
            save_persistent_tasks()
            break

def update_task_pid_persistent(task_id: str, new_pid: int):
    global persistent_tasks
    for task in persistent_tasks:
        if task['id'] == task_id:
            task['pid'] = new_pid
            save_persistent_tasks()
            break

def mark_task_completed_persistent(task_id: str):
    global persistent_tasks
    for task in persistent_tasks:
        if task['id'] == task_id:
            task['status'] = 'completed'
            save_persistent_tasks()
            break

def restore_tasks_on_start():
    load_persistent_tasks()
    print(f"🔄 Restoring {len([t for t in persistent_tasks if t.get('type') == 'message_attack' and t['status'] == 'running'])} running message attacks...")
    for task in persistent_tasks[:]:
        if task.get('type') == 'message_attack' and task['status'] == 'running':
            old_pid = task['pid']
            try:
                os.kill(old_pid, signal.SIGTERM)
                time.sleep(1)
            except OSError:
                pass  # Already dead
            user_id = task['user_id']
            data = users_data.get(user_id)
            if not data:
                mark_task_stopped_persistent(task['id'])
                continue
            pair_list = task['pair_list']
            curr_idx = task['pair_index']
            curr_u = pair_list[curr_idx]
            curr_acc = None
            for acc in data['accounts']:
                if acc['ig_username'] == curr_u:
                    curr_acc = acc
                    break
            if not curr_acc:
                mark_task_stopped_persistent(task['id'])
                continue
            curr_pass = curr_acc['password']
            curr_u = curr_u.strip().lower()
            state_file = f"sessions/{user_id}_{curr_u}_state.json"
            if not os.path.exists(state_file):
                with open(state_file, 'w') as f:
                    json.dump(curr_acc['storage_state'], f)
            names_file = task['names_file']
            if not os.path.exists(names_file):
                # Recreate if missing? But skip for now
                mark_task_stopped_persistent(task['id'])
                continue
            cmd = [
                "python3", "msg.py",
                "--username", curr_u,
                "--password", curr_pass,
                "--thread-url", task['target_thread_url'],
                "--names", names_file,
                "--tabs", str(task['threads']),
                "--headless", "true",
                "--storage-state", state_file
            ]
            try:
                proc = subprocess.Popen(cmd)
                # Register runtime map
                running_processes[proc.pid] = proc
                new_pid = proc.pid
                update_task_pid_persistent(task['id'], new_pid)
                mem_task = task.copy()
                mem_task['proc'] = proc
                mem_task['proc_list'] = [proc.pid]
                mem_task['display_pid'] = task.get('display_pid', proc.pid)
                if user_id not in users_tasks:
                    users_tasks[user_id] = []
                users_tasks[user_id].append(mem_task)
                print(f"✅ Restored message attack {task['id']} for {task['target_display']} | New PID: {new_pid}")
            except Exception as e:
                logging.error(f"❌ Failed to restore message attack {task['id']}: {e}")
                mark_task_stopped_persistent(task['id'])
    save_persistent_tasks()
    print("✅ Task restoration complete!")

async def send_resume_notification(user_id: int, task: Dict):
    ttype = task['target_type']
    tdisplay = task['target_display']
    disp = f"dm -> @{tdisplay}" if ttype == 'dm' else tdisplay
    msg = f"🔄 Attack auto resumed! New PID: {task['pid']} ({disp})\n"
    pair_list = task['pair_list']
    curr_idx = task['pair_index']
    curr_u = pair_list[curr_idx]
    for u in pair_list:
        if u == curr_u:
            msg += f"using - {u}\n"
        else:
            msg += f"cooldown - {u}\n"
    await APP.bot.send_message(chat_id=user_id, text=msg)

def get_switch_update(task: Dict) -> str:
    pair_list = task['pair_list']
    curr_idx = task['pair_index']
    curr_u = pair_list[curr_idx]
    lines = []
    for u in pair_list:
        if u == curr_u:
            lines.append(f"using - {u}")
        else:
            lines.append(f"cooldown - {u}")
    return '\n'.join(lines)

def switch_task_sync(task: Dict):
    user_id = task['user_id']

    # Keep reference to old proc (don't terminate it yet)
    try:
        old_proc = task.get('proc')
        old_pid = task.get('pid')
    except Exception:
        old_proc = None
        old_pid = task.get('pid')

    # Advance index first so new account is chosen
    task['pair_index'] = (task['pair_index'] + 1) % len(task['pair_list'])
    next_u = task['pair_list'][task['pair_index']]
    data = users_data.get(user_id)
    if not data:
        logging.error(f"No users_data for user {user_id} during switch")
        return

    next_acc = next((a for a in data['accounts'] if a['ig_username'] == next_u), None)
    if not next_acc:
        logging.error(f"Can't find account {next_u} for switch")
        try:
            asyncio.run_coroutine_threadsafe(
                APP.bot.send_message(user_id, f"can't find thread Id - {next_u}"),
                LOOP
            )
        except Exception:
            pass
        return

    next_pass = next_acc['password']
    next_state_file = f"sessions/{user_id}_{next_u}_state.json"
    if not os.path.exists(next_state_file):
        try:
            with open(next_state_file, 'w') as f:
                json.dump(next_acc.get('storage_state', {}), f)
        except Exception as e:
            logging.error(f"Failed to write state file for {next_u}: {e}")

    # Launch new process FIRST so overlap prevents downtime
    new_cmd = [
        "python3", "msg.py",
        "--username", next_u,
        "--password", next_pass,
        "--thread-url", task['target_thread_url'],
        "--names", task['names_file'],
        "--tabs", str(task['threads']),
        "--headless", "true",
        "--storage-state", next_state_file
    ]
    try:
        new_proc = subprocess.Popen(new_cmd)
    except Exception as e:
        logging.error(f"Failed to launch new proc for switch to {next_u}: {e}")
        return

    # Append new to proc_list
    task['proc_list'].append(new_proc.pid)

    # Register new proc and update task/persistent info
    running_processes[new_proc.pid] = new_proc
    task['cmd'] = new_cmd
    task['pid'] = new_proc.pid
    task['proc'] = new_proc
    task['last_switch_time'] = time.time()
    try:
        update_task_pid_persistent(task['id'], task['pid'])
    except Exception as e:
        logging.error(f"Failed to update persistent pid for task {task.get('id')}: {e}")

    # Give old proc a short cooldown window before killing it (avoid downtime)
    if old_proc and old_pid != new_proc.pid:
        try:
            # Allow overlap for a short cooldown
            time.sleep(5)
            try:
                old_proc.terminate()
            except Exception:
                pass
            # wait a bit for graceful shutdown
            time.sleep(2)
            if old_proc.poll() is None:
                try:
                    old_proc.kill()
                except Exception:
                    pass
            # Remove old from proc_list and running_processes
            if old_pid in task['proc_list']:
                task['proc_list'].remove(old_pid)
            if old_pid in running_processes:
                running_processes.pop(old_pid, None)
        except Exception as e:
            logging.error(f"Error while stopping old proc after switch: {e}")

    # Send/update status message (edit if message id present)
    try:
        chat_id = task.get('status_chat_id', user_id)
        msg_id = task.get('status_msg_id')
        text = "Spamming...!\n" + get_switch_update(task)
        text += f"\nTo stop 🛑 type /stop {task['display_pid']} or /stop all to stop all processes."
        if msg_id:
            asyncio.run_coroutine_threadsafe(
                APP.bot.edit_message_text(chat_id=chat_id, message_id=msg_id, text=text),
                LOOP
            )
        else:
            asyncio.run_coroutine_threadsafe(
                APP.bot.send_message(chat_id=chat_id, text=text),
                LOOP
            )
    except Exception as e:
        logging.error(f"Failed to update status message: {e}")

def switch_monitor():
    while True:
        time.sleep(30)
        for user_id in list(users_tasks):
            if user_id not in users_tasks:
                continue
            for task in users_tasks[user_id]:
                if task.get('type') == 'message_attack' and task['status'] == 'running' and task['proc'].poll() is None:
                    due_time = task['last_switch_time'] + task['switch_minutes'] * 60
                    if time.time() >= due_time:
                        if len(task['pair_list']) > 1:
                            switch_task_sync(task)

async def stop(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    🛑 ꜱᴛᴏᴘ ʀᴜɴɴɪɴɢ ᴛᴀꜱᴋꜱ
    """
    user_id = update.effective_user.id
    
    # ⚡ ᴀᴜᴛʜᴏʀɪᴢᴀᴛɪᴏɴ ᴄʜᴇᴄᴋ
    if not is_authorized(user_id):
        await update.message.reply_text(
            "╔══════════════════════╗\n"
            "║     ⚠ ᴜɴᴀᴜᴛʜᴏʀɪᴢᴇᴅ ║\n"
            "╠══════════════════════╣\n"
            "║ ᴅᴍ @ᴡʜʏ_ɴᴏᴛ_ᴢᴀʀᴋᴏ   ║\n"
            "║ ꜰᴏʀ ᴀᴄᴄᴇꜱꜱ         ║\n"
            "╚══════════════════════╝"
        )
        return
    
    # ❓ ᴜꜱᴀɢᴇ ᴄʜᴇᴄᴋ
    if not context.args:
        await update.message.reply_text(
            "╔══════════════════════╗\n"
            "║     ❓ ᴜꜱᴀɢᴇ        ║\n"
            "╠══════════════════════╣\n"
            "║ /ꜱᴛᴏᴘ <ᴘɪᴅ>        ║\n"
            "║ /ꜱᴛᴏᴘ ᴀʟʟ           ║\n"
            "╚══════════════════════╝"
        )
        return
    
    arg = context.args[0]
    
    # 📋 ᴛᴀꜱᴋ ᴄʜᴇᴄᴋ
    if user_id not in users_tasks or not users_tasks[user_id]:
        await update.message.reply_text(
            "╔══════════════════════╗\n"
            "║     ❌ ɴᴏ ᴛᴀꜱᴋꜱ     ║\n"
            "╠══════════════════════╣\n"
            "║ ɴᴏ ʀᴜɴɴɪɴɢ ᴛᴀꜱᴋꜱ   ║\n"
            "║ ꜰᴏᴜɴᴅ               ║\n"
            "╚══════════════════════╝"
        )
        return
    
    tasks = users_tasks[user_id]
    
    # =============================
    # 🛑 ꜱᴛᴏᴘ ᴀʟʟ ᴛᴀꜱᴋꜱ
    # =============================
    if arg == 'all':
        stopped_count = 0
        for task in tasks[:]:
            proc = task['proc']
            proc.terminate()
            await asyncio.sleep(3)
            if proc.poll() is None:
                proc.kill()
            
            # Remove from runtime map
            pid = task.get('pid')
            if pid in running_processes:
                running_processes.pop(pid, None)
            
            # Clean up names file
            if task.get('type') == 'message_attack' and 'names_file' in task:
                names_file = task['names_file']
                if os.path.exists(names_file):
                    os.remove(names_file)
            
            logging.info(f"{time.strftime('%Y-%m-%d %H:%M:%S')} Task stop user={user_id} task={task['id']}")
            mark_task_stopped_persistent(task['id'])
            tasks.remove(task)
            stopped_count += 1
        
        await update.message.reply_text(
            f"╔══════════════════════╗\n"
            f"║     🛑 ꜱᴛᴏᴘᴘᴇᴅ      ║\n"
            f"╠══════════════════════╣\n"
            f"║ ᴛᴀꜱᴋꜱ: {stopped_count:<2d}/ᴛᴏᴛᴀʟ     ║\n"
            f"╚══════════════════════╝"
        )
    
    # =============================
    # 🔢 ꜱᴛᴏᴘ ʙʏ ᴘɪᴅ
    # =============================
    elif arg.isdigit():
        pid_to_stop = int(arg)
        stopped_task = None
        
        # Try users_tasks by display_pid
        for task in tasks[:]:
            if task.get('display_pid') == pid_to_stop:
                proc_list = task.get('proc_list', [])
                for backend_pid in proc_list:
                    backend_proc = running_processes.get(backend_pid)
                    if backend_proc:
                        try:
                            backend_proc.terminate()
                        except Exception:
                            pass
                        await asyncio.sleep(3)
                        if backend_proc.poll() is None:
                            try:
                                backend_proc.kill()
                            except Exception:
                                pass
                    else:
                        try:
                            os.kill(backend_pid, signal.SIGTERM)
                        except Exception:
                            pass
                
                for backend_pid in proc_list:
                    running_processes.pop(backend_pid, None)
                
                mark_task_stopped_persistent(task['id'])
                
                if 'names_file' in task and os.path.exists(task['names_file']):
                    os.remove(task['names_file'])
                
                stopped_task = task
                tasks.remove(task)
                
                await update.message.reply_text(
                    f"╔══════════════════════╗\n"
                    f"║     🛑 ꜱᴛᴏᴘᴘᴇᴅ      ║\n"
                    f"╠══════════════════════╣\n"
                    f"║ ᴘɪᴅ: {pid_to_stop:<10d} ║\n"
                    f"╚══════════════════════╝"
                )
                break
        
        # Fallback to runtime map
        if not stopped_task:
            proc = running_processes.get(pid_to_stop)
            if proc:
                try:
                    proc.terminate()
                except Exception:
                    pass
                await asyncio.sleep(2)
                if proc.poll() is None:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                running_processes.pop(pid_to_stop, None)
                
                for t in persistent_tasks:
                    if t.get('pid') == pid_to_stop:
                        mark_task_stopped_persistent(t['id'])
                        break
                
                await update.message.reply_text(
                    f"╔══════════════════════╗\n"
                    f"║     🛑 ꜱᴛᴏᴘᴘᴇᴅ      ║\n"
                    f"╠══════════════════════╣\n"
                    f"║ ᴘɪᴅ: {pid_to_stop:<10d} ║\n"
                    f"╚══════════════════════╝"
                )
                return
        
        if not stopped_task:
            await update.message.reply_text(
                "╔══════════════════════╗\n"
                "║     ⚠ ɴᴏᴛ ꜰᴏᴜɴᴅ    ║\n"
                "╠══════════════════════╣\n"
                "║ ᴛᴀꜱᴋ ᴡɪᴛʜ ᴘɪᴅ      ║\n"
                f"║ {pid_to_stop:<18d} ║\n"
                "║ ɴᴏᴛ ꜰᴏᴜɴᴅ          ║\n"
                "╚══════════════════════╝"
            )
    
    # =============================
    # ❌ ɪɴᴠᴀʟɪᴅ ɪɴᴘᴜᴛ
    # =============================
    else:
        await update.message.reply_text(
            "╔══════════════════════╗\n"
            "║     ❓ ᴜꜱᴀɢᴇ        ║\n"
            "╠══════════════════════╣\n"
            "║ /ꜱᴛᴏᴘ <ᴘɪᴅ>        ║\n"
            "║ /ꜱᴛᴏᴘ ᴀʟʟ           ║\n"
            "╚══════════════════════╝"
        )
    
    users_tasks[user_id] = tasks

async def task_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    📋 ᴠɪᴇᴡ ʀᴜɴɴɪɴɢ ᴛᴀꜱᴋꜱ
    """
    user_id = update.effective_user.id
    
    # ⚡ ᴀᴜᴛʜᴏʀɪᴢᴀᴛɪᴏɴ ᴄʜᴇᴄᴋ
    if not is_authorized(user_id):
        await update.message.reply_text(
            "╔══════════════════════╗\n"
            "║     ⚠ ᴜɴᴀᴜᴛʜᴏʀɪᴢᴇᴅ ║\n"
            "╠══════════════════════╣\n"
            "║ ᴅᴍ @ᴡʜʏ_ɴᴏᴛ_ᴢᴀʀᴋᴏ   ║\n"
            "║ ꜰᴏʀ ᴀᴄᴄᴇꜱꜱ         ║\n"
            "╚══════════════════════╝"
        )
        return
    
    # 📋 ᴛᴀꜱᴋ ᴄʜᴇᴄᴋ
    if user_id not in users_tasks or not users_tasks[user_id]:
        await update.message.reply_text(
            "╔══════════════════════╗\n"
            "║     ❌ ɴᴏ ᴛᴀꜱᴋꜱ     ║\n"
            "╠══════════════════════╣\n"
            "║ ɴᴏ ᴏɴɢᴏɪɴɢ ᴛᴀꜱᴋꜱ   ║\n"
            "║ ꜰᴏᴜɴᴅ               ║\n"
            "╚══════════════════════╝"
        )
        return
    
    tasks = users_tasks[user_id]
    active_tasks = []
    
    # 🔄 ꜰɪʟᴛᴇʀ ᴀᴄᴛɪᴠᴇ ᴛᴀꜱᴋꜱ
    for t in tasks:
        if t['proc'].poll() is None:
            active_tasks.append(t)
        else:
            mark_task_completed_persistent(t['id'])
    
    users_tasks[user_id] = active_tasks
    
    if not active_tasks:
        await update.message.reply_text(
            "╔══════════════════════╗\n"
            "║     ❌ ɴᴏ ᴀᴄᴛɪᴠᴇ    ║\n"
            "╠══════════════════════╣\n"
            "║ ɴᴏ ᴀᴄᴛɪᴠᴇ ᴛᴀꜱᴋꜱ    ║\n"
            "║ ʀᴜɴɴɪɴɢ             ║\n"
            "╚══════════════════════╝"
        )
        return
    
    # 📊 ʙᴜɪʟᴅ ᴛᴀꜱᴋ ʟɪꜱᴛ
    task_lines = []
    for idx, task in enumerate(active_tasks, 1):
        tdisplay = task.get('target_display', 'ᴜɴᴋɴᴏᴡɴ')
        ttype = task.get('type', 'ᴜɴᴋɴᴏᴡɴ')
        preview = tdisplay[:15] + '...' if len(tdisplay) > 15 else tdisplay
        display_pid = task.get('display_pid', task['pid'])
        
        # Format task line with proper spacing
        task_lines.append(f"║ {idx:2d} │ ᴘɪᴅ:{display_pid:<6} ║")
        task_lines.append(f"║   ├─ {preview:<15} ║")
        task_lines.append(f"║   └─ [{ttype}]        ║")
        if idx < len(active_tasks):
            task_lines.append("║    ────────────────   ║")
    
    # Header and footer
    header = (
        "╔══════════════════════╗\n"
        f"║  📋 ᴀᴄᴛɪᴠᴇ: {len(active_tasks):2d}/{len(tasks):2d}    ║\n"
        "╠══════════════════════╣"
    )
    
    footer = "╚══════════════════════╝"
    
    # Combine all parts
    full_msg = header + "\n" + "\n".join(task_lines) + "\n" + footer
    
    await update.message.reply_text(full_msg)

async def usg_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    💻 ꜱʏꜱᴛᴇᴍ ꜱᴛᴀᴛᴜꜱ ᴍᴏɴɪᴛᴏʀ
    """
    if not is_authorized(update.effective_user.id):
        await update.message.reply_text(
            "╭─────────────────────────────────╮\n"
            "│     ⚠ ᴜɴᴀᴜᴛʜᴏʀɪᴢᴇᴅ           │\n"
            "├─────────────────────────────────┤\n"
            "│ ᴅᴍ @ᴡʜʏ_ɴᴏᴛ_ᴢᴀʀᴋᴏ ꜰᴏʀ ᴀᴄᴄᴇꜱꜱ │\n"
            "╰─────────────────────────────────╯"
        )
        return
    
    # 📊 ɢᴇᴛ ꜱʏꜱᴛᴇᴍ ɪɴꜰᴏ
    cpu = psutil.cpu_percent(interval=1)
    cpu_cores = psutil.cpu_count()
    mem = psutil.virtual_memory()
    ram_used = mem.used / (1024 ** 3)
    ram_total = mem.total / (1024 ** 3)
    ram_free = mem.free / (1024 ** 3)
    ram_percent = mem.percent
    
    # 💿 ꜱᴛᴏʀᴀɢᴇ ɪɴꜰᴏ (using root partition)
    disk = psutil.disk_usage('/')
    disk_used = disk.used / (1024 ** 3)
    disk_total = disk.total / (1024 ** 3)
    disk_free = disk.free / (1024 ** 3)
    disk_percent = disk.percent
    
    # 🎨 ᴄʀᴇᴀᴛᴇ ᴘʀᴏɢʀᴇꜱꜱ ʙᴀʀꜱ
    cpu_bar = create_progress_bar(cpu, 10)
    ram_bar = create_colored_bar(ram_percent, 10)
    disk_bar = create_colored_bar(disk_percent, 10)
    
    # ⏰ ᴛɪᴍᴇꜱᴛᴀᴍᴘ
    current_time = time.strftime("%H:%M:%S")
    
    # 📋 ʙᴜɪʟᴅ ꜱᴛᴀᴛᴜꜱ ᴍᴇꜱꜱᴀɢᴇ
    msg = (
        "╭─────────────────────────────────╮\n"
        "│    💻 ꜱʏꜱᴛᴇᴍ ꜱᴛᴀᴛᴜꜱ          │\n"
        "╰─────────────────────────────────╯\n\n"
        "┌─────────────────────────────────┐\n"
        "│     🖥️ ᴄᴘᴢ                    │\n"
        "├─────────────────────────────────┤\n"
        f"│ • ᴜꜱᴀɢᴇ:   {cpu:5.1f}%                    │\n"
        f"│ • ᴄᴏʀᴇꜱ:    {cpu_cores:<2d}                      │\n"
        f"│ {cpu_bar} {cpu:5.1f}%        │\n"
        "└─────────────────────────────────┘\n\n"
        "┌─────────────────────────────────┐\n"
        "│     🧠 ʀᴀᴍ                    │\n"
        "├─────────────────────────────────┤\n"
        f"│ • ᴛᴏᴛᴀʟ:   {ram_total:5.1f} ɢʙ                │\n"
        f"│ • ᴜꜱᴇᴅ:    {ram_used:5.1f} ɢʙ                │\n"
        f"│ • ꜰʀᴇᴇ:    {ram_free:5.1f} ɢʙ                │\n"
        f"│ • ᴜꜱᴀɢᴇ:   {ram_percent:5.1f}%                    │\n"
        f"│ {ram_bar} {ram_percent:5.1f}%        │\n"
        "└─────────────────────────────────┘\n\n"
        "┌─────────────────────────────────┐\n"
        "│     💿 ꜱᴛᴏʀᴀɢᴇ                │\n"
        "├─────────────────────────────────┤\n"
        f"│ • ᴛᴏᴛᴀʟ:   {disk_total:5.1f} ɢʙ                │\n"
        f"│ • ᴜꜱᴇᴅ:    {disk_used:5.1f} ɢʙ                │\n"
        f"│ • ꜰʀᴇᴇ:    {disk_free:5.1f} ɢʙ                │\n"
        f"│ • ᴜꜱᴀɢᴇ:   {disk_percent:5.1f}%                    │\n"
        f"│ {disk_bar} {disk_percent:5.1f}%        │\n"
        "└─────────────────────────────────┘\n\n"
        f"🕒 ʟᴀꜱᴛ ᴜᴘᴅᴀᴛᴇ: {current_time}"
    )
    
    await update.message.reply_text(msg)


def create_progress_bar(percent: float, length: int = 10) -> str:
    """
    📊 ᴄʀᴇᴀᴛᴇ ꜱᴛᴀɴᴅᴀʀᴅ ᴘʀᴏɢʀᴇꜱꜱ ʙᴀʀ
    """
    filled = int(round(percent / 100 * length))
    empty = length - filled
    return "█" * filled + "░" * empty


def create_colored_bar(percent: float, length: int = 10) -> str:
    """
    🎨 ᴄʀᴇᴀᴛᴇ ᴄᴏʟᴏʀ-ᴄᴏᴅᴇᴅ ᴘʀᴏɢʀᴇꜱꜱ ʙᴀʀ
    """
    filled = int(round(percent / 100 * length))
    empty = length - filled
    
    if percent < 50:
        bar = "🟢" * filled + "⚪" * empty
    elif percent < 80:
        bar = "🟡" * filled + "⚪" * empty
    else:
        bar = "🔴" * filled + "⚪" * empty
    
    return bar

async def cancel_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    ❌ ᴄᴀɴᴄᴇʟ ᴀᴄᴛɪᴠᴇ ꜰᴇᴛᴄʜɪɴɢ ᴘʀᴏᴄᴇꜱꜱ
    """
    user_id = update.effective_user.id
    
    if user_id in user_fetching:
        user_fetching.discard(user_id)
        await update.message.reply_text(
            "╔══════════════════════╗\n"
            "║     ❌ ᴄᴀɴᴄᴇʟʟᴇᴅ    ║\n"
            "╠══════════════════════╣\n"
            "║ ꜰᴇᴛᴄʜɪɴɢ ꜱᴛᴏᴘᴘᴇᴅ   ║\n"
            "║ ꜱᴜᴄᴄᴇꜱꜱꜰᴜʟʟʏ      ║\n"
            "╚══════════════════════╝"
        )
    else:
        await update.message.reply_text(
            "╔══════════════════════╗\n"
            "║     ℹ ɪɴꜰᴏ         ║\n"
            "╠══════════════════════╣\n"
            "║ ɴᴏ ᴀᴄᴛɪᴠᴇ ꜰᴇᴛᴄʜɪɴɢ ║\n"
            "║ ᴛᴏ ᴄᴀɴᴄᴇʟ          ║\n"
            "╚══════════════════════╝"
        )

async def add_user(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    ➕ ᴀᴅᴅ ᴀᴜᴛʜᴏʀɪᴢᴇᴅ ᴜꜱᴇʀ
    """
    user_id = update.effective_user.id
    
    if not is_owner(user_id):
        await update.message.reply_text(
            "╔══════════════════════╗\n"
            "║     ⚠ ᴀᴄᴄᴇꜱꜱ       ║\n"
            "╠══════════════════════╣\n"
            "║ ʏᴏᴜ ᴀʀᴇ ɴᴏᴛ ᴀɴ     ║\n"
            "║ ᴀᴅᴍɪɴ              ║\n"
            "╚══════════════════════╝"
        )
        return
    
    if len(context.args) != 1:
        await update.message.reply_text(
            "╔══════════════════════╗\n"
            "║     ❓ ᴜꜱᴀɢᴇ        ║\n"
            "╠══════════════════════╣\n"
            "║ /ᴀᴅᴅ <ᴛɢ_ɪᴅ>        ║\n"
            "╚══════════════════════╝"
        )
        return
    
    try:
        tg_id = int(context.args[0])
        
        if any(u['id'] == tg_id for u in authorized_users):
            await update.message.reply_text(
                "╔══════════════════════╗\n"
                "║     ❗ ᴇxɪꜱᴛꜱ      ║\n"
                "╠══════════════════════╣\n"
                "║ ᴜꜱᴇʀ ᴀʟʀᴇᴀᴅʏ     ║\n"
                "║ ᴀᴅᴅᴇᴅ              ║\n"
                "╚══════════════════════╝"
            )
            return
        
        authorized_users.append({'id': tg_id, 'username': ''})
        save_authorized()
        
        await update.message.reply_text(
            f"╔══════════════════════╗\n"
            f"║     ➕ ᴀᴅᴅᴇᴅ        ║\n"
            f"╠══════════════════════╣\n"
            f"║ {tg_id:<18d} ║\n"
            f"║ ᴀᴜᴛʜᴏʀɪᴢᴇᴅ ᴜꜱᴇʀ   ║\n"
            f"╚══════════════════════╝"
        )
        
    except ValueError:
        await update.message.reply_text(
            "╔══════════════════════╗\n"
            "║     ⚠ ɪɴᴠᴀʟɪᴅ      ║\n"
            "╠══════════════════════╣\n"
            "║ ɪɴᴠᴀʟɪᴅ ᴛɢ_ɪᴅ      ║\n"
            "║ ᴘʟᴇᴀꜱᴇ ᴇɴᴛᴇʀ      ║\n"
            "║ ᴀ ɴᴜᴍʙᴇʀ           ║\n"
            "╚══════════════════════╝"
        )

async def remove_user(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    ➖ ʀᴇᴍᴏᴠᴇ ᴀᴜᴛʜᴏʀɪᴢᴇᴅ ᴜꜱᴇʀ
    """
    global authorized_users   # ✔️ FIX: global hamesha top pe

    user_id = update.effective_user.id

    # 🔐 Only owner allowed
    if not is_owner(user_id):
        await update.message.reply_text(
            "╔══════════════════════╗\n"
            "║     ⚠ ᴀᴄᴄᴇꜱꜱ       ║\n"
            "╠══════════════════════╣\n"
            "║ ʏᴏᴜ ᴀʀᴇ ɴᴏᴛ ᴀɴ     ║\n"
            "║ ᴀᴅᴍɪɴ              ║\n"
            "╚══════════════════════╝"
        )
        return

    # ❓ Usage check
    if not context.args or not context.args[0].isdigit():
        await update.message.reply_text(
            "╔══════════════════════╗\n"
            "║     ❓ ᴜꜱᴀɢᴇ        ║\n"
            "╠══════════════════════╣\n"
            "║ /ʀᴇᴍᴏᴠᴇ <ᴛɢ_ɪᴅ>     ║\n"
            "╚══════════════════════╝"
        )
        return

    tg_id = int(context.args[0])

    # 🔍 Check before remove
    user_exists = any(u['id'] == tg_id for u in authorized_users)

    # ➖ Remove user
    authorized_users = [u for u in authorized_users if u['id'] != tg_id]
    save_authorized()

    # 📤 Response
    if user_exists:
        await update.message.reply_text(
            f"╔══════════════════════╗\n"
            f"║     ➖ ʀᴇᴍᴏᴠᴇᴅ      ║\n"
            f"╠══════════════════════╣\n"
            f"║ {tg_id:<18d} ║\n"
            f"║ ʀᴇᴍᴏᴠᴇᴅ ꜰʀᴏᴍ     ║\n"
            f"║ ᴀᴜᴛʜᴏʀɪᴢᴇᴅ ʟɪꜱᴛ   ║\n"
            f"╚══════════════════════╝"
        )
    else:
        await update.message.reply_text(
            f"╔══════════════════════╗\n"
            f"║     ⚠ ɴᴏᴛ ꜰᴏᴜɴᴅ    ║\n"
            f"╠══════════════════════╣\n"
            f"║ {tg_id:<18d} ║\n"
            f"║ ᴡᴀꜱ ɴᴏᴛ ɪɴ ᴛʜᴇ    ║\n"
            f"║ ᴀᴜᴛʜᴏʀɪᴢᴇᴅ ʟɪꜱᴛ   ║\n"
            f"╚══════════════════════╝"
        )

async def list_users(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    📜 ʟɪꜱᴛ ᴀᴜᴛʜᴏʀɪᴢᴇᴅ ᴜꜱᴇʀꜱ
    """
    user_id = update.effective_user.id
    
    if not is_owner(user_id):
        await update.message.reply_text(
            "╔══════════════════════╗\n"
            "║     ⚠ ᴀᴄᴄᴇꜱꜱ       ║\n"
            "╠══════════════════════╣\n"
            "║ ʏᴏᴜ ᴀʀᴇ ɴᴏᴛ ᴀɴ     ║\n"
            "║ ᴀᴅᴍɪɴ              ║\n"
            "╚══════════════════════╝"
        )
        return
    
    if not authorized_users:
        await update.message.reply_text(
            "╔══════════════════════╗\n"
            "║     ❌ ɴᴏ ᴜꜱᴇʀꜱ     ║\n"
            "╠══════════════════════╣\n"
            "║ ɴᴏ ᴀᴜᴛʜᴏʀɪᴢᴇᴅ      ║\n"
            "║ ᴜꜱᴇʀꜱ ꜰᴏᴜɴᴅ        ║\n"
            "╚══════════════════════╝"
        )
        return
    
    # Header
    lines = [
        "╔══════════════════════╗",
        "║  📜 ᴀᴜᴛʜᴏʀɪᴢᴇᴅ     ║",
        "║     ᴜꜱᴇʀꜱ           ║",
        "╠══════════════════════╣"
    ]
    
    # User list
    for i, u in enumerate(authorized_users, 1):
        user_id_num = u['id']
        
        if u['id'] == OWNER_TG_ID:
            role = "👑 ᴏᴡɴᴇʀ"
            lines.append(f"║ {i:2d} │ {user_id_num:<12d} ║")
            lines.append(f"║    └─ {role:<12} ║")
        elif u['username']:
            username = f"@{u['username']}"
            # Truncate if too long
            if len(username) > 12:
                username = username[:10] + ".."
            lines.append(f"║ {i:2d} │ {user_id_num:<12d} ║")
            lines.append(f"║    └─ {username:<12} ║")
        else:
            lines.append(f"║ {i:2d} │ {user_id_num:<12d} ║")
            lines.append(f"║    └─ ɴᴏ ᴜꜱᴇʀɴᴀᴍᴇ  ║")
        
        # Add separator between users (except last)
        if i < len(authorized_users):
            lines.append("║    ────────────────   ║")
    
    # Footer with count
    lines.append("╠══════════════════════╣")
    lines.append(f"║ ᴛᴏᴛᴀʟ: {len(authorized_users):2d} ᴜꜱᴇʀꜱ      ║")
    lines.append("╚══════════════════════╝")
    
    await update.message.reply_text("\n".join(lines))

# ==============================================================
# ========================= MAIN BOT ============================
# ==============================================================

def main_bot():
    from telegram.ext import (
        Application, CommandHandler, MessageHandler,
        ConversationHandler, CallbackQueryHandler, filters
    )
    from telegram.request import HTTPXRequest
    import asyncio
    import threading

    # ================= HTTP CONFIG =================
    request = HTTPXRequest(
        connect_timeout=30,
        read_timeout=30,
        write_timeout=30
    )

    application = Application.builder() \
        .token(BOT_TOKEN) \
        .request(request) \
        .build()

    # ================= GLOBALS =================
    global APP, LOOP
    APP = application

    # ================= LOOP BIND SAFE =================
    async def set_loop(app):
        global LOOP
        LOOP = asyncio.get_running_loop()

    # ================= RESUME NOTIFY =================
    async def post_init_resume(app):
        try:
            for user_id, tasks_list in list(users_tasks.items()):
                for task in tasks_list:
                    if task.get("type") == "message_attack" and task.get("status") == "running":
                        await send_resume_notification(user_id, task)
        except Exception as e:
            print(f"⚠️ post_init error: {e}")

    # ================= COMBINE POST_INIT =================
    async def combined_post_init(app):
        await set_loop(app)
        await post_init_resume(app)

    application.post_init = combined_post_init

    # ================= RESTORE TASKS =================
    try:
        restore_tasks_on_start()
        print("✅ Task restoration complete!")
    except Exception as e:
        print(f"⚠️ Task restore error: {e}")

    # ================= SWITCH MONITOR =================
    try:
        monitor_thread = threading.Thread(
            target=switch_monitor,
            daemon=True
        )
        monitor_thread.start()
    except Exception as e:
        print(f"⚠️ Switch monitor failed: {e}")

    # =========================================================
    # ------------------- COMMAND HANDLERS ---------------------
    # =========================================================
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("viewmyac", viewmyac))
    application.add_handler(CommandHandler("setig", setig))
    application.add_handler(CommandHandler("pair", pair_command))
    application.add_handler(CommandHandler("unpair", unpair_command))
    application.add_handler(CommandHandler("switch", switch_command))
    application.add_handler(CommandHandler("threads", threads_command))
    application.add_handler(CommandHandler("viewpref", viewpref))
    application.add_handler(CommandHandler("stop", stop))
    application.add_handler(CommandHandler("task", task_command))
    application.add_handler(CommandHandler("add", add_user))
    application.add_handler(CommandHandler("remove", remove_user))
    application.add_handler(CommandHandler("users", list_users))
    application.add_handler(CommandHandler("logout", logout_command))
    application.add_handler(CommandHandler("kill", cmd_kill))
    application.add_handler(CommandHandler("flush", flush))
    application.add_handler(CommandHandler("usg", usg_command))
    application.add_handler(CommandHandler("cancel", cancel_handler))

    # =========================================================
    # ---------------- LOGIN CONVERSATIONS ---------------------
    # =========================================================
    application.add_handler(ConversationHandler(
        entry_points=[CommandHandler("login", login_start)],
        states={
            USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_username)],
            PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_password)],
        },
        fallbacks=[],
    ))

    application.add_handler(ConversationHandler(
        entry_points=[CommandHandler("plogin", plogin_start)],
        states={
            PLO_USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, plogin_get_username)],
            PLO_PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, plogin_get_password)],
        },
        fallbacks=[],
    ))

    application.add_handler(ConversationHandler(
        entry_points=[CommandHandler("slogin", slogin_start)],
        states={
            SLOG_SESSION: [MessageHandler(filters.TEXT & ~filters.COMMAND, slogin_get_session)],
            SLOG_USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, slogin_get_username)],
        },
        fallbacks=[],
    ))

    application.add_handler(ConversationHandler(
        entry_points=[CommandHandler("psid", psid_start)],
        states={
            PSID_SESSION: [MessageHandler(filters.TEXT & ~filters.COMMAND, psid_get_session)],
            PSID_USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, psid_get_username)],
        },
        fallbacks=[],
    ))

    # =========================================================
    # -------------------- ATTACK FLOW -------------------------
    # =========================================================
    application.add_handler(ConversationHandler(
        entry_points=[CommandHandler("attack", attack_start)],
        states={
            MODE: [CallbackQueryHandler(mode_button_handler, pattern="^mode_")],
            SELECT_GC: [
                CallbackQueryHandler(gc_button_handler, pattern="^gc_"),
                CallbackQueryHandler(gc_button_handler, pattern="^gc_thread$")
            ],
            TARGET: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, get_target_handler),
                CallbackQueryHandler(dm_button_handler, pattern="^dm_thread$")
            ],
            MESSAGES: [
                MessageHandler(filters.Document.FileExtension("txt"), get_messages_file),
                MessageHandler(filters.TEXT & ~filters.COMMAND, get_messages),
            ],
        },
        fallbacks=[CommandHandler("cancel", cancel_handler)],
        allow_reentry=True,
        per_message=True   # ✅ WARNING FIX
    ))

    application.add_handler(ConversationHandler(
        entry_points=[CommandHandler("pattack", pattack_start)],
        states={
            P_MODE: [MessageHandler(filters.TEXT & ~filters.COMMAND, p_get_mode)],
            P_TARGET_DISPLAY: [MessageHandler(filters.TEXT & ~filters.COMMAND, p_get_target_display)],
            P_THREAD_URL: [MessageHandler(filters.TEXT & ~filters.COMMAND, p_get_thread_url)],
            P_MESSAGES: [
                MessageHandler(filters.Document.FileExtension("txt"), p_get_messages_file),
                MessageHandler(filters.TEXT & ~filters.COMMAND, p_get_messages),
            ],
        },
        fallbacks=[CommandHandler("cancel", cancel_handler)],
        per_message=True   # ✅ WARNING FIX
    ))

    # =========================================================
    # ---------------- GENERAL TEXT HANDLER --------------------
    # =========================================================
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))

    # =========================================================
    # ---------------- START BOT -------------------------------
    # =========================================================
    print("🚀 Bot starting with message attack system...")

    try:
        application.run_polling(drop_pending_updates=True)
    except Exception as e:
        print(f"❌ Bot crashed: {e}")
    finally:
        print("🛑 Bot stopped safely")


# ==============================================================
# ======================= ENTRY POINT ===========================
# ==============================================================

def start_bot():
    try:
        main_bot()
    except KeyboardInterrupt:
        print("\n🛑 Bot manually stopped")
    except Exception as e:
        import traceback
        print(f"❌ Fatal crash: {e}")
        traceback.print_exc()


if __name__ == "__main__":
    start_bot()
