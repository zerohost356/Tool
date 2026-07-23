#!/usr/bin/env python3
"""
Bypass LootLabs (loot-link.com / links.lootlabs.gg)
Flow: load page -> parse TID/KEY -> /verify -> CDN params -> /tc tasks
     -> WS round 1 (background) + Solver Mode A (get token)
     -> WS round 2 + Solver Mode B (exchange token for destination URL)
"""
import requests
import re
import json
import sys
import time
import base64
import random
import hashlib
import math
import os
import uuid
import threading

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    AESGCM = None

try:
    from curl_cffi import requests as cffi_requests
    HAS_CURL_CFFI = True
except ImportError:
    HAS_CURL_CFFI = False

CFFI_IMPERSONATE = "chrome131"
sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
    "Accept": "*/*",
    "Accept-Language": "en,vi-VN;q=0.9,vi;q=0.8,fr-FR;q=0.7,fr;q=0.6,en-US;q=0.5",
}


SOLVER_API = "http://fi7.bot-hosting.net:21463/api/lootsolver"
MODE_A_TIMEOUT = 10   # step 22: 10s max
MODE_B_TIMEOUT = 80   # step 25: 80s max

def _solver_modeA(http_session, url, tid, key):
    try:
        r = http_session.get(SOLVER_API, params={"url": url, "tid": tid, "key": key},
                             timeout=MODE_A_TIMEOUT)
        data = r.json()
    except Exception as e:
        return None, f"api exception {type(e).__name__}"
    if data.get("status") == "success":
        return data.get("result"), None
    return None, data.get("result", "unknown")

def _solver_modeB(http_session, url, token):
    try:
        r = http_session.get(SOLVER_API, params={"url": url, "token": token},
                             timeout=MODE_B_TIMEOUT)
        data = r.json()
    except Exception as e:
        return None, f"api exception {type(e).__name__}"
    if data.get("status") == "success":
        return data.get("result"), None
    return None, data.get("result", "unknown")
# ====================================================

# --- LOG ---
step_counter = 1
def log_step(msg):
    global step_counter
    print(f"[ {step_counter} ] : {msg}")
    step_counter += 1
def log_success(msg):
    global step_counter
    print(f"[ {step_counter} ] : [SUCCESS] {msg}")
    step_counter += 1
def log_warn(msg):
    global step_counter
    print(f"[ {step_counter} ] : [WARNING] {msg}")
    step_counter += 1
def log_error(msg):
    global step_counter
    print(f"[ {step_counter} ] : [ERROR] {msg}")
    step_counter += 1

# --- UTILS ---
def generate_session() -> str:
    first = str(random.randint(1, 9))
    middle = ''.join([str(random.randint(0, 9)) for _ in range(16)])
    last = str(random.randint(0, 9))
    return first + middle + last

def create_http_session():
    if HAS_CURL_CFFI:
        log_step("Using curl_cffi (impersonate Chrome TLS fingerprint)")
        return cffi_requests.Session(impersonate=CFFI_IMPERSONATE)
    log_warn("curl_cffi not installed — using plain requests (pip install curl_cffi)")
    return requests.Session()

def _botd_hash(x: float, y: float) -> float:
    v = 43758.5453 * math.sin(12.9898 * x + 78.233 * y)
    return v - math.floor(v)

def solve_nonce(sess_uuid: str) -> int:
    clean = sess_uuid.replace("-", "")[:8]
    seed = int(clean, 16) / 4294967295.0
    for n in range(100000):
        if _botd_hash(_botd_hash(_botd_hash(seed, n), n + 1), n + 2) < 0.001:
            return n
    return random.randint(1, 3000)

def make_botd(sess_uuid: str) -> str:
    if AESGCM is None:
        raise ImportError("cryptography required: pip install cryptography")
    upper = [c for c in sess_uuid if c.isupper()]
    ks = "".join(upper[:4]) if upper else "KEY1"
    ub = sess_uuid.encode()
    kb = ks.encode()
    tr = base64.b64encode(bytes(ub[i] ^ kb[i % len(kb)] for i in range(len(ub)))).decode()
    aes_key = hashlib.sha256(tr.encode()).digest()
    iv = os.urandom(12)
    nonce = solve_nonce(sess_uuid)
    botd = {
        "bot": False,
        "timestamp": int(time.time() * 1000),
        "webGLSolution": {"uuid": sess_uuid, "nonce": nonce, "time": random.randint(50, 300)},
    }
    pt = json.dumps(botd, separators=(",", ":")).encode()
    ct = AESGCM(aes_key).encrypt(iv, pt, None)
    botd["encrypted"] = base64.b64encode(iv + ct).decode()
    return json.dumps(botd, separators=(",", ":"))

def verify_page_session(http_session, page_session: str, referer: str) -> None:
    if not page_session:
        raise ValueError("document.session not found in HTML.")
    url = "https://links.lootlabs.gg/verify"
    payload = json.dumps({"session": page_session})
    log_step(f"POST /verify — session: {page_session[:8]}...")
    r = http_session.post(url, data=payload, headers={
        **HEADERS, "Content-Type": "application/json",
        "Origin": "https://links.lootlabs.gg", "Referer": referer,
    }, timeout=15)
    if r.status_code != 200:
        raise ValueError(f"/verify failed (HTTP {r.status_code}).")
    time.sleep(0.1)
    log_success("Page session verified via /verify")

def decode_publisher_link(encoded: str, key_len: int = 5) -> str:
    decoded_bytes = base64.b64decode(encoded)
    decoded_str = decoded_bytes.decode('latin-1')
    xor_key = decoded_str[:key_len]
    ciphertext = decoded_str[key_len:]
    result = ''
    for i, ch in enumerate(ciphertext):
        xor_char = xor_key[i % len(xor_key)]
        result += chr(ord(ch) ^ ord(xor_char))
    return result

def _extract_p_value(html: str, key: str):
    patterns = [
        rf"p\s*\[\s*['\"]{re.escape(key)}['\"]\s*\]\s*=\s*['\"]([^'\"]+)['\"]",
        rf"p\s*\[\s*['\"]{re.escape(key)}['\"]\s*\]\s*=\s*(\d+)",
        rf"p\s*\[\s*['\"]{re.escape(key)}['\"]\s*\]\s*=\s*(true|false)",
        rf"{re.escape(key)}\s*[:=]\s*['\"]([^'\"]+)['\"]",
        rf"{re.escape(key)}\s*[:=]\s*(\d+)",
        rf"{re.escape(key)}\s*[:=]\s*(true|false)",
    ]
    for pattern in patterns:
        m = re.search(pattern, html, re.IGNORECASE)
        if m:
            return m.group(1)
    return None

def parse_page(html: str) -> dict:
    data = {}
    tid = _extract_p_value(html, "TID")
    if tid:
        data["tid"] = int(tid)
    key = _extract_p_value(html, "KEY")
    if key:
        data["key"] = key
    cdn_domain = _extract_p_value(html, "CDN_DOMAIN")
    if cdn_domain:
        data["cdn_domain"] = cdn_domain
    publisher_link = _extract_p_value(html, "PUBLISHER_LINK")
    if publisher_link:
        data["publisher_link"] = publisher_link
    tier_id = _extract_p_value(html, "TIER_ID")
    if tier_id:
        data["tier_id"] = tier_id
    num_of_tasks = _extract_p_value(html, "NUM_OF_TASKS")
    if num_of_tasks:
        data["num_of_tasks"] = num_of_tasks
    show_unlocker = _extract_p_value(html, "SHOW_UNLOCKER")
    if show_unlocker:
        data["show_unlocker"] = show_unlocker
    offer = _extract_p_value(html, "OFFER")
    if offer:
        data["offer"] = offer
    ver = _extract_p_value(html, "WIDGET_VERSION")
    if ver:
        data["ver"] = ver
    return data

def get_params(session, cdn_domain: str, tid: int) -> list:
    url = f"https://{cdn_domain}/?tid={tid}&params_only=1"
    log_step(f"Fetching config from CDN: {url}")
    r = session.get(url, headers=HEADERS, timeout=15)
    if r.status_code == 204:
        raise ValueError("Service unavailable (204). Link may be dead.")
    r.raise_for_status()
    text = r.text.strip()
    try:
        line = '[' + text[1:-2] + ']'
        params = json.loads(line)
    except (json.JSONDecodeError, IndexError):
        try:
            params = json.loads(text)
        except json.JSONDecodeError:
            params = text.split(',')
    log_step(f"Received {len(params)} config params")
    return params

def get_tasks(session, syncer_domain: str, payload: dict, page_session: str,
              max_attempts: int = 3) -> list:
    url = f"https://{syncer_domain}/tc"
    log_step(f"Fetching task list from: {url}")
    headers = {
        **HEADERS, "Content-Type": "application/json",
        "Origin": "https://links.lootlabs.gg", "Referer": "https://links.lootlabs.gg/",
    }
    for attempt in range(max_attempts):
        if attempt > 0:
            payload["botd"] = make_botd(page_session)
            payload["botds"] = page_session
            log_warn(f"428 — regen botd, retry {attempt + 1}/{max_attempts}")
        ci = str(random.randint(10**15, 10**16 - 1))
        r = session.post(url, json=payload, headers=headers, cookies={"ci": ci}, timeout=20)
        if r.status_code == 429:
            raise ValueError("Rate limited (429). Please wait a moment and retry.")
        if r.status_code == 428:
            continue
        r.raise_for_status()
        tasks = r.json()
        if not isinstance(tasks, list):
            raise ValueError(f"/tc API returned invalid data: {type(tasks)}")
        log_step(f"Received {len(tasks)} tasks from API")
        return tasks
    raise ValueError("BotD check failed (428) after multiple attempts.")

def _normalize_url(url: str) -> str:
    if not url:
        return url
    if url.startswith("//"):
        return "https:" + url
    if url.startswith("/"):
        return "https://links.lootlabs.gg" + url
    return url

def _safe_req(session, url: str, method: str = "get", timeout: int = 8):
    try:
        norm = _normalize_url(url)
        if method == "post":
            session.post(norm, headers=HEADERS, timeout=timeout)
        else:
            session.get(norm, headers=HEADERS, timeout=timeout, allow_redirects=True)
    except Exception:
        pass

def _safe_get(session, url: str, timeout: int = 8):
    _safe_req(session, url, "get", timeout)

def _is_useful_dest(url: str, source_url: str) -> bool:
    if not url or not url.startswith("http"):
        return False
    if url.rstrip("/") == source_url.rstrip("/"):
        return False
    if "links.lootlabs.gg/s?" in url or "loot-link.com/s?" in url:
        return False
    return True

def _prepare_task_signals(session, syncer_domain: str, task: dict, session_id: str, tid: int):
    urid = str(task.get("urid", ""))
    task_id = str(task.get("task_id", ""))
    ad_url = task.get("ad_url", "")
    _safe_get(session, f"https://enaightdecipie.com/?event=task_clicked&session_id={session_id}&info=1")
    if ad_url:
        threading.Thread(target=lambda: _safe_get(session, ad_url), daemon=True).start()
    time.sleep(0.8)
    _safe_get(session,
              f"https://{syncer_domain}/td?ac=1&uid={urid}&cat={task_id}"
              f"&session_id={session_id}&is_loot=1&tid={tid}")
    _safe_req(session,
              f"https://enaightdecipie.com/?event=unlock_content_click&session_id={session_id}", "post")


def canserbero_ws(session, server_domain, syncer_domain, tasks, key, session_id, tid,
                  original_url=""):
    task = tasks[0]
    urid = str(task.get("urid", ""))
    task_id = str(task.get("task_id", ""))
    pixel_url = task.get("action_pixel_url", "")
    try:
        import websocket
    except ImportError:
        raise ImportError("websocket-client required: pip install websocket-client")

    primary = int(urid[-5:]) % 3 if len(urid) >= 5 else 0
    host = f"{primary}.{server_domain}"
    ws_headers = [f"User-Agent: {HEADERS['User-Agent']}", "Accept-Language: en-US,en;q=0.9"]

    def open_ws():
        st_url = f"https://{host}/st?uid={urid}&cat={task_id}"
        threading.Thread(target=lambda u=st_url: _safe_req(session, u, "post"), daemon=True).start()
        if pixel_url:
            threading.Thread(target=lambda: _safe_get(session, pixel_url), daemon=True).start()
        ws_url = (f"wss://{host}/c?uid={urid}&cat={task_id}&key={key}"
                  f"&session_id={session_id}&is_loot=1&tid={tid}")
        ws = websocket.create_connection(ws_url, timeout=10, header=ws_headers,
                                         origin=f"https://{server_domain}")
        ws.send("0")
        return ws

    def drain(ws, seconds):
        ws.settimeout(1)
        end = time.time() + seconds
        while time.time() < end:
            try:
                ws.recv()
            except Exception:
                try:
                    ws.send("0")
                except Exception:
                    break


    ws1 = None
    try:
        log_step(f"WS {host} (round 1)...")
        ws1 = open_ws()
        log_success(f"WebSocket OK - solving: ({MODE_A_TIMEOUT}s max)")
        token, errA = _solver_modeA(session, original_url, tid, key)
        if not token:
            log_warn(f"Solver did not issue token: {errA}")
            return None
        def fire_td():
            time.sleep(2)
            td = (f"https://{syncer_domain}/td?ac=1&uid={urid}&cat={task_id}"
                  f"&session_id={session_id}&is_loot=1&tid={tid}")
            _safe_get(session, td)
        threading.Thread(target=fire_td, daemon=True).start()
        log_step(f"Sent /td Token: {token}")
        drain(ws1, 3)
    except Exception as e:
        log_warn(f"WS round 1 error: {e}")
        return None
    finally:
        if ws1:
            try:
                ws1.close()
            except Exception:
                pass


    ws2 = None
    try:
        log_step(f"WS {host} (round 2)...")
        ws2 = open_ws()
        log_success(f"WebSocket OK — waiting r: ({MODE_B_TIMEOUT}s max)")
        dest, errB = _solver_modeB(session, original_url, token)
        if dest:
            return dest
        log_warn(f"Solver did not return URL: {errB}")
        return None
    except Exception as e:
        log_warn(f"WS round 2 error: {e}")
        return None
    finally:
        if ws2:
            try:
                ws2.close()
            except Exception:
                pass


def bypass(link: str) -> str:
    global step_counter
    step_counter = 1
    http_session = create_http_session()
    print("\n=========================================")
    log_step("Starting LootLabs Bypass flow")

    link = link.strip()
    if "loot-link.com" in link:
        link = link.replace("loot-link.com", "links.lootlabs.gg")
    elif "loot-links.com" in link:
        link = link.replace("loot-links.com", "links.lootlabs.gg")

    log_step(f"Loading page: {link}")
    r = None
    for attempt in range(1, 4):
        try:
            r = http_session.get(link, headers={
                **HEADERS,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }, timeout=30, allow_redirects=True)
            r.raise_for_status()
            break
        except requests.exceptions.Timeout:
            if attempt < 3:
                log_warn(f"Timeout attempt {attempt}/3, retrying...")
                time.sleep(2)
            else:
                raise ValueError("Cannot connect after 3 attempts (timeout).")
        except requests.exceptions.ConnectionError:
            if attempt < 3:
                log_warn(f"Connection error attempt {attempt}/3, retrying...")
                time.sleep(2)
            else:
                raise ValueError("Cannot connect after 3 attempts.")

    html = r.text
    actual_url = r.url
    log_step(f"Actual URL after redirect: {actual_url}")

    page_session_m = re.search(r"document\.session\s*=\s*'([^']+)'", html)
    page_session = page_session_m.group(1) if page_session_m else None
    verify_page_session(http_session, page_session, actual_url)

    config = parse_page(html)
    tid = config.get('tid')
    key = config.get('key')
    cdn_domain = config.get('cdn_domain')
    publisher_link_encoded = config.get('publisher_link')
    tier_id = config.get('tier_id', '4')
    num_of_tasks = config.get('num_of_tasks', '5')
    offer = config.get('offer', '0')
    ver = config.get('ver', 'v1')
    show_unlocker = config.get('show_unlocker', 'true')

    if not tid:
        raise ValueError("TID not found in HTML. Link may be invalid.")
    if not cdn_domain:
        raise ValueError("CDN_DOMAIN not found in HTML.")

    log_step(f"TID: {tid}")
    log_step(f"KEY: {key}")
    log_step(f"CDN Domain: {cdn_domain}")
    if publisher_link_encoded:
        log_step(f"Publisher Link (encoded): {publisher_link_encoded[:30]}...")

    params = get_params(http_session, cdn_domain, tid)
    incentive_server_domain = params[9] if len(params) > 9 else None
    syncer_domain = params[29] if len(params) > 29 else None
    max_tasks = params[6] if len(params) > 6 else 2
    bl_tasks = params[7] if len(params) > 7 else []

    if not incentive_server_domain:
        raise ValueError("Could not get INCENTIVE_SERVER_DOMAIN from params.")
    if not syncer_domain:
        raise ValueError("Could not get INCENTIVE_SYNCER_DOMAIN from params.")

    log_step(f"Server Domain: {incentive_server_domain}")
    log_step(f"Syncer Domain: {syncer_domain}")
    log_step(f"Max Tasks: {max_tasks}")

    session_id = generate_session()
    cookie_id = str(random.randint(100000000, 999999999))
    botd_json = make_botd(page_session)
    log_step(f"botds (= document.session): {page_session[:8]}...")

    tier_id_val = int(tier_id) if str(tier_id).isdigit() else tier_id
    tc_payload = {
        "tid": tid, "bl": bl_tasks if isinstance(bl_tasks, list) else [10],
        "session": session_id, "max_tasks": max_tasks, "design_id": 135,
        "cur_url": actual_url, "doc_ref": "", "tier_id": tier_id_val,
        "num_of_tasks": num_of_tasks, "is_loot": True, "rkey": key,
        "cookie_id": cookie_id, "botd": botd_json, "botds": page_session,
        "offer": offer, "ver": ver, "test_unlocker_app": -1, "allow_unlocker": True,
        "show_unlocker": True if show_unlocker in ('true', '1', True) else False,
        "desktop_design": 0, "unlocker_only": 0, "fid": -1,
        "clid": str(uuid.uuid4()), "additional_info": {}, "taboola_user_sync": "",
    }

    tasks = get_tasks(http_session, syncer_domain, tc_payload, page_session)
    if not tasks:
        if publisher_link_encoded:
            log_warn("No tasks. Trying to decode PUBLISHER_LINK directly...")
            try:
                dest = decode_publisher_link(publisher_link_encoded)
                if _is_useful_dest(dest, actual_url):
                    return dest
            except Exception:
                pass
        raise ValueError("/tc API returned empty task list and no PUBLISHER_LINK.")

    first_urid = str(tasks[0].get('urid', '0'))
    subdomain_id = int(first_urid[-5:]) % 3 if len(first_urid) >= 5 else 0
    log_step(f"Subdomain ID: {subdomain_id}")
    t0 = tasks[0]
    log_step(f"Task: [{t0.get('task_id', '?')}] {t0.get('title', '')[:40]} "
             f"(urid {str(t0.get('urid', ''))[-6:]})")

    _prepare_task_signals(http_session, syncer_domain, t0, session_id, tid)

    dest_url = canserbero_ws(
        http_session, server_domain=incentive_server_domain, syncer_domain=syncer_domain,
        tasks=tasks, key=key, session_id=session_id, tid=tid, original_url=actual_url,
    )

    if dest_url and dest_url.startswith("http") and dest_url.rstrip("/") != actual_url.rstrip("/"):
        return dest_url

    # Fallback: PUBLISHER_LINK
    if publisher_link_encoded:
        log_warn("Solver did not return URL. Trying fallback...")
        try:
            dest = decode_publisher_link(publisher_link_encoded)
            if _is_useful_dest(dest, actual_url):
                return dest
        except Exception as e:
            log_error(f"Could not decode PUBLISHER_LINK: {e}")

    raise ValueError("Solver Failed")

# ================== MAIN ==================
if __name__ == "__main__":
    # Supports both: py lootlabs.py <link>  or  py lootlabs.py (then input)
    if len(sys.argv) >= 2:
        link = sys.argv[1]
    else:
        link = input("Enter LootLabs link: ").strip()

    if not link:
        print("Please enter a link!")
        sys.exit(1)

    start_time = time.time()
    try:
        final_url = bypass(link)
        elapsed = time.time() - start_time
        print("\n---------------------------------------------------------")
        print(f"[SUCCESS] Bypass successful!")
        print(f"Result: {final_url}")
        print(f"Time: {elapsed:.2f}s")
        print("---------------------------------------------------------")
    except Exception as e:
        elapsed = time.time() - start_time
        print("\n---------------------------------------------------------")
        print(f"[ERROR] Bypass failed!")
        print(f"Result: {e}")
        print(f"Time: {elapsed:.2f}s")
        print("---------------------------------------------------------")
        sys.exit(1)
