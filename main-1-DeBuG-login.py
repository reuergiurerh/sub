# ============================================================
# PXPanel 13.8.0
# Railway Ready
# Created By PIXON
# ============================================================
import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
import string
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote, parse_qs
import aiofiles
import httpx
import uvicorn
from fastapi import (
    FastAPI,
    Request,
    HTTPException,
    Depends,
)
from fastapi.responses import (
    Response,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
)
from fastapi.middleware.cors import CORSMiddleware

# ============================================================
# APP
# ============================================================

APP_NAME = "PXPanel"
APP_VERSION = "13.10.0"

SUPPORT_USERNAME = "@logic_sec"
SUPPORT_URL = "https://t.me/logic_sec"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

logger = logging.getLogger(APP_NAME)

# ============================================================
# TIMEZONE
# ============================================================

try:
    from zoneinfo import ZoneInfo

    IRAN_TZ = ZoneInfo("Asia/Tehran")

except Exception:
    IRAN_TZ = None


# ============================================================
# RAILWAY
# ============================================================

PORT = int(
    os.environ.get(
        "PORT",
        "8000",
    )
)

DATA_DIR = Path(
    os.environ.get(
        "RAILWAY_VOLUME_MOUNT_PATH",
        os.environ.get(
            "DATA_DIR",
            "./data",
        ),
    )
)

DATA_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

DATA_FILE = DATA_DIR / "pixonpanel_state.json"
TG_FILE = DATA_DIR / "telegram_settings.json"

SECRET_FILE = DATA_DIR / "pixonpanel_secret.key"


# ============================================================
# FASTAPI
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    docs_url=None,
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# LOCKS
# ============================================================

SAVE_LOCK = asyncio.Lock()
LINKS_LOCK = asyncio.Lock()
SUBS_LOCK = asyncio.Lock()
SESSIONS_LOCK = asyncio.Lock()


# ============================================================
# SECRET
# ============================================================

def load_or_create_secret() -> str:
    env_secret = os.environ.get("SECRET_KEY")

    if env_secret:
        return env_secret

    try:
        if SECRET_FILE.exists():
            existing = (
                SECRET_FILE
                .read_text(
                    encoding="utf-8"
                )
                .strip()
            )

            if existing:
                return existing

        generated = secrets.token_urlsafe(48)

        SECRET_FILE.write_text(
            generated,
            encoding="utf-8",
        )

        return generated

    except Exception as exc:
        logger.warning(
            "Could not persist SECRET_KEY: %s",
            exc,
        )

        return secrets.token_urlsafe(48)


SECRET_KEY = load_or_create_secret()


# ============================================================
# CONFIG
# ============================================================

CONFIG = {
    "port": PORT,
    "secret": SECRET_KEY,
    "host": os.environ.get(
        "RAILWAY_PUBLIC_DOMAIN",
        "localhost",
    ),
}


# ============================================================
# STATE
# ============================================================

LINKS: dict = {}
SUBS: dict = {}
SESSIONS: dict = {}
connections: dict = {}
CATEGORIES: dict = {}

stats = {
    "total_bytes": 0,
    "total_requests": 0,
    "total_errors": 0,
    "start_time": time.time(),
}

error_logs = deque(maxlen=100)
activity_logs = deque(maxlen=250)

hourly_traffic = defaultdict(int)

http_client: httpx.AsyncClient | None = None


# ============================================================
# PROTOCOL
# ============================================================

PROTOCOLS = (
    "vless-ws",
    "xhttp-packet-up",
    "xhttp-stream-up",
    "xhttp-stream-one",
    "vmess-ws",
    "trojan-ws",
    "shadowsocks",
    "socks5",
    "http",
    "hysteria2",
    "tuic",
    "wireguard",
    "highspeed-demo",
    "gaming-lite-demo",
)

PROTOCOL_LABELS = {
    "vless-ws": "VLESS WebSocket ⭐",
    "xhttp-packet-up": "XHTTP Packet Up",
    "xhttp-stream-up": "XHTTP Stream Up",
    "xhttp-stream-one": "XHTTP Stream One",
    "vmess-ws": "VMess WebSocket",
    "trojan-ws": "Trojan WebSocket",
    "shadowsocks": "Shadowsocks",
    "socks5": "SOCKS5",
    "http": "HTTP Proxy",
    "hysteria2": "Hysteria 2",
    "tuic": "TUIC",
    "wireguard": "WireGuard",
    "highspeed-demo": "HighSpeed Upload/Download (دمو)",
    "gaming-lite-demo": "Gaming Lite (دمو)",
}

PROTOCOL_ALIASES = {
    "vmess": "vmess-ws", "trojan": "trojan-ws", "ss": "shadowsocks",
    "socks": "socks5", "hy2": "hysteria2", "hysteria": "hysteria2",
}

DEFAULT_PROTOCOL = "vless-ws"

FINGERPRINTS = (
    "chrome",
    "firefox",
    "safari",
    "ios",
    "android",
    "edge",
    "360",
    "qq",
    "random",
    "randomized",
)

DEFAULT_FINGERPRINT = "chrome"

DEFAULT_ALPN_BY_PROTOCOL = {
    "vless-ws": "http/1.1",
    "xhttp-packet-up": "h2,http/1.1",
    "xhttp-stream-up": "h2,http/1.1",
    "xhttp-stream-one": "h2,http/1.1",
}

DEFAULT_PORT = 443
MIN_PORT = 1
MAX_PORT = 65535

DEFAULT_SPEED_LIMIT = 0


def normalize_protocol(protocol: str | None) -> str:
    value = str(protocol or DEFAULT_PROTOCOL).strip().lower()
    value = PROTOCOL_ALIASES.get(value, value)
    return value if value in PROTOCOLS else DEFAULT_PROTOCOL


# ============================================================
# LOGGING
# ============================================================

def log_activity(
    kind: str,
    message: str,
    level: str = "info",
):
    activity_logs.append(
        {
            "kind": kind,
            "level": level,
            "message": message,
            "time": datetime.now().isoformat(),
        }
    )


# ============================================================
# HELPERS
# ============================================================

def escape_html(value) -> str:
    return (
        str(
            value
            if value is not None
            else ""
        )
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#039;")
    )


def safe_int(
    value,
    default=0,
    minimum=0,
    maximum=None,
):
    try:
        number = int(value)
    except Exception:
        number = default

    if number < minimum:
        number = minimum

    if maximum is not None and number > maximum:
        number = maximum

    return number


def safe_float(
    value,
    default=0.0,
    minimum=0.0,
):
    try:
        number = float(value)
    except Exception:
        number = default

    return max(
        minimum,
        number,
    )


def generate_uuid():
    value = secrets.token_hex(16)

    return (
        f"{value[:8]}-"
        f"{value[8:12]}-"
        f"{value[12:16]}-"
        f"{value[16:20]}-"
        f"{value[20:32]}"
    )


def random_config_name(existing=None):
    existing = existing or set()
    alphabet = string.ascii_lowercase + string.digits
    for _ in range(80):
        length = secrets.randbelow(6) + 8
        name = "".join(secrets.choice(alphabet) for _ in range(length))
        if name not in existing and name and not name[0].isdigit():
            return name
    return secrets.token_hex(6)

def sanitize_config_name(name: str) -> str:
    if not name:
        return random_config_name()
    cleaned = "".join(ch for ch in str(name) if ch.isascii() and ch.isalnum())
    if not cleaned or cleaned[0].isdigit():
        cleaned = ("a" + cleaned) if cleaned else random_config_name()
    return cleaned[:40]

def auto_config_name() -> str:
    return random_config_name()


def now_ir():
    if IRAN_TZ:
        return datetime.now(IRAN_TZ)

    return datetime.now()


def uptime():
    seconds = int(
        time.time()
        - stats["start_time"]
    )

    h = seconds // 3600

    m = (
        seconds
        % 3600
    ) // 60

    s = (
        seconds
        % 60
    )

    return (
        f"{h:02d}:"
        f"{m:02d}:"
        f"{s:02d}"
    )


def fmt_bytes(value: int):
    value = int(
        value or 0
    )

    if value < 1024:
        return f"{value} B"

    if value < 1024 ** 2:
        return (
            f"{value / 1024:.1f} KB"
        )

    if value < 1024 ** 3:
        return (
            f"{value / 1024 ** 2:.2f} MB"
        )

    return (
        f"{value / 1024 ** 3:.2f} GB"
    )


def parse_size_to_bytes(
    value: float,
    unit: str,
):
    if value <= 0:
        return 0

    unit = (
        unit
        or "GB"
    ).upper()

    if unit == "TB":
        return int(
            value
            * 1024 ** 4
        )

    if unit == "GB":
        return int(
            value
            * 1024 ** 3
        )

    if unit == "MB":
        return int(
            value
            * 1024 ** 2
        )

    if unit == "KB":
        return int(
            value
            * 1024
        )

    return int(value)


def parse_speed_to_bytes(
    value: float,
    unit: str,
):
    if value <= 0:
        return 0

    unit = (
        unit
        or "MBIT"
    ).upper()

    if unit == "MBIT":
        return int(
            value
            * 1024
            * 1024
            / 8
        )

    if unit == "KB":
        return int(
            value * 1024
        )

    if unit == "MB":
        return int(
            value
            * 1024
            * 1024
        )

    return int(value)


def is_link_expired(
    link: dict,
):
    expiry = link.get(
        "expires_at"
    )

    if not expiry:
        return False

    try:
        return (
            datetime.now()
            > datetime.fromisoformat(
                expiry
            )
        )

    except Exception:
        return False


def is_link_allowed(
    link: dict | None,
):
    if link is None:
        return False

    if not link.get(
        "active",
        True,
    ):
        return False

    if is_link_expired(link):
        return False

    limit = int(
        link.get(
            "limit_bytes",
            0,
        )
        or 0
    )

    used = int(
        link.get(
            "used_bytes",
            0,
        )
        or 0
    )

    if (
        limit > 0
        and used >= limit
    ):
        return False

    return True


def unique_ips_for_uuid(
    uuid: str,
):
    return {
        connection.get("ip")
        for connection in connections.values()
        if connection.get("uuid") == uuid
        and connection.get("ip")
    }


def client_ip(
    request: Request,
):
    forwarded = request.headers.get(
        "x-forwarded-for"
    )

    if forwarded:
        return (
            forwarded
            .split(",")[0]
            .strip()
        )

    real = request.headers.get(
        "x-real-ip"
    )

    if real:
        return real.strip()

    if request.client:
        return request.client.host

    return "unknown"


def is_ip_allowed(
    link: dict | None,
    uuid: str,
    ip: str,
):
    if link is None:
        return False

    limit = int(
        link.get(
            "ip_limit",
            0,
        )
        or 0
    )

    if limit <= 0:
        return True

    ips = unique_ips_for_uuid(uuid)

    if ip in ips:
        return True

    return len(ips) < limit


def get_host(
    request: Request | None = None,
) -> str:

    if request is not None:
        forwarded = request.headers.get(
            "x-forwarded-host"
        )

        normal = request.headers.get(
            "host"
        )

        host = (
            forwarded
            or normal
        )

        if host:
            host = host.split(":")[0].strip()

            CONFIG["host"] = host

            return host

    railway_domain = os.environ.get(
        "RAILWAY_PUBLIC_DOMAIN"
    )

    if railway_domain:
        return railway_domain

    return CONFIG["host"]


# ============================================================
# PASSWORD
# ============================================================

def hash_password(
    password: str,
) -> str:

    payload = (
        password
        + SECRET_KEY
    ).encode("utf-8")

    return hashlib.sha256(
        payload
    ).hexdigest()


# No default password — first-run setup required unless ADMIN_PASSWORD env is set
_env_pw = os.environ.get("ADMIN_PASSWORD", "").strip()
AUTH = {
    "password_hash": hash_password(_env_pw) if _env_pw else "",
    "password_configured": bool(_env_pw),
}

# Sub-admin accounts (panel operators with granular permissions)
ADMIN_ACCOUNTS: dict = {}
# session_token -> {"role": "owner"|"admin", "admin_id": str|None, "username": str}
SESSION_META: dict = {}

ALL_PERMS = (
    "dash", "configs", "create", "stats", "logs",
    "settings", "support", "telegram", "news", "admins",
)
DEFAULT_PERMS = {p: True for p in ALL_PERMS}


def default_admin_record(username: str, password: str, **kwargs) -> dict:
    return {
        "id": secrets.token_hex(8),
        "username": username.strip().lower(),
        "password_hash": hash_password(password),
        "label": kwargs.get("label") or username,
        "limit_bytes": int(kwargs.get("limit_bytes") or 0),
        "used_bytes": 0,
        "expires_at": kwargs.get("expires_at"),
        "active": True,
        "blocked": False,
        "permissions": {**DEFAULT_PERMS, **(kwargs.get("permissions") or {})},
        "created_at": datetime.now().isoformat(),
    }


def find_admin_by_username(username: str):
    u = (username or "").strip().lower()
    for aid, a in ADMIN_ACCOUNTS.items():
        if a.get("username") == u:
            return aid, a
    return None, None


def admin_is_valid(admin: dict) -> bool:
    if not admin or admin.get("blocked") or not admin.get("active", True):
        return False
    exp = admin.get("expires_at")
    if exp:
        try:
            if datetime.now() > datetime.fromisoformat(str(exp)):
                return False
        except Exception:
            pass
    limit = int(admin.get("limit_bytes") or 0)
    used = int(admin.get("used_bytes") or 0)
    if limit > 0 and used >= limit:
        return False
    return True



# ============================================================
# LOGIN BRUTE-FORCE PROTECTION
# ============================================================
# Maximum failed login attempts per IP inside the rolling window.
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 15 * 60
LOGIN_LOCKOUT_SECONDS = 30 * 60  # 30 minutes lockout
LOGIN_MIN_PASSWORD_LENGTH = 6

LOGIN_FAILURES = defaultdict(deque)
LOGIN_LOCKED_UNTIL = {}


def _cleanup_login_state(ip: str, now: float | None = None):
    now = now if now is not None else time.time()

    locked_until = LOGIN_LOCKED_UNTIL.get(ip, 0)
    if locked_until and locked_until <= now:
        LOGIN_LOCKED_UNTIL.pop(ip, None)

    failures = LOGIN_FAILURES.get(ip)
    if not failures:
        return

    cutoff = now - LOGIN_WINDOW_SECONDS
    while failures and failures[0] <= cutoff:
        failures.popleft()

    if not failures:
        LOGIN_FAILURES.pop(ip, None)


def login_is_blocked(ip: str):
    now = time.time()
    _cleanup_login_state(ip, now)

    locked_until = LOGIN_LOCKED_UNTIL.get(ip, 0)
    if locked_until > now:
        return True, max(1, int(locked_until - now))

    return False, 0


def register_login_failure(ip: str):
    now = time.time()
    _cleanup_login_state(ip, now)

    failures = LOGIN_FAILURES.setdefault(ip, deque())
    failures.append(now)

    if len(failures) >= LOGIN_MAX_ATTEMPTS:
        LOGIN_LOCKED_UNTIL[ip] = now + LOGIN_LOCKOUT_SECONDS
        failures.clear()
        log_activity(
            "auth",
            f"IP به دلیل تلاش‌های متعدد ورود ناموفق به مدت {LOGIN_LOCKOUT_SECONDS // 60} دقیقه مسدود شد: {ip}",
            "err",
        )
        return True, LOGIN_LOCKOUT_SECONDS

    return False, max(0, LOGIN_MAX_ATTEMPTS - len(failures))


def clear_login_failures(ip: str):
    LOGIN_FAILURES.pop(ip, None)
    LOGIN_LOCKED_UNTIL.pop(ip, None)


# ============================================================
# SESSION
# ============================================================

SESSION_COOKIE = "pixonpanel_session"

SESSION_TTL = (
    60
    * 60
    * 24
    * 365
)


async def create_session(meta: dict | None = None) -> str:

    token = secrets.token_urlsafe(48)

    async with SESSIONS_LOCK:
        SESSIONS[token] = (
            time.time()
            + SESSION_TTL
        )
        SESSION_META[token] = meta or {"role": "owner", "admin_id": None, "username": "owner"}

    return token


async def is_valid_session(
    token: str | None,
) -> bool:

    if not token:
        return False

    async with SESSIONS_LOCK:

        expiry = SESSIONS.get(token)

        if expiry is None:
            return False

        if expiry < time.time():

            SESSIONS.pop(
                token,
                None,
            )

            return False

        return True


async def destroy_session(
    token: str | None,
):
    if not token:
        return

    async with SESSIONS_LOCK:
        SESSIONS.pop(
            token,
            None,
        )
        SESSION_META.pop(token, None)


def get_session_meta(token: str | None) -> dict:
    if not token:
        return {"role": "owner", "admin_id": None, "username": "owner", "permissions": {p: True for p in ALL_PERMS}}
    meta = dict(SESSION_META.get(token) or {"role": "owner", "admin_id": None, "username": "owner"})
    if meta.get("role") == "owner":
        meta["permissions"] = {p: True for p in ALL_PERMS}
    else:
        aid = meta.get("admin_id")
        admin = ADMIN_ACCOUNTS.get(aid or "") or {}
        meta["permissions"] = {p: bool((admin.get("permissions") or {}).get(p, False)) for p in ALL_PERMS}
        meta["blocked"] = bool(admin.get("blocked"))
    return meta


def require_perm(perm: str):
    async def _dep(request: Request, token=Depends(require_auth)):
        meta = get_session_meta(token)
        if meta.get("role") == "owner":
            return token
        if not (meta.get("permissions") or {}).get(perm):
            raise HTTPException(status_code=403, detail="دسترسی به این بخش مجاز نیست")
        return token
    return _dep


async def require_auth(
    request: Request,
):
    token = request.cookies.get(
        SESSION_COOKIE
    )

    if not await is_valid_session(
        token
    ):
        raise HTTPException(
            status_code=401,
            detail="unauthorized",
        )

    meta = get_session_meta(token)
    if meta.get("role") == "admin":
        aid = meta.get("admin_id")
        admin = ADMIN_ACCOUNTS.get(aid or "")
        if not admin_is_valid(admin or {}):
            await destroy_session(token)
            raise HTTPException(status_code=401, detail="حساب منقضی یا مسدود شده است")

    return token


def set_auth_cookie(
    response,
    request: Request,
    token: str,
):
    forwarded_proto = (
        request.headers
        .get(
            "x-forwarded-proto",
            "",
        )
        .lower()
    )

    is_https = (
        forwarded_proto == "https"
        or request.url.scheme == "https"
    )

    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=SESSION_TTL,
        httponly=True,
        samesite="lax",
        path="/",
        secure=is_https,
    )


# ============================================================
# VLESS LINK GENERATION
# ============================================================

def generate_vless_link(
    uuid: str, host: str, remark: str = "PXPanel",
    protocol: str = DEFAULT_PROTOCOL, fingerprint: str | None = None,
    alpn: str | None = None, port: int | None = None,
):
    protocol = normalize_protocol(protocol)
    fp = (fingerprint or DEFAULT_FINGERPRINT).strip().lower()
    if fp not in FINGERPRINTS: fp = DEFAULT_FINGERPRINT
    port_value = safe_int(port, DEFAULT_PORT, MIN_PORT, MAX_PORT)
    alpn_value = (alpn or DEFAULT_ALPN_BY_PROTOCOL.get(protocol, "http/1.1")).strip()
    label = quote(str(remark or "PXPanel"), safe="")
    if protocol == "vless-ws":
        q = {"encryption":"none","security":"tls","type":"ws","host":host,"path":f"/ws/{uuid}","sni":host,"fp":fp,"alpn":alpn_value}
        return "vless://" + uuid + "@" + host + ":" + str(port_value) + "?" + "&".join(f"{k}={quote(str(v), safe=',/') }" for k,v in q.items()) + "#" + label
    if protocol.startswith("xhttp-"):
        mode = protocol.replace("xhttp-", "")
        q = {"encryption":"none","security":"tls","type":"xhttp","mode":mode,"host":host,"path":f"/xhttp-siz10/{mode}/{uuid}","sni":host,"fp":fp,"alpn":alpn_value}
        return "vless://" + uuid + "@" + host + ":" + str(port_value) + "?" + "&".join(f"{k}={quote(str(v), safe=',/') }" for k,v in q.items()) + "#" + label
    if protocol == "vmess-ws":
        raw = {"v":"2","ps":remark,"add":host,"port":port_value,"id":uuid,"aid":0,"scy":"auto","net":"ws","type":"none","host":host,"path":f"/ws/{uuid}","tls":"tls","sni":host,"fp":fp}
        return "vmess://" + base64.b64encode(json.dumps(raw,separators=(",",":"),ensure_ascii=False).encode()).decode()
    if protocol == "trojan-ws":
        return f"trojan://{uuid}@{host}:{port_value}?security=tls&type=ws&host={quote(host)}&path={quote('/ws/'+uuid)}&sni={quote(host)}#{label}"
    if protocol == "shadowsocks":
        method = os.getenv("SS_METHOD", "aes-256-gcm")
        userinfo = base64.urlsafe_b64encode(f"{method}:{uuid}".encode()).decode().rstrip("=")
        return f"ss://{userinfo}@{host}:{port_value}#{label}"
    if protocol == "socks5": return f"socks5://{uuid}:{uuid}@{host}:{port_value}#{label}"
    if protocol == "http": return f"http://{uuid}:{uuid}@{host}:{port_value}#{label}"
    if protocol == "hysteria2": return f"hysteria2://{uuid}@{host}:{port_value}/?sni={quote(host)}&insecure=0#{label}"
    if protocol == "tuic": return f"tuic://{uuid}:{uuid}@{host}:{port_value}?sni={quote(host)}&alpn=h3#{label}"
    if protocol == "wireguard": return f"wireguard://{uuid}@{host}:{port_value}?publicKey={uuid}#{label}"
    if protocol == "highspeed-demo":
        q = {"encryption":"none","security":"tls","type":"xhttp","mode":"stream-up","host":host,"path":f"/xhttp-siz10/stream-up/{uuid}","sni":host,"fp":fp,"alpn":"h2,http/1.1"}
        return "vless://" + uuid + "@" + host + ":" + str(port_value) + "?" + "&".join(f"{k}={quote(str(v), safe=',/')}" for k,v in q.items()) + "#" + label
    if protocol == "gaming-lite-demo":
        return f"hysteria2://{uuid}@{host}:{port_value}/?sni={quote(host)}&insecure=0&obfs=salamander#{label}"
    return f"vless://{uuid}@{host}:{port_value}"

def vless_link_for_link(
    link: dict,
    uid: str,
    host: str,
):
    return generate_vless_link(
        uid,
        host,
        remark=str(link.get("label") or "Config"),
        protocol=link.get(
            "protocol",
            DEFAULT_PROTOCOL,
        ),
        fingerprint=link.get(
            "fingerprint",
            DEFAULT_FINGERPRINT,
        ),
        alpn=link.get(
            "alpn"
        ),
        port=link.get(
            "port",
            DEFAULT_PORT,
        ),
    )


def get_link_info(
    link: dict,
    uid: str,
    host: str,
):
    connected_count = len(unique_ips_for_uuid(uid))
    is_active = is_link_allowed(link)
    limit_b = int(link.get("limit_bytes", 0) or 0)
    used_b = int(link.get("used_bytes", 0) or 0)
    is_expired = is_link_expired(link) or (limit_b > 0 and used_b >= limit_b)
    if not is_active or is_expired:
        status_color = "red"
    elif connected_count > 0:
        status_color = "green"
    else:
        status_color = "gray"
    clean_ips = link.get("clean_ips") or []
    cfg_count = int(link.get("config_count") or 1)
    show_vless = len(clean_ips) <= 1 and cfg_count <= 1
    cat = CATEGORIES.get(str(link.get("category_id") or "0")) or {}
    return {
        "uuid": uid,
        "name": link.get("label", ""),
        "label": link.get("label", ""),
        "protocol": link.get("protocol", DEFAULT_PROTOCOL),
        "active": is_active,
        "used_bytes": used_b,
        "limit_bytes": limit_b,
        "expires_at": link.get("expires_at"),
        "ip_limit": int(link.get("ip_limit", 0) or 0),
        "speed_limit_bytes": int(link.get("speed_limit_bytes", 0) or 0),
        "connection_limit": int(link.get("connection_limit", 0) or 0),
        "fragment": link.get("fragment", "off"),
        "fingerprint": link.get("fingerprint", DEFAULT_FINGERPRINT),
        "alpn": link.get("alpn", ""),
        "port": link.get("port", DEFAULT_PORT),
        "note": link.get("note", ""),
        "clean_ips": clean_ips,
        "alarm_enabled": bool(link.get("alarm_enabled", False)),
        "category_id": str(link.get("category_id") or "0"),
        "sort_order": int(link.get("sort_order") or 0),
        "category_number": int(cat.get("number", 0)),
        "category_name": str(cat.get("name", "عمومی")),
        "config_count": cfg_count,
        "status_color": status_color,
        "connected_ips": connected_count,
        "show_vless": show_vless,
        "vless": vless_link_for_link(link, uid, host) if show_vless else "",
        "vless_full": vless_link_for_link(link, uid, host),
        "sub": f"https://{host}/sub/{uid}",
        "info": f"https://{host}/info/{uid}",
        "support": SUPPORT_USERNAME,
    }


# ============================================================
# PERSISTENCE
# ============================================================

async def load_state():

    global AUTH

    try:

        DATA_DIR.mkdir(
            parents=True,
            exist_ok=True,
        )

        if not DATA_FILE.exists():
            return

        async with aiofiles.open(
            DATA_FILE,
            "r",
            encoding="utf-8",
        ) as file:
            raw = await file.read()

        data = json.loads(raw)

        LINKS.update(
            data.get(
                "links",
                {},
            )
        )

        SUBS.update(
            data.get(
                "subs",
                {},
            )
        )

        CATEGORIES.update(
            data.get(
                "categories",
                {},
            )
        )

        ADMIN_ACCOUNTS.clear()
        ADMIN_ACCOUNTS.update(data.get("admin_accounts") or {})

        stored_password = data.get(
            "password_hash"
        )

        if stored_password:
            AUTH["password_hash"] = stored_password
            AUTH["password_configured"] = True

        # Compatibility for older records
        for uid, link in LINKS.items():

            link.setdefault(
                "protocol",
                DEFAULT_PROTOCOL,
            )

            link.setdefault(
                "fingerprint",
                DEFAULT_FINGERPRINT,
            )

            link.setdefault(
                "alpn",
                "",
            )

            link.setdefault(
                "port",
                DEFAULT_PORT,
            )

            link.setdefault(
                "ip_limit",
                0,
            )

            link.setdefault(
                "speed_limit_bytes",
                0,
            )

            link.setdefault(
                "connection_limit",
                0,
            )

            link.setdefault(
                "fragment",
                "off",
            )

            link.setdefault(
                "used_bytes",
                0,
            )
            link.setdefault("clean_ips", [])
            link.setdefault("alarm_enabled", False)
            link.setdefault("category_id", "0")
            link.setdefault("config_count", 1)
            link.setdefault("sort_order", 0)
            link.setdefault("usage_history", [])

        logger.info(
            "State loaded: %d links / %d subscriptions",
            len(LINKS),
            len(SUBS),
        )

    except Exception as exc:

        logger.exception(
            "Could not load state: %s",
            exc,
        )


async def save_state():

    async with SAVE_LOCK:

        try:

            DATA_DIR.mkdir(
                parents=True,
                exist_ok=True,
            )

            payload = {
                "links":
                    dict(LINKS),

                "subs":
                    dict(SUBS),

                "categories":
                    dict(CATEGORIES),

                "admin_accounts":
                    dict(ADMIN_ACCOUNTS),

                "password_hash":
                    AUTH[
                        "password_hash"
                    ],

                "saved_at":
                    datetime.now().isoformat(),
            }

            temp_file = (
                DATA_FILE.with_suffix(
                    ".tmp"
                )
            )

            async with aiofiles.open(
                temp_file,
                "w",
                encoding="utf-8",
            ) as file:

                await file.write(
                    json.dumps(
                        payload,
                        ensure_ascii=False,
                        indent=2,
                    )
                )

            temp_file.replace(
                DATA_FILE
            )

        except Exception as exc:

            logger.exception(
                "Could not save state: %s",
                exc,
            )


# ============================================================
# DEFAULT LINK
# ============================================================

_default_link_created = False



async def ensure_default_categories():
    # گروه‌های پیش‌فرض ساخته نمی‌شوند — کاربر خودش می‌سازد
    return


async def ensure_default_link():

    global _default_link_created

    if _default_link_created:
        return

    async with LINKS_LOCK:

        if not any(
            item.get("is_default")
            for item in LINKS.values()
        ):

            digest = hashlib.sha256(
                (
                    "default"
                    + SECRET_KEY
                ).encode("utf-8")
            ).hexdigest()

            uid = (
                f"{digest[:8]}-"
                f"{digest[8:12]}-"
                f"{digest[12:16]}-"
                f"{digest[16:20]}-"
                f"{digest[20:32]}"
            )

            LINKS[uid] = {
                "label":
                    "لینک پیش‌فرض",

                "limit_bytes":
                    0,

                "used_bytes":
                    0,

                "created_at":
                    datetime.now().isoformat(),

                "active":
                    True,

                "expires_at":
                    None,

                "note":
                    "",

                "is_default":
                    True,

                "sub_id":
                    None,

                "protocol":
                    DEFAULT_PROTOCOL,

                "fingerprint":
                    DEFAULT_FINGERPRINT,

                "alpn":
                    "http/1.1",

                "port":
                    DEFAULT_PORT,

                "ip_limit":
                    0,

                "speed_limit_bytes":
                    DEFAULT_SPEED_LIMIT,

                "connection_limit":
                    0,

                "fragment":
                    "off",
            }

            asyncio.create_task(
                save_state()
            )

    _default_link_created = True


# ============================================================
# LINK MANAGEMENT
# ============================================================

async def make_link(
    label: str = "لینک جدید",
    limit_bytes: int = 0,
    expires_at: str | None = None,
    note: str = "",
    sub_id: str | None = None,
    protocol: str = DEFAULT_PROTOCOL,
    fingerprint: str = DEFAULT_FINGERPRINT,
    alpn: str = "",
    port: int = DEFAULT_PORT,
    ip_limit: int = 0,
    speed_limit_bytes: int = 0,
    connection_limit: int = 0,
    fragment: str = "off",
    clean_ips=None,
    alarm_enabled: bool = False,
    category_id: str = "0",
    config_count: int = 1,
):

    protocol = normalize_protocol(protocol)

    fingerprint = (
        fingerprint
        or DEFAULT_FINGERPRINT
    ).strip().lower()

    if fingerprint not in FINGERPRINTS:
        fingerprint = DEFAULT_FINGERPRINT

    if not (
        MIN_PORT
        <= port
        <= MAX_PORT
    ):
        port = DEFAULT_PORT

    uid = generate_uuid()

    record = {
        "label":
            sanitize_config_name((label or "").strip() or random_config_name()),

        "limit_bytes":
            max(
                0,
                int(limit_bytes),
            ),

        "used_bytes":
            0,

        "created_at":
            datetime.now().isoformat(),

        "active":
            True,

        "expires_at":
            expires_at,

        "note":
            (
                note
                or ""
            ).strip()[:500],

        "is_default":
            False,

        "sub_id":
            sub_id,

        "protocol":
            protocol,

        "fingerprint":
            fingerprint,

        "alpn":
            (
                alpn
                or ""
            ).strip()[:100],

        "port":
            port,

        "ip_limit":
            max(
                0,
                int(ip_limit),
            ),

        "speed_limit_bytes":
            max(
                0,
                int(speed_limit_bytes),
            ),

        "connection_limit":
            max(
                0,
                int(connection_limit),
            ),

        "fragment":
            (
                fragment
                or "off"
            ).strip().lower(),

        "security_profile": "balanced",
        "multi_login": False,
        "protocol_label": PROTOCOL_LABELS.get(protocol, protocol),
        "clean_ips": list(clean_ips or []),
        "alarm_enabled": bool(alarm_enabled),
        "category_id": str(category_id or "0"),
        "config_count": max(1, min(40, int(config_count or 1))),
        "usage_history": [],
    }

    async with LINKS_LOCK:
        LINKS[uid] = record

    if sub_id:

        async with SUBS_LOCK:

            if sub_id in SUBS:

                ids = SUBS[
                    sub_id
                ].setdefault(
                    "link_ids",
                    [],
                )

                if uid not in ids:
                    ids.append(uid)

    await save_state()

    log_activity(
        "link",
        (
            f"کانفیگ "
            f"«{record['label']}» "
            f"ساخته شد"
        ),
        "ok",
    )

    return uid, record


async def remove_link(
    uid: str,
):

    async with LINKS_LOCK:

        if uid not in LINKS:
            return None

        label = LINKS[
            uid
        ].get(
            "label",
            uid,
        )

        sub_id = LINKS[
            uid
        ].get(
            "sub_id"
        )

        del LINKS[uid]

    if sub_id:

        async with SUBS_LOCK:

            if sub_id in SUBS:

                ids = SUBS[
                    sub_id
                ].get(
                    "link_ids",
                    [],
                )

                if uid in ids:
                    ids.remove(uid)

    await save_state()

    log_activity(
        "link",
        (
            f"کانفیگ "
            f"«{label}» "
            f"حذف شد"
        ),
        "warn",
    )

    return label


async def set_link_active(
    uid: str,
    active: bool,
):

    async with LINKS_LOCK:

        if uid not in LINKS:
            return None

        LINKS[
            uid
        ][
            "active"
        ] = bool(active)

        record = LINKS[uid]

    await save_state()

    log_activity(
        "link",
        (
            f"کانفیگ "
            f"«{record['label']}» "
            f"{'فعال' if active else 'غیرفعال'} شد"
        ),
        "ok"
        if active
        else "warn",
    )

    return record


# ============================================================
# SUB GROUPS
# ============================================================

async def create_sub_group(
    name: str = "گروه جدید",
    desc: str = "",
    password: str = "",
):

    name = (
        name
        or "گروه جدید"
    ).strip()[:60]

    desc = (
        desc
        or ""
    ).strip()[:200]

    password = (
        password
        or ""
    ).strip()

    sub_id = generate_uuid()

    uuid_key = secrets.token_urlsafe(16)

    record = {
        "name":
            name,

        "desc":
            desc,

        "password_hash":
            (
                hash_password(password)
                if password
                else None
            ),

        "uuid_key":
            uuid_key,

        "created_at":
            datetime.now().isoformat(),

        "link_ids":
            [],
    }

    async with SUBS_LOCK:
        SUBS[sub_id] = record

    await save_state()

    log_activity(
        "sub",
        (
            f"گروه "
            f"«{name}» "
            f"ساخته شد"
        ),
        "ok",
    )

    return (
        sub_id,
        record,
    )


async def set_link_sub(
    uid: str,
    sub_id: str | None,
):

    async with LINKS_LOCK:

        if uid not in LINKS:
            return False

        old_sub = LINKS[
            uid
        ].get(
            "sub_id"
        )

        label = LINKS[
            uid
        ].get(
            "label",
            uid,
        )

    if sub_id is not None:

        async with SUBS_LOCK:

            if sub_id not in SUBS:
                return False

    async with SUBS_LOCK:

        if (
            old_sub
            and old_sub in SUBS
        ):

            ids = SUBS[
                old_sub
            ].get(
                "link_ids",
                [],
            )

            if uid in ids:
                ids.remove(uid)

        if (
            sub_id
            and sub_id in SUBS
        ):

            ids = SUBS[
                sub_id
            ].setdefault(
                "link_ids",
                [],
            )

            if uid not in ids:
                ids.append(uid)

    async with LINKS_LOCK:

        if uid in LINKS:

            LINKS[
                uid
            ][
                "sub_id"
            ] = sub_id

    await save_state()

    log_activity(
        "link",
        (
            f"کانفیگ "
            f"«{label}» "
            f"{'به گروه اضافه شد' if sub_id else 'از گروه خارج شد'}"
        ),
        "info",
    )

    return True


async def remove_sub_group(
    sub_id: str,
):

    async with SUBS_LOCK:

        if sub_id not in SUBS:
            return None

        name = SUBS[
            sub_id
        ].get(
            "name",
            sub_id,
        )

        del SUBS[sub_id]

    async with LINKS_LOCK:

        for link in LINKS.values():

            if (
                link.get("sub_id")
                == sub_id
            ):
                link["sub_id"] = None

    await save_state()

    log_activity(
        "sub",
        (
            f"گروه "
            f"«{name}» "
            f"حذف شد"
        ),
        "warn",
    )

    return name


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
async def startup():

    global http_client

    limits = httpx.Limits(
        max_connections=500,
        max_keepalive_connections=100,
    )

    timeout = httpx.Timeout(
        30.0,
        connect=10.0,
    )

    http_client = httpx.AsyncClient(
        limits=limits,
        timeout=timeout,
        follow_redirects=True,
    )

    await load_state()

    await ensure_default_categories()
    await ensure_default_link()

    log_activity(
        "system",
        (
            f"{APP_NAME} "
            f"v{APP_VERSION} "
            f"راه‌اندازی شد"
        ),
        "ok",
    )

    logger.info(
        "%s v%s started on 0.0.0.0:%s",
        APP_NAME,
        APP_VERSION,
        PORT,
    )

    logger.info(
        "Data directory: %s",
        DATA_DIR,
    )


@app.on_event("shutdown")
async def shutdown():

    await save_state()

    if http_client:
        await http_client.aclose()


# ============================================================
# LANDING
# ============================================================

LOGO_IMAGE_DATA = "data:image/png;base64,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"

LANDING_HTML = r"""
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">

<title>PX Panel</title>

<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>

<link
href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800;900&display=swap"
rel="stylesheet">

<style>
*{
    box-sizing:border-box;
}

html,body{
    margin:0;
    min-height:100%;
}

body{
    min-height:100vh;
    display:flex;
    justify-content:center;
    align-items:center;
    padding:20px;
    color:#fff;
    font-family:"Vazirmatn",sans-serif;

    background:
        radial-gradient(
            circle at 15% 15%,
            rgba(37,99,235,.22),
            transparent 30%
        ),
        radial-gradient(
            circle at 85% 85%,
            rgba(59,130,246,.18),
            transparent 30%
        ),
        #07070a;
}

.card{
    width:100%;
    max-width:580px;
    padding:32px;
    border-radius:28px;

    border:1px solid rgba(255,255,255,.09);

    background:
        linear-gradient(
            145deg,
            rgba(255,255,255,.07),
            rgba(255,255,255,.025)
        );

    backdrop-filter:blur(28px) saturate(150%);

    box-shadow:
        0 30px 90px rgba(0,0,0,.45);
}

.brand{
    display:flex;
    align-items:center;
    gap:12px;
}

.logo{
    width:48px;
    height:48px;
    min-width:48px;
    border-radius:15px;
    overflow:hidden;
    display:flex;
    justify-content:center;
    align-items:center;
    background:#000;
    border:1px solid rgba(255,255,255,.10);
    box-shadow:0 8px 24px rgba(0,0,0,.35);
}

.logo img{
    width:100%;
    height:100%;
    display:block;
    object-fit:cover;
    object-position:center;
}

.brand-name{
    font-size:17px;
    font-weight:900;
}

.version{
    margin-top:4px;
    font-size:11px;
    color:#60a5fa;
}

.status{
    display:inline-block;
    margin-top:23px;
    padding:7px 11px;
    border-radius:999px;

    color:#86efac;
    background:rgba(34,197,94,.07);
    border:1px solid rgba(34,197,94,.15);

    font-size:11px;
}

h1{
    margin:18px 0 0;
    font-size:28px;
    line-height:1.55;
}

.desc{
    margin-top:12px;
    color:rgba(255,255,255,.52);
    line-height:2;
    font-size:13px;
}

.path{
    margin-top:22px;
    padding:15px;
    border-radius:15px;

    background:rgba(0,0,0,.18);
    border:1px solid rgba(255,255,255,.07);

    direction:ltr;
    text-align:left;
    font-family:Consolas,monospace;
    color:#93c5fd;
}

.actions{
    display:flex;
    gap:10px;
    margin-top:20px;
}

.btn{
    flex:1;
    padding:13px;
    border-radius:14px;
    text-align:center;
    text-decoration:none;

    font-size:12px;
    font-weight:800;
}

.primary{
    color:#fff;
    background:
        linear-gradient(
            135deg,
            #2563eb,
            #3b82f6
        );
}

.secondary{
    color:#fff;
    background:rgba(255,255,255,.035);
    border:1px solid rgba(255,255,255,.08);
}

.footer{
    margin-top:22px;
    padding-top:16px;
    border-top:1px solid rgba(255,255,255,.07);

    display:flex;
    justify-content:space-between;

    font-size:10px;
    color:rgba(255,255,255,.35);
}

.support{
    color:#60a5fa;
    text-decoration:none;
}

@media(max-width:600px){
    .card{
        padding:24px;
        border-radius:22px;
    }

    h1{
        font-size:23px;
    }

    .actions{
        flex-direction:column;
    }
}

/* PXPanel 13.0.1 responsive system */
html{scroll-behavior:smooth} body{overflow-x:hidden} button,input,select,textarea{touch-action:manipulation} .modal{overscroll-behavior:contain}
@media(max-width:900px){.container,.shell,.dashboard,.main,.content{max-width:100%!important;width:100%!important}.grid,.stats-grid,.cards-grid,.form-grid{grid-template-columns:repeat(2,minmax(0,1fr))!important}.sidebar{z-index:1000}}
@media(max-width:640px){body{padding:10px!important;font-size:14px}.grid,.stats-grid,.cards-grid,.form-grid{grid-template-columns:1fr!important}.card,.panel,.section,.modal{border-radius:18px!important}.modal{max-height:92vh;overflow:auto;padding:14px!important}.header,.topbar,.toolbar,.actions{flex-wrap:wrap!important}.header>* ,.topbar>*{max-width:100%}.btn,button{min-height:44px}.field input,.field select,.field textarea,input,select,textarea{min-height:44px;font-size:16px;max-width:100%}table{display:block;overflow-x:auto;white-space:nowrap}.link-row,.config-row{flex-direction:column!important;align-items:stretch!important}.brand-name{font-size:15px}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.01ms!important;transition-duration:.01ms!important;scroll-behavior:auto!important}}

/* Toggle switch */
.switch{position:relative;display:inline-block;width:42px;height:24px;vertical-align:middle}
.switch input{opacity:0;width:0;height:0}
.slider{position:absolute;cursor:pointer;inset:0;background:rgba(255,255,255,.12);border-radius:24px;transition:.2s}
.slider:before{position:absolute;content:"";height:18px;width:18px;left:3px;bottom:3px;background:#fff;border-radius:50%;transition:.2s}
.switch input:checked+.slider{background:var(--green)}
.switch input:checked+.slider:before{transform:translateX(18px)}


.conn-badge{display:inline-flex;align-items:center;justify-content:center;min-width:22px;height:20px;padding:0 7px;border-radius:8px;font-size:10px;font-weight:800}
.conn-badge.green{background:rgba(34,197,94,.18);color:#4ade80}
.conn-badge.gray{background:rgba(148,163,184,.15);color:#94a3b8}
.conn-badge.orange{background:rgba(245,158,11,.18);color:#fbbf24}
.conn-badge.red{background:rgba(239,68,68,.18);color:#f87171}


.bottom-bulk{position:fixed;left:0;right:0;bottom:0;z-index:400;display:none;padding:12px 16px;background:var(--card);border-top:1px solid var(--card-b);backdrop-filter:blur(12px)}
.bottom-bulk.show{display:block}
.bottom-bulk-inner{max-width:960px;margin:0 auto;display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:center}
.bottom-bulk select{padding:8px 10px;border-radius:10px;border:1px solid var(--card-b);background:var(--input-bg);color:var(--t1);font-family:inherit;font-size:12px}

table th:first-child, table td:first-child{overflow:visible}
.cfg-chk{accent-color:var(--accent)}
#page-donate .page-title{width:100%}
</style>
</head>

<body>

<div class="card">

<div class="brand">

<div class="logo"><img src="{LOGO_IMAGE_DATA}" alt="DeBuG Logo"></div>

<div>
<div class="brand-name">
PX Panel
</div>

<div class="version">
13.8.0
</div>
</div>

</div>

<div class="status">
● سیستم آنلاین و فعال است
</div>

<h1>
برای ورود به پنل
<br>
ابتدا وارد شوید
</h1>

<div class="desc">
این صفحه، درگاه عمومی PX Panel است.
برای دسترسی به داشبورد مدیریت از مسیر ورود استفاده کنید.
</div>

<div class="path">
/login
</div>

<div class="actions">

<a
href="/login"
class="btn primary"
>
ورود به پنل
</a>

<a
href="https://t.me/Pixonal"
target="_blank"
rel="noopener"
class="btn secondary"
>
پشتیبانی
</a>

</div>

<div class="footer">

<span>
PX Panel · 13.8.0
</span>

<a
href="https://t.me/Pixonal"
target="_blank"
class="support"
>
@Pixonal
</a>

</div>

</div>


<div id="bottomBulkBar" class="bottom-bulk">
  <div class="bottom-bulk-inner">
    <span id="bulkCount">0 انتخاب</span>
    <select id="bulkGroup"></select>
    <button class="btn btn-sm" onclick="bulkMoveGroup()">انتقال به گروه</button>
    <button class="btn btn-sm btn-d" onclick="bulkDelete()">حذف انتخاب‌شده</button>
    <button class="btn btn-sm" onclick="clearSelection()">لغو</button>
  </div>
</div>
</body>
</html>
"""


@app.get(
    "/",
    response_class=HTMLResponse,
)
async def root(
    request: Request,
):

    if await is_valid_session(
        request.cookies.get(
            SESSION_COOKIE
        )
    ):
        return RedirectResponse(
            "/dashboard"
        )

    return HTMLResponse(
        LANDING_HTML.replace("{LOGO_IMAGE_DATA}", LOGO_IMAGE_DATA)
    )


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
async def health():

    return {
        "status": "ok",
        "service": APP_NAME,
        "version": APP_VERSION,
        "connections": len(connections),
        "uptime": uptime(),
    }


# ============================================================
# LOGIN
# ============================================================

LOGIN_HTML = r"""
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>DeBuG Panel</title>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--red:#ef233c;--red2:#ff4d00;--orange:#ff8a00;--glass:rgba(255,255,255,.055)}
html,body{min-height:100%;background:#020203}
body{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;overflow:hidden;font-family:Vazirmatn,sans-serif;color:#fff;position:relative}
body:before,body:after{content:"";position:fixed;width:55vw;height:55vw;max-width:700px;max-height:700px;border-radius:50%;filter:blur(80px);opacity:.13;pointer-events:none;animation:float 8s ease-in-out infinite alternate}
body:before{background:#e90020;top:-30vw;right:-18vw} body:after{background:#ff7600;bottom:-32vw;left:-18vw;animation-delay:-3s}
.grid{position:fixed;inset:0;pointer-events:none;opacity:.12;background-image:linear-gradient(rgba(255,255,255,.035) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.035) 1px,transparent 1px);background-size:42px 42px;mask-image:linear-gradient(to bottom,transparent,#000 25%,#000 75%,transparent)}
.wrap{width:100%;max-width:430px;position:relative;z-index:2;animation:enter .8s cubic-bezier(.2,.8,.2,1)}
.brand{text-align:center;margin-bottom:22px}
.logo-orbit{width:118px;height:118px;margin:0 auto 15px;border-radius:50%;padding:3px;position:relative;background:conic-gradient(from 0deg,transparent 0 18%,#ef233c 28%,#ff7a00 43%,transparent 55% 100%);animation:spin 7s linear infinite;box-shadow:0 0 28px rgba(239,35,60,.18),0 0 55px rgba(255,122,0,.10)}
.logo-orbit:before{content:"";position:absolute;inset:5px;border-radius:50%;background:#030304;border:1px solid rgba(255,255,255,.08)}
.logo{position:absolute;inset:10px;border-radius:50%;overflow:hidden;background:#000;border:1px solid rgba(255,255,255,.12);box-shadow:inset 0 0 25px rgba(0,0,0,.8),0 0 25px rgba(239,35,60,.12);animation:counterspin 7s linear infinite}
.logo img{width:100%;height:100%;display:block;object-fit:cover}
.brand-name{font-size:25px;font-weight:900;letter-spacing:2px;text-shadow:0 0 20px rgba(239,35,60,.25)}
.brand-sub{margin-top:5px;font-size:11px;color:rgba(255,255,255,.38);letter-spacing:3px;text-transform:uppercase}
.panel{padding:25px;border-radius:26px;background:linear-gradient(145deg,rgba(255,255,255,.075),rgba(255,255,255,.025));border:1px solid rgba(255,255,255,.10);backdrop-filter:blur(25px) saturate(150%);box-shadow:0 35px 90px rgba(0,0,0,.6),inset 0 1px rgba(255,255,255,.05);position:relative;overflow:hidden}
.panel:before{content:"";position:absolute;top:0;left:14%;right:14%;height:1px;background:linear-gradient(90deg,transparent,#ef233c,#ff8a00,transparent);box-shadow:0 0 18px #ef233c;opacity:.75}
.head{text-align:center;margin-bottom:22px}.head h1{font-size:20px;font-weight:900}.head p{margin-top:7px;font-size:11px;color:rgba(255,255,255,.38)}
.err{display:none;background:rgba(239,68,68,.10);border:1px solid rgba(239,68,68,.28);color:#fca5a5;padding:10px 12px;border-radius:12px;font-size:11px;margin-bottom:13px;line-height:1.8}.err.show{display:block}
.warn{background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.25);border-radius:13px;padding:12px;font-size:11px;line-height:1.9;color:#fbbf24;margin-bottom:16px}.warn code{background:rgba(0,0,0,.4);padding:2px 6px;border-radius:6px;font-family:ui-monospace,monospace;color:#93c5fd}
.field{margin-bottom:14px}.field-label{display:flex;align-items:center;justify-content:space-between;margin-bottom:7px;font-size:11px;color:rgba(255,255,255,.52);font-weight:700}
input{width:100%;padding:13px 14px;border-radius:13px;border:1px solid rgba(255,255,255,.09);background:rgba(0,0,0,.34);color:#fff;font-family:inherit;font-size:13px;outline:none;direction:ltr;text-align:left;transition:.2s;box-shadow:inset 0 1px rgba(255,255,255,.025)}
input::placeholder{color:rgba(255,255,255,.22)} input:focus{border-color:rgba(239,35,60,.65);box-shadow:0 0 0 3px rgba(239,35,60,.08),0 0 22px rgba(239,35,60,.08)}
button{width:100%;padding:13px;border:1px solid rgba(255,255,255,.12);border-radius:13px;background:linear-gradient(135deg,#d90429,#ef233c 48%,#ff6a00);color:#fff;font-family:inherit;font-size:13px;font-weight:900;cursor:pointer;margin-top:3px;box-shadow:0 10px 30px rgba(239,35,60,.18);transition:.2s;position:relative;overflow:hidden}
button:before{content:"";position:absolute;top:0;bottom:0;width:80px;left:-100px;background:linear-gradient(90deg,transparent,rgba(255,255,255,.25),transparent);transform:skewX(-20deg);transition:.5s}button:hover{transform:translateY(-1px);box-shadow:0 14px 35px rgba(239,35,60,.28)}button:hover:before{left:110%}button:disabled{opacity:.5;cursor:not-allowed;transform:none}
.hidden{display:none!important}.foot{text-align:center;margin-top:15px;color:rgba(255,255,255,.22);font-size:9px;letter-spacing:1px}.foot b{color:rgba(255,120,60,.65)}
@keyframes spin{to{transform:rotate(360deg)}}@keyframes counterspin{to{transform:rotate(-360deg)}}@keyframes float{to{transform:translate(3vw,2vw) scale(1.08)}}@keyframes enter{from{opacity:0;transform:translateY(18px) scale(.98)}to{opacity:1;transform:none}}
@media(max-width:480px){body{padding:14px}.panel{padding:21px;border-radius:22px}.logo-orbit{width:104px;height:104px}.brand-name{font-size:22px}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}}
</style>
</head>
<body>
<div class="grid"></div>
<div class="wrap">
  <div class="brand">
    <div class="logo-orbit"><div class="logo"><img src="{LOGO_IMAGE_DATA}" alt="DeBuG"></div></div>
    <div class="brand-name">DeBuG PANEL</div>
    <div class="brand-sub">SECURE CONTROL CENTER</div>
  </div>
  <div class="panel">
    <div class="head"><h1>ورود امن به پنل</h1><p>برای ادامه، اطلاعات دسترسی خود را وارد کنید</p></div>
    <div id="setupBox" class="hidden">
      <div class="warn">برای نگه‌داشتن داده‌ها روی Railway حتماً Volume با مسیر <code>/data</code> وصل کنید.</div>
      <div class="err" id="setupErr"></div>
      <div class="field"><div class="field-label">رمز عبور پنل</div><input type="password" id="setupPw" placeholder="حداقل ۶ کاراکتر" autocomplete="new-password"></div>
      <div class="field"><div class="field-label">تکرار رمز عبور</div><input type="password" id="setupPw2" placeholder="تکرار رمز" autocomplete="new-password"></div>
      <button type="button" id="setupBtn" onclick="doSetup()">تنظیم رمز و ورود</button>
    </div>
    <div id="loginBox" class="hidden">
      <div class="err" id="loginErr"></div>
      <form id="loginForm">
        <div class="field"><div class="field-label">نام کاربری ادمین</div><input type="text" id="loginUser" placeholder="خالی = مالک پنل" autocomplete="username"></div>
        <div class="field"><div class="field-label">رمز عبور</div><input type="password" id="loginPw" placeholder="رمز عبور" autocomplete="current-password" required></div>
        <button type="submit" id="loginBtn">ورود به DeBuG Panel</button>
      </form>
    </div>
    <div class="foot">DEBuG • <b>SECURE</b> • PX PANEL</div>
  </div>
</div>
<script>
async function checkSetup(){try{const r=await fetch('/api/setup/status',{cache:'no-store'});const d=await r.json();if(d.needs_setup){document.getElementById('setupBox').classList.remove('hidden');document.getElementById('setupPw').focus()}else{document.getElementById('loginBox').classList.remove('hidden');document.getElementById('loginPw').focus()}}catch(e){document.getElementById('loginBox').classList.remove('hidden')}}
async function doSetup(){const pw=document.getElementById('setupPw').value,pw2=document.getElementById('setupPw2').value,err=document.getElementById('setupErr');err.classList.remove('show');if(pw.length<6){err.textContent='رمز حداقل ۶ کاراکتر';err.classList.add('show');return}if(pw!==pw2){err.textContent='تکرار رمز یکسان نیست';err.classList.add('show');return}const btn=document.getElementById('setupBtn');btn.disabled=true;try{const r=await fetch('/api/setup/password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw,repeat_password:pw2})});const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.detail||'خطا');location.href='/dashboard'}catch(e){err.textContent=e.message||'خطا';err.classList.add('show');btn.disabled=false}}
document.getElementById('loginForm').addEventListener('submit',async e=>{e.preventDefault();const err=document.getElementById('loginErr');err.classList.remove('show');const btn=document.getElementById('loginBtn');btn.disabled=true;try{const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('loginPw').value,username:document.getElementById('loginUser').value})});if(!r.ok){const d=await r.json().catch(()=>({}));throw new Error(d.detail||'رمز اشتباه است')}location.href='/dashboard'}catch(e){err.textContent=e.message;err.classList.add('show');btn.disabled=false}});checkSetup();
</script>
</body>
</html>
"""





def login_error_html(
    message: str,
):
    safe_message = escape_html(
        message
    )

    return LOGIN_HTML.replace("{LOGO_IMAGE_DATA}", LOGO_IMAGE_DATA).replace(
        "</form>",
        (
            f"""
            <div class="error">
                {safe_message}
            </div>
            </form>
            """
        ),
    )



# ============================================================
# FIRST-RUN SETUP
# ============================================================

@app.get("/api/setup/status")
async def setup_status():
    return {
        "password_configured": bool(AUTH.get("password_configured") and AUTH.get("password_hash")),
        "needs_setup": not bool(AUTH.get("password_configured") and AUTH.get("password_hash")),
    }


@app.post("/api/setup/password")
async def setup_password(request: Request):
    if AUTH.get("password_configured") and AUTH.get("password_hash"):
        raise HTTPException(status_code=400, detail="رمز قبلاً تنظیم شده است")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="اطلاعات نامعتبر")
    pw = str(body.get("password") or "")
    rp = str(body.get("repeat_password") or body.get("confirm") or "")
    if len(pw) < 6:
        raise HTTPException(status_code=400, detail="رمز باید حداقل ۶ کاراکتر باشد")
    if pw != rp:
        raise HTTPException(status_code=400, detail="تکرار رمز یکسان نیست")
    AUTH["password_hash"] = hash_password(pw)
    AUTH["password_configured"] = True
    await save_state()
    token = await create_session()
    response = JSONResponse({"ok": True, "message": "رمز تنظیم شد"})
    set_auth_cookie(response, request, token)
    log_activity("auth", "رمز اولیه پنل تنظیم شد", "ok")
    return response


@app.get(
    "/login",
    response_class=HTMLResponse,
)
async def login_page(
    request: Request,
):

    if await is_valid_session(
        request.cookies.get(
            SESSION_COOKIE
        )
    ):
        return RedirectResponse(
            "/dashboard"
        )

    return HTMLResponse(
        LOGIN_HTML.replace("{LOGO_IMAGE_DATA}", LOGO_IMAGE_DATA)
    )


@app.post("/login")
async def login_form(
    request: Request,
):
    if not (AUTH.get("password_configured") and AUTH.get("password_hash")):
        return HTMLResponse(login_error_html("ابتدا از صفحه ورود، رمز اولیه را تنظیم کنید"))


    try:

        content_type = (
            request.headers
            .get(
                "content-type",
                "",
            )
            .lower()
        )

        if "application/json" in content_type:

            body = await request.json()

            password = str(
                body.get(
                    "password",
                    "",
                )
            ).strip()

        else:

            raw = await request.body()

            parsed = parse_qs(
                raw.decode(
                    "utf-8",
                    errors="ignore",
                )
            )

            password = (
                parsed.get(
                    "password",
                    [""],
                )[0]
                .strip()
            )

    except Exception as exc:

        logger.exception(
            "Login parser error: %s",
            exc,
        )

        return HTMLResponse(
            login_error_html(
                "خطا در پردازش اطلاعات ورود."
            ),
            status_code=400,
        )

    ip = client_ip(request)

    blocked, retry_after = login_is_blocked(ip)
    if blocked:
        minutes = max(1, (retry_after + 59) // 60)
        return HTMLResponse(
            login_error_html(
                f"به دلیل تلاش‌های ناموفق متعدد، ورود موقتاً مسدود شده است. حدود {minutes} دقیقه دیگر دوباره تلاش کنید."
            ),
            status_code=429,
            headers={"Retry-After": str(retry_after)},
        )

    if not password:
        register_login_failure(ip)
        return HTMLResponse(
            login_error_html(
                "رمز عبور را وارد کنید."
            ),
            status_code=400,
        )

    if (
        hash_password(password)
        != AUTH["password_hash"]
    ):

        locked, value = register_login_failure(ip)
        if locked:
            return HTMLResponse(
                login_error_html(
                    "تعداد تلاش‌های ناموفق بیش از حد مجاز بود. این IP برای ۱۵ دقیقه مسدود شد."
                ),
                status_code=429,
                headers={"Retry-After": str(LOGIN_LOCKOUT_SECONDS)},
            )

        remaining = value
        log_activity(
            "auth",
            (
                f"تلاش ورود ناموفق از {ip}؛ "
                f"{remaining} تلاش باقی مانده"
            ),
            "err",
        )

        return HTMLResponse(
            login_error_html(
                f"رمز عبور اشتباه است. {remaining} تلاش دیگر باقی مانده است."
            ),
            status_code=401,
        )

    clear_login_failures(ip)

    token = await create_session()

    response = RedirectResponse(
        "/dashboard?login=1",
        status_code=303,
    )

    set_auth_cookie(
        response,
        request,
        token,
    )

    log_activity(
        "auth",
        (
            f"ورود موفق به پنل "
            f"از {client_ip(request)}"
        ),
        "ok",
    )

    return response


@app.post("/api/login")
async def api_login(request: Request):
    if not (AUTH.get("password_configured") and AUTH.get("password_hash")):
        raise HTTPException(status_code=400, detail="ابتدا رمز پنل را در راه‌اندازی تنظیم کنید")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="JSON نامعتبر است")
    password = str(body.get("password", "")).strip()
    username = str(body.get("username", "")).strip().lower()
    ip = client_ip(request)
    blocked, retry_after = login_is_blocked(ip)
    if blocked:
        raise HTTPException(status_code=429, detail=f"ورود موقتاً مسدود است. حدود {max(1, (retry_after + 59) // 60)} دقیقه دیگر تلاش کنید.", headers={"Retry-After": str(retry_after)})
    if not password:
        register_login_failure(ip)
        raise HTTPException(status_code=400, detail="رمز عبور الزامی است")
    meta = {"role": "owner", "admin_id": None, "username": "owner"}
    ok = False
    if username and username not in ("owner", "admin", "root"):
        aid, admin = find_admin_by_username(username)
        if admin and admin.get("password_hash") == hash_password(password):
            if not admin_is_valid(admin):
                raise HTTPException(status_code=403, detail="حساب مسدود یا منقضی شده است")
            ok = True
            meta = {"role": "admin", "admin_id": aid, "username": username}
    else:
        if hash_password(password) == AUTH["password_hash"]:
            ok = True
    if not ok:
        locked, value = register_login_failure(ip)
        if locked:
            raise HTTPException(status_code=429, detail="تعداد تلاش بیش از حد. ۱۵ دقیقه صبر کنید.", headers={"Retry-After": str(LOGIN_LOCKOUT_SECONDS)})
        raise HTTPException(status_code=401, detail=f"نام کاربری یا رمز اشتباه است. {value} تلاش باقی‌مانده")
    clear_login_failures(ip)
    token = await create_session(meta)
    response = JSONResponse({"ok": True, "role": meta["role"], "username": meta["username"]})
    set_auth_cookie(response, request, token)
    log_activity("auth", f"ورود موفق ({meta['username']}) از {ip}", "ok")
    return response


@app.post("/api/logout")
async def api_logout(
    request: Request,
):

    await destroy_session(
        request.cookies.get(
            SESSION_COOKIE
        )
    )

    response = JSONResponse(
        {
            "ok": True
        }
    )

    response.delete_cookie(
        SESSION_COOKIE,
        path="/",
    )

    return response





# ============================================================
# CHANGE PASSWORD
# ============================================================

@app.post("/api/change-password")
async def api_change_password(
    request: Request,
    token=Depends(require_auth),
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="اطلاعات نامعتبر است",
        )

    current_password = str(
        body.get(
            "current_password",
            "",
        )
    )

    if (
        hash_password(current_password)
        != AUTH["password_hash"]
    ):
        raise HTTPException(
            status_code=400,
            detail="رمز فعلی اشتباه است",
        )

    new_password = str(
        body.get(
            "new_password",
            "",
        )
    )

    repeat_password = str(
        body.get(
            "repeat_password",
            "",
        )
    )

    if len(new_password) < 6:
        raise HTTPException(
            status_code=400,
            detail="رمز جدید باید حداقل ۶ کاراکتر باشد",
        )

    if new_password != repeat_password:
        raise HTTPException(
            status_code=400,
            detail="تکرار رمز عبور یکسان نیست",
        )

    AUTH[
        "password_hash"
    ] = hash_password(
        new_password
    )

    async with SESSIONS_LOCK:

        SESSIONS.clear()

        SESSIONS[token] = (
            time.time()
            + SESSION_TTL
        )

    await save_state()

    log_activity(
        "auth",
        "رمز عبور پنل تغییر کرد",
        "ok",
    )

    return {
        "ok": True
    }


# ============================================================
# CREATE LINK
# ============================================================

@app.post("/api/links")
async def create_link_api(
    request: Request,
    _=Depends(require_auth),
):

    try:
        body = await request.json()

        if not isinstance(body, dict):
            raise ValueError(
                "body is not object"
            )

    except Exception as exc:

        logger.exception(
            "Create link JSON error: %s",
            exc,
        )

        raise HTTPException(
            status_code=400,
            detail="اطلاعات ارسال‌شده معتبر نیست.",
        )

    limit_value = safe_float(
        body.get(
            "limit_value",
            0,
        )
    )

    limit_unit = str(
        body.get(
            "limit_unit",
            "GB",
        )
        or "GB"
    ).upper()

    limit_bytes = (
        0
        if limit_value <= 0
        else parse_size_to_bytes(
            limit_value,
            limit_unit,
        )
    )

    expires_days = safe_int(
        body.get(
            "expires_days",
            0,
        ),
        minimum=0,
    )

    expires_at = (
        (
            datetime.now()
            + timedelta(
                days=expires_days
            )
        ).isoformat()
        if expires_days > 0
        else None
    )

    port = safe_int(
        body.get(
            "port",
            DEFAULT_PORT,
        ),
        default=DEFAULT_PORT,
        minimum=MIN_PORT,
        maximum=MAX_PORT,
    )

    ip_limit = safe_int(
        body.get(
            "ip_limit",
            0,
        ),
        minimum=0,
    )

    speed_value = safe_float(
        body.get(
            "speed_limit_value",
            0,
        )
    )

    speed_unit = str(
        body.get(
            "speed_limit_unit",
            "MBIT",
        )
        or "MBIT"
    ).upper()

    speed_bytes = (
        0
        if speed_value <= 0
        else parse_speed_to_bytes(
            speed_value,
            speed_unit,
        )
    )

    connection_limit = safe_int(
        body.get(
            "connection_limit",
            0,
        ),
        minimum=0,
    )

    protocol = str(
        body.get(
            "protocol",
            DEFAULT_PROTOCOL,
        )
        or DEFAULT_PROTOCOL
    ).strip()

    if protocol not in PROTOCOLS:
        protocol = DEFAULT_PROTOCOL

    fingerprint = str(
        body.get(
            "fingerprint",
            DEFAULT_FINGERPRINT,
        )
        or DEFAULT_FINGERPRINT
    ).strip().lower()

    if fingerprint not in FINGERPRINTS:
        fingerprint = DEFAULT_FINGERPRINT

    fragment = str(
        body.get(
            "fragment",
            "off",
        )
        or "off"
    ).strip().lower()

    allowed_fragments = {
        "off",
        "safe",
        "balanced",
        "aggressive",
    }

    if fragment not in allowed_fragments:
        fragment = "off"

    raw_clean = body.get("clean_ips") or body.get("clean_ip") or ""
    if isinstance(raw_clean, list):
        clean_ips = [str(x).strip() for x in raw_clean if str(x).strip()]
    else:
        clean_ips = [x.strip() for x in str(raw_clean).replace(",", "\n").splitlines() if x.strip()]
    alarm_enabled = bool(body.get("alarm_enabled", False))
    category_id = str(body.get("category_id") or "0")
    if category_id not in CATEGORIES:
        category_id = "0"
    config_count = safe_int(body.get("config_count", 1), minimum=1, maximum=40)
    cat = CATEGORIES.get(category_id) or {}
    if cat.get("limit_bytes") and limit_bytes <= 0:
        limit_bytes = int(cat["limit_bytes"])
    if cat.get("expires_days") and expires_days <= 0:
        expires_days = int(cat["expires_days"])
        expires_at = (datetime.now() + timedelta(days=expires_days)).isoformat() if expires_days > 0 else None
    if cat.get("connection_limit") and connection_limit <= 0:
        connection_limit = int(cat["connection_limit"])
    if cat.get("speed_limit_bytes") and speed_bytes <= 0:
        speed_bytes = int(cat["speed_limit_bytes"])
    if cat.get("ip_limit") and ip_limit <= 0:
        ip_limit = int(cat["ip_limit"])
    if cat.get("clean_ips") and not clean_ips:
        clean_ips = list(cat["clean_ips"])
    if cat.get("single_user"):
        if ip_limit == 0: ip_limit = 1
        if connection_limit == 0: connection_limit = 1
    label_val = body.get("label", "")
    if cat.get("random_name") or not str(label_val).strip():
        label_val = random_config_name()
    else:
        label_val = sanitize_config_name(str(label_val))

    uid, link = await make_link(
        label=label_val,
        limit_bytes=limit_bytes,
        expires_at=expires_at,
        note=body.get(
            "note",
            "",
        ),
        sub_id=body.get(
            "sub_id"
        ),
        protocol=protocol,
        fingerprint=fingerprint,
        alpn=body.get(
            "alpn",
            DEFAULT_ALPN_BY_PROTOCOL.get(
                protocol,
                "http/1.1",
            ),
        ),
        port=port,
        ip_limit=ip_limit,
        speed_limit_bytes=speed_bytes,
        connection_limit=connection_limit,
        fragment=fragment,
        clean_ips=clean_ips,
        alarm_enabled=alarm_enabled,
        category_id=category_id,
        config_count=config_count,
    )

    host = get_host(request)

    result = {
        **get_link_info(
            link,
            uid,
            host,
        ),
        "ok": True,
    }

    return result


# ============================================================
# AUTO CREATE
# ============================================================

@app.post("/api/links/auto")
async def create_auto_link(
    request: Request,
    _=Depends(require_auth),
):
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict): body = {}
    host = get_host(request)
    protocol = normalize_protocol(body.get("protocol", DEFAULT_PROTOCOL))
    profile = str(body.get("profile", "balanced")).strip().lower()
    profiles = {
        "normal": {"ip":0,"conn":0,"speed":0,"fp":"chrome","fragment":"off"},
        "balanced": {"ip":2,"conn":4,"speed":0,"fp":"chrome","fragment":"safe"},
        "gaming": {"ip":1,"conn":2,"speed":0,"fp":"chrome","fragment":"safe"},
        "maximum": {"ip":0,"conn":0,"speed":0,"fp":"randomized","fragment":"safe"},
    }
    cfg = profiles.get(profile, profiles["balanced"])
    config_count = safe_int(body.get("config_count", 1), minimum=1, maximum=40)
    uid, link = await make_link(
        label=auto_config_name(), limit_bytes=0, expires_at=None,
        ip_limit=cfg["ip"], speed_limit_bytes=cfg["speed"], connection_limit=cfg["conn"],
        note=f"Auto generated by PXPanel | profile={profile}",
        protocol=protocol, fingerprint=cfg["fp"],
        alpn=DEFAULT_ALPN_BY_PROTOCOL.get(protocol, ""), port=443, fragment=cfg["fragment"],
        config_count=config_count,
    )
    link["security_profile"] = profile
    result = {**get_link_info(link, uid, host), "ok": True, "profile": profile}
    log_activity("link", f"کانفیگ خودکار «{link['label']}» با {PROTOCOL_LABELS.get(protocol, protocol)} ساخته شد", "ok")
    return result


# ============================================================
# LIST LINKS
# ============================================================

@app.get("/api/protocols")
async def api_protocols(request: Request):
    require_auth(request)
    return {"protocols": [{"id": p, "label": PROTOCOL_LABELS.get(p, p)} for p in PROTOCOLS], "default": DEFAULT_PROTOCOL}


@app.get("/api/links")
async def list_links(
    request: Request,
    _=Depends(require_auth),
):

    host = get_host(request)

    async with LINKS_LOCK:
        snapshot = dict(LINKS)

    result = []

    for uid, link in snapshot.items():

        info = get_link_info(
            link,
            uid,
            host,
        )

        result.append(
            {
                **info,

                "created_at":
                    link.get(
                        "created_at"
                    ),

                "expired":
                    is_link_expired(
                        link
                    ),

                "sub_url":
                    f"https://{host}/sub/{uid}",

                "info_url":
                    f"https://{host}/info/{uid}",

                "connected_ips":
                    len(
                        unique_ips_for_uuid(
                            uid
                        )
                    ),
            }
        )

    result = sorted(
        result,
        key=lambda item: (
            -int(item.get("sort_order") or 0),
            str(item.get("created_at") or ""),
        ),
    )

    return {
        "links": result
    }


# ============================================================
# LINK INFO API
# ============================================================

@app.get("/api/links/{uid}/info")
async def link_info_api(
    uid: str,
    request: Request,
    _=Depends(require_auth),
):

    async with LINKS_LOCK:

        link = LINKS.get(uid)

        if not link:
            raise HTTPException(
                status_code=404,
                detail="link not found",
            )

        snapshot = dict(link)

    host = get_host(request)

    return {
        "ok": True,
        **get_link_info(
            snapshot,
            uid,
            host,
        ),
    }


# ============================================================
# UPDATE LINK
# ============================================================



@app.post("/api/links/reorder")
async def reorder_links(request: Request, _=Depends(require_auth)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, detail="JSON نامعتبر")
    order = body.get("order") or body.get("ids") or []
    if not isinstance(order, list):
        raise HTTPException(400, detail="order باید آرایه باشد")
    # first item = highest priority
    n = len(order)
    async with LINKS_LOCK:
        for i, uid in enumerate(order):
            uid = str(uid)
            if uid in LINKS:
                LINKS[uid]["sort_order"] = n - i
    await save_state()
    return {"ok": True, "count": n}


@app.post("/api/links/bulk-delete")
async def bulk_delete_links(request: Request, _=Depends(require_auth)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, detail="JSON نامعتبر")
    ids = body.get("ids") or []
    if not isinstance(ids, list) or not ids:
        raise HTTPException(400, detail="ids خالی است")
    deleted = []
    for uid in ids:
        uid = str(uid)
        if uid in LINKS:
            await remove_link(uid)
            deleted.append(uid)
    log_activity("link", f"حذف گروهی {len(deleted)} کانفیگ", "warn")
    return {"ok": True, "deleted": len(deleted)}


@app.post("/api/links/bulk-category")
async def bulk_category(request: Request, _=Depends(require_auth)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, detail="JSON نامعتبر")
    ids = body.get("ids") or []
    cid = str(body.get("category_id") or "0")
    if cid not in CATEGORIES:
        cid = "0"
    n = 0
    async with LINKS_LOCK:
        for uid in ids:
            uid = str(uid)
            if uid in LINKS:
                LINKS[uid]["category_id"] = cid
                n += 1
    await save_state()
    return {"ok": True, "updated": n}


@app.patch("/api/links/{uid}")
async def update_link(
    uid: str,
    request: Request,
    _=Depends(require_auth),
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="اطلاعات نامعتبر است",
        )

    if not isinstance(body, dict):
        raise HTTPException(
            status_code=400,
            detail="اطلاعات نامعتبر است",
        )

    async with LINKS_LOCK:

        if uid not in LINKS:
            raise HTTPException(
                status_code=404,
                detail="link not found",
            )

        link = LINKS[uid]

        old_sub = link.get(
            "sub_id"
        )

        label = link.get(
            "label",
            uid,
        )

        if "active" in body:
            link["active"] = bool(
                body["active"]
            )

        if "category_id" in body:
            cid = str(body.get("category_id") or "0")
            if cid not in CATEGORIES:
                cid = "0"
            link["category_id"] = cid

        if "sort_order" in body:
            try:
                link["sort_order"] = int(body.get("sort_order") or 0)
            except Exception:
                pass

        if "label" in body:

            value = str(
                body["label"]
            ).strip()

            if value:
                link["label"] = value[:60]

        if "note" in body:

            link["note"] = str(
                body.get(
                    "note",
                    "",
                )
            )[:500]

        if "reset_usage" in body:

            if body.get(
                "reset_usage"
            ):
                link[
                    "used_bytes"
                ] = 0


        if "limit_value" in body:

            value = safe_float(
                body.get(
                    "limit_value",
                    0,
                )
            )

            unit = str(
                body.get(
                    "limit_unit",
                    "GB",
                )
                or "GB"
            )

            link[
                "limit_bytes"
            ] = (
                0
                if value <= 0
                else parse_size_to_bytes(
                    value,
                    unit,
                )
            )

        if "expires_days" in body:

            days = safe_int(
                body.get(
                    "expires_days",
                    0,
                ),
                minimum=0,
            )

            link[
                "expires_at"
            ] = (
                (
                    datetime.now()
                    + timedelta(
                        days=days
                    )
                ).isoformat()
                if days > 0
                else None
            )

        if "fingerprint" in body:

            fingerprint = str(
                body.get(
                    "fingerprint",
                    DEFAULT_FINGERPRINT,
                )
            ).strip().lower()

            link[
                "fingerprint"
            ] = (
                fingerprint
                if fingerprint in FINGERPRINTS
                else DEFAULT_FINGERPRINT
            )

        if "alpn" in body:

            link["alpn"] = str(
                body.get(
                    "alpn",
                    "",
                )
            )[:100]

        if "port" in body:

            p = safe_int(
                body.get(
                    "port",
                    DEFAULT_PORT,
                ),
                default=DEFAULT_PORT,
                minimum=MIN_PORT,
                maximum=MAX_PORT,
            )

            link["port"] = p

        if "ip_limit" in body:

            link["ip_limit"] = safe_int(
                body.get(
                    "ip_limit",
                    0,
                ),
                minimum=0,
            )

        if "connection_limit" in body:

            link[
                "connection_limit"
            ] = safe_int(
                body.get(
                    "connection_limit",
                    0,
                ),
                minimum=0,
            )

        if "speed_limit_value" in body:

            speed_value = safe_float(
                body.get(
                    "speed_limit_value",
                    0,
                )
            )

            speed_unit = str(
                body.get(
                    "speed_limit_unit",
                    "MBIT",
                )
                or "MBIT"
            )

            link[
                "speed_limit_bytes"
            ] = (
                0
                if speed_value <= 0
                else parse_speed_to_bytes(
                    speed_value,
                    speed_unit,
                )
            )

        if "protocol" in body:

            protocol = str(
                body.get(
                    "protocol",
                    DEFAULT_PROTOCOL,
                )
            ).strip()

            link["protocol"] = (
                protocol
                if protocol in PROTOCOLS
                else DEFAULT_PROTOCOL
            )

        if "fragment" in body:

            fragment = str(
                body.get(
                    "fragment",
                    "off",
                )
                or "off"
            ).strip().lower()

            if fragment not in {
                "off",
                "safe",
                "balanced",
                "aggressive",
            }:
                fragment = "off"

            link["fragment"] = fragment

        if "sub_id" in body:

            link[
                "sub_id"
            ] = (
                body.get(
                    "sub_id"
                )
                or None
            )

        new_sub = body.get(
            "sub_id",
            "UNCHANGED",
        )

    if new_sub != "UNCHANGED":

        async with SUBS_LOCK:

            if (
                old_sub
                and old_sub in SUBS
            ):

                ids = SUBS[
                    old_sub
                ].get(
                    "link_ids",
                    [],
                )

                if uid in ids:
                    ids.remove(uid)

            if (
                new_sub
                and new_sub in SUBS
            ):

                ids = SUBS[
                    new_sub
                ].setdefault(
                    "link_ids",
                    [],
                )

                if uid not in ids:
                    ids.append(uid)

    await save_state()

    log_activity(
        "link",
        (
            f"کانفیگ "
            f"«{label}» "
            f"ویرایش شد"
        ),
        "info",
    )

    return {
        "ok": True
    }


# ============================================================
# RESET USAGE
# ============================================================

@app.post(
    "/api/links/{uid}/reset-usage"
)
async def reset_link_usage(
    uid: str,
    _=Depends(require_auth),
):

    async with LINKS_LOCK:

        link = LINKS.get(uid)

        if not link:
            raise HTTPException(
                status_code=404,
                detail="link not found",
            )

        link["used_bytes"] = 0

        label = link.get(
            "label",
            uid,
        )

    await save_state()

    log_activity(
        "link",
        (
            f"مصرف کانفیگ "
            f"«{label}» ریست شد"
        ),
        "info",
    )

    return {
        "ok": True,
        "uuid": uid,
        "used_bytes": 0,
    }


# ============================================================
# LINK ACTION
# ============================================================

@app.post(
    "/api/links/{uid}/action"
)
async def link_action(
    uid: str,
    request: Request,
    _=Depends(require_auth),
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="JSON نامعتبر است",
        )

    action = str(
        body.get(
            "action",
            "",
        )
    ).strip().lower()

    if action == "reset":

        await reset_link_usage(
            uid,
            _
        )

        return {
            "ok": True,
            "action": "reset",
        }

    if action == "enable":

        result = await set_link_active(
            uid,
            True,
        )

        if result is None:
            raise HTTPException(
                status_code=404,
                detail="link not found",
            )

        return {
            "ok": True,
            "action": "enable",
        }

    if action == "disable":

        result = await set_link_active(
            uid,
            False,
        )

        if result is None:
            raise HTTPException(
                status_code=404,
                detail="link not found",
            )

        return {
            "ok": True,
            "action": "disable",
        }

    raise HTTPException(
        status_code=400,
        detail="unknown action",
    )


# ============================================================
# DELETE LINK
# ============================================================

@app.delete("/api/links/{uid}")
async def delete_link(
    uid: str,
    _=Depends(require_auth),
):

    label = await remove_link(uid)

    if label is None:
        raise HTTPException(
            status_code=404,
            detail="link not found",
        )

    return {
        "ok": True,
        "deleted": uid,
    }




def subscription_metadata_headers(used_bytes: int, limit_bytes: int, expires_at, host: str, info_url: str, title: str):
    """Standard subscription headers understood by v2rayNG/v2rayN/Hiddify and similar clients."""
    used_bytes = max(0, int(used_bytes or 0))
    limit_bytes = max(0, int(limit_bytes or 0))

    expire_unix = 0
    if expires_at:
        try:
            dt = datetime.fromisoformat(str(expires_at))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=IRAN_TZ) if IRAN_TZ else dt
            expire_unix = max(0, int(dt.timestamp()))
        except Exception:
            expire_unix = 0

    userinfo = f"upload=0; download={used_bytes}; total={limit_bytes}; expire={expire_unix}"

    return {
        "profile-title": quote(title, safe=""),
        "profile-web-page-url": info_url,
        "support-url": SUPPORT_URL,
        "profile-update-interval": "12",
        "subscription-userinfo": userinfo,
        "content-disposition": 'inline; filename="subscription.txt"',
    }

# ============================================================
# SINGLE SUB
# ============================================================

@app.get("/sub/{uuid}")
async def subscription_single(
    uuid: str,
    request: Request,
):

    async with LINKS_LOCK:
        link = LINKS.get(uuid)

    if not is_link_allowed(link):
        raise HTTPException(
            status_code=404,
            detail="not found or inactive",
        )

    host = get_host(request)
    clean_ips = link.get("clean_ips") or []
    used = int(link.get("used_bytes", 0) or 0)
    limit = int(link.get("limit_bytes", 0) or 0)
    remaining = max(0, limit - used) if limit > 0 else 0
    volume_text = f"{fmt_bytes(used)}/{fmt_bytes(limit)} (باقی {fmt_bytes(remaining)})" if limit > 0 else f"{fmt_bytes(used)}/∞"
    expires_at = link.get("expires_at")
    if expires_at:
        try:
            exp_dt = datetime.fromisoformat(str(expires_at))
            now_dt = datetime.now(exp_dt.tzinfo) if getattr(exp_dt, "tzinfo", None) else datetime.now()
            secs = int((exp_dt - now_dt).total_seconds())
            if secs <= 0:
                time_text = "منقضی"
            else:
                days, rem = divmod(secs, 86400)
                hours, rem = divmod(rem, 3600)
                mins = rem // 60
                time_text = f"{days}د {hours}س" if days else (f"{hours}س {mins}د" if hours else f"{mins}د")
        except Exception:
            time_text = str(expires_at)[:16]
    else:
        time_text = "∞"
    label = str(link.get("label") or "Config")
    stats_remark = f"{label} | {volume_text} | {time_text}"
    stats_line = generate_vless_link(uuid, "0.0.0.0", remark=stats_remark, protocol=link.get("protocol", DEFAULT_PROTOCOL), fingerprint=link.get("fingerprint", DEFAULT_FINGERPRINT), alpn=link.get("alpn"), port=link.get("port", DEFAULT_PORT))
    lines = [stats_line]
    used_names = set()
    cfg_count = max(1, min(40, int(link.get("config_count") or 1)))
    if clean_ips:
        hosts = list(clean_ips)
        while len(hosts) < cfg_count:
            hosts.extend(clean_ips)
        hosts = hosts[:cfg_count]
        for cip in hosts:
            name = random_config_name(used_names)
            used_names.add(name)
            lines.append(generate_vless_link(uuid, cip, remark=name, protocol=link.get("protocol", DEFAULT_PROTOCOL), fingerprint=link.get("fingerprint", DEFAULT_FINGERPRINT), alpn=link.get("alpn"), port=link.get("port", DEFAULT_PORT)))
    else:
        for i in range(cfg_count):
            name = random_config_name(used_names)
            used_names.add(name)
            lines.append(generate_vless_link(uuid, host, remark=name, protocol=link.get("protocol", DEFAULT_PROTOCOL), fingerprint=link.get("fingerprint", DEFAULT_FINGERPRINT), alpn=link.get("alpn"), port=link.get("port", DEFAULT_PORT)))
    content = base64.b64encode("\n".join(lines).encode()).decode()
    profile_title = f"0.0.0.0 | {stats_remark}"
    headers = subscription_metadata_headers(
        used,
        limit,
        link.get("expires_at"),
        host,
        f"https://{host}/info/{uuid}",
        profile_title,
    )

    return Response(
        content=content,
        media_type="text/plain; charset=utf-8",
        headers=headers,
    )

# ============================================================
# SUB ALL
# ============================================================

@app.get("/sub-all")
async def subscription_all(
    request: Request,
    _=Depends(require_auth),
):

    host = get_host(request)

    async with LINKS_LOCK:

        lines = [
            vless_link_for_link(
                link,
                uid,
                host,
            )

            for uid, link
            in LINKS.items()

            if is_link_allowed(link)
        ]

    content = (
        base64
        .b64encode(
            "\n".join(
                lines
            ).encode()
        )
        .decode()
    )

    return Response(
        content=content,
        media_type="text/plain",
    )


# ============================================================
# INFO PAGE
# ============================================================

@app.get(
    "/info/{uid}",
    response_class=HTMLResponse,
)
async def info_page(
    uid: str,
    request: Request,
):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link:
            return HTMLResponse("<html lang=\"fa\" dir=\"rtl\"><body style=\"margin:0;background:#07070a;color:#fff;font-family:sans-serif;padding:40px\"><h2>کانفیگ پیدا نشد</h2></body></html>", status_code=404)
        snapshot = dict(link)

    host = get_host(request)
    vless_url = vless_link_for_link(snapshot, uid, host)
    sub_url = f"https://{host}/sub/{uid}"
    used = int(snapshot.get("used_bytes", 0) or 0)
    limit = int(snapshot.get("limit_bytes", 0) or 0)
    if limit > 0:
        usage_percent = max(0, min(100, round((used / limit) * 100, 1)))
        usage_value = f"{fmt_bytes(used)} / {fmt_bytes(limit)}"
        remaining_value = fmt_bytes(max(0, limit - used))
    else:
        usage_percent = 0
        usage_value = f"{fmt_bytes(used)} / نامحدود"
        remaining_value = "نامحدود"

    expires_at = snapshot.get("expires_at")
    if expires_at:
        try:
            expiry_dt = datetime.fromisoformat(str(expires_at))
            now_dt = datetime.now(expiry_dt.tzinfo) if expiry_dt.tzinfo else datetime.now()
            seconds = int((expiry_dt - now_dt).total_seconds())
            if seconds <= 0:
                expiry_remaining = "منقضی شده"
            else:
                days, rem = divmod(seconds, 86400)
                hours, rem = divmod(rem, 3600)
                minutes, _ = divmod(rem, 60)
                expiry_remaining = f"{days} روز و {hours} ساعت" if days else (f"{hours} ساعت و {minutes} دقیقه" if hours else f"{minutes} دقیقه")
        except Exception:
            expiry_remaining = "نامشخص"
        expiry_display = str(expires_at)
    else:
        expiry_remaining = "نامحدود"
        expiry_display = "نامحدود"

    status_text = "فعال" if is_link_allowed(snapshot) else "غیرفعال"
    status_class = "good" if status_text == "فعال" else "bad"
    ip_limit = "نامحدود" if not snapshot.get("ip_limit", 0) else str(snapshot.get("ip_limit"))
    connection_limit = "نامحدود" if not snapshot.get("connection_limit", 0) else str(snapshot.get("connection_limit"))
    speed_limit = "نامحدود" if not snapshot.get("speed_limit_bytes", 0) else fmt_bytes(snapshot.get("speed_limit_bytes", 0)) + "/s"

    usage_history = snapshot.get("usage_history", [])
    svg_points = "0,50 300,50"
    if usage_history and len(usage_history) > 1:
        max_hist = max(usage_history) if max(usage_history) > 0 else 1
        pts = []
        step = 300 / (len(usage_history) - 1)
        for i, val in enumerate(usage_history):
            x = i * step
            y = 60 - min(60, max(4, (val / max_hist) * 52))
            pts.append(f"{x:.1f},{y:.1f}")
        svg_points = " ".join(pts)
    elif usage_history and len(usage_history) == 1:
        svg_points = f"0,50 300,{60 - min(60, max(4, (usage_history[0] / (limit if limit > 0 else max(used, 1))) * 52)):.1f}"

    status_badge_html = 'text-emerald-300 border border-emerald-400/25 bg-emerald-400/10' if status_class == 'good' else 'text-rose-300 border border-rose-400/25 bg-rose-400/10'
    label_escaped = escape_html(snapshot.get("label", "PXpanel"))
    uid_escaped = escape_html(uid)
    app_version_str = escape_html(str(APP_VERSION))
    used_bytes_str = escape_html(fmt_bytes(used))
    limit_bytes_str = escape_html(fmt_bytes(limit)) if limit > 0 else '∞'
    remaining_value_escaped = escape_html(remaining_value)
    expiry_remaining_escaped = escape_html(expiry_remaining)
    expiry_display_escaped = escape_html(expiry_display)
    ip_limit_escaped = escape_html(ip_limit)
    connection_limit_escaped = escape_html(connection_limit)
    speed_limit_escaped = escape_html(speed_limit)
    protocol_escaped = escape_html(snapshot.get("protocol", "vless-ws"))
    fingerprint_escaped = escape_html(snapshot.get("fingerprint", "chrome"))
    vless_url_escaped = escape_html(vless_url)
    sub_url_escaped = escape_html(sub_url)
    dash_calc_offset = f"{339.29 - (339.29 * min(usage_percent, 100) / 100):.1f}"

    info_html = f"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>{label_escaped} | INFO</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.min.js"></script>
<script>
  tailwind.config = {{
    theme: {{
      extend: {{
        fontFamily: {{ vazir: ['Vazirmatn','system-ui','sans-serif'] }}
      }}
    }}
  }}
</script>
<style>
  :root {{
    --bg-main: #05060a;
    --bg-card: rgba(255, 255, 255, 0.04);
    --bg-card-hover: rgba(255, 255, 255, 0.07);
    --border-color: rgba(255, 255, 255, 0.1);
    --text-main: #f1f5f9;
    --text-muted: rgba(255, 255, 255, 0.4);
    --bg-sub-card: rgba(0, 0, 0, 0.2);
    --grad-1: rgba(96,165,250,.16);
    --grad-2: rgba(96,165,250,.13);
    --grad-3: rgba(52,211,153,.08);
  }}

  body.theme-lighter {{
    --bg-main: #131722;
    --bg-card: rgba(255, 255, 255, 0.075);
    --bg-card-hover: rgba(255, 255, 255, 0.115);
    --border-color: rgba(255, 255, 255, 0.16);
    --text-main: #ffffff;
    --text-muted: rgba(255, 255, 255, 0.6);
    --bg-sub-card: rgba(0, 0, 0, 0.35);
    --grad-1: rgba(96,165,250,.24);
    --grad-2: rgba(96,165,250,.20);
    --grad-3: rgba(52,211,153,.13);
  }}

  html,body{{background:var(--bg-main); transition: background 0.3s ease, color 0.3s ease;}}
  body{{
    background:
      radial-gradient(ellipse 80% 50% at 10% -10%, var(--grad-1), transparent 50%),
      radial-gradient(ellipse 60% 40% at 95% 15%, var(--grad-2), transparent 45%),
      radial-gradient(ellipse 55% 35% at 60% 100%, var(--grad-3), transparent 40%),
      var(--bg-main);
  }}
  .status-dot{{box-shadow:0 0 10px currentColor}}
  ::-webkit-scrollbar{{width:8px;height:8px}}
  ::-webkit-scrollbar-thumb{{background:rgba(255,255,255,.12);border-radius:99px}}
  * {{ box-shadow: none !important; }}
  .copy-btn svg{{transition:none}}
  
  .dynamic-card {{
    background-color: var(--bg-card);
    border-color: var(--border-color);
    transition: background-color 0.3s ease, border-color 0.3s ease;
  }}
  .dynamic-card:hover {{
    background-color: var(--bg-card-hover);
  }}
  .sub-box {{
    background-color: var(--bg-sub-card);
  }}
</style>
</head>
<body class="font-vazir text-slate-100 antialiased min-h-screen py-8 px-3 sm:px-4 md:py-14">

<div class="w-full max-w-4xl mx-auto space-y-5 sm:space-y-6 md:space-y-8">

  <!-- Top Bar Theme Toggle Button -->
  <div class="flex justify-end">
    <button type="button" onclick="toggleTheme()" class="inline-flex items-center gap-1.5 px-4 py-2 rounded-full text-xs font-extrabold text-amber-300 border border-amber-400/30 bg-amber-400/10 hover:bg-amber-400/20 transition-colors shadow-lg">
      <svg id="themeIcon" xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/></svg>
      تغییر تم
    </button>
  </div>

  <!-- Hero -->
  <section class="rounded-[26px] sm:rounded-[28px] border dynamic-card backdrop-blur-2xl p-5 sm:p-6 md:p-8">
    <div class="flex flex-col md:flex-row md:items-center md:justify-between gap-5">
      <div class="flex items-center gap-4">
        <div class="w-13 h-13 sm:w-14 sm:h-14 shrink-0 rounded-2xl grid place-items-center bg-gradient-to-br from-blue-400/20 to-purple-400/10 border border-blue-400/25 text-blue-300">
          <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l8 4v6c0 5.2-3.4 9-8 10-4.6-1-8-4.8-8-10V6l8-4z"/><path d="M9.5 12l1.8 1.8L15 10"/></svg>
        </div>
        <div class="min-w-0">
          <h1 class="text-lg sm:text-xl md:text-2xl font-black tracking-tight truncate">{label_escaped}</h1>
          <p class="mt-1.5 text-[10.5px] sm:text-[11px] text-white/40 break-all">UUID: {uid_escaped} &nbsp;·&nbsp; PXpanel {app_version_str}</p>
        </div>
      </div>
      <div class="flex items-center gap-2.5 self-start md:self-auto flex-wrap">
        <button type="button" onclick="openQrModal()" class="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-full text-xs font-extrabold text-purple-300 border border-purple-400/30 bg-purple-400/10 hover:bg-purple-400/20 transition-colors">
          <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
          QR Code
        </button>
        <div class="inline-flex items-center gap-2 px-4 py-2 rounded-full text-xs font-extrabold {status_badge_html}">
          <span class="status-dot w-2 h-2 rounded-full bg-current"></span>
          {status_text}
        </div>
      </div>
    </div>
  </section>

  <!-- Usage overview -->
  <section class="grid grid-cols-1 lg:grid-cols-[1.6fr_1fr] gap-5 sm:gap-6">

    <div class="rounded-[22px] border dynamic-card backdrop-blur-2xl p-5 sm:p-6 md:p-7">
      <div class="flex items-center gap-2.5">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" class="text-white/35"><path d="M3 3v18h18"/><path d="M7 15l4-6 3 3 4-7"/></svg>
        <div>
          <p class="text-[10px] font-extrabold tracking-widest uppercase text-white/30">Traffic Overview</p>
          <p class="mt-0.5 text-sm font-black">مصرف سرویس</p>
        </div>
      </div>

      <div class="mt-6 flex flex-col sm:flex-row items-center sm:items-start gap-6">
        <div class="relative shrink-0 w-[128px] h-[128px]">
          <svg width="128" height="128" viewBox="0 0 132 132" class="-rotate-90">
            <circle cx="66" cy="66" r="54" fill="none" stroke="rgba(255,255,255,0.07)" stroke-width="10"/>
            <circle cx="66" cy="66" r="54" fill="none" stroke="url(#usageRingGradient)" stroke-width="10" stroke-linecap="round"
              stroke-dasharray="339.29" stroke-dashoffset="{dash_calc_offset}"/>
            <defs>
              <linearGradient id="usageRingGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stop-color="#34d399"/>
                <stop offset="100%" stop-color="#f59e0b"/>
              </linearGradient>
            </defs>
          </svg>
          <div class="absolute inset-0 grid place-items-center">
            <div class="text-center">
              <p class="text-xl font-black leading-none">{usage_percent}%</p>
              <p class="mt-1.5 text-[10px] text-white/40">مصرف‌شده</p>
            </div>
          </div>
        </div>

        <div class="flex-1 w-full min-w-0">
          <div class="text-xl sm:text-2xl font-black tracking-tight">
            {used_bytes_str}
            <span class="text-sm font-semibold text-white/40"> / {limit_bytes_str}</span>
          </div>

          <div class="mt-4 rounded-xl border border-white/[0.05] sub-box px-3 pt-3 pb-1.5">
            <p class="flex items-center gap-1.5 text-[10px] text-white/35 mb-1">
              <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M3 17l6-6 4 4 8-8"/><path d="M17 7h4v4"/></svg>
              روند مصرف
            </p>
            <svg viewBox="0 0 300 64" class="w-full h-14" preserveAspectRatio="none">
              <defs>
                <linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stop-color="#60a5fa" stop-opacity="0.35"/>
                  <stop offset="100%" stop-color="#60a5fa" stop-opacity="0"/>
                </linearGradient>
              </defs>
              <path d="M0,64 L{svg_points} L300,64 Z" fill="url(#trendFill)"/>
              <path d="M{svg_points}" fill="none" stroke="#60a5fa" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
          </div>

          <div class="mt-4 flex items-center justify-between text-[11px] text-white/40 flex-wrap gap-2">
            <span class="inline-flex items-center gap-1.5">
              <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/></svg>
              باقی‌مانده: <b class="text-white/70 font-bold">{remaining_value_escaped}</b>
            </span>
            <span class="inline-flex items-center gap-1.5">
              <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="17" rx="2"/><path d="M3 9h18M8 3v3M16 3v3"/></svg>
              زمان: <b class="text-white/70 font-bold">{expiry_remaining_escaped}</b>
            </span>

          </div>
        </div>
      </div>
    </div>

    <div class="rounded-[22px] border dynamic-card backdrop-blur-2xl p-5 sm:p-6 md:p-7">
      <div class="flex items-center gap-2.5">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" class="text-white/35"><circle cx="12" cy="12" r="9"/><path d="M12 8v4l3 2"/></svg>
        <p class="text-[10px] font-extrabold tracking-widest uppercase text-white/30">Service</p>
      </div>
      <div class="mt-4 divide-y divide-white/[0.06]">
        <div class="flex items-center justify-between py-3 first:pt-0">
          <span class="inline-flex items-center gap-2 text-[11px] text-white/45">
            <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="17" rx="2"/><path d="M3 9h18M8 3v3M16 3v3"/></svg>
            انقضا
          </span>
          <span class="text-xs font-extrabold">{expiry_display_escaped}</span>
        </div>
        <div class="flex items-center justify-between py-3">
          <span class="inline-flex items-center gap-2 text-[11px] text-white/45">
            <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.55a11 11 0 0 1 14 0"/><path d="M8.5 16a6 6 0 0 1 7 0"/><path d="M12 20h.01"/></svg>
            IP Limit
          </span>
          <span class="text-xs font-extrabold">{ip_limit_escaped}</span>
        </div>
        <div class="flex items-center justify-between py-3">
          <span class="inline-flex items-center gap-2 text-[11px] text-white/45">
            <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 9V7a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v2"/><rect x="2" y="9" width="20" height="8" rx="2"/><path d="M6 17v2M18 17v2"/></svg>
            Connection
          </span>
          <span class="text-xs font-extrabold">{connection_limit_escaped}</span>
        </div>
        <div class="flex items-center justify-between py-3 last:pb-0">
          <span class="inline-flex items-center gap-2 text-[11px] text-white/45">
            <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2L3 14h7l-1 8 10-12h-7l1-8z"/></svg>
            Speed
          </span>
          <span class="text-xs font-extrabold">{speed_limit_escaped}</span>
        </div>
      </div>
    </div>

  </section>

  <!-- Stats -->
  <section class="grid grid-cols-2 md:grid-cols-4 gap-3.5 sm:gap-4 md:gap-5">

    <div class="rounded-2xl border dynamic-card backdrop-blur-xl p-4 sm:p-5 hover:border-emerald-400/20 transition-colors duration-200">
      <div class="w-9 h-9 rounded-xl grid place-items-center bg-emerald-400/10 border border-emerald-400/20 text-emerald-300">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3v18h18"/><path d="M18 9l-5 5-3-3-4 4"/></svg>
      </div>
      <p class="mt-4 text-[11px] text-white/45">مصرف فعلی</p>
      <p class="mt-1 text-[14px] sm:text-[15px] font-black text-emerald-300 break-words">{used_bytes_str}</p>
    </div>

    <div class="rounded-2xl border dynamic-card backdrop-blur-xl p-4 sm:p-5 hover:border-amber-400/20 transition-colors duration-200">
      <div class="w-9 h-9 rounded-xl grid place-items-center bg-amber-400/10 border border-amber-400/20 text-amber-300">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/></svg>
      </div>
      <p class="mt-4 text-[11px] text-white/45">باقی‌مانده</p>
      <p class="mt-1 text-[14px] sm:text-[15px] font-black text-amber-300 break-words">{remaining_value_escaped}</p>
    </div>

    <div class="rounded-2xl border dynamic-card backdrop-blur-xl p-4 sm:p-5 hover:border-blue-400/20 transition-colors duration-200">
      <div class="w-9 h-9 rounded-xl grid place-items-center bg-blue-400/10 border border-blue-400/20 text-blue-300">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="3"/><path d="M9 4v16M4 9h16"/></svg>
      </div>
      <p class="mt-4 text-[11px] text-white/45">اتصالات فعال</p>
      <p class="mt-1 text-[14px] sm:text-[15px] font-black text-blue-300 break-words">{len(unique_ips_for_uuid(uid))}</p>
    </div>

    <div class="rounded-2xl border dynamic-card backdrop-blur-xl p-4 sm:p-5 hover:border-purple-400/20 transition-colors duration-200">
      <div class="w-9 h-9 rounded-xl grid place-items-center bg-purple-400/10 border border-purple-400/20 text-purple-300">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l9 4.5v6c0 5-3.6 8.7-9 9.5-5.4-.8-9-4.5-9-9.5v-6L12 2z"/></svg>
      </div>
      <p class="mt-4 text-[11px] text-white/45">زمان باقی‌مانده</p>
      <p class="mt-1 text-[14px] sm:text-[15px] font-black text-purple-300 break-words">{expiry_remaining_escaped}</p>
    </div>

  </section>

  <!-- Technical details -->
  <section class="rounded-[22px] border dynamic-card backdrop-blur-2xl p-5 sm:p-6 md:p-7">
    <div class="flex items-center justify-between gap-3 mb-5">
      <p class="flex items-center gap-2 text-sm font-black">
        <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" class="text-white/40"><path d="M4 21v-7M4 10V3M12 21v-11M12 6V3M20 21v-5M20 12V3"/><path d="M1 14h6M9 8h6M17 16h6"/></svg>
        جزئیات فنی
      </p>
      <p class="text-[11px] text-white/40">Configuration Details</p>
    </div>
    <div class="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
      <div class="rounded-2xl border border-white/[0.06] sub-box p-4">
        <p class="text-[11px] text-white/45">Protocol</p>
        <p class="mt-2 text-[11px] font-medium text-purple-300 tracking-wide" dir="ltr" style="font-family:ui-monospace,Consolas,monospace">{protocol_escaped}</p>
      </div>
      <div class="rounded-2xl border border-white/[0.06] sub-box p-4">
        <p class="text-[11px] text-white/45">Fingerprint</p>
        <p class="mt-2 text-[11px] font-medium text-purple-300 tracking-wide" dir="ltr" style="font-family:ui-monospace,Consolas,monospace">{fingerprint_escaped}</p>
      </div>
      <div class="rounded-2xl border border-white/[0.06] sub-box p-4">
        <p class="text-[11px] text-white/45">IP Limit</p>
        <p class="mt-2 text-xs font-bold text-white/85">{ip_limit_escaped}</p>
      </div>
      <div class="rounded-2xl border border-white/[0.06] sub-box p-4">
        <p class="text-[11px] text-white/45">Connection Limit</p>
        <p class="mt-2 text-xs font-bold text-white/85">{connection_limit_escaped}</p>
      </div>
      <div class="rounded-2xl border border-white/[0.06] sub-box p-4">
        <p class="text-[11px] text-white/45">Speed Limit</p>
        <p class="mt-2 text-xs font-bold text-white/85">{speed_limit_escaped}</p>
      </div>
      <div class="rounded-2xl border border-white/[0.06] sub-box p-4">
        <p class="text-[11px] text-white/45">تاریخ انقضا</p>
        <p class="mt-2 text-xs font-bold text-white/85">{expiry_display_escaped}</p>
      </div>
    </div>
  </section>

  <!-- Links -->
  <section class="rounded-[22px] border dynamic-card backdrop-blur-2xl p-5 sm:p-6 md:p-7">
    <div class="flex items-center justify-between gap-3 mb-5">
      <p class="flex items-center gap-2 text-sm font-black">
        <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" class="text-white/40"><path d="M10 13a5 5 0 0 0 7.07 0l2.83-2.83a5 5 0 0 0-7.07-7.07L11.5 4.5"/><path d="M14 11a5 5 0 0 0-7.07 0l-2.83 2.83a5 5 0 0 0 7.07 7.07l1.41-1.41"/></svg>
        لینک‌های سرویس
      </p>
      <p class="text-[11px] text-white/40">Copy / Import</p>
    </div>

    <div class="space-y-3">
      <div class="flex flex-col sm:flex-row sm:items-center gap-3 sm:gap-4 rounded-2xl border border-white/[0.06] sub-box p-4 hover:border-purple-400/25 transition-colors duration-200">
        <div class="min-w-0 flex-1">
          <p class="text-[11px] font-extrabold text-white/45 tracking-wide">VLESS</p>
          <p id="vlessLinkText" class="mt-1.5 text-[11px] text-purple-300 break-all leading-6" dir="ltr" style="font-family:ui-monospace,Consolas,monospace">{vless_url_escaped}</p>
        </div>
        <button id="vlessCopyBtn" type="button" onclick="pxCopy('vlessLinkText','vlessCopyBtn')"
          class="copy-btn shrink-0 self-start sm:self-center inline-flex items-center gap-1.5 text-[11px] font-bold text-white/60 px-3.5 py-2 rounded-xl bg-white/[0.05] border border-white/10 hover:bg-white/[0.1] hover:text-white transition-colors duration-200">
          <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>
          <span>کپی</span>
        </button>
      </div>

      <div class="flex flex-col sm:flex-row sm:items-center gap-3 sm:gap-4 rounded-2xl border border-white/[0.06] sub-box p-4 hover:border-purple-400/25 transition-colors duration-200">
        <div class="min-w-0 flex-1">
          <p class="text-[11px] font-extrabold text-white/45 tracking-wide">SUBSCRIPTION</p>
          <p id="subLinkText" class="mt-1.5 text-[11px] text-purple-300 break-all leading-6" dir="ltr" style="font-family:ui-monospace,Consolas,monospace">{sub_url_escaped}</p>
        </div>
        <button id="subCopyBtn" type="button" onclick="pxCopy('subLinkText','subCopyBtn')"
          class="copy-btn shrink-0 self-start sm:self-center inline-flex items-center gap-1.5 text-[11px] font-bold text-white/60 px-3.5 py-2 rounded-xl bg-white/[0.05] border border-white/10 hover:bg-white/[0.1] hover:text-white transition-colors duration-200">
          <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>
          <span>کپی</span>
        </button>
      </div>
    </div>
  </section>

  <!-- Downloads -->
  <section class="rounded-[22px] border dynamic-card backdrop-blur-2xl p-5 sm:p-6 md:p-7">
    <div class="flex items-center justify-between gap-3 mb-5">
      <p class="flex items-center gap-2 text-sm font-black">
        <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" class="text-white/40"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5 5 5-5"/><path d="M12 15V3"/></svg>
        دانلود برنامه‌ها
      </p>
      <p class="text-[11px] text-white/40">Official Releases</p>
    </div>

    <div class="grid grid-cols-1 sm:grid-cols-3 gap-3.5">
      <a href="https://github.com/2dust/v2rayNG/releases/latest" target="_blank" rel="noopener noreferrer"
         class="flex items-center gap-3 rounded-2xl border border-white/10 sub-box p-4 hover:border-blue-400/25 transition-colors duration-200">
        <div class="w-10 h-10 shrink-0 rounded-xl grid place-items-center bg-blue-400/10 border border-blue-400/20 text-blue-300 font-black text-[11px]">NG</div>
        <div class="min-w-0">
          <p class="text-xs font-extrabold">v2rayNG</p>
          <p class="mt-0.5 text-[10px] text-white/40">Android</p>
        </div>
      </a>
      <a href="https://github.com/2dust/v2rayN/releases/latest" target="_blank" rel="noopener noreferrer"
         class="flex items-center gap-3 rounded-2xl border border-white/10 sub-box p-4 hover:border-blue-400/25 transition-colors duration-200">
        <div class="w-10 h-10 shrink-0 rounded-xl grid place-items-center bg-blue-400/10 border border-blue-400/20 text-blue-300 font-black text-[11px]">N</div>
        <div class="min-w-0">
          <p class="text-xs font-extrabold">v2rayN</p>
          <p class="mt-0.5 text-[10px] text-white/40">Windows / macOS / Linux</p>
        </div>
      </a>
      <a href="https://github.com/hiddify/hiddify-app/releases/latest" target="_blank" rel="noopener noreferrer"
         class="flex items-center gap-3 rounded-2xl border border-white/10 sub-box p-4 hover:border-blue-400/25 transition-colors duration-200">
        <div class="w-10 h-10 shrink-0 rounded-xl grid place-items-center bg-blue-400/10 border border-blue-400/20 text-blue-300 font-black text-[11px]">H</div>
        <div class="min-w-0">
          <p class="text-xs font-extrabold">Hiddify</p>
          <p class="mt-0.5 text-[10px] text-white/40">Android / Windows / macOS / Linux</p>
        </div>
      </a>
    </div>
  </section>

  <!-- Footer -->
  <div class="rounded-2xl border border-emerald-400/15 bg-emerald-400/[0.05] p-4 text-center text-xs text-white/45">
    پشتیبانی و اطلاعیه‌ها &nbsp;·&nbsp; <b class="text-emerald-300">کانال تلگرام: logic_sec</b>
  </div>

</div>

<!-- QR Code Modal Popup -->
<div id="qrModal" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md hidden">
  <div class="w-full max-w-sm rounded-[24px] border border-white/15 bg-[#0b0c14] p-6 text-center shadow-2xl relative">
    <button type="button" onclick="closeQrModal()" class="absolute top-4 left-4 w-8 h-8 rounded-full bg-white/5 border border-white/10 grid place-items-center text-white/60 hover:text-white">✕</button>
    <p class="text-sm font-black text-white/90 mb-2">QR Code اسکن کانفیگ</p>
    <p class="text-[11px] text-white/40 mb-4">برای اتصال سریع با گوشی موبایل</p>
    <div id="qrcodeContainer" class="bg-white p-4 rounded-2xl inline-block mx-auto mb-4 border border-white/10"></div>
    <p id="qrModalText" class="text-[10px] text-purple-300 break-all max-h-16 overflow-y-auto px-2" dir="ltr"></p>
  </div>
</div>

<script>
const vlessUrlData = "{vless_url}";

// Theme toggle logic with localStorage support (2 themes total)
function toggleTheme() {{
  const body = document.body;
  body.classList.toggle('theme-lighter');
  const isLighter = body.classList.contains('theme-lighter');
  localStorage.setItem('px_theme', isLighter ? 'lighter' : 'dark');
}}

// Initialize saved theme on load
(function() {{
  if (localStorage.getItem('px_theme') === 'lighter') {{
    document.body.classList.add('theme-lighter');
  }}
}})();

function openQrModal() {{
  var modal = document.getElementById('qrModal');
  var container = document.getElementById('qrcodeContainer');
  var txtEl = document.getElementById('qrModalText');
  container.innerHTML = "";
  txtEl.textContent = vlessUrlData;
  modal.classList.remove('hidden');
  try {{
    var typeNumber = 0;
    var errorCorrectionLevel = 'L';
    var qr = qrcode(typeNumber, errorCorrectionLevel);
    qr.addData(vlessUrlData);
    qr.make();
    container.innerHTML = qr.createImgTag(5, 8);
  }} catch (e) {{
    container.innerHTML = "<p class='text-xs text-black'>خطا در تولید QR Code</p>";
  }}
}}

function closeQrModal() {{
  document.getElementById('qrModal').classList.add('hidden');
}}

document.getElementById('qrModal').addEventListener('click', function(e) {{
  if (e.target === this) closeQrModal();
}});

function pxCopy(textId, btnId) {{
  var el = document.getElementById(textId);
  var btn = document.getElementById(btnId);
  if (!el || !btn) return;
  var text = el.textContent.textContext || el.textContent.trim();
  var done = function() {{
    var original = btn.getAttribute('data-original');
    if (!original) {{
      original = btn.innerHTML;
      btn.setAttribute('data-original', original);
    }}
    btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg><span>کپی شد</span>';
    btn.classList.add('text-emerald-300','border-emerald-400/30','bg-emerald-400/10');
    setTimeout(function() {{
      btn.innerHTML = original;
      btn.classList.remove('text-emerald-300','border-emerald-400/30','bg-emerald-400/10');
    }}, 1700);
  }};
  if (navigator.clipboard && navigator.clipboard.writeText) {{
    navigator.clipboard.writeText(text).then(done).catch(function() {{ fallbackCopy(text, done); }});
  }} else {{
    fallbackCopy(text, done);
  }}
}}
function fallbackCopy(text, cb) {{
  var ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  try {{ document.execCommand('copy'); }} catch (e) {{}}
  document.body.removeChild(ta);
  if (cb) cb();
}}
</script>
</body>
</html>"""
    return HTMLResponse(info_html)
# ============================================================
# SUB GROUP API
# ============================================================

@app.post("/api/subs")
async def create_sub_api(
    request: Request,
    _=Depends(require_auth),
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="JSON نامعتبر است",
        )

    sub_id, sub = await create_sub_group(
        name=body.get(
            "name",
            "گروه جدید",
        ),
        desc=body.get(
            "desc",
            "",
        ),
        password=body.get(
            "password",
            "",
        ),
    )

    host = get_host(request)

    return {
        "sub_id":
            sub_id,

        **sub,

        "password_hash":
            None,

        "public_url":
            (
                f"https://{host}"
                f"/p/{sub['uuid_key']}"
            ),

        "sub_url":
            (
                f"https://{host}"
                f"/sub-group/{sub['uuid_key']}"
            ),
    }


@app.get("/api/subs")
async def list_subs_api(
    request: Request,
    _=Depends(require_auth),
):

    host = get_host(request)

    async with SUBS_LOCK:
        snapshot_subs = dict(SUBS)

    async with LINKS_LOCK:
        snapshot_links = dict(LINKS)

    result = []

    for sid, sub in snapshot_subs.items():

        link_ids = sub.get(
            "link_ids",
            [],
        )

        active_count = sum(
            1
            for lid in link_ids
            if is_link_allowed(
                snapshot_links.get(
                    lid
                )
            )
        )

        total_used = sum(
            snapshot_links[
                lid
            ].get(
                "used_bytes",
                0,
            )

            for lid in link_ids

            if lid in snapshot_links
        )

        result.append(
            {
                "sub_id":
                    sid,

                **sub,

                "password_hash":
                    None,

                "has_password":
                    sub.get(
                        "password_hash"
                    ) is not None,

                "links_count":
                    len(link_ids),

                "active_count":
                    active_count,

                "total_used_bytes":
                    total_used,

                "total_used_fmt":
                    fmt_bytes(
                        total_used
                    ),

                "public_url":
                    (
                        f"https://{host}"
                        f"/p/{sub['uuid_key']}"
                    ),

                "sub_url":
                    (
                        f"https://{host}"
                        f"/sub-group/{sub['uuid_key']}"
                    ),
            }
        )

    result.sort(
        key=lambda item:
            item.get(
                "created_at",
                "",
            ),
        reverse=True,
    )

    return {
        "subs": result
    }


@app.patch("/api/subs/{sub_id}")
async def update_sub_api(
    sub_id: str,
    request: Request,
    _=Depends(require_auth),
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="JSON نامعتبر است",
        )

    async with SUBS_LOCK:

        if sub_id not in SUBS:
            raise HTTPException(
                status_code=404,
                detail="sub not found",
            )

        sub = SUBS[sub_id]

        if "name" in body:
            sub["name"] = str(
                body["name"]
            )[:60]

        if "desc" in body:
            sub["desc"] = str(
                body["desc"]
            )[:200]

        if "password" in body:

            password = str(
                body.get(
                    "password",
                    "",
                )
            ).strip()

            sub["password_hash"] = (
                hash_password(password)
                if password
                else None
            )

        if "link_ids" in body:

            sub["link_ids"] = list(
                body["link_ids"]
            )

    await save_state()

    return {
        "ok": True
    }


@app.delete("/api/subs/{sub_id}")
async def delete_sub_api(
    sub_id: str,
    _=Depends(require_auth),
):

    name = await remove_sub_group(
        sub_id
    )

    if name is None:
        raise HTTPException(
            status_code=404,
            detail="sub not found",
        )

    return {
        "ok": True,
        "deleted": sub_id,
    }


@app.post("/api/subs/{sub_id}/links")
async def assign_link_to_sub(
    sub_id: str,
    request: Request,
    _=Depends(require_auth),
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="JSON نامعتبر است",
        )

    link_id = str(
        body.get(
            "link_id",
            "",
        )
    )

    action = str(
        body.get(
            "action",
            "add",
        )
    )

    if action == "add":

        success = await set_link_sub(
            link_id,
            sub_id,
        )

    else:

        success = await set_link_sub(
            link_id,
            None,
        )

    if not success:
        raise HTTPException(
            status_code=404,
            detail="link or sub not found",
        )

    return {
        "ok": True
    }


# ============================================================
# GROUP SUB
# ============================================================

@app.get("/sub-group/{uuid_key}")
async def sub_group_subscription(
    uuid_key: str,
    request: Request,
):

    async with SUBS_LOCK:

        sub = next(
            (
                item
                for item
                in SUBS.values()
                if item.get(
                    "uuid_key"
                ) == uuid_key
            ),
            None,
        )

    if not sub:
        raise HTTPException(
            status_code=404,
            detail="not found",
        )

    if sub.get(
        "password_hash"
    ):

        password = (
            request.query_params.get(
                "pw",
                "",
            )
        )

        if (
            hash_password(password)
            != sub["password_hash"]
        ):

            raise HTTPException(
                status_code=403,
                detail="wrong password",
            )

    host = get_host(request)

    async with LINKS_LOCK:

        lines = []

        for link_id in sub.get(
            "link_ids",
            [],
        ):

            link = LINKS.get(
                link_id
            )

            if (
                link
                and is_link_allowed(
                    link
                )
            ):

                lines.append(
                    vless_link_for_link(
                        link,
                        link_id,
                        host,
                    )
                )

    content = (
        base64
        .b64encode(
            "\n".join(
                lines
            ).encode()
        )
        .decode()
    )

    total_used = 0
    total_limit = 0
    expiries = []
    valid_ids = list(sub.get("link_ids", []))

    async with LINKS_LOCK:
        for link_id in valid_ids:
            link = LINKS.get(link_id)
            if not link or not is_link_allowed(link):
                continue
            total_used += int(link.get("used_bytes", 0) or 0)
            total_limit += int(link.get("limit_bytes", 0) or 0)
            if link.get("expires_at"):
                expiries.append(str(link.get("expires_at")))

    # For a group subscription, expose aggregate usage/expiry in standard headers.
    group_limit = total_limit if total_limit > 0 else 0
    group_expiry = None
    if expiries:
        try:
            group_expiry = min(
                expiries,
                key=lambda x: datetime.fromisoformat(x)
            )
        except Exception:
            group_expiry = expiries[0]

    group_volume_text = (
        f"{fmt_bytes(total_used)}/{fmt_bytes(group_limit)}"
        if group_limit > 0
        else f"{fmt_bytes(total_used)}/∞"
    )
    group_expiry_text = group_expiry or "∞"
    group_title = (
        f"0.0.0.0 | {group_volume_text} | {group_expiry_text} | "
        f"{sub['name']} | کانال تلگرام: logic_sec"
    )
    headers = subscription_metadata_headers(
        total_used,
        group_limit,
        group_expiry,
        host,
        f"https://{host}/public-sub/{uuid_key}",
        group_title,
    )

    return Response(
        content=content,
        media_type="text/plain; charset=utf-8",
        headers=headers,
    )


# ============================================================
# PUBLIC GROUP
# ============================================================

PUBLIC_SUB_HTML = r"""
<!DOCTYPE html>
<html lang="fa" dir="rtl">

<head>
<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1"
>

<title>
PX Panel
</title>

<style>

*{
    box-sizing:border-box;
}

body{
    margin:0;
    min-height:100vh;

    display:flex;
    justify-content:center;
    align-items:center;

    padding:20px;

    font-family:Arial,sans-serif;

    color:#fff;

    background:
        radial-gradient(
            circle at top right,
            rgba(37,99,235,.17),
            transparent 30%
        ),
        #07070a;
}

.card{
    width:100%;
    max-width:560px;

    padding:28px;
    border-radius:25px;

    background:rgba(255,255,255,.045);

    border:
        1px solid
        rgba(255,255,255,.08);

    backdrop-filter:blur(25px);
}

h1{
    margin-top:0;
}

.text{
    color:rgba(255,255,255,.55);
    line-height:2;
    font-size:13px;
}

.url{
    margin-top:20px;
    padding:14px;

    border-radius:13px;

    background:rgba(0,0,0,.22);

    color:#93c5fd;

    direction:ltr;
    word-break:break-all;

    font-family:Consolas,monospace;
}

.support{
    display:inline-block;
    margin-top:18px;

    color:#60a5fa;
    text-decoration:none;
}

.version{
    color:#60a5fa;
    font-size:11px;
}

</style>
</head>

<body>

<div class="card">

<h1>
PX Panel
</h1>

<div class="version">
13.8.0
</div>

<div class="text">
اشتراک شما آماده است.
</div>

<div
class="url"
id="subUrl"
></div>

<a
class="support"
href="https://t.me/Pixonal"
target="_blank"
rel="noopener"
>
پشتیبانی @Pixonal
</a>

</div>

<script>

const url =
    location.origin +
    location.pathname.replace(
        "/p/",
        "/sub-group/"
    );

document.getElementById(
    "subUrl"
).textContent = url;

</script>

</body>
</html>
"""


@app.get(
    "/p/{uuid_key}",
    response_class=HTMLResponse,
)
async def public_sub_page(
    uuid_key: str,
):

    async with SUBS_LOCK:

        exists = any(
            item.get(
                "uuid_key"
            ) == uuid_key
            for item in SUBS.values()
        )

    if not exists:

        return HTMLResponse(
            """
            <h2
            style="
            font-family:sans-serif;
            padding:40px;
            "
            >
            گروه پیدا نشد
            </h2>
            """,
            status_code=404,
        )

    return HTMLResponse(
        PUBLIC_SUB_HTML
    )


@app.get("/api/public/sub/{uuid_key}")
async def public_sub_data(
    uuid_key: str,
    request: Request,
):

    async with SUBS_LOCK:

        entry = next(
            (
                (
                    sid,
                    item,
                )

                for sid, item
                in SUBS.items()

                if item.get(
                    "uuid_key"
                ) == uuid_key
            ),
            None,
        )

    if not entry:
        raise HTTPException(
            status_code=404,
            detail="not found",
        )

    _, sub = entry

    has_password = (
        sub.get(
            "password_hash"
        ) is not None
    )

    if has_password:

        password = (
            request
            .query_params
            .get(
                "pw",
                "",
            )
        )

        if (
            hash_password(password)
            != sub[
                "password_hash"
            ]
        ):

            return JSONResponse(
                {
                    "locked": True,
                    "name":
                        sub["name"],
                }
            )

    host = get_host(request)

    async with LINKS_LOCK:
        snapshot = dict(LINKS)

    links_out = []

    active_connections = 0

    for link_id in sub.get(
        "link_ids",
        [],
    ):

        link = snapshot.get(
            link_id
        )

        if not link:
            continue

        allowed = is_link_allowed(
            link
        )

        connection_count = sum(
            1
            for item in connections.values()
            if item.get("uuid") == link_id
        )

        active_connections += (
            connection_count
        )

        links_out.append(
            {
                "uuid":
                    link_id,

                "label":
                    link.get(
                        "label"
                    ),

                "active":
                    allowed,

                "protocol":
                    link.get(
                        "protocol",
                        DEFAULT_PROTOCOL,
                    ),

                "used_bytes":
                    link.get(
                        "used_bytes",
                        0,
                    ),

                "used_fmt":
                    fmt_bytes(
                        link.get(
                            "used_bytes",
                            0,
                        )
                    ),

                "limit_bytes":
                    link.get(
                        "limit_bytes",
                        0,
                    ),

                "limit_fmt":
                    (
                        "∞"
                        if not link.get(
                            "limit_bytes",
                            0,
                        )
                        else fmt_bytes(
                            link[
                                "limit_bytes"
                            ]
                        )
                    ),

                "expires_at":
                    link.get(
                        "expires_at"
                    ),

                "vless_link":
                    vless_link_for_link(
                        link,
                        link_id,
                        host,
                    ),

                "sub_url":
                    (
                        f"https://{host}"
                        f"/sub/{link_id}"
                    ),

                "info_url":
                    (
                        f"https://{host}"
                        f"/info/{link_id}"
                    ),

                "connections":
                    connection_count,

                "ip_limit":
                    link.get(
                        "ip_limit",
                        0,
                    ),

                "speed_limit_bytes":
                    link.get(
                        "speed_limit_bytes",
                        0,
                    ),

                "connection_limit":
                    link.get(
                        "connection_limit",
                        0,
                    ),
            }
        )

    total_used = sum(
        item["used_bytes"]
        for item in links_out
    )

    return {
        "locked": False,

        "name":
            sub["name"],

        "desc":
            sub.get(
                "desc",
                "",
            ),

        "sub_url":
            (
                f"https://{host}"
                f"/sub-group/{uuid_key}"
            ),

        "active_connections":
            active_connections,

        "total_used_fmt":
            fmt_bytes(
                total_used
            ),

        "support":
            SUPPORT_USERNAME,

        "links":
            links_out,
    }




@app.post("/api/mix-sub")
async def mix_subscription(request: Request, _=Depends(require_auth)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="JSON نامعتبر")
    ids = body.get("link_ids") or []
    if not isinstance(ids, list) or len(ids) < 2:
        raise HTTPException(status_code=400, detail="حداقل ۲ کانفیگ انتخاب کنید")
    if len(ids) > 40:
        raise HTTPException(status_code=400, detail="حداکثر ۴۰ کانفیگ")
    host = get_host(request)
    lines = []
    used_names = set()
    total_used = 0
    total_limit = 0
    labels = []
    async with LINKS_LOCK:
        for lid in ids:
            link = LINKS.get(lid)
            if not link or not is_link_allowed(link):
                continue
            labels.append(str(link.get("label") or lid[:8]))
            total_used += int(link.get("used_bytes", 0) or 0)
            total_limit += int(link.get("limit_bytes", 0) or 0)
            name = random_config_name(used_names)
            used_names.add(name)
            lines.append(generate_vless_link(
                lid, host, remark=name,
                protocol=link.get("protocol", DEFAULT_PROTOCOL),
                fingerprint=link.get("fingerprint", DEFAULT_FINGERPRINT),
                alpn=link.get("alpn"),
                port=link.get("port", DEFAULT_PORT),
            ))
    if not lines:
        raise HTTPException(status_code=400, detail="هیچ کانفیگ معتبری انتخاب نشده")
    # stats first line
    vol = f"{fmt_bytes(total_used)}/{fmt_bytes(total_limit)}" if total_limit > 0 else f"{fmt_bytes(total_used)}/∞"
    mix_label = "Mix-" + random_config_name()[:6]
    stats = f"{mix_label} | {vol} | {len(lines)} configs"
    first = generate_vless_link(ids[0], "127.0.0.1", remark=stats, protocol="vless-ws")
    content = base64.b64encode(("\n".join([first] + lines)).encode()).decode()
    # store as a sub group for reuse
    sub_id, sub = await create_sub_group(name=mix_label, desc="مخلوط‌سازی کانفیگ‌ها")
    async with SUBS_LOCK:
        if sub_id in SUBS:
            SUBS[sub_id]["link_ids"] = list(ids)
    await save_state()
    return {
        "ok": True,
        "sub_url": f"https://{host}/sub-group/{sub['uuid_key']}",
        "name": mix_label,
        "count": len(lines),
        "content_preview": stats,
    }


@app.get("/api/categories")
async def list_categories(_=Depends(require_auth)):
    items = [{**cat, "id": cid} for cid, cat in CATEGORIES.items()]
    items.sort(key=lambda x: int(x.get("number", 0)))
    return {"categories": items}

@app.post("/api/categories")
async def create_category(request: Request, _=Depends(require_auth)):
    if len(CATEGORIES) >= 50:
        raise HTTPException(status_code=400, detail="حداکثر ۵۰ گروه")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="JSON نامعتبر")
    name = str(body.get("name") or "دسته جدید").strip()[:40]
    used = {int(x.get("number", 0)) for x in CATEGORIES.values()}
    num = 0
    while num in used:
        num += 1
    cid = str(num)
    limit_value = safe_float(body.get("limit_value", 0))
    limit_unit = str(body.get("limit_unit") or "GB").upper()
    limit_bytes = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    speed_value = safe_float(body.get("speed_limit_value", 0))
    speed_bytes = 0 if speed_value <= 0 else parse_speed_to_bytes(speed_value, "MBIT")
    raw_clean = body.get("clean_ips") or ""
    if isinstance(raw_clean, list):
        clean_ips = [str(x).strip() for x in raw_clean if str(x).strip()]
    else:
        clean_ips = [x.strip() for x in str(raw_clean).replace(",", "\n").splitlines() if x.strip()]
    record = {
        "id": cid, "name": name, "number": num,
        "limit_bytes": limit_bytes,
        "expires_days": safe_int(body.get("expires_days", 0), minimum=0),
        "connection_limit": safe_int(body.get("connection_limit", 0), minimum=0),
        "speed_limit_bytes": speed_bytes,
        "ip_limit": safe_int(body.get("ip_limit", 0), minimum=0),
        "clean_ips": clean_ips,
        "random_name": bool(body.get("random_name", False)),
        "single_user": bool(body.get("single_user", False)),
        "created_at": datetime.now().isoformat(),
    }
    CATEGORIES[cid] = record
    await save_state()
    return {"ok": True, **record}


@app.patch("/api/categories/{cid}")
async def update_category(cid: str, request: Request, _=Depends(require_auth)):
    if cid not in CATEGORIES:
        raise HTTPException(status_code=404, detail="یافت نشد")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="JSON نامعتبر")
    cat = CATEGORIES[cid]
    if "name" in body:
        cat["name"] = str(body.get("name") or cat["name"]).strip()[:40]
    if "limit_value" in body:
        lv = safe_float(body.get("limit_value", 0))
        unit = str(body.get("limit_unit") or "GB").upper()
        cat["limit_bytes"] = 0 if lv <= 0 else parse_size_to_bytes(lv, unit)
    if "expires_days" in body:
        cat["expires_days"] = safe_int(body.get("expires_days", 0), minimum=0)
    if "connection_limit" in body:
        cat["connection_limit"] = safe_int(body.get("connection_limit", 0), minimum=0)
    if "speed_limit_value" in body:
        sv = safe_float(body.get("speed_limit_value", 0))
        cat["speed_limit_bytes"] = 0 if sv <= 0 else parse_speed_to_bytes(sv, "MBIT")
    if "ip_limit" in body:
        cat["ip_limit"] = safe_int(body.get("ip_limit", 0), minimum=0)
    if "clean_ips" in body:
        raw = body.get("clean_ips") or ""
        if isinstance(raw, list):
            cat["clean_ips"] = [str(x).strip() for x in raw if str(x).strip()]
        else:
            cat["clean_ips"] = [x.strip() for x in str(raw).replace(",", "\n").splitlines() if x.strip()]
    if "random_name" in body:
        cat["random_name"] = bool(body.get("random_name"))
    if "single_user" in body:
        cat["single_user"] = bool(body.get("single_user"))
    await save_state()
    return {"ok": True, **cat}

@app.delete("/api/categories/{cid}")
async def delete_category(cid: str, _=Depends(require_auth)):
    if cid not in CATEGORIES:
        raise HTTPException(status_code=404, detail="یافت نشد")
    del CATEGORIES[cid]
    for link in LINKS.values():
        if str(link.get("category_id")) == cid:
            link["category_id"] = "0"
    await save_state()
    return {"ok": True}

# ============================================================
# STATS
# ============================================================

@app.get("/stats")
async def get_stats(
    _=Depends(require_auth),
):

    async with LINKS_LOCK:
        snapshot = dict(LINKS)

    return {
        "service":
            APP_NAME,

        "version":
            APP_VERSION,

        "active_connections":
            len(connections),

        "total_traffic_mb":
            round(
                stats[
                    "total_bytes"
                ]
                / (
                    1024 ** 2
                ),
                2,
            ),

        "total_traffic_bytes":
            stats[
                "total_bytes"
            ],

        "total_requests":
            stats[
                "total_requests"
            ],

        "total_errors":
            stats[
                "total_errors"
            ],

        "uptime":
            uptime(),

        "timestamp":
            datetime.now().isoformat(),

        "hourly":
            dict(
                hourly_traffic
            ),

        "recent_errors":
            list(
                error_logs
            )[-10:],

        "links_count":
            len(snapshot),

        "active_links":
            sum(
                1
                for link
                in snapshot.values()
                if is_link_allowed(
                    link
                )
            ),

        "expired_links":
            sum(
                1
                for link
                in snapshot.values()
                if is_link_expired(
                    link
                )
            ),

        "subs_count":
            len(SUBS),
    }


@app.get("/api/activity")
async def get_activity(
    _=Depends(require_auth),
):

    return {
        "logs":
            list(
                activity_logs
            )[-150:]
    }


# ============================================================
# CONNECTIONS
# ============================================================

@app.get("/api/connections")
async def get_connections(
    _=Depends(require_auth),
):

    async with LINKS_LOCK:
        snapshot = dict(LINKS)

    grouped = {}

    for connection in connections.values():

        ip = connection.get(
            "ip",
            "نامشخص",
        )

        link = snapshot.get(
            connection.get(
                "uuid"
            )
        )

        label = (
            link.get(
                "label"
            )
            if link
            else "نامشخص"
        )

        group = grouped.get(ip)

        if group is None:

            group = {
                "ip":
                    ip,

                "sessions":
                    0,

                "bytes":
                    0,

                "labels":
                    set(),

                "transports":
                    set(),

                "first_connected_at":
                    connection.get(
                        "connected_at"
                    ),

                "last_connected_at":
                    connection.get(
                        "connected_at"
                    ),
            }

            grouped[ip] = group

        group["sessions"] += 1

        group["bytes"] += int(
            connection.get(
                "bytes",
                0,
            )
            or 0
        )

        group["labels"].add(
            label
        )

        group["transports"].add(
            connection.get(
                "transport",
                DEFAULT_PROTOCOL,
            )
        )

    result = []

    for group in grouped.values():

        result.append(
            {
                "ip":
                    group["ip"],

                "sessions":
                    group["sessions"],

                "labels":
                    sorted(
                        group["labels"]
                    ),

                "label":
                    (
                        " · ".join(
                            sorted(
                                group["labels"]
                            )
                        )
                        if group["labels"]
                        else "نامشخص"
                    ),

                "transports":
                    sorted(
                        group["transports"]
                    ),

                "bytes":
                    group["bytes"],

                "bytes_fmt":
                    fmt_bytes(
                        group["bytes"]
                    ),

                "connected_at":
                    group[
                        "first_connected_at"
                    ],

                "last_connected_at":
                    group[
                        "last_connected_at"
                    ],
            }
        )

    result.sort(
        key=lambda item:
            item.get(
                "last_connected_at"
            )
            or "",
        reverse=True,
    )

    return {
        "connections":
            result,

        "count":
            len(result),

        "raw_count":
            len(connections),
    }


# ============================================================
# OPTIONAL EXISTING PROJECT MODULES
# ============================================================

# ============================================================
# IMPORTANT:
# DO NOT REPLACE THIS VLESS CORE.
# ============================================================

try:

    from relay_vless import (
        RELAY_BUF,
        parse_vless_header,
        check_and_use,
        relay_ws_to_tcp,
        relay_tcp_to_ws,
        websocket_tunnel,
    )

    app.add_api_websocket_route(
        "/ws/{uuid}",
        websocket_tunnel,
    )

    logger.info(
        "VLESS relay loaded."
    )

except Exception as exc:

    logger.warning(
        "VLESS relay module unavailable: %s",
        exc,
    )


# ============================================================
# XHTTP
# ============================================================

try:

    from xhttp_siz10 import (
        router as xhttp_router
    )

    app.include_router(
        xhttp_router
    )

    logger.info(
        "XHTTP module loaded."
    )

except Exception as exc:

    logger.warning(
        "XHTTP module unavailable: %s",
        exc,
    )



# ============================================================

@app.get("/api/me")
async def api_me_info(request: Request, token=Depends(require_auth)):
    meta = get_session_meta(token)
    return {
        "ok": True,
        "role": meta.get("role"),
        "username": meta.get("username"),
        "permissions": meta.get("permissions") or {p: True for p in ALL_PERMS},
        "uptime": uptime(),
    }


@app.get("/api/admins")
async def api_admins_list(token=Depends(require_perm("admins"))):
    meta = get_session_meta(token)
    if meta.get("role") != "owner":
        raise HTTPException(403, detail="فقط مالک پنل")
    out = []
    for aid, a in ADMIN_ACCOUNTS.items():
        out.append({
            "id": aid,
            "username": a.get("username"),
            "label": a.get("label"),
            "limit_bytes": int(a.get("limit_bytes") or 0),
            "used_bytes": int(a.get("used_bytes") or 0),
            "expires_at": a.get("expires_at"),
            "active": bool(a.get("active", True)),
            "blocked": bool(a.get("blocked")),
            "permissions": a.get("permissions") or {},
            "created_at": a.get("created_at"),
            "valid": admin_is_valid(a),
        })
    out.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    return {"admins": out}


@app.post("/api/admins")
async def api_admins_create(request: Request, token=Depends(require_perm("admins"))):
    meta = get_session_meta(token)
    if meta.get("role") != "owner":
        raise HTTPException(403, detail="فقط مالک پنل")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, detail="JSON نامعتبر")
    username = str(body.get("username") or "").strip().lower()
    password = str(body.get("password") or "")
    repeat = str(body.get("repeat_password") or body.get("confirm") or "")
    if not username or len(username) < 3:
        raise HTTPException(400, detail="نام کاربری حداقل ۳ کاراکتر")
    if not username.isalnum():
        raise HTTPException(400, detail="نام کاربری فقط حروف و عدد انگلیسی")
    if username in ("owner", "admin", "root"):
        raise HTTPException(400, detail="این نام کاربری رزرو شده است")
    if find_admin_by_username(username)[0]:
        raise HTTPException(400, detail="نام کاربری تکراری است")
    if len(password) < 6:
        raise HTTPException(400, detail="رمز حداقل ۶ کاراکتر")
    if password != repeat:
        raise HTTPException(400, detail="تکرار رمز یکسان نیست")
    limit_value = safe_float(body.get("limit_value", 0))
    limit_unit = str(body.get("limit_unit") or "GB").upper()
    limit_bytes = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    days = safe_int(body.get("expires_days", 0), minimum=0)
    expires_at = (datetime.now() + timedelta(days=days)).isoformat() if days > 0 else None
    perms_in = body.get("permissions") or {}
    permissions = {p: bool(perms_in.get(p, False)) for p in ALL_PERMS}
    rec = default_admin_record(username, password, limit_bytes=limit_bytes, expires_at=expires_at, permissions=permissions, label=body.get("label") or username)
    ADMIN_ACCOUNTS[rec["id"]] = rec
    await save_state()
    log_activity("admin", f"اکانت ادمین «{username}» ساخته شد", "ok")
    return {"ok": True, "id": rec["id"], "username": username}


@app.patch("/api/admins/{aid}")
async def api_admins_patch(aid: str, request: Request, token=Depends(require_perm("admins"))):
    meta = get_session_meta(token)
    if meta.get("role") != "owner":
        raise HTTPException(403, detail="فقط مالک پنل")
    if aid not in ADMIN_ACCOUNTS:
        raise HTTPException(404, detail="یافت نشد")
    body = await request.json()
    a = ADMIN_ACCOUNTS[aid]
    if "blocked" in body:
        a["blocked"] = bool(body["blocked"])
    if "active" in body:
        a["active"] = bool(body["active"])
    if "label" in body:
        a["label"] = str(body["label"])[:40]
    if "permissions" in body and isinstance(body["permissions"], dict):
        a["permissions"] = {p: bool(body["permissions"].get(p, False)) for p in ALL_PERMS}
    if "limit_value" in body:
        lv = safe_float(body.get("limit_value", 0))
        lu = str(body.get("limit_unit") or "GB").upper()
        a["limit_bytes"] = 0 if lv <= 0 else parse_size_to_bytes(lv, lu)
    if "expires_days" in body:
        days = safe_int(body.get("expires_days", 0), minimum=0)
        a["expires_at"] = (datetime.now() + timedelta(days=days)).isoformat() if days > 0 else None
    if body.get("password"):
        pw = str(body["password"])
        if len(pw) < 6:
            raise HTTPException(400, detail="رمز حداقل ۶ کاراکتر")
        a["password_hash"] = hash_password(pw)
    await save_state()
    log_activity("admin", f"اکانت ادمین «{a.get('username')}» ویرایش شد", "ok")
    return {"ok": True}


@app.delete("/api/admins/{aid}")
async def api_admins_delete(aid: str, token=Depends(require_perm("admins"))):
    meta = get_session_meta(token)
    if meta.get("role") != "owner":
        raise HTTPException(403, detail="فقط مالک پنل")
    a = ADMIN_ACCOUNTS.pop(aid, None)
    if not a:
        raise HTTPException(404, detail="یافت نشد")
    await save_state()
    log_activity("admin", f"اکانت ادمین «{a.get('username')}» حذف شد", "warn")
    return {"ok": True}


NEWS_FILE = Path(__file__).resolve().parent / "news.json"


@app.get("/api/news")
async def api_news(token=Depends(require_auth)):
    try:
        if NEWS_FILE.exists():
            data = json.loads(NEWS_FILE.read_text(encoding="utf-8"))
        else:
            data = {"enabled": False, "title": "", "message": "", "updated_at": ""}
        return {"ok": True, **data}
    except Exception as e:
        return {"ok": False, "enabled": False, "title": "", "message": str(e), "updated_at": ""}




# ============================================================
# BACKUP / RESTORE
# ============================================================


@app.get("/api/security/status")
async def security_status(token=Depends(require_auth)):
    meta = get_session_meta(token)
    if meta.get("role") != "owner":
        raise HTTPException(403, detail="فقط مالک")
    now = time.time()
    locked = []
    for ip, until in list(LOGIN_LOCKED_UNTIL.items()):
        if until > now:
            locked.append({"ip": ip, "remaining_sec": int(until - now)})
    return {
        "ok": True,
        "max_attempts": LOGIN_MAX_ATTEMPTS,
        "window_seconds": LOGIN_WINDOW_SECONDS,
        "lockout_seconds": LOGIN_LOCKOUT_SECONDS,
        "locked_ips": locked,
        "tracked_ips": len(LOGIN_FAILURES),
    }


@app.post("/api/security/unlock")
async def security_unlock(request: Request, token=Depends(require_auth)):
    meta = get_session_meta(token)
    if meta.get("role") != "owner":
        raise HTTPException(403, detail="فقط مالک")
    try:
        body = await request.json()
    except Exception:
        body = {}
    ip = str((body or {}).get("ip") or "").strip()
    if ip:
        LOGIN_FAILURES.pop(ip, None)
        LOGIN_LOCKED_UNTIL.pop(ip, None)
    else:
        LOGIN_FAILURES.clear()
        LOGIN_LOCKED_UNTIL.clear()
    log_activity("auth", f"رفع مسدودی brute-force ({ip or 'all'})", "ok")
    return {"ok": True}


@app.get("/api/backup/users")
async def backup_users(token=Depends(require_auth)):
    meta = get_session_meta(token)
    # owner always; admin needs settings perm
    if meta.get("role") != "owner":
        if not (meta.get("permissions") or {}).get("settings"):
            raise HTTPException(403, detail="دسترسی ندارید")
    payload = {
        "type": "pxpanel_users_backup",
        "version": APP_VERSION,
        "created_at": datetime.now().isoformat(),
        "links": dict(LINKS),
        "subs": dict(SUBS),
        "categories": dict(CATEGORIES),
        "admin_accounts": dict(ADMIN_ACCOUNTS),
    }
    body = json.dumps(payload, ensure_ascii=False, indent=2)
    return Response(
        content=body,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="pxpanel-users-{datetime.now().strftime("%Y%m%d-%H%M%S")}.json"'
        },
    )


@app.get("/api/backup/bot")
async def backup_bot(token=Depends(require_auth)):
    meta = get_session_meta(token)
    if meta.get("role") != "owner":
        if not (meta.get("permissions") or {}).get("settings"):
            raise HTTPException(403, detail="دسترسی ندارید")
    data = {}
    try:
        if TG_FILE.exists():
            data = json.loads(TG_FILE.read_text(encoding="utf-8"))
    except Exception:
        data = {}
    payload = {
        "type": "pxpanel_bot_backup",
        "version": APP_VERSION,
        "created_at": datetime.now().isoformat(),
        "telegram": data,
    }
    body = json.dumps(payload, ensure_ascii=False, indent=2)
    return Response(
        content=body,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="pxpanel-bot-{datetime.now().strftime("%Y%m%d-%H%M%S")}.json"'
        },
    )


@app.post("/api/restore/users")
async def restore_users(request: Request, token=Depends(require_auth)):
    meta = get_session_meta(token)
    if meta.get("role") != "owner":
        raise HTTPException(403, detail="فقط مالک پنل")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, detail="فایل JSON نامعتبر")
    if not isinstance(body, dict):
        raise HTTPException(400, detail="فرمت نامعتبر")
    # accept either wrapper or raw state
    links = body.get("links")
    if links is None and body.get("type") == "pxpanel_users_backup":
        raise HTTPException(400, detail="لینک‌ها در بک‌آپ نیست")
    if links is None:
        raise HTTPException(400, detail="فایل بک‌آپ کاربران نیست")
    if not isinstance(links, dict):
        raise HTTPException(400, detail="links نامعتبر")
    mode = str(body.get("mode") or "merge").lower()  # merge | replace
    async with LINKS_LOCK:
        if mode == "replace":
            LINKS.clear()
            SUBS.clear()
            CATEGORIES.clear()
            ADMIN_ACCOUNTS.clear()
        LINKS.update(links)
        if isinstance(body.get("subs"), dict):
            SUBS.update(body["subs"])
        if isinstance(body.get("categories"), dict):
            CATEGORIES.update(body["categories"])
        if isinstance(body.get("admin_accounts"), dict):
            ADMIN_ACCOUNTS.update(body["admin_accounts"])
        for uid, link in list(LINKS.items()):
            if not isinstance(link, dict):
                LINKS.pop(uid, None)
                continue
            link.setdefault("protocol", DEFAULT_PROTOCOL)
            link.setdefault("fingerprint", DEFAULT_FINGERPRINT)
            link.setdefault("used_bytes", 0)
            link.setdefault("active", True)
            link.setdefault("config_count", 1)
    await save_state()
    log_activity("backup", f"بازیابی کاربران ({mode}) — {len(links)} کانفیگ", "ok")
    return {"ok": True, "links": len(LINKS), "subs": len(SUBS), "mode": mode}


@app.post("/api/restore/bot")
async def restore_bot(request: Request, token=Depends(require_auth)):
    meta = get_session_meta(token)
    if meta.get("role") != "owner":
        raise HTTPException(403, detail="فقط مالک پنل")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, detail="فایل JSON نامعتبر")
    tg = body.get("telegram") if isinstance(body, dict) else None
    if tg is None and isinstance(body, dict) and (body.get("token") or body.get("admin_ids") is not None):
        tg = body
    if not isinstance(tg, dict):
        raise HTTPException(400, detail="فایل بک‌آپ ربات نیست")
    # merge with existing
    current = {}
    try:
        if TG_FILE.exists():
            current = json.loads(TG_FILE.read_text(encoding="utf-8"))
    except Exception:
        current = {}
    current.update({k: v for k, v in tg.items() if v is not None})
    TG_FILE.parent.mkdir(parents=True, exist_ok=True)
    TG_FILE.write_text(json.dumps(current, ensure_ascii=False, indent=2), encoding="utf-8")
    # try activate
    try:
        from telegram_bot import configure_bot, start_bot, stop_bot, setup_webhook
        await stop_bot()
        configure_bot(current.get("token") or "", current.get("admin_ids") or "")
        host = get_host(request)
        if current.get("webhook") and host and host != "localhost":
            wh = f"https://{host}/telegram/webhook"
            await setup_webhook(wh)
            await start_bot(mode="webhook")
        else:
            await setup_webhook("")
            await start_bot(mode="polling")
    except Exception as exc:
        logger.warning("restore bot activate: %s", exc)
        log_activity("backup", f"بک‌آپ ربات ذخیره شد (فعال‌سازی: {exc})", "warn")
        return {"ok": True, "warning": str(exc)}
    log_activity("backup", "بازیابی تنظیمات ربات انجام شد", "ok")
    return {"ok": True, "message": "ربات بازیابی و فعال شد"}



# TELEGRAM SETTINGS API
# ============================================================

def load_tg_settings():
    try:
        if TG_FILE.exists():
            return json.loads(TG_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {
        "token": os.environ.get("TELEGRAM_BOT_TOKEN", "").strip(),
        "admin_ids": os.environ.get("TELEGRAM_ADMIN_IDS", "").strip(),
        "webhook": False,
        "enabled": False,
    }


def save_tg_settings(data: dict):
    TG_FILE.parent.mkdir(parents=True, exist_ok=True)
    TG_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


@app.get("/api/telegram/settings")
async def api_tg_get(_=Depends(require_auth)):
    s = load_tg_settings()
    token = s.get("token") or ""
    masked = (token[:8] + "…" + token[-4:]) if len(token) > 14 else ("••••" if token else "")
    return {
        "token_masked": masked,
        "has_token": bool(token),
        "admin_ids": s.get("admin_ids") or "",
        "webhook": bool(s.get("webhook")),
        "enabled": bool(s.get("enabled")),
    }


@app.post("/api/telegram/settings")
async def api_tg_save(request: Request, _=Depends(require_auth)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, detail="invalid json")
    s = load_tg_settings()
    token = str(body.get("token") or "").strip()
    admin_ids = str(body.get("admin_ids") or "").strip()
    use_webhook = bool(body.get("webhook", True))
    if token:
        s["token"] = token
    if admin_ids is not None:
        s["admin_ids"] = admin_ids
    s["webhook"] = use_webhook
    s["enabled"] = True
    save_tg_settings(s)
    # apply runtime
    try:
        from telegram_bot import configure_bot, start_bot, stop_bot, setup_webhook
        await stop_bot()
        configure_bot(s.get("token") or "", s.get("admin_ids") or "")
        host = get_host(request)
        if use_webhook and host and host != "localhost":
            wh = f"https://{host}/telegram/webhook"
            ok = await setup_webhook(wh)
            s["webhook_url"] = wh
            s["webhook_ok"] = bool(ok)
            save_tg_settings(s)
            await start_bot(mode="webhook")
        else:
            await setup_webhook("")  # delete webhook -> polling
            await start_bot(mode="polling")
        log_activity("telegram", "ربات تلگرام پیکربندی و فعال شد", "ok")
        return {"ok": True, "webhook": use_webhook, "message": "ربات فعال شد"}
    except Exception as exc:
        logger.warning("telegram activate error: %s", exc)
        return {"ok": True, "warning": str(exc), "message": "تنظیمات ذخیره شد"}


@app.post("/telegram/webhook")
async def telegram_webhook(request: Request):
    try:
        from telegram_bot import process_update
        data = await request.json()
        await process_update(data)
    except Exception as exc:
        logger.warning("webhook error: %s", exc)
    return {"ok": True}


# ============================================================
# TELEGRAM
# ============================================================

try:

    from telegram_bot import (
        start_bot as _tg_start_bot,
        stop_bot as _tg_stop_bot,
    )

except Exception:

    async def _tg_start_bot():
        return None

    async def _tg_stop_bot():
        return None


@app.on_event("startup")
async def start_optional_telegram():

    try:

        await _tg_start_bot()

        logger.info(
            "Telegram module initialized."
        )

    except Exception as exc:

        logger.warning(
            "Telegram bot disabled/error: %s",
            exc,
        )


# ============================================================
# HTTP PROXY
# ============================================================

_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-encoding",
    "content-length",
}


@app.api_route(
    "/proxy/{target_url:path}",
    methods=[
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "PATCH",
        "HEAD",
        "OPTIONS",
    ],
)
async def http_proxy(
    target_url: str,
    request: Request,
):

    if not target_url.startswith("http"):
        target_url = (
            "https://"
            + target_url
        )

    if http_client is None:
        raise HTTPException(
            status_code=503,
            detail="HTTP client not ready",
        )

    try:

        body = await request.body()

        headers = {
            key: value
            for key, value
            in request.headers.items()
            if (
                key.lower()
                not in _HOP
            )
            and (
                key.lower()
                != "host"
            )
        }

        response = await http_client.request(
            method=request.method,
            url=target_url,
            headers=headers,
            content=body,
        )

        stats["total_bytes"] += len(
            response.content
        )

        stats["total_requests"] += 1

        hourly_traffic[
            now_ir().strftime(
                "%H:00"
            )
        ] += len(
            response.content
        )

        output_headers = {
            key: value
            for key, value
            in response.headers.items()
            if key.lower() not in _HOP
        }

        return Response(
            content=response.content,
            status_code=response.status_code,
            headers=output_headers,
        )

    except Exception as exc:

        stats["total_errors"] += 1

        error_logs.append(
            {
                "error":
                    str(exc),

                "url":
                    target_url,

                "time":
                    datetime.now().isoformat(),
            }
        )

        logger.exception(
            "Proxy error: %s",
            target_url,
        )

        raise HTTPException(
            status_code=502,
            detail=(
                "Proxy error: "
                f"{exc}"
            ),
        )


# ============================================================
# DASHBOARD
# ============================================================

DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="fa" dir="rtl" id="htmlRoot">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>PXPanel 13.8.0</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#06060b;--bg2:#0b0b12;--bg3:#12121c;--card:rgba(18,18,28,.92);--card-b:rgba(255,255,255,.08);
  --accent:#3b82f6;--accent2:#60a5fa;--purple:#8b5cf6;--green:#22c55e;--red:#ef4444;--amber:#f59e0b;
  --t1:#f8fafc;--t2:rgba(248,250,252,.72);--t3:rgba(248,250,252,.42);
  --sb:252px;--sb-c:74px;--radius:18px;--shadow:0 12px 40px rgba(0,0,0,.45);
  --input-bg:rgba(0,0,0,.4);--hover:rgba(59,130,246,.12);
  --glow:0 0 40px rgba(59,130,246,.12);--glass:blur(16px);
}
html.light{
  --bg:#eef1f8;--bg2:#ffffff;--bg3:#f1f4fa;--card:#ffffff;--card-b:rgba(15,23,42,.09);
  --accent:#2563eb;--accent2:#3b82f6;--purple:#7c3aed;--green:#16a34a;--red:#dc2626;--amber:#d97706;
  --t1:#0f172a;--t2:#475569;--t3:#94a3b8;
  --shadow:0 10px 32px rgba(15,23,42,.08);
  --input-bg:#f8fafc;--hover:rgba(37,99,235,.08);
  --glow:0 0 32px rgba(37,99,235,.08);--glass:blur(12px);
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{min-height:100%}
body{font-family:'Vazirmatn',sans-serif;background:var(--bg);color:var(--t1);display:flex;min-height:100vh;overflow-x:hidden;transition:background .3s,color .3s}
body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;
  background:
    radial-gradient(ellipse 80% 50% at 100% 0%, rgba(59,130,246,.14), transparent 50%),
    radial-gradient(ellipse 60% 40% at 0% 100%, rgba(139,92,246,.10), transparent 45%);
}
html.light body::before{
  background:
    radial-gradient(ellipse 80% 50% at 100% 0%, rgba(37,99,235,.08), transparent 50%),
    radial-gradient(ellipse 60% 40% at 0% 100%, rgba(124,58,237,.06), transparent 45%);
}
.sidebar,.main,.mob-bar,.modal-bg,.toast{position:relative;z-index:1}
.sidebar{z-index:300}.mob-bar{z-index:250}.modal-bg{z-index:500}.toast{z-index:999}
body.en{font-family:'Inter',system-ui,sans-serif}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-thumb{background:var(--t3);border-radius:99px}

.sidebar{position:fixed;right:0;top:0;bottom:0;width:var(--sb);background:var(--bg2);border-left:1px solid var(--card-b);display:flex;flex-direction:column;z-index:300;transition:width .28s cubic-bezier(.4,0,.2,1),transform .28s,background .3s;box-shadow:var(--shadow);backdrop-filter:var(--glass)}
.sidebar.collapsed{width:var(--sb-c)}
.sb-toggle{position:absolute;left:-15px;top:50%;transform:translateY(-50%);width:30px;height:30px;border-radius:8px;background:var(--accent);border:2px solid var(--bg);color:#fff;display:flex;align-items:center;justify-content:center;cursor:pointer;z-index:310;box-shadow:0 4px 14px rgba(37,99,235,.4);transition:.2s}
.sb-toggle:hover{filter:brightness(1.1);transform:translateY(-50%) scale(1.05)}
.sb-toggle svg{width:14px;height:14px;transition:transform .28s}
.sidebar.collapsed .sb-toggle svg{transform:rotate(180deg)}
.sb-logo{display:flex;align-items:center;gap:12px;padding:20px 16px;border-bottom:1px solid var(--card-b)}
.sb-logo-icon{width:40px;height:40px;border-radius:12px;background:linear-gradient(135deg,#3b82f6,#8b5cf6);display:flex;align-items:center;justify-content:center;font-weight:800;font-size:13px;color:#fff;flex-shrink:0;box-shadow:0 4px 14px rgba(59,130,246,.35)}
.sb-logo-text{overflow:hidden;white-space:nowrap}
.sb-logo-name{font-size:15px;font-weight:800;letter-spacing:-.02em}
.sb-logo-ver{font-size:10px;color:var(--t3);margin-top:2px}
.sidebar.collapsed .sb-logo-text,
.sidebar.collapsed .nav-label,
.sidebar.collapsed .nav-sec,
.sidebar.collapsed .sb-foot span{display:none!important}
.sidebar.collapsed .sb-logo{justify-content:center;padding:16px 8px}
.sidebar.collapsed .sb-logo-icon{margin:0 auto}
.nav{flex:1;overflow-y:auto;padding:10px 0}
.nav-sec{padding:14px 18px 6px;font-size:9px;letter-spacing:.14em;text-transform:uppercase;color:var(--t3);font-weight:700}
.nav-item{display:flex;align-items:center;gap:11px;padding:11px 16px;margin:2px 10px;border-radius:12px;color:var(--t3);cursor:pointer;transition:.15s;border:none;background:transparent;width:calc(100% - 20px);font-family:inherit;font-size:13px;font-weight:500}
.nav-item svg{width:18px;height:18px;min-width:18px;min-height:18px;flex-shrink:0;display:block}
.nav-item:hover{background:var(--hover);color:var(--t2)}
.nav-item.on{background:var(--hover);color:var(--accent2);font-weight:700;box-shadow:inset -3px 0 0 var(--accent)}
.sidebar.collapsed .nav-item{justify-content:center;align-items:center;padding:12px 0;margin:3px 10px;width:calc(100% - 20px);gap:0}
.sidebar.collapsed .nav-item svg{margin:0 auto}
.sidebar.collapsed .nav-item.on{box-shadow:none}
.sidebar.collapsed .sb-foot button,.sidebar.collapsed .sb-foot a.btn{padding:10px 0;gap:0}
.sidebar.collapsed .sb-foot button svg,.sidebar.collapsed .sb-foot a.btn svg{margin:0 auto;display:block}
.sb-foot{padding:12px;border-top:1px solid var(--card-b);display:flex;flex-direction:column;gap:7px}
.sb-foot button,.sb-foot a.btn{display:flex;align-items:center;justify-content:center;gap:8px;padding:10px;border-radius:11px;border:1px solid var(--card-b);background:var(--bg3);color:var(--t2);cursor:pointer;font-family:inherit;font-size:12px;width:100%;text-decoration:none;font-weight:600;transition:.15s}
.sb-foot button:hover,.sb-foot a.btn:hover{background:var(--hover);color:var(--t1)}
.sb-foot a.danger{background:rgba(239,68,68,.08);border-color:rgba(239,68,68,.2);color:var(--red)}

.main{margin-right:var(--sb);flex:1;min-width:0;padding:28px 24px 60px;transition:margin .28s}
.main.expanded{margin-right:var(--sb-c)}
.page{display:none;animation:fadeIn .25s ease}
.page.on{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
.page-head{display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:14px;margin-bottom:22px}
.page-title{font-size:20px;font-weight:800;display:flex;align-items:center;gap:10px;letter-spacing:-.02em}
.page-title svg{width:22px;height:22px;color:var(--accent2)}
.page-sub{font-size:12px;color:var(--t3);margin-top:5px}

.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:20px}
.metric{background:var(--card);border:1px solid var(--card-b);border-radius:var(--radius);padding:18px;box-shadow:var(--shadow);transition:.25s;backdrop-filter:var(--glass)}
.metric:hover{border-color:rgba(59,130,246,.25)}
.metric-label{font-size:11px;color:var(--t3);margin-bottom:8px;display:flex;align-items:center;gap:6px;font-weight:600}
.metric-val{font-size:24px;font-weight:800;letter-spacing:-.03em}
.card{background:var(--card);border:1px solid var(--card-b);border-radius:var(--radius);padding:20px;margin-bottom:14px;box-shadow:var(--shadow);backdrop-filter:var(--glass);transition:border-color .2s,box-shadow .2s}
.card-title{font-size:13px;font-weight:700;margin-bottom:14px;display:flex;align-items:center;gap:8px}
.card-title svg{width:16px;height:16px;color:var(--accent2)}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px}
.action-card{cursor:pointer;transition:.2s;border:1px solid var(--card-b)}
.action-card:hover{border-color:rgba(59,130,246,.4);transform:translateY(-2px);box-shadow:0 12px 28px rgba(59,130,246,.12)}
.action-card.purple:hover{border-color:rgba(139,92,246,.45)}

.btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;padding:10px 16px;border-radius:11px;border:1px solid var(--card-b);background:var(--bg3);color:var(--t2);cursor:pointer;font-family:inherit;font-size:12px;font-weight:600;transition:.15s}
.btn:hover{color:var(--t1);border-color:var(--accent)}
.btn-p{background:linear-gradient(135deg,#3b82f6,#6366f1);border:none;color:#fff;box-shadow:0 6px 20px rgba(59,130,246,.35)}
.btn-p:hover{filter:brightness(1.08);color:#fff}
.btn-d{background:rgba(239,68,68,.1);border-color:rgba(239,68,68,.25);color:var(--red)}
.btn-sm{padding:7px 11px;font-size:11px;border-radius:9px}
.btn svg{width:15px;height:15px}

.table-wrap{overflow-x:auto;border-radius:14px;border:1px solid var(--card-b)}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th{text-align:right;padding:12px 14px;background:var(--bg3);color:var(--t3);font-weight:700;white-space:nowrap}
td{padding:12px 14px;border-top:1px solid var(--card-b);vertical-align:middle}
tr:hover td{background:var(--hover)}
.ops{display:flex;gap:5px;flex-wrap:wrap;align-items:center}

.range-tabs{display:flex;gap:4px;background:var(--bg3);padding:4px;border-radius:12px;border:1px solid var(--card-b)}
.range-tab{padding:7px 13px;border-radius:9px;font-size:11px;font-weight:700;color:var(--t3);cursor:pointer;border:none;background:transparent;font-family:inherit;transition:.15s}
.range-tab.on{background:var(--accent);color:#fff;box-shadow:0 2px 8px rgba(37,99,235,.35)}

.field{margin-bottom:14px}
.field label{display:block;font-size:11px;color:var(--t3);margin-bottom:6px;font-weight:700}
.field input,.field select,.field textarea{width:100%;padding:11px 13px;border-radius:11px;border:1px solid var(--card-b);background:var(--input-bg);color:var(--t1);font-family:inherit;font-size:13px;outline:none;transition:.15s}
.field input:focus,.field select:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(59,130,246,.15)}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:12px}

.support-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px}
.support-tile{display:flex;align-items:center;gap:14px;padding:20px;background:var(--card);border:1px solid var(--card-b);border-radius:var(--radius);text-decoration:none;color:inherit;transition:.2s;box-shadow:var(--shadow)}
.support-tile:hover{border-color:rgba(59,130,246,.35);transform:translateY(-3px)}
.support-icon{width:48px;height:48px;border-radius:14px;background:var(--hover);display:flex;align-items:center;justify-content:center;flex-shrink:0}
.support-icon svg{width:22px;height:22px;color:var(--accent2)}
.support-label{font-size:11px;color:var(--t3);font-weight:600}
.support-val{font-size:13px;font-weight:700;margin-top:3px}

.log-item{padding:12px 0;border-bottom:1px solid var(--card-b);font-size:12px;display:flex;gap:12px;align-items:flex-start}
.log-time{color:var(--t3);font-size:10px;white-space:nowrap;min-width:72px;font-weight:600}
.log-msg{color:var(--t2);flex:1;line-height:1.5}

.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.55);backdrop-filter:blur(6px);z-index:500;display:none;align-items:center;justify-content:center;padding:16px}
.modal-bg.open{display:flex}
.modal{background:var(--bg2);border:1px solid var(--card-b);border-radius:20px;width:min(520px,100%);max-height:90vh;overflow-y:auto;padding:24px;box-shadow:0 24px 64px rgba(0,0,0,.4)}
.modal-title{font-size:17px;font-weight:800;margin-bottom:16px}
.modal-actions{display:flex;gap:8px;justify-content:flex-end;margin-top:18px;flex-wrap:wrap}
.link-box{background:var(--input-bg);border:1px solid var(--card-b);border-radius:12px;padding:12px;font-size:11px;word-break:break-all;color:var(--t2);margin:8px 0 12px;font-family:ui-monospace,monospace;line-height:1.6;max-height:90px;overflow:auto}

.toast{position:fixed;bottom:28px;left:50%;transform:translateX(-50%) translateY(90px);background:var(--bg2);border:1px solid var(--card-b);color:var(--t1);padding:13px 22px;border-radius:14px;font-size:13px;font-weight:600;z-index:999;opacity:0;transition:.3s;pointer-events:none;box-shadow:var(--shadow)}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}

.switch{position:relative;display:inline-block;width:44px;height:26px;vertical-align:middle}
.switch input{opacity:0;width:0;height:0}
.slider{position:absolute;cursor:pointer;inset:0;background:rgba(148,163,184,.35);border-radius:26px;transition:.2s}
.slider:before{position:absolute;content:"";height:20px;width:20px;left:3px;bottom:3px;background:#fff;border-radius:50%;transition:.2s;box-shadow:0 2px 6px rgba(0,0,0,.2)}
.switch input:checked+.slider{background:var(--green)}
.switch input:checked+.slider:before{transform:translateX(18px)}

.mob-bar{display:none;position:fixed;top:0;left:0;right:0;height:56px;background:var(--bg2);border-bottom:1px solid var(--card-b);z-index:250;align-items:center;justify-content:space-between;padding:0 16px;box-shadow:var(--shadow)}
.overlay{position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:290;display:none}
.overlay.show{display:block}

@media(max-width:900px){
  .sidebar{transform:translateX(100%)}
  .sidebar.open{transform:translateX(0)}
  .sb-toggle{display:none!important}
  .main,.main.expanded{margin-right:0;padding-top:72px}
  .mob-bar{display:flex}
  .metrics{grid-template-columns:1fr 1fr}
  .g2,.form-row{grid-template-columns:1fr}
}
@media(max-width:480px){.metrics{grid-template-columns:1fr}}
.spin{width:36px;height:36px;border:3px solid var(--card-b);border-top-color:var(--accent);border-radius:50%;margin:0 auto;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}

.conn-badge{display:inline-flex;align-items:center;justify-content:center;min-width:22px;height:20px;padding:0 7px;border-radius:8px;font-size:10px;font-weight:800}
.conn-badge.green{background:rgba(34,197,94,.18);color:#4ade80}
.conn-badge.gray{background:rgba(148,163,184,.15);color:#94a3b8}
.conn-badge.orange{background:rgba(245,158,11,.18);color:#fbbf24}
.conn-badge.red{background:rgba(239,68,68,.18);color:#f87171}
.spin{width:36px;height:36px;border:3px solid var(--card-b);border-top-color:var(--accent);border-radius:50%;margin:0 auto;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
</style>
</head>
<body>

<div class="mob-bar">
  <div style="font-weight:800;font-size:15px">PXPanel</div>
  <button class="btn btn-sm" id="mobMenuBtn" aria-label="menu">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20"><path d="M4 6h16M4 12h16M4 18h16"/></svg>
  </button>
</div>
<div class="overlay" id="overlay"></div>

<aside class="sidebar" id="sidebar">
  <button class="sb-toggle" id="sbToggle" title="Toggle">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M15 18l-6-6 6-6"/></svg>
  </button>
  <div class="sb-logo">
    <div class="sb-logo-icon">PX</div>
    <div class="sb-logo-text">
      <div class="sb-logo-name">PXPanel</div>
      <div class="sb-logo-ver">v13.9.4</div>
    </div>
  </div>
  <nav class="nav">
    <div class="nav-sec" data-i18n="sec_panel">پنــــل</div>
    <button class="nav-item on" data-page="dash" data-perm="dash">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>
      <span class="nav-label" data-i18n="nav_dash">داشبـورد</span>
    </button>
    <button class="nav-item" data-page="configs" data-perm="configs">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
      <span class="nav-label" data-i18n="nav_configs">کانفیگ‌هـا</span>
    </button>
    <button class="nav-item" data-page="groups" data-perm="configs">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
      <span class="nav-label" data-i18n="nav_groups">گروه‌هـا</span>
    </button>
    <button class="nav-item" data-page="create" data-perm="create">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 5v14M5 12h14"/></svg>
      <span class="nav-label" data-i18n="nav_create">ساخت کانفیـگ</span>
    </button>
    <button class="nav-item" data-page="stats" data-perm="stats">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 3v18h18"/><path d="M7 16l4-8 4 4 5-6"/></svg>
      <span class="nav-label" data-i18n="nav_stats">امـار</span>
    </button>
    <button class="nav-item" data-page="logs" data-perm="logs">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M16 13H8M16 17H8M10 9H8"/></svg>
      <span class="nav-label" data-i18n="nav_logs">لاگ فعالیـت</span>
    </button>
    <div class="nav-sec" data-i18n="sec_sys">سیستـم</div>
    <button class="nav-item" data-page="telegram" data-perm="telegram">
      <svg viewBox="0 0 24 24" fill="currentColor" width="18" height="18"><path d="M12 0C5.37 0 0 5.37 0 12s5.37 12 12 12 12-5.37 12-12S18.63 0 12 0zm5.56 8.2-1.86 8.77c-.14.62-.5.77-1.01.48l-2.8-2.06-1.35 1.3c-.15.15-.27.27-.55.27l.2-2.84 5.18-4.68c.22-.2-.05-.31-.35-.12l-6.4 4.03-2.76-.86c-.6-.19-.61-.6.12-.89l10.78-4.16c.5-.18.94.12.78.86z"/></svg>
      <span class="nav-label" data-i18n="nav_telegram">پی ایکس بات</span>
    </button>
    <button class="nav-item" data-page="news" data-perm="news">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 22h16a2 2 0 0 0 2-2V4a2 2 0 0 0-2-2H8a2 2 0 0 0-2 2v16a2 2 0 0 1-2 2Zm0 0a2 2 0 0 1-2-2v-9c0-1.1.9-2 2-2h2"/><path d="M18 14h-8M15 18h-5M10 6h8v4h-8V6Z"/></svg>
      <span class="nav-label" data-i18n="nav_news">اخبـار</span>
    </button>
    <button class="nav-item" data-page="admins" data-perm="admins">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/></svg>
      <span class="nav-label" data-i18n="nav_admins">ادمین‌هـا</span>
    </button>
    <button class="nav-item" data-page="settings" data-perm="settings">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="3"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>
      <span class="nav-label" data-i18n="nav_settings">تنظیمـات</span>
    </button>
    <button class="nav-item" data-page="support" data-perm="support">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 18v-6a9 9 0 0 1 18 0v6"/><path d="M21 19a2 2 0 0 1-2 2h-1a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2h3zM3 19a2 2 0 0 0 2 2h1a2 2 0 0 0 2-2v-3a2 2 0 0 0-2-2H3z"/></svg>
      <span class="nav-label" data-i18n="nav_support">پشتیبانـی</span>
    </button>
    <button class="nav-item" data-page="donate">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>
      <span class="nav-label" data-i18n="nav_donate">حمایت مالـی</span>
    </button>
  </nav>
  <div class="sb-foot">
    <button type="button" id="themeBtn" onclick="toggleTheme()">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" width="16" height="16"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>
      <span id="themeLabel" data-i18n="theme">تم روشـن</span>
    </button>
    <button type="button" onclick="refreshAll()" title="Stats">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" width="16" height="16"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.5 9a9 9 0 0 1 14.1-3.4L23 10M1 14l5.4 4.4A9 9 0 0 0 20.5 15"/></svg>
      <span data-i18n="refresh_stats">بروزرسانی امـار</span>
    </button>
    <button type="button" onclick="panelUpdate()" title="Panel" style="background:rgba(16,185,129,.12);border-color:rgba(16,185,129,.35);color:#34d399">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" width="16" height="16"><path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/><path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16"/><path d="M16 16h5v5"/></svg>
      <span data-i18n="refresh_panel">بروزرسانی پنـل</span>
    </button>
    <a href="/logout" class="btn danger">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" width="16" height="16"><path d="M10 5H5v14h5"/><path d="m14 8 4 4-4 4"/><path d="M18 12H9"/></svg>
      <span data-i18n="logout">خروج</span>
    </a>
  </div>
</aside>

<main class="main" id="main">

<section class="page on" id="page-dash">
  <div class="page-head">
    <div>
      <div class="page-title">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>
        <span data-i18n="nav_dash">داشبورد</span>
      </div>
      <div class="page-sub" id="lastUpd" data-i18n="loading">در حال بارگـذاری...</div>
    </div>
  </div>
  <div class="metrics">
    <div class="metric"><div class="metric-label" data-i18n="m_conns">اتصالات فعـال</div><div class="metric-val" id="mConns">—</div></div>
    <div class="metric"><div class="metric-label" data-i18n="m_traffic">ترافیک کـل</div><div class="metric-val" id="mTraffic">—</div></div>
    <div class="metric"><div class="metric-label" data-i18n="m_links">کانفیگ‌هـا</div><div class="metric-val" id="mLinks">—</div></div>
    <div class="metric"><div class="metric-label" data-i18n="m_uptime">آپتایـم سرور</div><div class="metric-val" id="mUptime" style="font-size:17px">—</div></div>
  </div>
  <div class="g2">
    <div class="card action-card" onclick="goPage('create')">
      <div class="card-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 5v14M5 12h14"/></svg><span data-i18n="quick_create">ساخت کانفیگ</span></div>
      <p style="color:var(--t2);font-size:12px;line-height:1.6" data-i18n="quick_create_desc">ساخت دستی با محدودیت ترافیک، سرعت، تعداد و انقضا</p>
    </div>
    <div class="card action-card purple" onclick="doAutoCreate()">
      <div class="card-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="3"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2"/></svg><span data-i18n="auto_create">ساخت خودکار (پیشنهادی)</span></div>
      <p style="color:var(--t2);font-size:12px;line-height:1.6" data-i18n="auto_create_desc">ساخت سریع با تنظیمات بهینه · لینک VLESS و ساب</p>
    </div>
  </div>
</section>

<section class="page" id="page-configs">
  <div class="page-head">
    <div>
      <div class="page-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg><span data-i18n="nav_configs">کانفیگ‌ها</span></div>
      <div class="page-sub" data-i18n="configs_sub">مدیریـت لینک‌هــا · VLESS و سـاب</div>
    </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
      <input id="cfgSearch" placeholder="جستجو..." oninput="filterConfigs()" style="padding:8px 12px;border-radius:10px;border:1px solid var(--card-b);background:var(--input-bg);color:var(--t1);font-family:inherit;font-size:12px;min-width:140px">

      <button class="btn btn-p btn-sm" onclick="goPage('create')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M12 5v14M5 12h14"/></svg></button>
      <button class="btn btn-sm" onclick="refreshAll()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.5 9a9 9 0 0 1 14.1-3.4L23 10"/></svg></button>
    </div>
  </div>
  <div class="card" style="padding:0">
    <div class="table-wrap">
      <div id="bulkBar" style="display:none"></div>
      <table>
        <thead><tr>
          <th style="width:40px;text-align:center;padding:10px 8px">
            <input type="checkbox" id="chkAll" onchange="toggleSelectAll(this.checked);updateBulkBar()" title="انتخاب همه" style="width:16px;height:16px;margin:0;vertical-align:middle;cursor:pointer">
          </th>
          <th style="width:28px;padding:10px 4px"></th>
          <th data-i18n="th_name">نـام</th><th data-i18n="th_proto">پروتکـل</th><th data-i18n="th_status">وضعیت</th>
          <th data-i18n="th_usage">مصـرف</th><th data-i18n="th_ops">عملیـات</th>
        </tr></thead>
        <tbody id="linksTable"><tr><td colspan="7" style="text-align:center;color:var(--t3);padding:32px">...</td></tr></tbody>
      </table>
    </div>
  </div>
</section>

<section class="page" id="page-create">
  <div class="page-head">
    <div><div class="page-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 5v14M5 12h14"/></svg><span data-i18n="nav_create">ساخت کانفیگ</span></div></div>
  </div>
  <div class="g2">
    <div class="card">
      <div class="card-title" data-i18n="manual_create">ساخت دستی</div>
      <div class="field"><label data-i18n="label_name">نام</label>
        <div style="display:flex;gap:8px;align-items:center">
          <input id="cName" placeholder="auto" style="flex:1">
          <button type="button" class="btn btn-sm" onclick="randomName()" title="Random" style="min-width:44px;height:42px">
            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M16 3h5v5M4 20L21 3M21 16v5h-5M15 15l6 6M4 4l5 5"/></svg>
          </button>
        </div>
      </div>
            <div class="field"><label data-i18n="label_proto">پروتکـل</label><select id="cProto"></select></div>
      <div class="field"><label>گروه</label><select id="cGroup"></select></div>
<div class="form-row">
        <div class="field"><label data-i18n="label_count">تعداد کانفیگ در ساب (۱–۴۰)</label><input id="cCount" type="number" value="1" min="1" max="40"></div>
        <div class="field"><label data-i18n="label_days">انقضـا (روز)</label><input id="cDays" type="number" value="0" min="0"></div>
      </div>
      <div class="form-row">
        <div class="field"><label data-i18n="label_limit">محدودیت حجم</label><input id="cLimit" type="number" value="0" min="0"></div>
        <div class="field"><label data-i18n="label_unit">واحد</label><select id="cUnit"><option>GB</option><option>MB</option><option>KB</option></select></div>
      </div>
      <div class="form-row">
        <div class="field"><label data-i18n="label_ip">محدودیت IP</label><input id="cIp" type="number" value="0" min="0"></div>
        <div class="field"><label data-i18n="label_speed">سرعـت (Mbps)</label><input id="cSpeed" type="number" value="0" min="0"></div>
      </div>
      <button class="btn btn-p" style="width:100%" onclick="doManualCreate()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M12 5v14M5 12h14"/></svg>
        <span data-i18n="btn_create">ساخت</span>
      </button>
    </div>
    <div class="card" style="border-color:rgba(139,92,246,.35)">
      <div class="card-title" data-i18n="auto_create">ساخت خودکـار (پیشنهــادی)</div>
      <p style="color:var(--t2);font-size:13px;line-height:1.75;margin-bottom:14px" data-i18n="auto_desc">با یک کلیک کانفیگ بهینه ساخته می‌شود. بعد از ساخت لینک VLESS و ساب در اختیار شماست.</p>
      <div class="field"><label data-i18n="label_proto">پروتکـل</label><select id="aProto"></select></div>
      <div class="field"><label data-i18n="label_count">تعداد کانفیگ در سـاب (1-40)</label><input id="aCount" type="number" value="1" min="1" max="40"></div>
      <button class="btn btn-p" style="width:100%;background:linear-gradient(135deg,#8b5cf6,#6366f1)" onclick="doAutoCreate()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><circle cx="12" cy="12" r="3"/><path d="M12 2v2M12 20v2"/></svg>
        <span data-i18n="btn_auto">ساخـت خودکــار</span>
      </button>
    </div>
  </div>
</section>


<section class="page" id="page-groups">
  <div class="page-head">
    <div>
      <div class="page-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg><span data-i18n="nav_groups">گروه‌ها</span></div>
      <div class="page-sub">ساخـت گـروه و اختصـاص کانفیـگ هـای دستـی و خودکـار</div>
    </div>
  </div>
  <div class="g2">
    <div class="card">
      <div class="card-title">ساخت گروه جدیـد</div>
      <div class="field"><label>نام گروه</label><input id="grpName" placeholder="مثلا اختصاصـی"></div>
      <button class="btn btn-p" style="width:100%" onclick="createGroup()">ساخـت گروه</button>
    </div>
    <div class="card" style="padding:0">
      <div style="padding:16px 18px;border-bottom:1px solid var(--card-b);font-weight:700">لیست گروه‌ها</div>
      <div id="groupsList" style="padding:12px;max-height:480px;overflow:auto">...</div>
    </div>
  </div>
</section>
<section class="page" id="page-stats">
  <div class="page-head">
    <div>
      <div class="page-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 3v18h18"/><path d="M7 16l4-8 4 4 5-6"/></svg><span data-i18n="nav_stats">آمار</span></div>
      <div class="page-sub" data-i18n="stats_sub">ترافیـک و اتصـالات · فیلتـر زمانـی</div>
    </div>
    <div class="range-tabs" id="rangeTabs">
      <button class="range-tab" data-r="day" onclick="setRange('day',this)" data-i18n="r_day">روز</button>
      <button class="range-tab" data-r="week" onclick="setRange('week',this)" data-i18n="r_week">هفتـه</button>
      <button class="range-tab on" data-r="month" onclick="setRange('month',this)" data-i18n="r_month">مـاه</button>
      <button class="range-tab" data-r="all" onclick="setRange('all',this)" data-i18n="r_all">کـل</button>
    </div>
  </div>
  <div class="metrics">
    <div class="metric"><div class="metric-label" data-i18n="m_traffic">ترافیـک</div><div class="metric-val" id="sTraffic">—</div></div>
    <div class="metric"><div class="metric-label" data-i18n="m_conns">اتصـالات</div><div class="metric-val" id="sConns">—</div></div>
    <div class="metric"><div class="metric-label" data-i18n="m_links">کانفیـگ فعـال</div><div class="metric-val" id="sActive">—</div></div>
    <div class="metric"><div class="metric-label" data-i18n="m_uptime">آپتایـم</div><div class="metric-val" id="sUptime" style="font-size:16px">—</div></div>
  </div>
  <div class="card"><div class="card-title" data-i18n="panel_info">اطلاعات کل پنل</div><div id="panelInfo" style="font-size:13px;color:var(--t2);line-height:2"></div></div>
</section>

<section class="page" id="page-logs">
  <div class="page-head">
    <div><div class="page-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg><span data-i18n="nav_logs">لاگ فعالیت</span></div></div>
    <button class="btn btn-sm" onclick="loadLogs()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.5 9a9 9 0 0 1 14.1-3.4L23 10"/></svg></button>
  </div>
  <div class="card" id="logsBox"><div style="text-align:center;color:var(--t3);padding:28px">...</div></div>
</section>

<section class="page" id="page-settings">
  <div class="page-head"><div><div class="page-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="3"/></svg><span data-i18n="nav_settings">تنظیمات</span></div></div></div>
  <div class="card">
    <div class="card-title" data-i18n="theme">تــــم هـا</div>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      <button class="btn btn-p" onclick="setTheme('dark')" data-i18n="theme_dark">تـم دارک</button>
      <button class="btn" onclick="setTheme('light')" data-i18n="theme_light">تـم روشـن</button>
    </div>
  </div>
  <div class="card">
    <div class="card-title" data-i18n="lang_label">زبـان / Language</div>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      <button class="btn btn-p" onclick="setLang('fa')">فارسـی</button>
      <button class="btn" onclick="setLang('en')">English</button>
    </div>
  </div>
  <div class="card">
    <div class="card-title" data-i18n="change_pw">تغییر رمز عبـور</div>
    <div class="field"><label data-i18n="pw_cur">رمز فعلـی</label><input type="password" id="pwCur"></div>
    <div class="field"><label data-i18n="pw_new">رمـز جدیـد</label><input type="password" id="pwNew"></div>
    <div class="field"><label data-i18n="pw_cf">تکـرار رمـز</label><input type="password" id="pwCf"></div>
    <button class="btn btn-p" onclick="doChangePw()"><span data-i18n="btn_save">ذخیـره</span></button>
  </div>
  
  <div class="card">
    <div class="card-title">امنیت بیشتـر</div>
    <p style="font-size:12px;color:var(--t3);line-height:1.8;margin-bottom:12px">پـس از 5 تـلاش ناموفـق، ایپـی به مدت 30 دقیقه مسدود می‌شود.</p>
    <div id="secStatus" style="font-size:12px;color:var(--t2);margin-bottom:10px">—</div>
    <button class="btn btn-sm" onclick="loadSecurity()">بروزرسانی وضعیـت</button>
    <button class="btn btn-sm btn-d" onclick="unlockAllIps()">رفع مسدودی همـه ایپــی هــا</button>
  </div>
<div class="card">
    <div class="card-title">بــک آپ و بازیابــی</div>
    <p style="font-size:12px;color:var(--t3);line-height:1.8;margin-bottom:14px">در صورت خرابی پنل، بک‌آپ را دانلود کنید و در پنل جدید وارد کنید.</p>
    <div class="g2" style="margin-bottom:12px">
      <button class="btn btn-p" style="width:100%" onclick="downloadBackup('users')">دانلود بک‌آپ کاربران</button>
      <button class="btn btn-p" style="width:100%;background:linear-gradient(135deg,#8b5cf6,#6366f1)" onclick="downloadBackup('bot')">دانلود بک‌آپ ربات</button>
    </div>
    <div class="field">
      <label>وارد کردن بـک‌آپ کاربران</label>
      <input type="file" id="restoreUsersFile" accept="application/json,.json" style="padding:10px">
      <div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap">
        <button class="btn btn-sm" onclick="restoreUsers('merge')">ادغام بــــا فعلـی</button>
        <button class="btn btn-sm btn-d" onclick="restoreUsers('replace')">جایگزینی کامـل</button>
      </div>
    </div>
    <div class="field" style="margin-top:12px">
      <label>وارد کردن بــک آپ ربـات</label>
      <input type="file" id="restoreBotFile" accept="application/json,.json" style="padding:10px">
      <button class="btn btn-sm" style="margin-top:8px" onclick="restoreBot()">بازیابـی ربـات</button>
    </div>
  </div>
</section>


<section class="page" id="page-news">
  <div class="page-head">
    <div>
      <div class="page-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 22h16a2 2 0 0 0 2-2V4a2 2 0 0 0-2-2H8a2 2 0 0 0-2 2v16a2 2 0 0 1-2 2Zm0 0a2 2 0 0 1-2-2v-9c0-1.1.9-2 2-2h2"/></svg><span data-i18n="nav_news">اخبار</span></div>
      
    </div>
    <button class="btn btn-sm" onclick="loadNews(true)"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.5 9a9 9 0 0 1 14.1-3.4L23 10"/></svg> <span data-i18n="refresh_news">بروزرسانی اطلاعیه</span></button>
  </div>
  <div class="card" id="newsCard">
    <div class="card-title" id="newsTitle">—</div>
    <div id="newsBody" style="white-space:pre-wrap;line-height:1.9;color:var(--t2);font-size:13px">...</div>
    <div id="newsMeta" style="margin-top:14px;font-size:11px;color:var(--t3)"></div>
  </div>
</section>

<section class="page" id="page-admins">
  <div class="page-head">
    <div>
      <div class="page-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/></svg><span data-i18n="nav_admins">(نسخـه دمـو) ادمیـن هــا</span></div>
      <div class="page-sub" data-i18n="admins_sub">ساخت اکانت ادمین با دسترسی سفارشـی</div>
    </div>
  </div>
  <div class="g2">
    <div class="card">
      <div class="card-title" data-i18n="admin_create">ساخـت اکانـت ادمیـن</div>
      <div class="field"><label data-i18n="admin_user">نام کاربـری</label><input id="adUser" placeholder="user1" style="direction:ltr;text-align:left"></div>
      <div class="form-row">
        <div class="field"><label data-i18n="admin_pw">رمز عبـور</label><input id="adPw" type="password"></div>
        <div class="field"><label data-i18n="admin_pw2">تکرار رمـز</label><input id="adPw2" type="password"></div>
      </div>
      <div class="form-row">
        <div class="field"><label data-i18n="label_limit">حجـم</label><input id="adLimit" type="number" value="0" min="0"></div>
        <div class="field"><label data-i18n="label_unit">واحـد</label><select id="adUnit"><option>GB</option><option>MB</option></select></div>
      </div>
      <div class="field"><label data-i18n="label_days">مدت اعتبـار (روز)</label><input id="adDays" type="number" value="0" min="0"></div>
      <div class="card-title" style="margin-top:8px" data-i18n="admin_perms">دسترسی‌ها</div>
      <div id="adPerms" style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:12px"></div>
      <button class="btn btn-p" style="width:100%;margin-top:14px" onclick="createAdmin()" data-i18n="admin_btn">ساخت اکانت</button>
    </div>
    <div class="card" style="padding:0">
      <div style="padding:16px 18px;border-bottom:1px solid var(--card-b);font-weight:700" data-i18n="admin_list">لیست ادمین‌ها</div>
      <div id="adminsList" style="padding:12px;max-height:480px;overflow:auto"><div style="color:var(--t3);text-align:center;padding:20px">...</div></div>
    </div>
  </div>
</section>


<section class="page" id="page-donate">
  <div class="page-head" style="justify-content:center">
    <div>
      <div class="page-title" style="justify-content:center">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>
        <span data-i18n="nav_donate">حمایـت مالــــی</span>
      </div>
    </div>
  </div>
  <div style="display:flex;justify-content:center;width:100%">
  <div class="card" style="max-width:560px;width:100%;line-height:2;font-size:14px;color:var(--t2);text-align:center">
    <div style="font-size:16px;font-weight:800;color:var(--t1);margin-bottom:12px">💖 حمایت از پروژه (اختیاری)</div>
    <p>اگه از پروژه خوشتون اومده یا براتون مفید بوده، می‌تونید با یه حمایت کوچیک مالی به ادامه‌ی توسعه و بهتر شدن پروژه کمک کنید. 🫶🏻✨</p>
    <p style="margin-top:10px">💰 هر مقدار حمایتی، حتی کم، برای ما ارزشمنده و باعث میشه با انگیزه‌ی بیشتری ادامه بدیم! 🚀❤️‍🔥</p>
    <p style="margin-top:10px">🔗 لینک حمایت مالی:</p>
    <div style="margin-top:12px;display:flex;justify-content:center"><a href="https://reymit.ir/moditor" target="_blank" rel="noopener" class="btn btn-p" style="display:inline-flex;text-decoration:none">🙂 reymit.ir/moditor</a></div>
    <p style="margin-top:16px;font-size:13px;color:var(--t3)">🙏🏻 ممنون از حمایت و همراهی‌تون عشقا! ❤️‍🔥🌹</p>
    <p style="margin-top:8px;font-size:12px;color:var(--t3)">کاملاً اختیاری است و هیچ اجباری وجود ندارد.</p>
  </div>
  </div>
</section>

<section class="page" id="page-support">
  <div class="page-head"><div><div class="page-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 18v-6a9 9 0 0 1 18 0v6"/></svg><span data-i18n="nav_support">پشتیبانی</span></div></div></div>
  <div class="support-grid">
    <a class="support-tile" href="https://github.com/iran-px-panel/pxpanel" target="_blank" rel="noopener">
      <div class="support-icon"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.3 3.44 9.8 8.2 11.4.6.1.82-.26.82-.58v-2.03c-3.34.73-4.03-1.61-4.03-1.61-.55-1.39-1.34-1.76-1.34-1.76-1.1-.75.08-.74.08-.74 1.21.09 1.85 1.24 1.85 1.24 1.07 1.84 2.81 1.31 3.5 1 .11-.78.42-1.31.76-1.61-2.66-.3-5.46-1.33-5.46-5.93 0-1.31.47-2.38 1.24-3.22-.12-.3-.54-1.52.12-3.18 0 0 1.01-.32 3.3 1.23a11.5 11.5 0 0 1 6 0c2.29-1.55 3.3-1.23 3.3-1.23.66 1.66.24 2.88.12 3.18.77.84 1.24 1.91 1.24 3.22 0 4.61-2.8 5.62-5.48 5.92.43.37.81 1.1.81 2.22v3.29c0 .32.22.69.83.57C20.56 21.8 24 17.3 24 12 24 5.37 18.63 0 12 0z"/></svg></div>
      <div><div class="support-label" data-i18n="github">گیت هـاب پروژه</div><div class="support-val">iran-px-panel/pxpanel</div></div>
    </a>
    <a class="support-tile" href="https://t.me/logic_sec" target="_blank" rel="noopener">
      <div class="support-icon"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12s5.37 12 12 12 12-5.37 12-12S18.63 0 12 0zm5.56 8.2-1.86 8.77c-.14.62-.5.77-1.01.48l-2.8-2.06-1.35 1.3c-.15.15-.27.27-.55.27l.2-2.84 5.18-4.68c.22-.2-.05-.31-.35-.12l-6.4 4.03-2.76-.86c-.6-.19-.61-.6.12-.89l10.78-4.16c.5-.18.94.12.78.86z"/></svg></div>
      <div><div class="support-label" data-i18n="telegram">کانال تلگـرام</div><div class="support-val">@logic_sec</div></div>
    </a>
    <a class="support-tile" href="https://t.me/logictop12" target="_blank" rel="noopener">
      <div class="support-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M22 2L11 13M22 2l-7 20-4-9-9-4 20-7z"/></svg></div>
      <div><div class="support-label" data-i18n="channel">گروه تلگـرام (پشتیبانی)</div><div class="support-val">t.me/logictop12</div></div>
    </a>
  </div>
</section>

<section class="page" id="page-telegram">
  <div class="page-head">
    <div>
      <div class="page-title">
        <svg viewBox="0 0 24 24" fill="currentColor" width="22" height="22"><path d="M12 0C5.37 0 0 5.37 0 12s5.37 12 12 12 12-5.37 12-12S18.63 0 12 0zm5.56 8.2-1.86 8.77c-.14.62-.5.77-1.01.48l-2.8-2.06-1.35 1.3c-.15.15-.27.27-.55.27l.2-2.84 5.18-4.68c.22-.2-.05-.31-.35-.12l-6.4 4.03-2.76-.86c-.6-.19-.61-.6.12-.89l10.78-4.16c.5-.18.94.12.78.86z"/></svg>
        <span data-i18n="nav_telegram">پی ایکس بات</span>
      </div>
      <div class="page-sub" data-i18n="tg_sub">توکن ربات و آیدی عددی ادمین · فعال‌سازی خودکار و وب‌هوک</div>
    </div>
  </div>
  <div class="card">
    <div class="card-title" data-i18n="tg_config">پیکربندی ربات</div>
    <div class="field"><label data-i18n="tg_token">توکن ربات (BotFather)</label><input id="tgToken" placeholder="123456:ABC-DEF..." autocomplete="off"></div>
    <div class="field"><label data-i18n="tg_admin">آیدی عددی ادمین</label><input id="tgAdmin" placeholder="123456789" inputmode="numeric"></div>
    <div class="field" style="display:flex;align-items:center;gap:10px">
      <label class="switch"><input type="checkbox" id="tgWebhook" checked><span class="slider"></span></label>
      <span data-i18n="tg_webhook" style="font-size:13px;color:var(--t2)">فعال‌سازی Webhook (پیشنهادی روی Railway)</span>
    </div>
    <div id="tgStatus" style="font-size:12px;color:var(--t3);margin:10px 0"></div>
    <button class="btn btn-p" style="width:100%" onclick="saveTelegram()">
      <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 2L11 13"/><path d="M22 2l-7 20-4-9-9-4 20-7z"/></svg>
      <span data-i18n="tg_activate">ذخیره و فعال‌سازی ربات</span>
    </button>
  </div>
  <div class="card">
    <div class="card-title" data-i18n="tg_help">راهنما</div>
    <ol style="color:var(--t2);font-size:13px;line-height:2;padding-right:18px">
      <li data-i18n="tg_h1">از @BotFather یک ربات بساز و توکن را کپی کن</li>
      <li data-i18n="tg_h2">آیدی عددی خودت را از @userinfobot بگیر</li>
      <li data-i18n="tg_h3">ذخیره کن — وب‌هوک خودکار روی دامنه Railway ست می‌شود</li>
    </ol>
  </div>
</section>

</main>

<!-- Result modal after create -->
<div class="modal-bg" id="resultModal">
  <div class="modal">
    <div class="modal-title" data-i18n="created_title">کانفیگ ساخته شد</div>
    <div class="field"><label>VLESS</label><div class="link-box" id="resVless">—</div>
      <button class="btn btn-p btn-sm" style="width:100%" onclick="copyText(document.getElementById('resVless').textContent)">
        <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
        <span data-i18n="copy_vless">کپی VLESS</span>
      </button>
    </div>
    <div class="field" style="margin-top:14px"><label data-i18n="sub_label">سابسکریپشن</label><div class="link-box" id="resSub">—</div>
      <button class="btn btn-sm" style="width:100%" onclick="copyText(document.getElementById('resSub').textContent)">
        <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 11a9 9 0 0 1 9 9M4 4a16 16 0 0 1 16 16"/><circle cx="5" cy="19" r="1"/></svg>
        <span data-i18n="copy_sub">کپی ساب</span>
      </button>
    </div>
    <div class="modal-actions">
      <button class="btn" onclick="closeResult()">OK</button>
    </div>
  </div>
</div>

<div class="modal-bg" id="panelModal">
  <div class="modal">
    <div class="modal-title" id="panelModalTitle">...</div>
    <div id="panelModalBody" style="color:var(--t2);font-size:13px;line-height:1.8"></div>
    <div class="modal-actions">
      <button class="btn" onclick="document.getElementById('panelModal').classList.remove('open')">OK</button>
    </div>
  </div>
</div>
<div class="toast" id="toast"></div>

<script>
const I18N={
fa:{sec_panel:'پنل',sec_sys:'سیستم',nav_dash:'داشبورد',nav_configs:'کانفیگ‌ها',nav_groups:'گروه‌ها',nav_create:'ساخت کانفیگ',nav_stats:'آمار',nav_logs:'لاگ فعالیت',nav_settings:'تنظیمات',nav_support:'پشتیبانی',nav_donate:'حمایت مالی',nav_news:'اخبار',nav_admins:'ادمین‌ها',refresh_news:'بروزرسانی اطلاعیه',admins_sub:'ساخت اکانت ادمین با دسترسی سفارشی',admin_create:'ساخت اکانت ادمین',admin_user:'نام کاربری',admin_pw:'رمز عبور',admin_pw2:'تکرار رمز',admin_perms:'دسترسی‌ها',admin_btn:'ساخت اکانت',admin_list:'لیست ادمین‌ها',refresh:'بروزرسانی',refresh_stats:'بروزرسانی آمار',refresh_panel:'بروزرسانی پنل',nav_telegram:'ربات تلگرام',tg_sub:'توکن ربات و آیدی عددی ادمین · فعال‌سازی خودکار و وب‌هوک',tg_config:'پیکربندی ربات',tg_token:'توکن ربات (BotFather)',tg_admin:'آیدی عددی ادمین',tg_webhook:'فعال‌سازی Webhook (پیشنهادی روی Railway)',tg_activate:'ذخیره و فعال‌سازی ربات',tg_help:'راهنما',tg_h1:'از @BotFather یک ربات بساز و توکن را کپی کن',tg_h2:'آیدی عددی خودت را از @userinfobot بگیر',tg_h3:'ذخیره کن — وب‌هوک خودکار روی دامنه Railway ست می‌شود',logout:'خروج',loading:'در حال بارگذاری...',m_conns:'اتصالات فعال',m_traffic:'ترافیک کل',m_links:'کانفیگ‌ها',m_uptime:'آپتایم سرور',quick_create:'ساخت کانفیگ',quick_create_desc:'ساخت دستی با محدودیت ترافیک، سرعت، تعداد و انقضا',auto_create:'ساخت خودکار (پیشنهادی)',auto_create_desc:'ساخت سریع با تنظیمات بهینه · لینک VLESS و ساب',configs_sub:'مدیریت لینک‌ها · VLESS و ساب',th_name:'نام',th_proto:'پروتکل',th_status:'وضعیت',th_usage:'مصرف',th_ops:'عملیات',manual_create:'ساخت دستی',label_name:'نام',label_proto:'پروتکل',label_count:'تعداد کانفیگ در ساب (۱–۴۰)',label_limit:'محدودیت حجم',label_unit:'واحد',label_days:'انقضا (روز)',label_ip:'محدودیت IP',label_speed:'سرعت (Mbps)',btn_create:'ساخت',btn_auto:'ساخت خودکار',auto_desc:'با یک کلیک کانفیگ بهینه ساخته می‌شود. بعد از ساخت لینک VLESS و ساب در اختیار شماست.',stats_sub:'ترافیک و اتصالات · فیلتر زمانی',r_day:'روز',r_week:'هفته',r_month:'ماه',r_all:'کل',panel_info:'اطلاعات کل پنل',lang_label:'زبان',change_pw:'تغییر رمز عبور',pw_cur:'رمز فعلی',pw_new:'رمز جدید',pw_cf:'تکرار رمز',btn_save:'ذخیره',github:'گیت‌هاب',telegram:'تلگرام',channel:'کانال پشتیبان',theme:'تم',theme_dark:'تم تیره',theme_light:'تم روشن',created_title:'کانفیگ ساخته شد',copy_vless:'کپی VLESS',copy_sub:'کپی ساب',sub_label:'سابسکریپشن'},
en:{sec_panel:'PANEL',sec_sys:'SYSTEM',nav_dash:'Dashboard',nav_configs:'Configs',nav_groups:'Groups',nav_create:'Create Config',nav_stats:'Statistics',nav_logs:'Activity Log',nav_settings:'Settings',nav_support:'Support',nav_donate:'Donate',nav_news:'News',nav_admins:'Admins',refresh_news:'Refresh news',admins_sub:'Create admin accounts with custom access',admin_create:'Create admin account',admin_user:'Username',admin_pw:'Password',admin_pw2:'Confirm password',admin_perms:'Permissions',admin_btn:'Create account',admin_list:'Admin list',refresh:'Refresh',refresh_stats:'Refresh stats',refresh_panel:'Update panel',nav_telegram:'Telegram bot',tg_sub:'Bot token and numeric admin ID · auto activate and webhook',tg_config:'Bot configuration',tg_token:'Bot token (BotFather)',tg_admin:'Admin numeric ID',tg_webhook:'Enable Webhook (recommended on Railway)',tg_activate:'Save and activate bot',tg_help:'Guide',tg_h1:'Create a bot with @BotFather and copy the token',tg_h2:'Get your numeric ID from @userinfobot',tg_h3:'Save — webhook is set automatically on Railway domain',logout:'Logout',loading:'Loading...',m_conns:'Active connections',m_traffic:'Total traffic',m_links:'Configs',m_uptime:'Server uptime',quick_create:'Create Config',quick_create_desc:'Manual create with traffic, speed, count and expiry',auto_create:'Auto Create (Suggested)',auto_create_desc:'Quick optimal create · VLESS and Sub links',configs_sub:'Manage links · VLESS and Sub',th_name:'Name',th_proto:'Protocol',th_status:'Status',th_usage:'Usage',th_ops:'Actions',manual_create:'Manual create',label_name:'Name',label_proto:'Protocol',label_count:'Configs in sub (1–40)',label_limit:'Traffic limit',label_unit:'Unit',label_days:'Expiry (days)',label_ip:'IP limit',label_speed:'Speed (Mbps)',btn_create:'Create',btn_auto:'Auto create',auto_desc:'One click creates an optimal config. VLESS and Sub links will be shown.',stats_sub:'Traffic and connections · time filter',r_day:'Day',r_week:'Week',r_month:'Month',r_all:'All',panel_info:'Panel overview',lang_label:'Language',change_pw:'Change password',pw_cur:'Current password',pw_new:'New password',pw_cf:'Confirm password',btn_save:'Save',github:'GitHub',telegram:'Telegram',channel:'Support channel',theme:'Theme',theme_dark:'Dark theme',theme_light:'Light theme',created_title:'Config created',copy_vless:'Copy VLESS',copy_sub:'Copy Sub',sub_label:'Subscription'}
};
let lang=localStorage.getItem('px_lang')||'fa';
let statRange='month';
function t(k){return (I18N[lang]||I18N.fa)[k]||k}
function applyLang(){
  document.getElementById('htmlRoot').lang=lang;
  document.getElementById('htmlRoot').dir=lang==='fa'?'rtl':'ltr';
  document.body.classList.toggle('en',lang==='en');
  document.querySelectorAll('[data-i18n]').forEach(el=>{const k=el.getAttribute('data-i18n');if(I18N[lang][k])el.textContent=I18N[lang][k]});
  const tl=document.getElementById('themeLabel');
  if(tl) tl.textContent=document.documentElement.classList.contains('light')?t('theme_dark'):t('theme_light');
}
function setLang(l){lang=l;localStorage.setItem('px_lang',l);applyLang();toast(l==='fa'?'زبان فارسی':'English')}

function setTheme(mode){
  if(mode==='light') document.documentElement.classList.add('light');
  else document.documentElement.classList.remove('light');
  localStorage.setItem('px_theme',mode);
  applyLang();
}
function toggleTheme(){
  const isLight=document.documentElement.classList.contains('light');
  setTheme(isLight?'dark':'light');
}
(function(){const th=localStorage.getItem('px_theme')||'dark';setTheme(th)})();

const sb=document.getElementById('sidebar'),main=document.getElementById('main');
document.getElementById('sbToggle').onclick=()=>{
  sb.classList.toggle('collapsed');
  main.classList.toggle('expanded',sb.classList.contains('collapsed'));
  localStorage.setItem('sb_c',sb.classList.contains('collapsed')?'1':'0');
};
if(localStorage.getItem('sb_c')==='1'){sb.classList.add('collapsed');main.classList.add('expanded')}
document.getElementById('mobMenuBtn').onclick=()=>{sb.classList.add('open');document.getElementById('overlay').classList.add('show')};
document.getElementById('overlay').onclick=()=>{sb.classList.remove('open');document.getElementById('overlay').classList.remove('show')};

function goPage(name){
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.toggle('on',n.dataset.page===name));
  document.querySelectorAll('.page').forEach(p=>p.classList.toggle('on',p.id==='page-'+name));
  sb.classList.remove('open');document.getElementById('overlay').classList.remove('show');
  window.scrollTo({top:0,behavior:'smooth'});
  if(name==='logs')loadLogs();
  if(name==='configs'||name==='dash'||name==='stats')refreshAll();
}
document.querySelectorAll('.nav-item').forEach(el=>el.addEventListener('click',()=>goPage(el.dataset.page)));

function toast(msg){
  const el=document.getElementById('toast');
  el.textContent=msg;el.classList.add('show');
  clearTimeout(window.__tt);window.__tt=setTimeout(()=>el.classList.remove('show'),2200);
}
async function api(url,opts={}){
  try{
    const r=await fetch(url,{cache:'no-store',credentials:'same-origin',...opts});
    if(r.status===401){location.href='/login';return null}
    let data=null;try{data=await r.json()}catch{data={ok:false}}
    if(!r.ok){toast(data.detail||data.error||'Error');return null}
    return data;
  }catch(e){toast(lang==='fa'?'ارتباط برقرار نشد':'Connection failed');return null}
}
function fmtB(b){b=Number(b)||0;if(b<1024)return b+' B';if(b<1024**2)return (b/1024).toFixed(1)+' KB';if(b<1024**3)return (b/1024**2).toFixed(2)+' MB';return (b/1024**3).toFixed(2)+' GB'}
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;')}

async function refreshAll(){
  if(typeof loadGroups==='function') try{await loadGroups()}catch(e){}
  const links=await api('/api/links');
  if(!links)return;
  const arr=Array.isArray(links.links)?links.links:(Array.isArray(links)?links:[]);
  document.getElementById('mLinks').textContent=arr.length;
  let active=0,used=0;
  arr.forEach(l=>{if(l.active!==false)active++;used+=Number(l.used_bytes||0)});
  document.getElementById('mTraffic').textContent=fmtB(used);
  document.getElementById('sTraffic').textContent=fmtB(used);
  document.getElementById('sActive').textContent=active;
  document.getElementById('lastUpd').textContent=(lang==='fa'?'بروزرسانی: ':'Updated: ')+new Date().toLocaleTimeString(lang==='fa'?'fa-IR':'en-US');
  try{
    const c=await api('/api/connections');
    const cnt=(c&&c.connections)?c.connections.length:((c&&typeof c.count==='number')?c.count:0);
    document.getElementById('mConns').textContent=cnt;
    document.getElementById('sConns').textContent=cnt;
  }catch(e){}
  try{
    const h=await fetch('/health',{cache:'no-store'}).then(r=>r.json());
    if(h&&h.uptime){
      document.getElementById('mUptime').textContent=h.uptime;
      const su=document.getElementById('sUptime');if(su)su.textContent=h.uptime;
    }
  }catch(e){}
    __allLinks=arr;
  softUpdateLinks(arr);
  document.getElementById('panelInfo').innerHTML=lang==='fa'
    ?`کل کانفیگ: <b>${arr.length}</b> · فعال: <b>${active}</b> · مصرف: <b>${fmtB(used)}</b> · بازه: <b>${statRange}</b>`
    :`Total: <b>${arr.length}</b> · Active: <b>${active}</b> · Usage: <b>${fmtB(used)}</b> · Range: <b>${statRange}</b>`;
}


function linkBadgeClass(l){
  const conn=Number(l.connected_ips||0);
  const used=Number(l.used_bytes||0), lim=Number(l.limit_bytes||0);
  let usagePct=lim>0?(used/lim)*100:0;
  let expWarn=false, expDead=false;
  if(l.expires_at){try{const ms=new Date(l.expires_at)-Date.now();if(ms<=0)expDead=true;else if(ms<3*864e5)expWarn=true}catch(e){}}
  if(expDead||usagePct>=90) return 'conn-badge red';
  if(expWarn||usagePct>=70) return 'conn-badge orange';
  if(conn>0) return 'conn-badge green';
  return 'conn-badge gray';
}
function softUpdateLinks(arr){
  const tb=document.getElementById('linksTable');
  if(!tb) return;
  const rows=[...tb.querySelectorAll('tr[data-uid]')];
  const existing=rows.map(r=>r.getAttribute('data-uid'));
  const incoming=arr.map(l=>String(l.uuid||l.id||''));
  const same = existing.length===incoming.length && existing.every((id,i)=>id===incoming[i]);
  // اگر در حال درگ یا انتخاب هستیم، فقط سلول‌ها را آپدیت کن
  const selecting = document.querySelectorAll('.cfg-chk:checked').length>0;
  const dragging = !!__dragUid;
  if(!same || existing.length===0){
    if(dragging || selecting){
      // فقط آمار ردیف‌های موجود را آپدیت کن، ساختار را نشکن
      window.__linksMap = window.__linksMap || {};
      arr.forEach(l=>{
        const uid=String(l.uuid||l.id||'');
        window.__linksMap[uid]=l;
        const tr=tb.querySelector(`tr[data-uid="${uid}"]`);
        if(!tr) return;
        patchLinkRow(tr, l);
      });
      return;
    }
    renderLinks(arr);
    return;
  }
  window.__linksMap = window.__linksMap || {};
  arr.forEach(l=>{
    const uid=String(l.uuid||l.id||'');
    window.__linksMap[uid]=l;
    const tr=tb.querySelector(`tr[data-uid="${uid}"]`);
    if(tr) patchLinkRow(tr, l);
  });
}
function patchLinkRow(tr, l){
  const conn=Number(l.connected_ips||0);
  const badge=tr.querySelector('.conn-badge');
  if(badge){ badge.textContent=String(conn); badge.className=linkBadgeClass(l); }
  const usageCell=tr.querySelector('[data-usage]');
  if(usageCell){
    usageCell.textContent = fmtB(l.used_bytes) + (l.limit_bytes?(' / '+fmtB(l.limit_bytes)):'');
  }
  // وضعیت سوئیچ را اگر کاربر همین الان عوض نکرده دست نزن — فقط اگر API فرق دارد و فوکوس نیست
  const sw=tr.querySelector('.switch input[type=checkbox]');
  if(sw && document.activeElement!==sw){
    const on=l.active!==false&&!l.expired;
    if(sw.checked!==on) sw.checked=on;
  }
}
function renderLinks(arr){
  const tb=document.getElementById('linksTable');
  if(!arr.length){tb.innerHTML=`<tr><td colspan="7" style="text-align:center;color:var(--t3);padding:28px">${lang==='fa'?'کانفیگی نیست':'No configs'}</td></tr>`;updateBulkBar();return}
  window.__linksMap={};
  const catMap=window.__catMap||{};
  // preserve checked state
  const prevChecked=new Set([...document.querySelectorAll('.cfg-chk:checked')].map(c=>c.value));
  tb.innerHTML=arr.map(l=>{
    const uid=l.uuid||l.id||'';
    window.__linksMap[uid]=l;
    const name=l.label||l.name||String(uid).slice(0,8);
    const proto=l.protocol||'vless-ws';
    const on=l.active!==false&&!l.expired;
    const conn=Number(l.connected_ips||0);
    const gname=catMap[String(l.category_id||'')]||'';
    const chk=prevChecked.has(uid)?'checked':'';
    return `<tr draggable="true" data-uid="${esc(uid)}" ondragstart="cfgDragStart(event)" ondragover="cfgDragOver(event)" ondrop="cfgDrop(event)" ondragend="cfgDragEnd(event)">
      <td style="text-align:center;padding:10px 8px;vertical-align:middle"><input type="checkbox" class="cfg-chk" value="${esc(uid)}" ${chk} onchange="updateBulkBar()" style="width:16px;height:16px;margin:0;vertical-align:middle;cursor:pointer"></td>
      <td style="cursor:grab;color:var(--t3);user-select:none" title="کشیدن">⋮⋮</td>
      <td>
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
          <b>${esc(name)}</b>
          <span class="${linkBadgeClass(l)}" title="${lang==='fa'?'متصل الان':'Online now'}">${conn}</span>
          ${gname?`<span style="font-size:10px;padding:2px 7px;border-radius:8px;background:var(--hover);color:var(--t3)">${esc(gname)}</span>`:''}
        </div>
      </td>
      <td style="color:var(--t3);font-size:11px">${esc(proto)}</td>
      <td><label class="switch"><input type="checkbox" ${on?'checked':''} onchange="toggleLink('${esc(uid)}',this.checked)"><span class="slider"></span></label></td>
      <td data-usage>${fmtB(l.used_bytes)}${l.limit_bytes?(' / '+fmtB(l.limit_bytes)):''}</td>
      <td class="ops">
        <button class="btn btn-sm" onclick="copyLinkById('${esc(uid)}')" title="VLESS"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></button>
        <button class="btn btn-sm" onclick="copySubById('${esc(uid)}')" title="Sub"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 11a9 9 0 0 1 9 9M4 4a16 16 0 0 1 16 16"/><circle cx="5" cy="19" r="1"/></svg></button>
        <a class="btn btn-sm" href="/info/${esc(uid)}" target="_blank" title="INFO" style="text-decoration:none"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg></a>
        <button class="btn btn-sm" onclick="resetUsage('${esc(uid)}')" title="Reset"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg></button>
        <button class="btn btn-sm btn-d" onclick="deleteLink('${esc(uid)}')"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6"/></svg></button>
      </td>
    </tr>`;
  }).join('');
  updateBulkBar();
}
function getLinkUrl(l){if(!l)return '';return l.vless_full||l.vless||l.vless_link||l.link||''}
function getSubUrl(l){if(!l)return '';return l.sub||l.sub_url||l.info||''}
async function copyText(text){
  text=String(text||'').trim();
  if(!text||text==='—'){toast(lang==='fa'?'لینکی نیست':'Nothing to copy');return}
  try{
    if(navigator.clipboard&&window.isSecureContext) await navigator.clipboard.writeText(text);
    else{const ta=document.createElement('textarea');ta.value=text;ta.style.cssText='position:fixed;left:-9999px';document.body.appendChild(ta);ta.select();document.execCommand('copy');document.body.removeChild(ta)}
    toast(lang==='fa'?'کپی شد':'Copied');
  }catch(e){toast(lang==='fa'?'کپی نشد':'Copy failed')}
}
async function copyLinkById(uid){await copyText(getLinkUrl((window.__linksMap||{})[uid]))}
async function copySubById(uid){await copyText(getSubUrl((window.__linksMap||{})[uid]))}
async function toggleLink(uid,state){
  // optimistic UI — رنگ بلافاصله عوض می‌شود
  if(window.__linksMap && window.__linksMap[uid]){
    window.__linksMap[uid].active = !!state;
    if(window.__linksMap[uid].expired && state) window.__linksMap[uid].expired = false;
  }
  if(typeof __allLinks !== 'undefined' && Array.isArray(__allLinks)){
    const item = __allLinks.find(x => (x.uuid||x.id)===uid);
    if(item) item.active = !!state;
  }
  const r=await api('/api/links/'+uid,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({active:!!state})});
  if(r===null){
    // rollback
    if(window.__linksMap && window.__linksMap[uid]) window.__linksMap[uid].active = !state;
    refreshAll();
    return;
  }
  toast(state?(lang==='fa'?'فعال شد':'Enabled'):(lang==='fa'?'غیرفعال شد':'Disabled'));
}
async function deleteLink(uid){
  if(!confirm(lang==='fa'?'حذف شود؟':'Delete?'))return;
  const r=await api('/api/links/'+uid,{method:'DELETE'});
  if(r!==null){toast(lang==='fa'?'حذف شد':'Deleted');refreshAll()}
}
function showResult(data){
  if(!data)return;
  document.getElementById('resVless').textContent=getLinkUrl(data)||'—';
  document.getElementById('resSub').textContent=getSubUrl(data)||'—';
  document.getElementById('resultModal').classList.add('open');
}
function closeResult(){document.getElementById('resultModal').classList.remove('open')}
document.getElementById('resultModal').addEventListener('click',e=>{if(e.target.id==='resultModal')closeResult()});

async function doAutoCreate(){
  toast(lang==='fa'?'در حال ساخت...':'Creating...');
  const count=Math.max(1,Math.min(40,Number(document.getElementById('aCount')?.value)||1));
  const protocol=document.getElementById('aProto')?.value||undefined;
  let r=await api('/api/links/auto',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({config_count:count,protocol})});
  if(!r){
    r=await api('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label:'auto-'+Date.now().toString(36).slice(-5),limit_value:0,limit_unit:'GB',config_count:count})});
  }
  if(r){showResult(r);refreshAll()}
}
async function doManualCreate(){
  const body={
    label:document.getElementById('cName').value||undefined,
    protocol:document.getElementById('cProto')?.value||undefined,
    category_id:document.getElementById('cGroup')?.value||'0',
    config_count:Math.max(1,Math.min(40,Number(document.getElementById('cCount').value)||1)),
    limit_value:Number(document.getElementById('cLimit').value)||0,
    limit_unit:document.getElementById('cUnit').value||'GB',
    expires_days:Number(document.getElementById('cDays').value)||0,
    ip_limit:Number(document.getElementById('cIp').value)||0,
    speed_limit_value:Number(document.getElementById('cSpeed').value)||0,
    speed_limit_unit:'MBIT'
  };
  const r=await api('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(r){showResult(r);refreshAll()}
}
async function doChangePw(){
  const cur=document.getElementById('pwCur').value,nw=document.getElementById('pwNew').value,cf=document.getElementById('pwCf').value;
  if(nw!==cf){toast(lang==='fa'?'رمزها یکی نیستند':'Passwords mismatch');return}
  const r=await api('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:cur,new_password:nw,repeat_password:cf})});
  if(r){toast(lang==='fa'?'رمز تغییر کرد':'Password changed');document.getElementById('pwCur').value='';document.getElementById('pwNew').value='';document.getElementById('pwCf').value=''}
}
async function loadLogs(){
  const box=document.getElementById('logsBox');
  const data=await api('/api/activity');
  const logs=Array.isArray(data)?data:(data&&data.logs)||[];
  if(!logs.length){box.innerHTML=`<div style="text-align:center;color:var(--t3);padding:24px">${lang==='fa'?'لاگی نیست':'No logs'}</div>`;return}
  box.innerHTML=logs.slice().reverse().map(l=>{
    const tm=(l.time||l.ts||'').toString().slice(11,19)||'—';
    return `<div class="log-item"><div class="log-time">${esc(tm)}</div><div class="log-msg">${esc(l.message||l.msg||JSON.stringify(l))}</div></div>`;
  }).join('');
}
function setRange(r,el){
  statRange=r;
  document.querySelectorAll('#rangeTabs .range-tab').forEach(t=>t.classList.toggle('on',t.dataset.r===r));
  refreshAll();toast(t('r_'+r));
}
function randomName(){
  const chars='abcdefghijklmnopqrstuvwxyz0123456789';
  let s='';
  for(let i=0;i<10;i++) s+=chars[Math.floor(Math.random()*chars.length)];
  if(/^[0-9]/.test(s)) s='a'+s.slice(1);
  document.getElementById('cName').value=s;
}
async function panelUpdate(){
  const m=document.getElementById('panelModal');
  const t=document.getElementById('panelModalTitle');
  const b=document.getElementById('panelModalBody');
  t.textContent=lang==='fa'?'در حال بررسی آپدیت...':'Checking update...';
  b.innerHTML='<div style="text-align:center;padding:20px"><div class="spin"></div></div>';
  m.classList.add('open');
  await new Promise(r=>setTimeout(r,1400));
  t.textContent=lang==='fa'?'آپدیت پنل':'Panel update';
  b.innerHTML=(lang==='fa'
    ?'<p style="margin-bottom:12px">اپدیت با خطا مواجه شد. اپدیت را دستی انجام دهید.</p><a href="https://github.com/iran-px-panel/pxpanel" target="_blank" rel="noopener" style="color:var(--accent2);font-weight:700">github.com/iran-px-panel/pxpanel</a>'
    :'<p style="margin-bottom:12px">Update failed. Please update manually.</p><a href="https://github.com/iran-px-panel/pxpanel" target="_blank" rel="noopener" style="color:var(--accent2);font-weight:700">github.com/iran-px-panel/pxpanel</a>');
}
async function saveTelegram(){
  const token=document.getElementById('tgToken').value.trim();
  const admin=document.getElementById('tgAdmin').value.trim();
  const webhook=document.getElementById('tgWebhook').checked;
  if(!token||!admin){toast(lang==='fa'?'توکن و آیدی لازم است':'Token and admin ID required');return}
  toast(lang==='fa'?'در حال فعال‌سازی...':'Activating...');
  const r=await api('/api/telegram/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token,admin_ids:admin,webhook})});
  if(r){
    document.getElementById('tgStatus').textContent=r.message||(lang==='fa'?'فعال شد':'Enabled');
    toast(r.message||'OK');
  }
}
async function loadTelegram(){
  const r=await api('/api/telegram/settings');
  if(!r)return;
  if(r.admin_ids) document.getElementById('tgAdmin').value=r.admin_ids;
  document.getElementById('tgWebhook').checked=r.webhook!==false;
  document.getElementById('tgStatus').textContent=r.has_token?(lang==='fa'?'توکن ذخیره شده: ':'Token saved: ')+(r.token_masked||''):'';
}
const _goPage=goPage;
goPage=function(name){
  _goPage(name);
  if(name==='telegram') loadTelegram();
  if(name==='news') loadNews();
  if(name==='admins') loadAdmins();
  if(name==='groups') loadGroups();
  if(name==='settings') loadSecurity();
};

const PERM_LABELS={
  fa:{dash:'داشبورد',configs:'کانفیگ‌ها',create:'ساخت',stats:'آمار',logs:'لاگ',settings:'تنظیمات',support:'پشتیبانی',telegram:'ربات',news:'اخبار',admins:'ادمین‌ها'},
  en:{dash:'Dashboard',configs:'Configs',create:'Create',stats:'Stats',logs:'Logs',settings:'Settings',support:'Support',telegram:'Bot',news:'News',admins:'Admins'}
};
let USER_PERMS=null;
let USER_ROLE='owner';
function buildPermChecks(containerId, selected){
  const box=document.getElementById(containerId);
  if(!box)return;
  const labels=PERM_LABELS[lang]||PERM_LABELS.fa;
  box.innerHTML=Object.keys(labels).map(k=>{
    const on=selected?!!selected[k]:(['dash','configs','create','stats','news'].includes(k));
    return `<div style="display:flex;align-items:center;justify-content:space-between;gap:10px;padding:10px 12px;border-radius:12px;background:var(--bg3);border:1px solid var(--card-b)">
      <span style="font-size:12px;font-weight:600">${labels[k]}</span>
      <label class="switch"><input type="checkbox" data-perm="${k}" ${on?'checked':''}><span class="slider"></span></label>
    </div>`;
  }).join('');
}
function readPermChecks(containerId){
  const out={};
  document.querySelectorAll('#'+containerId+' input[data-perm]').forEach(inp=>{out[inp.getAttribute('data-perm')]=inp.checked});
  return out;
}
async function loadMe(){
  const r=await api('/api/me');
  if(!r)return;
  USER_ROLE=r.role||'owner';
  USER_PERMS=r.permissions||{};
  document.querySelectorAll('.nav-item[data-perm]').forEach(el=>{
    const p=el.getAttribute('data-perm');
    if(USER_ROLE==='owner'){el.style.display='';return}
    el.style.display=USER_PERMS[p]?'':'none';
  });
  // hide admins for non-owner always if no perm
  document.querySelectorAll('.nav-item[data-page="admins"]').forEach(el=>{
    if(USER_ROLE!=='owner') el.style.display='none';
  });
}
async function loadNews(toastOk){
  const r=await api('/api/news');
  if(!r)return;
  document.getElementById('newsTitle').textContent=r.title||(lang==='fa'?'بدون عنوان':'No title');
  document.getElementById('newsBody').textContent=r.message||'';
  document.getElementById('newsMeta').textContent=(lang==='fa'?'بروزرسانی: ':'Updated: ')+(r.updated_at||'—');
  if(toastOk) toast(lang==='fa'?'اطلاعیه بروزرسانی شد':'News refreshed');
}
async function loadAdmins(){
  buildPermChecks('adPerms');
  const r=await api('/api/admins');
  const box=document.getElementById('adminsList');
  if(!r||!r.admins){box.innerHTML='<div style="color:var(--t3);text-align:center;padding:20px">—</div>';return}
  if(!r.admins.length){box.innerHTML=`<div style="color:var(--t3);text-align:center;padding:20px">${lang==='fa'?'ادمینی نیست':'No admins'}</div>`;return}
  const labels=PERM_LABELS[lang]||PERM_LABELS.fa;
  box.innerHTML=r.admins.map(a=>{
    const st=a.blocked?'🔴 مسدود':(a.valid?'🟢 فعال':'🟠 نامعتبر');
    const perms=Object.entries(a.permissions||{}).filter(([,v])=>v).map(([k])=>labels[k]||k).join(' · ')||'—';
    return `<div style="border:1px solid var(--card-b);border-radius:12px;padding:12px;margin-bottom:10px;background:var(--bg3)">
      <div style="display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap;align-items:center">
        <div><b>${esc(a.username)}</b> <span style="font-size:11px;color:var(--t3)">${st}</span></div>
        <div class="ops" style="align-items:center">
          <label class="switch" title="مسدود">
            <input type="checkbox" ${a.blocked?'checked':''} onchange="toggleBlockAdmin('${esc(a.id)}',this.checked)">
            <span class="slider"></span>
          </label>
          <button class="btn btn-sm btn-d" onclick="deleteAdmin('${esc(a.id)}')">حذف</button>
        </div>
      </div>
      <div style="font-size:11px;color:var(--t3);margin-top:8px">حجم: ${fmtB(a.used_bytes)}${a.limit_bytes?(' / '+fmtB(a.limit_bytes)):' / ∞'} · انقضا: ${a.expires_at||'∞'}</div>
      <div style="font-size:11px;color:var(--t2);margin-top:6px">${perms}</div>
    </div>`;
  }).join('');
}
async function createAdmin(){
  const body={
    username:document.getElementById('adUser').value.trim(),
    password:document.getElementById('adPw').value,
    repeat_password:document.getElementById('adPw2').value,
    limit_value:Number(document.getElementById('adLimit').value)||0,
    limit_unit:document.getElementById('adUnit').value,
    expires_days:Number(document.getElementById('adDays').value)||0,
    permissions:readPermChecks('adPerms')
  };
  const r=await api('/api/admins',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(r){toast(lang==='fa'?'اکانت ساخته شد':'Created');document.getElementById('adUser').value='';document.getElementById('adPw').value='';document.getElementById('adPw2').value='';loadAdmins()}
}
async function toggleBlockAdmin(id,blocked){
  const r=await api('/api/admins/'+id,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({blocked})});
  if(r){toast(blocked?'مسدود شد':'رفع شد');loadAdmins()}
}
async function deleteAdmin(id){
  if(!confirm(lang==='fa'?'حذف اکانت؟':'Delete?'))return;
  const r=await api('/api/admins/'+id,{method:'DELETE'});
  if(r){toast('OK');loadAdmins()}
}


async function loadProtocols(){
  const r=await api('/api/protocols');
  const list=(r&&r.protocols)||[];
  const def=(r&&r.default)||'vless-ws';
  ['cProto','aProto'].forEach(id=>{
    const el=document.getElementById(id);
    if(!el)return;
    el.innerHTML=list.map(p=>`<option value="${esc(p.id)}" ${p.id===def?'selected':''}>${esc(p.label||p.id)}</option>`).join('')
      ||'<option value="vless-ws">VLESS WebSocket</option>';
  });
}
let __allLinks=[];
function filterConfigs(){
  const q=(document.getElementById('cfgSearch')?.value||'').trim().toLowerCase();
  if(!q){renderLinks(__allLinks);return}
  renderLinks(__allLinks.filter(l=>{
    const name=(l.label||l.name||'').toLowerCase();
    const proto=(l.protocol||'').toLowerCase();
    const uid=String(l.uuid||l.id||'').toLowerCase();
    return name.includes(q)||proto.includes(q)||uid.includes(q);
  }));
}
async function resetUsage(uid){
  if(!confirm(lang==='fa'?'مصرف ریست شود؟':'Reset usage?'))return;
  const r=await api('/api/links/'+uid+'/reset-usage',{method:'POST'});
  if(r!==null){toast(lang==='fa'?'مصرف ریست شد':'Usage reset');refreshAll()}
}


let __dragUid=null;
function cfgDragStart(e){__dragUid=e.currentTarget.getAttribute('data-uid');e.currentTarget.style.opacity='.5';e.dataTransfer.effectAllowed='move';}
function cfgDragOver(e){e.preventDefault();e.dataTransfer.dropEffect='move';const tr=e.currentTarget;if(tr&&tr.tagName==='TR')tr.style.background='var(--hover)';}
function cfgDragEnd(e){e.currentTarget.style.opacity='1';document.querySelectorAll('#linksTable tr').forEach(tr=>tr.style.background='');}
async function cfgDrop(e){
  e.preventDefault();
  const target=e.currentTarget.getAttribute('data-uid');
  document.querySelectorAll('#linksTable tr').forEach(tr=>tr.style.background='');
  if(!__dragUid||!target||__dragUid===target)return;
  const rows=[...document.querySelectorAll('#linksTable tr[data-uid]')];
  const ids=rows.map(r=>r.getAttribute('data-uid'));
  const from=ids.indexOf(__dragUid), to=ids.indexOf(target);
  if(from<0||to<0)return;
  ids.splice(from,1);ids.splice(to,0,__dragUid);
  // reorder DOM optimistically
  const tb=document.getElementById('linksTable');
  ids.forEach(id=>{const el=tb.querySelector(`tr[data-uid="${id}"]`);if(el)tb.appendChild(el);});
  await api('/api/links/reorder',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({order:ids})});
  toast(lang==='fa'?'ترتیب ذخیره شد':'Order saved');
}

function updateBulkBar(){
  const n=document.querySelectorAll('.cfg-chk:checked').length;
  const bar=document.getElementById('bottomBulkBar');
  const cnt=document.getElementById('bulkCount');
  if(cnt) cnt.textContent = n + (lang==='fa'?' انتخاب‌شده':' selected');
  if(bar) bar.classList.toggle('show', n>0);
  const all=document.getElementById('chkAll');
  if(all && n===0) all.checked=false;
}
function clearSelection(){
  document.querySelectorAll('.cfg-chk').forEach(c=>c.checked=false);
  const all=document.getElementById('chkAll');
  if(all) all.checked=false;
  updateBulkBar();
}
function toggleSelectAll(on){
  document.querySelectorAll('.cfg-chk').forEach(c=>c.checked=!!on);
  updateBulkBar();
}

function selectedCfgIds(){return [...document.querySelectorAll('.cfg-chk:checked')].map(c=>c.value)}
async function bulkDelete(){
  const ids=selectedCfgIds();
  if(!ids.length){toast(lang==='fa'?'چیزی انتخاب نشده':'Nothing selected');return}
  if(!confirm(lang==='fa'?`حذف ${ids.length} کانفیگ؟`:`Delete ${ids.length}?`))return;
  const r=await api('/api/links/bulk-delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ids})});
  if(r){toast(lang==='fa'?`حذف شد: ${r.deleted}`:`Deleted: ${r.deleted}`);refreshAll()}
}
async function bulkMoveGroup(){
  const ids=selectedCfgIds();
  const cid=document.getElementById('bulkGroup')?.value||'0';
  if(!ids.length){toast(lang==='fa'?'چیزی انتخاب نشده':'Nothing selected');return}
  const r=await api('/api/links/bulk-category',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ids,category_id:cid})});
  if(r){toast(lang==='fa'?'به گروه منتقل شد':'Moved');refreshAll()}
}
async function loadGroups(){
  const r=await api('/api/categories');
  const list=(r&&r.categories)||[];
  window.__catMap={};
  list.forEach(g=>{window.__catMap[String(g.id)]=g.name||g.id});
  const bulk=document.getElementById('bulkGroup');
  const cGroup=document.getElementById('cGroup');
  const opts=list.map(g=>`<option value="${esc(g.id)}">${esc(g.name||g.id)}</option>`).join('');
  if(bulk) bulk.innerHTML=opts||'<option value="0">عمومی</option>';
  if(cGroup) cGroup.innerHTML=opts||'<option value="0">عمومی</option>';
  const box=document.getElementById('groupsList');
  if(box){
    if(!list.length){box.innerHTML='<div style="color:var(--t3);text-align:center;padding:16px">—</div>';}
    else{
      box.innerHTML=list.map(g=>{
        const cnt=(__allLinks||[]).filter(l=>String(l.category_id||'0')===String(g.id)).length;
        return `<div style="border:1px solid var(--card-b);border-radius:12px;padding:12px;margin-bottom:8px;background:var(--bg3);display:flex;justify-content:space-between;gap:8px;align-items:center;flex-wrap:wrap">
          <div><b>${esc(g.name)}</b> <span style="font-size:11px;color:var(--t3)">${cnt} کانفیگ</span></div>
          <button class="btn btn-sm btn-d" onclick="deleteGroup('${esc(g.id)}')">حذف</button>
        </div>`;
      }).join('');
    }
  }
}
async function createGroup(){
  const name=document.getElementById('grpName').value.trim();
  if(!name){toast('نام لازم است');return}
  const r=await api('/api/categories',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name})});
  if(r){toast('گروه ساخته شد');document.getElementById('grpName').value='';loadGroups()}
}
async function deleteGroup(id){
  if(!confirm('حذف گروه؟'))return;
  const r=await api('/api/categories/'+id,{method:'DELETE'});
  if(r){toast('حذف شد');loadGroups();refreshAll()}
}


async function loadSecurity(){
  const r=await api('/api/security/status');
  const el=document.getElementById('secStatus');
  if(!r||!el)return;
  const locked=(r.locked_ips||[]).map(x=>`${x.ip} (${Math.ceil(x.remaining_sec/60)}د)`).join(' · ')||'—';
  el.innerHTML=`حداکثر تلاش: <b>${r.max_attempts}</b> · قفل: <b>${Math.round(r.lockout_seconds/60)} دقیقه</b><br>IPهای مسدود: ${locked}`;
}
async function unlockAllIps(){
  if(!confirm('رفع مسدودی همه؟'))return;
  const r=await api('/api/security/unlock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({})});
  if(r){toast('انجام شد');loadSecurity()}
}


async function downloadBackup(kind){
  try{
    const url = kind==='bot' ? '/api/backup/bot' : '/api/backup/users';
    const r = await fetch(url, {credentials:'same-origin', cache:'no-store'});
    if(r.status===401){ location.href='/login'; return; }
    if(!r.ok){
      let msg='خطا';
      try{ const j=await r.json(); msg=j.detail||msg; }catch(e){}
      toast(String(msg)); return;
    }
    const text = await r.text();
    // validate json
    try{ JSON.parse(text); }catch(e){ toast('پاسخ نامعتبر'); return; }
    const blob = new Blob([text], {type:'application/json;charset=utf-8'});
    const a = document.createElement('a');
    const stamp = new Date().toISOString().slice(0,19).replace(/[:T]/g,'-');
    a.href = URL.createObjectURL(blob);
    a.download = kind==='bot' ? ('pxpanel-bot-'+stamp+'.json') : ('pxpanel-users-'+stamp+'.json');
    document.body.appendChild(a);
    a.click();
    setTimeout(()=>{ URL.revokeObjectURL(a.href); a.remove(); }, 500);
    toast(lang==='fa'?'دانلود شد':'Downloaded');
  }catch(e){ toast(String(e.message||e)); }
}
function readJsonFile(inputId){
  return new Promise((resolve,reject)=>{
    const inp=document.getElementById(inputId);
    if(!inp||!inp.files||!inp.files[0]){ reject(new Error(lang==='fa'?'فایل انتخاب نشده':'No file')); return; }
    const fr=new FileReader();
    fr.onload=()=>{ try{ resolve(JSON.parse(fr.result)); }catch(e){ reject(new Error('JSON نامعتبر')); } };
    fr.onerror=()=>reject(new Error('خواندن فایل ناموفق'));
    fr.readAsText(inp.files[0],'utf-8');
  });
}
async function restoreUsers(mode){
  try{
    const data = await readJsonFile('restoreUsersFile');
    data.mode = mode||'merge';
    if(mode==='replace' && !confirm(lang==='fa'?'همه داده‌های فعلی پاک و جایگزین می‌شود. مطمئنی؟':'Replace all current data?')) return;
    const r = await api('/api/restore/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
    if(r){ toast(lang==='fa'?('بازیابی شد: '+r.links+' کانفیگ'):('Restored: '+r.links)); refreshAll(); }
  }catch(e){ toast(e.message||String(e)); }
}
async function restoreBot(){
  try{
    const data = await readJsonFile('restoreBotFile');
    const r = await api('/api/restore/bot',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
    if(r) toast(r.message||(lang==='fa'?'ربات بازیابی شد':'Bot restored'));
  }catch(e){ toast(e.message||String(e)); }
}

applyLang();loadMe();loadProtocols();loadGroups();refreshAll();setInterval(refreshAll,1000);


</script>
</body>
</html>
"""




@app.get(
    "/dashboard",
    response_class=HTMLResponse,
)
async def dashboard(
    request: Request,
):

    if not await is_valid_session(
        request.cookies.get(
            SESSION_COOKIE
        )
    ):
        return RedirectResponse(
            "/login"
        )

    await ensure_default_categories()
    await ensure_default_link()

    return HTMLResponse(
        DASHBOARD_HTML
    )


# ============================================================
# TEST
# ============================================================

@app.get(
    "/test-ws",
    response_class=HTMLResponse,
)
async def test_ws():

    return HTMLResponse(
        """
        <script>
        location.href='/dashboard'
        </script>
        """
    )


# ============================================================
# GLOBAL ERROR HANDLER
# ============================================================

@app.exception_handler(Exception)
async def global_exception_handler(
    request: Request,
    exc: Exception,
):

    stats[
        "total_errors"
    ] += 1

    error_logs.append(
        {
            "error":
                str(exc),

            "path":
                str(request.url),

            "method":
                request.method,

            "time":
                datetime.now().isoformat(),
        }
    )

    logger.exception(
        "Unhandled exception: %s %s",
        request.method,
        request.url,
    )

    # API requests
    if (
        request.url.path.startswith(
            "/api/"
        )
        or request.url.path == "/stats"
    ):

        return JSONResponse(
            {
                "ok": False,
                "error":
                    str(exc)
                or "internal server error",
            },
            status_code=500,
        )

    return HTMLResponse(
        """
        <html lang="fa" dir="rtl">
        <body style="
            background:#07070a;
            color:#fff;
            font-family:sans-serif;
            padding:40px;
        ">
            <h2>
            خطای داخلی PX Panel
            </h2>

            <p>
            لطفاً لاگ Railway را بررسی کنید.
            </p>
        </body>
        </html>
        """,
        status_code=500,
    )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=PORT,
        log_level="info",
        workers=1,
    )
