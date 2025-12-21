import os
import json
import re
import urllib.parse
import urllib.request
import logging
import uuid
from http.server import BaseHTTPRequestHandler
from typing import Any, Dict, Optional, Tuple

# ------------------------------------------------------------
# Логирование
# ------------------------------------------------------------
if not logging.getLogger().handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
logger = logging.getLogger(__name__)

# ------------------------------------------------------------
# 1) Мини-загрузчик .env (локально удобно; на Vercel env задаются в UI)
# ------------------------------------------------------------
def load_dotenv(path: str = ".env") -> None:
    if not os.path.exists(path):
        logger.info(".env not found at %s, skipping", path)
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                os.environ.setdefault(k, v)
        logger.info("Loaded environment variables from %s", path)
    except Exception:
        logger.exception("Failed to load .env from %s", path)


load_dotenv()

# ------------------------------------------------------------
# 2) Настройки из окружения
# ------------------------------------------------------------
BOT_TOKEN = os.environ["BOT_TOKEN"]
FAMILY_CHAT_ID = int(os.environ["FAMILY_CHAT_ID"])

def clean_env(v: str) -> str:
    return (v or "").strip().replace("\r", "").replace("\n", "").strip('"').strip("'").strip()

# Секрет ТОЛЬКО для Telegram webhook (X-Telegram-Bot-Api-Secret-Token)
TG_SECRET = clean_env(os.environ.get("TG_SECRET", ""))

# (опционально) allowlist пользователей Яндекса по session.user_id
ALLOWED_YANDEX_USER_IDS = {
    x.strip()
    for x in os.environ.get("ALLOWED_YANDEX_USER_IDS", "").split(",")
    if x.strip()
}

# Маппинг имён в нужном падеже:
# NAME_ALIASES=илья:Ильи,илье:Ильи,илью:Ильи,веронике:Вероники
RAW_ALIASES = os.environ.get("NAME_ALIASES", "").strip()

def normalize_text(s: str) -> str:
    return (s or "").strip().lower().replace("ё", "е")

def parse_aliases(raw: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not raw:
        return out
    for part in raw.split(","):
        part = part.strip()
        if not part or ":" not in part:
            continue
        k, v = part.split(":", 1)
        k = normalize_text(k)
        v = v.strip()
        if k and v:
            out[k] = v
    logger.info("Parsed %d name aliases", len(out))
    return out

NAME_ALIASES = parse_aliases(RAW_ALIASES)

# ------------------------------------------------------------
# 3) Telegram API helper (stdlib)
# ------------------------------------------------------------
def tg_api(method: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/{method}"
    data = urllib.parse.urlencode(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:
        raw = resp.read().decode("utf-8")

    try:
        result = json.loads(raw)
        if not result.get("ok", False):
            logger.warning("Telegram API error (%s): %s", method, result.get("description"))
        return result
    except Exception:
        logger.exception("Failed to decode Telegram response for %s", method)
        return {"ok": False, "description": "bad json from telegram"}

def tg_send_message(chat_id: int, text: str) -> bool:
    logger.info("Sending message to chat_id=%s", chat_id)
    res = tg_api("sendMessage", {"chat_id": chat_id, "text": text})
    return bool(res.get("ok"))

def tg_leave_chat(chat_id: int) -> bool:
    logger.warning("Leaving chat chat_id=%s", chat_id)
    res = tg_api("leaveChat", {"chat_id": chat_id})
    return bool(res.get("ok"))

# ------------------------------------------------------------
# 4) Парсинг команд "передай/попроси"
# ------------------------------------------------------------
CMD_RE = re.compile(
    r"^(?:алиса[\s,:\-]*)?(?:передай|попроси)\s+(\S+)\s+(.+)$",
    re.IGNORECASE,
)

def canonical_name(raw_name: str) -> str:
    key = normalize_text(raw_name)
    if key in NAME_ALIASES:
        return NAME_ALIASES[key]
    n = (raw_name or "").strip()
    return n[:1].upper() + n[1:] if n else n

def parse_forward_command(text: str) -> Optional[Tuple[str, str]]:
    t = (text or "").strip()
    if not t:
        return None

    m = CMD_RE.match(t)
    if not m:
        return None

    to_raw = m.group(1).strip()
    msg = m.group(2).strip()

    msg = re.sub(r"^[\s:\-]+", "", msg).strip()
    if normalize_text(msg).startswith("что "):
        msg = msg.split(" ", 1)[1].strip()

    if not to_raw or not msg:
        return None

    return canonical_name(to_raw), msg

def format_out(to_name: str, msg: str) -> str:
    return f"Для {to_name}\n{msg.strip()}"

# ------------------------------------------------------------
# 5) Яндекс Диалоги (Алиса): распознавание payload и ответы
# ------------------------------------------------------------
def is_yandex_dialogs_payload(obj: Dict[str, Any]) -> bool:
    return (
        isinstance(obj, dict)
        and isinstance(obj.get("request"), dict)
        and isinstance(obj.get("session"), dict)
        and "version" in obj
    )

def extract_alice_text(payload: Dict[str, Any]) -> str:
    req = payload.get("request") or {}
    return (req.get("command") or req.get("original_utterance") or "").strip()

def extract_alice_access_token(headers, payload: Dict[str, Any]) -> str:
    auth = headers.get("Authorization", "") or headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return auth.split(" ", 1)[1].strip()

    # На всякий случай: иногда токен кладут иначе
    sess = payload.get("session") or {}
    user = sess.get("user") or {}
    tok = user.get("access_token") or ""
    return (tok or "").strip()

def alice_user_allowed(payload: Dict[str, Any]) -> bool:
    if not ALLOWED_YANDEX_USER_IDS:
        return True
    uid = (payload.get("session") or {}).get("user_id") or ""
    return uid in ALLOWED_YANDEX_USER_IDS

def alice_response_text(payload: Dict[str, Any], text: str, end_session: bool = True) -> Dict[str, Any]:
    return {
        "version": payload.get("version", "1.0"),
        "session": payload.get("session", {}),
        "response": {"text": text, "end_session": end_session},
    }

def alice_response_start_linking(payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "version": payload.get("version", "1.0"),
        "session": payload.get("session", {}),
        "start_account_linking": {},
    }

# ------------------------------------------------------------
# 6) Telegram update: распознавание и защита от дублей
# ------------------------------------------------------------
def is_telegram_update(payload: Dict[str, Any]) -> bool:
    # Telegram update обычно содержит update_id
    return isinstance(payload, dict) and ("update_id" in payload or "message" in payload or "my_chat_member" in payload)

def telegram_secret_ok(headers) -> bool:
    if not TG_SECRET:
        return True
    got = clean_env(headers.get("X-Telegram-Bot-Api-Secret-Token", "") or headers.get("x-telegram-bot-api-secret-token", ""))
    return got == TG_SECRET

def is_from_bot(message: Dict[str, Any]) -> bool:
    frm = message.get("from") or {}
    if isinstance(frm, dict) and frm.get("is_bot") is True:
        return True
    # Иногда прилетает sender_chat, или via_bot — это тоже можно считать “не от человека”
    if message.get("via_bot"):
        return True
    if message.get("sender_chat"):
        return True
    return False

# ------------------------------------------------------------
# 7) Handler
# ------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    def _ok_text(self, text: str = "ok", extra_headers: Optional[Dict[str, str]] = None):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, str(v))
        self.end_headers()
        self.wfile.write(text.encode("utf-8"))

    def _json(self, status: int, obj: Dict[str, Any], extra_headers: Optional[Dict[str, str]] = None):
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, str(v))
        self.end_headers()
        self.wfile.write(json.dumps(obj, ensure_ascii=False).encode("utf-8"))

    def do_GET(self):
        self._ok_text("ok")

    def do_POST(self):
        req_id = str(uuid.uuid4())
        debug_on = clean_env(self.headers.get("X-Debug", "")) == "1"

        length = int(self.headers.get("content-length", 0))
        raw = self.rfile.read(length) if length > 0 else b"{}"

        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except Exception:
            self._json(400, {"ok": False, "error": "invalid json"}, extra_headers={"X-Req-Id": req_id})
            return

        # ----------------------------
        # ВЕТКА A: Алиса
        # ----------------------------
        if is_yandex_dialogs_payload(payload):
            spoken = extract_alice_text(payload)
            token = extract_alice_access_token(self.headers, payload)
            user_id = (payload.get("session") or {}).get("user_id")

            if not token:
                resp = alice_response_start_linking(payload)
                if debug_on:
                    resp["debug"] = {"req_id": req_id, "is_alice": True, "token_present": False, "user_id": user_id, "command": spoken}
                self._json(200, resp, extra_headers={"X-Req-Id": req_id})
                return

            if not alice_user_allowed(payload):
                resp = alice_response_text(payload, "У вас нет доступа к этому навыку.", end_session=True)
                if debug_on:
                    resp["debug"] = {"req_id": req_id, "is_alice": True, "token_present": True, "user_id": user_id, "command": spoken, "reason": "user_not_allowed"}
                self._json(200, resp, extra_headers={"X-Req-Id": req_id})
                return

            parsed = parse_forward_command(spoken)
            if not parsed:
                resp = alice_response_text(
                    payload,
                    "Скажи так: «передай <имя> <сообщение>». Например: «передай Илье купить хлеб».",
                    end_session=True,
                )
                if debug_on:
                    resp["debug"] = {"req_id": req_id, "is_alice": True, "token_present": True, "user_id": user_id, "command": spoken, "parsed": None}
                self._json(200, resp, extra_headers={"X-Req-Id": req_id})
                return

            to_name, msg = parsed
            sent_ok = tg_send_message(FAMILY_CHAT_ID, format_out(to_name, msg))

            resp = alice_response_text(payload, f"Ок, передала для {to_name}.", end_session=True)
            if debug_on:
                resp["debug"] = {"req_id": req_id, "is_alice": True, "token_present": True, "user_id": user_id, "command": spoken, "parsed": [to_name, msg], "telegram_sent_ok": sent_ok}
            self._json(200, resp, extra_headers={"X-Req-Id": req_id})
            return

        # ----------------------------
        # ВЕТКА B: Telegram webhook
        # ----------------------------
        if is_telegram_update(payload):
            if not telegram_secret_ok(self.headers):
                self._json(401, {"ok": False, "error": "unauthorized"}, extra_headers={"X-Req-Id": req_id})
                return

            my_chat_member = payload.get("my_chat_member")
            if isinstance(my_chat_member, dict):
                chat = my_chat_member.get("chat") or {}
                chat_id = chat.get("id")
                if isinstance(chat_id, int) and chat_id != FAMILY_CHAT_ID:
                    tg_leave_chat(chat_id)
                self._ok_text("ok", extra_headers={"X-Req-Id": req_id})
                return

            message = payload.get("message") or payload.get("edited_message") or {}
            if not isinstance(message, dict) or not message:
                self._ok_text("ok", extra_headers={"X-Req-Id": req_id})
                return

            # 🔥 Главный анти-дубль: игнорируем сообщения, которые отправил бот (и похожие системные источники)
            if is_from_bot(message):
                self._ok_text("ok", extra_headers={"X-Req-Id": req_id})
                return

            chat = message.get("chat") or {}
            chat_id = chat.get("id")
            text = (message.get("text") or "").strip()

            if chat_id != FAMILY_CHAT_ID:
                self._ok_text("ok", extra_headers={"X-Req-Id": req_id})
                return

            parsed = parse_forward_command(text)
            if parsed:
                to_name, msg = parsed
                # Важно: если ты хочешь, чтобы команда в чате превращалась в новое сообщение,
                # это место верное. Если не хочешь дублей — анти-дубль выше должен спасти.
                tg_send_message(FAMILY_CHAT_ID, format_out(to_name, msg))

            self._ok_text("ok", extra_headers={"X-Req-Id": req_id})
            return

        # ----------------------------
        # ИНАЧЕ: неизвестный POST
        # ----------------------------
        self._json(400, {"ok": False, "error": "unknown payload"}, extra_headers={"X-Req-Id": req_id})

    def log_message(self, format, *args):
        return


handler = Handler
