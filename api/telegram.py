import os
import json
import urllib.parse
import urllib.request
import logging
import uuid
from http.server import BaseHTTPRequestHandler
from typing import Any, Dict, Optional


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
# 1) Мини-загрузчик .env
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
# 2) ENV
# ------------------------------------------------------------
BOT_TOKEN = os.environ["BOT_TOKEN"]
FAMILY_CHAT_ID = int(os.environ["FAMILY_CHAT_ID"])


def clean_env(v: str) -> str:
    return (v or "").strip().replace("\r", "").replace("\n", "").strip('"').strip("'").strip()


TG_SECRET = clean_env(os.environ.get("TG_SECRET", ""))

# (опционально) allowlist пользователей Яндекса по session.user_id
ALLOWED_YANDEX_USER_IDS = {
    x.strip()
    for x in os.environ.get("ALLOWED_YANDEX_USER_IDS", "").split(",")
    if x.strip()
}


# ------------------------------------------------------------
# 3) Telegram API helper (stdlib)
# ------------------------------------------------------------
def tg_api(method: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/{method}"
    data = urllib.parse.urlencode(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read().decode("utf-8")
    except Exception as e:
        logger.exception("Telegram request failed: method=%s err=%r", method, e)
        return {"ok": False, "description": f"telegram request failed: {e!r}"}

    try:
        result = json.loads(raw)
        if not result.get("ok", False):
            logger.warning("Telegram API error (%s): %s", method, result.get("description"))
        return result
    except Exception:
        logger.exception("Failed to decode Telegram response for %s: %r", method, raw[:400])
        return {"ok": False, "description": "bad json from telegram"}


def tg_send_message(chat_id: int, text: str) -> Dict[str, Any]:
    logger.info("TG sendMessage chat_id=%s text_preview=%r", chat_id, text[:160])
    return tg_api("sendMessage", {"chat_id": chat_id, "text": text})


def tg_leave_chat(chat_id: int) -> Dict[str, Any]:
    logger.warning("TG leaveChat chat_id=%s", chat_id)
    return tg_api("leaveChat", {"chat_id": chat_id})


# ------------------------------------------------------------
# 4) Алиса helpers
# ------------------------------------------------------------
def is_yandex_dialogs_payload(obj: Dict[str, Any]) -> bool:
    return (
        isinstance(obj, dict)
        and isinstance(obj.get("request"), dict)
        and isinstance(obj.get("session"), dict)
        and "version" in obj
    )


def extract_alice_text(payload: Dict[str, Any]) -> str:
    """
    Берём исходную пользовательскую фразу "как сказал человек".
    Приоритет: original_utterance -> command -> tokens fallback.
    """
    req = payload.get("request") or {}

    v = req.get("original_utterance")
    if isinstance(v, str) and v.strip():
        return v.strip()

    v = req.get("command")
    if isinstance(v, str) and v.strip():
        return v.strip()

    nlu = req.get("nlu") or {}
    tokens = nlu.get("tokens")
    if isinstance(tokens, list) and tokens:
        joined = " ".join(str(t) for t in tokens if t)
        if joined.strip():
            return joined.strip()

    return ""


def extract_alice_access_token(headers, payload: Dict[str, Any]) -> str:
    auth = headers.get("Authorization", "") or headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return auth.split(" ", 1)[1].strip()

    sess = payload.get("session") or {}
    user = sess.get("user") or {}
    tok = user.get("access_token") or ""
    return (tok or "").strip()


def alice_user_allowed(payload: Dict[str, Any]) -> bool:
    if not ALLOWED_YANDEX_USER_IDS:
        return True
    uid = (payload.get("session") or {}).get("user_id") or ""
    return uid in ALLOWED_YANDEX_USER_IDS


def alice_response_text(payload: Dict[str, Any], text: str, end_session: bool) -> Dict[str, Any]:
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
# 5) Telegram update helpers
# ------------------------------------------------------------
def is_telegram_update(payload: Dict[str, Any]) -> bool:
    # строго: чтобы не путать с Алисой
    return isinstance(payload, dict) and "update_id" in payload


def telegram_secret_ok(headers) -> bool:
    if not TG_SECRET:
        return True
    got = clean_env(
        headers.get("X-Telegram-Bot-Api-Secret-Token", "")
        or headers.get("x-telegram-bot-api-secret-token", "")
    )
    return got == TG_SECRET


def is_from_bot(message: Dict[str, Any]) -> bool:
    frm = message.get("from") or {}
    if isinstance(frm, dict) and frm.get("is_bot") is True:
        return True
    if message.get("via_bot"):
        return True
    if message.get("sender_chat"):
        return True
    return False


# ------------------------------------------------------------
# 6) Handler
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

        logger.info("Received POST from %s", getattr(self, "client_address", None))

        length = int(self.headers.get("content-length", 0))
        raw = self.rfile.read(length) if length > 0 else b"{}"

        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except Exception:
            logger.warning("Invalid JSON")
            self._json(400, {"ok": False, "error": "invalid json"}, extra_headers={"X-Req-Id": req_id})
            return

        # ----------------------------
        # A) Алиса — первой
        # ----------------------------
        if is_yandex_dialogs_payload(payload):
            req = payload.get("request") or {}
            sess = payload.get("session") or {}

            spoken = extract_alice_text(payload)
            token = extract_alice_access_token(self.headers, payload)

            logger.info(
                "Alice: skill_id=%s user_id=%s type=%r new=%s message_id=%s spoken=%r token_present=%s",
                sess.get("skill_id"),
                sess.get("user_id"),
                req.get("type"),
                bool(sess.get("new")),
                sess.get("message_id"),
                spoken,
                bool(token),
            )

            # Если пришёл старт навыка без текста — спрашиваем коротко и НЕ закрываем сессию
            if sess.get("new") and not spoken:
                resp = alice_response_text(payload, "Говори.", end_session=False)
                if debug_on:
                    resp["debug"] = {"req_id": req_id, "note": "new_session_empty"}
                self._json(200, resp, extra_headers={"X-Req-Id": req_id})
                return

            # Если хочешь вообще убрать привязку — удали этот блок целиком.
            if not token:
                resp = alice_response_start_linking(payload)
                if debug_on:
                    resp["debug"] = {"req_id": req_id, "token_present": False}
                self._json(200, resp, extra_headers={"X-Req-Id": req_id})
                return

            if not alice_user_allowed(payload):
                resp = alice_response_text(payload, "Нет доступа.", end_session=True)
                if debug_on:
                    resp["debug"] = {"req_id": req_id, "reason": "user_not_allowed"}
                self._json(200, resp, extra_headers={"X-Req-Id": req_id})
                return

            if not spoken:
                resp = alice_response_text(payload, "Повтори.", end_session=False)
                if debug_on:
                    resp["debug"] = {"req_id": req_id, "note": "empty_spoken"}
                self._json(200, resp, extra_headers={"X-Req-Id": req_id})
                return

            # Главное изменение: просто пересылаем фразу как есть
            tg_res = tg_send_message(FAMILY_CHAT_ID, spoken)
            logger.info("Telegram send: ok=%s desc=%r", tg_res.get("ok"), tg_res.get("description"))

            # Минимальный ответ
            ok = bool(tg_res.get("ok"))
            resp = alice_response_text(payload, "Готово." if ok else "Не получилось.", end_session=True)

            if debug_on:
                resp["debug"] = {
                    "req_id": req_id,
                    "spoken": spoken,
                    "telegram_ok": tg_res.get("ok"),
                    "telegram_desc": tg_res.get("description"),
                }

            self._json(200, resp, extra_headers={"X-Req-Id": req_id})
            return

        # ----------------------------
        # B) Telegram webhook — секрет только тут
        # ----------------------------
        if is_telegram_update(payload):
            if not telegram_secret_ok(self.headers):
                logger.warning("Unauthorized POST: bad secret token")
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

            # анти-дубль: игнорируем сообщения, которые отправил бот
            if is_from_bot(message):
                self._ok_text("ok", extra_headers={"X-Req-Id": req_id})
                return

            # В Telegram-ветке мы ничего не преобразуем — просто подтверждаем приём
            self._ok_text("ok", extra_headers={"X-Req-Id": req_id})
            return

        logger.warning("Unknown payload")
        self._json(400, {"ok": False, "error": "unknown payload"}, extra_headers={"X-Req-Id": req_id})

    def log_message(self, format, *args):
        return


handler = Handler
