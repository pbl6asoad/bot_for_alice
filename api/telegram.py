import os
import json
import re
import urllib.parse
import urllib.request
import logging
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
    """
    Простой парсер .env:
      KEY=VALUE
    Игнорирует пустые строки и комментарии (#).
    Не перетирает уже существующие переменные окружения.
    """
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

# Секрет ТОЛЬКО для Telegram webhook (X-Telegram-Bot-Api-Secret-Token)
TG_SECRET = os.environ.get("TG_SECRET", "").strip()

# (опционально) Секрет для запросов от твоего прокси/инфры (если хочешь защитить Алису доп.ключом)
# Тогда ты сам должен отправлять заголовок X-Api-Key: <ALICE_SECRET> со своей стороны.
ALICE_SECRET = os.environ.get("ALICE_SECRET", "").strip()
debug_on = (self.headers.get("X-Debug", "") == "1") and (not ALICE_SECRET or self.headers.get("X-Api-Key", "") == ALICE_SECRET)

# (опционально) allowlist пользователей Яндекса по session.user_id
# Пример: ALLOWED_YANDEX_USER_IDS=AAABBB,CCCDDD
ALLOWED_YANDEX_USER_IDS = {
    x.strip()
    for x in os.environ.get("ALLOWED_YANDEX_USER_IDS", "").split(",")
    if x.strip()
}

# Маппинг имён (чтобы сделать "Для Ильи" и т.п.)
# ВАЖНО: "Для <кого?>" — это родительный падеж, поэтому алиасы стоит хранить уже в нужном падеже.
# Пример:
# NAME_ALIASES=илья:Ильи,илье:Ильи,илью:Ильи,веронике:Вероники
RAW_ALIASES = os.environ.get("NAME_ALIASES", "").strip()


def normalize_text(s: str) -> str:
    """trim + lowercase + ё->е"""
    return (s or "").strip().lower().replace("ё", "е")


def parse_aliases(raw: str) -> Dict[str, str]:
    """
    "илье:Ильи,веронике:Вероники" -> {"илье":"Ильи", "веронике":"Вероники"}
    """
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
# 3) Telegram API helper
# ------------------------------------------------------------
def tg_api(method: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Вызов Telegram Bot API стандартной библиотекой (без requests).
    """
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


def tg_send_message(chat_id: int, text: str) -> None:
    logger.info("Sending message to chat_id=%s", chat_id)
    tg_api("sendMessage", {"chat_id": chat_id, "text": text})


def tg_leave_chat(chat_id: int) -> None:
    logger.warning("Leaving chat chat_id=%s", chat_id)
    tg_api("leaveChat", {"chat_id": chat_id})


# ------------------------------------------------------------
# 4) Парсинг команд "передай/попроси"
# ------------------------------------------------------------
# Поддерживаем:
# - "передай илье купить что-то"
# - "алиса передай илье купить что-то"
# - "попроси илью настроить бота"
CMD_RE = re.compile(
    r"^(?:алиса[\s,:\-]*)?(?:передай|попроси)\s+(\S+)\s+(.+)$",
    re.IGNORECASE,
)


def canonical_name(raw_name: str) -> str:
    """
    Приводим имя к нужному виду через алиасы.
    Если алиаса нет — просто делаем первую букву заглавной (падеж не исправляет).
    """
    key = normalize_text(raw_name)
    if key in NAME_ALIASES:
        return NAME_ALIASES[key]
    n = (raw_name or "").strip()
    return n[:1].upper() + n[1:] if n else n


def parse_forward_command(text: str) -> Optional[Tuple[str, str]]:
    """
    Возвращает (to_name, message) или None.
    """
    t = (text or "").strip()
    if not t:
        return None

    m = CMD_RE.match(t)
    if not m:
        return None

    to_raw = m.group(1).strip()
    msg = m.group(2).strip()

    # уберём ведущие двоеточия/тире после имени
    msg = re.sub(r"^[\s:\-]+", "", msg).strip()

    # "передай илье что я дома" -> "я дома"
    if normalize_text(msg).startswith("что "):
        msg = msg.split(" ", 1)[1].strip()

    if not to_raw or not msg:
        return None

    return canonical_name(to_raw), msg


def format_out(to_name: str, msg: str) -> str:
    # Пример, как ты хочешь:
    # "Для Ильи\nкупить что-то"
    return f"Для {to_name}\n{msg.strip()}"


# ------------------------------------------------------------
# 5) Яндекс Диалоги (Алиса): распознавание payload и ответы
# ------------------------------------------------------------
def is_yandex_dialogs_payload(obj: Dict[str, Any]) -> bool:
    """
    Диалоги присылают JSON с полями meta/request/session/version.
    Мы используем более мягкую проверку: request + session + version.
    """
    return (
        isinstance(obj, dict)
        and isinstance(obj.get("request"), dict)
        and isinstance(obj.get("session"), dict)
        and "version" in obj
    )


def extract_alice_text(payload: Dict[str, Any]) -> str:
    """
    В Диалогах фраза пользователя лежит в request.command (нормализовано).
    Fallback: original_utterance.
    """
    req = payload.get("request") or {}
    return (req.get("command") or req.get("original_utterance") or "").strip()


def extract_alice_access_token(headers, payload: Dict[str, Any]) -> str:
    """
    После account linking токен обычно приходит:
      - в заголовке Authorization: Bearer <token>
      - или в payload.session.user.access_token
    """
    auth = headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth.split(" ", 1)[1].strip()

    sess = payload.get("session") or {}
    user = sess.get("user") or {}
    tok = user.get("access_token") or ""
    return (tok or "").strip()


def alice_user_allowed(payload: Dict[str, Any]) -> bool:
    """
    Если allowlist пустой — разрешаем всем (удобно на этапе разработки).
    Если задан ALLOWED_YANDEX_USER_IDS — разрешаем только перечисленным user_id.
    """
    if not ALLOWED_YANDEX_USER_IDS:
        return True
    uid = (payload.get("session") or {}).get("user_id") or ""
    return uid in ALLOWED_YANDEX_USER_IDS


def alice_response_text(payload: Dict[str, Any], text: str, end_session: bool = True) -> Dict[str, Any]:
    return {
        "version": payload.get("version", "1.0"),
        "session": payload.get("session", {}),
        "response": {
            "text": text,
            "end_session": end_session,
        },
    }


def alice_response_start_linking(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ответ, который запускает привязку аккаунта.
    """
    return {
        "version": payload.get("version", "1.0"),
        "session": payload.get("session", {}),
        "start_account_linking": {},
    }


# ------------------------------------------------------------
# 6) Handler (Vercel Python Function)
# ------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    def _ok_text(self, text: str = "ok", extra_headers: dict | None = None):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, str(v))
        self.end_headers()
        self.wfile.write(text.encode("utf-8"))

    def _json(self, status: int, obj: dict, extra_headers: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, str(v))
        self.end_headers()
        self.wfile.write(json.dumps(obj, ensure_ascii=False).encode("utf-8"))


    def do_GET(self):
        # Healthcheck
        logger.info("GET %s from %s", self.path, self.client_address)
        self._ok_text("ok")

    def do_POST(self):
        logger.info("POST %s from %s", self.path, self.client_address)
        req_id = str(uuid.uuid4())

        # Читаем тело
        length = int(self.headers.get("content-length", 0))
        raw = self.rfile.read(length) if length > 0 else b"{}"

        # Диалоги и Telegram присылают UTF-8 JSON
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except Exception:
            logger.exception("Invalid JSON body")
            self._json(400, {"ok": False, "error": "invalid json"})
            return

        # ----------------------------
        # ВЕТКА A: Яндекс Диалоги (Алиса)
        # ----------------------------
        if is_yandex_dialogs_payload(payload):
            # (опционально) доп. защита, если ты сам прокидываешь X-Api-Key через свой прокси
            if ALICE_SECRET:
                got = self.headers.get("X-Api-Key", "")
                if got != ALICE_SECRET:
                    logger.warning("Alice request unauthorized (bad X-Api-Key)")
                    self._json(200, alice_response_text(payload, "Доступ запрещён.", end_session=True))
                    return

            spoken = extract_alice_text(payload)
            token = extract_alice_access_token(self.headers, payload)
            user_id = (payload.get("session") or {}).get("user_id")

            logger.info(
                "Alice user_id=%s token_present=%s token_len=%d command=%r",
                user_id,
                bool(token),
                len(token) if token else 0,
                spoken,
            )

            # Если токена нет — просим сделать привязку аккаунта
            if not token:
                self._json(200, alice_response_start_linking(payload))
                return

            # Ограничение доступа по allowlist (если задан)
            if not alice_user_allowed(payload):
                self._json(200, alice_response_text(payload, "У вас нет доступа к этому навыку.", end_session=True))
                return

            parsed = parse_forward_command(spoken)
            if not parsed:
                self._json(
                    200,
                    alice_response_text(
                        payload,
                        "Скажи так: «передай <имя> <сообщение>». Например: «передай Илье купить хлеб».",
                        end_session=True,
                    ),
                )
                return

            to_name, msg = parsed
            tg_send_message(FAMILY_CHAT_ID, format_out(to_name, msg))
            self._json(200, alice_response_text(payload, f"Ок, передала для {to_name}.", end_session=True))
            return

        # ----------------------------
        # ВЕТКА B: Telegram webhook
        # ----------------------------
        if TG_SECRET:
            got = self.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
            if got != TG_SECRET:
                logger.warning("Telegram request unauthorized (bad secret)")
                self._json(401, {"ok": False, "error": "unauthorized"})
                return

        # my_chat_member — если бота добавили в чужой чат, выходим
        my_chat_member = payload.get("my_chat_member")
        if isinstance(my_chat_member, dict):
            chat = my_chat_member.get("chat") or {}
            chat_id = chat.get("id")
            if isinstance(chat_id, int) and chat_id != FAMILY_CHAT_ID:
                tg_leave_chat(chat_id)
            self._ok_text("ok")
            return

        # Обычное сообщение
        message = payload.get("message") or payload.get("edited_message") or {}
        chat = message.get("chat") or {}
        chat_id = chat.get("id")
        text = message.get("text") or ""

        if chat_id != FAMILY_CHAT_ID:
            self._ok_text("ok")
            return

        parsed = parse_forward_command(text)
        if parsed:
            to_name, msg = parsed
            tg_send_message(FAMILY_CHAT_ID, format_out(to_name, msg))

        self._ok_text("ok")

    def log_message(self, format, *args):
        # чтобы не дублировать стандартный http.server лог
        logger.info("%s - - %s", self.client_address[0], format % args)


# Vercel ищет переменную handler
handler = Handler
