import os
import json
import re
import urllib.parse
import urllib.request
import logging
from http.server import BaseHTTPRequestHandler

if not logging.getLogger().handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

logger = logging.getLogger(__name__)

# ----------------------------
# 1) Мини-загрузчик .env
# ----------------------------
def load_dotenv(path: str = ".env") -> None:
    """
    Очень простой парсер .env:
    - читает строки KEY=VALUE
    - игнорирует пустые строки и комментарии #
    - значения кладёт в os.environ, если их там ещё нет
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

# ----------------------------
# 2) Настройки из окружения
# ----------------------------
BOT_TOKEN = os.environ["BOT_TOKEN"]
FAMILY_CHAT_ID = int(os.environ["FAMILY_CHAT_ID"])

# Секрет только для Telegram webhook (X-Telegram-Bot-Api-Secret-Token).
TG_SECRET = os.environ.get("TG_SECRET", "").strip()

# (Опционально) Секрет/ключ для Алисы. В Диалогах нет обязательного общего "секретного заголовка",
# поэтому по умолчанию мы НЕ проверяем. Если хочешь — можешь прокинуть свой shared secret
# и проверять его по заголовку X-Api-Key (или любому другому, который ты сам выставишь на прокси).
ALICE_SECRET = os.environ.get("ALICE_SECRET", "").strip()

# Маппинг имён из env:
# NAME_ALIASES=илье:Ильи,илью:Ильи,илья:Ильи,веронике:Веронике,...
RAW_ALIASES = os.environ.get("NAME_ALIASES", "").strip()


def normalize_text(s: str) -> str:
    """trim + lowercase + ё->е"""
    return (s or "").strip().lower().replace("ё", "е")


def parse_aliases(raw: str) -> dict:
    """
    "илье:Ильи,веронике:Веронике" -> {"илье":"Ильи", "веронике":"Веронике"}
    """
    out = {}
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

# ----------------------------
# 3) Telegram API helper
# ----------------------------
def tg_api(method: str, payload: dict) -> dict:
    logger.info("Calling Telegram API method %s", method)
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


# ----------------------------
# 4) Парсинг фразы "передай ..."
# ----------------------------
# Поддерживаем:
# - "передай илье купить что-то"
# - "алиса передай илье купить что-то"
# - "попроси илью настроить бота" (если хочешь)
CMD_RE = re.compile(
    r"^(?:алиса[\s,:\-]*)?(?:передай|попроси)\s+(\S+)\s+(.+)$",
    re.IGNORECASE
)


def canonical_name(raw_name: str) -> str:
    """
    Через алиасы можно добиться нужного падежа.
    Например: илье:Ильи -> будет "Для Ильи".
    """
    key = normalize_text(raw_name)
    if key in NAME_ALIASES:
        return NAME_ALIASES[key]
    n = (raw_name or "").strip()
    return n[:1].upper() + n[1:] if n else n


def parse_pereday(text: str):
    """Возвращает (to_name, message) или None."""
    t = (text or "").strip()
    if not t:
        return None

    m = CMD_RE.match(t)
    if not m:
        return None

    to_raw = m.group(1).strip()
    msg = m.group(2).strip()

    msg = re.sub(r"^[\s:\-]+", "", msg).strip()

    # "передай илье что я дома" -> "я дома"
    if normalize_text(msg).startswith("что "):
        msg = msg.split(" ", 1)[1].strip()

    if not to_raw or not msg:
        return None

    return canonical_name(to_raw), msg


def format_out(to_name: str, msg: str) -> str:
    # пример: "Для Ильи\nкупить что-то"
    return f"Для {to_name}\n{msg.strip()}"


# ----------------------------
# 5) Отличаем Telegram update от Яндекс Диалогов
# ----------------------------
def is_yandex_dialogs_payload(obj: dict) -> bool:
    """
    У Диалогов обычно есть meta/request/session/version.
    """
    if not isinstance(obj, dict):
        return False
    return (
        "request" in obj
        and "session" in obj
        and "version" in obj
        and isinstance(obj.get("request"), dict)
        and isinstance(obj.get("session"), dict)
    )


def build_alice_response(request_payload: dict, text: str, end_session: bool = True) -> dict:
    """
    Ответ в формате Яндекс Диалогов.
    Важно вернуть version + response + тот же session (можно целиком).
    """
    return {
        "version": request_payload.get("version", "1.0"),
        "session": request_payload.get("session", {}),
        "response": {
            "text": text,
            "end_session": end_session,
        },
    }


def extract_alice_text(payload: dict) -> str:
    """
    Что пользователь сказал: лучше брать request.command
    (если вдруг пусто — fallback на original_utterance).
    """
    req = payload.get("request") or {}
    return (req.get("command") or req.get("original_utterance") or "").strip()


# ----------------------------
# 6) Обработчик Webhook для Vercel
# ----------------------------
class Handler(BaseHTTPRequestHandler):
    def _ok_text(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"ok")

    def _json(self, status: int, obj: dict):
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps(obj, ensure_ascii=False).encode("utf-8"))

    def do_GET(self):
        # Healthcheck
        logger.info("Healthcheck GET from %s", self.client_address)
        self._ok_text()

    def do_POST(self):
        logger.info("Received POST from %s", self.client_address)

        # 1) читаем JSON тела один раз
        length = int(self.headers.get("content-length", 0))
        raw = self.rfile.read(length) if length > 0 else b"{}"

        # Декодируем безопасно: Диалоги и Telegram шлют UTF-8.
        try:
            raw_text = raw.decode("utf-8")
            payload = json.loads(raw_text) if raw_text else {}
        except Exception:
            logger.exception("Invalid JSON body")
            self._json(400, {"ok": False, "error": "invalid json"})
            return

        # 2) Ветка A: Яндекс Диалоги (Алиса)
        if is_yandex_dialogs_payload(payload):
            # (опционально) своя проверка доступа, если ты сам прокидываешь заголовок из прокси
            if ALICE_SECRET:
                got = self.headers.get("X-Api-Key", "")
                if got != ALICE_SECRET:
                    logger.warning("Alice request unauthorized (bad X-Api-Key)")
                    self._json(401, build_alice_response(payload, "Доступ запрещён.", end_session=True))
                    return

            spoken = extract_alice_text(payload)
            logger.info("Alice command: %s", spoken)

            parsed = parse_pereday(spoken)
            if parsed:
                to_name, msg = parsed
                tg_send_message(FAMILY_CHAT_ID, format_out(to_name, msg))
                # Алисе отвечаем коротко
                resp = build_alice_response(payload, f"Ок, передала для {to_name}.", end_session=True)
            else:
                resp = build_alice_response(
                    payload,
                    "Скажи так: «передай <имя> <сообщение>». Например: «передай Илье купить хлеб».",
                    end_session=True
                )

            self._json(200, resp)
            return

        # 3) Ветка B: Telegram webhook (как раньше)
        # Проверяем секрет ТОЛЬКО если это Telegram.
        if TG_SECRET:
            got = self.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
            if got != TG_SECRET:
                logger.warning("Telegram request unauthorized (bad secret)")
                self._json(401, {"ok": False, "error": "unauthorized"})
                return

        # Событие "бота добавили в чат" — выйти, если не наш чат
        my_chat_member = payload.get("my_chat_member")
        if isinstance(my_chat_member, dict):
            chat = my_chat_member.get("chat") or {}
            chat_id = chat.get("id")
            if isinstance(chat_id, int) and chat_id != FAMILY_CHAT_ID:
                tg_leave_chat(chat_id)
            self._ok_text()
            return

        # Обычное сообщение
        message = payload.get("message") or payload.get("edited_message") or {}
        chat = message.get("chat") or {}
        chat_id = chat.get("id")
        text = message.get("text") or ""

        if chat_id != FAMILY_CHAT_ID:
            self._ok_text()
            return

        parsed = parse_pereday(text)
        if parsed:
            to_name, msg = parsed
            tg_send_message(FAMILY_CHAT_ID, format_out(to_name, msg))

        self._ok_text()

    def log_message(self, format, *args):
        # глушим дефолтный http.server лог, чтобы не дублировать
        logger.info("%s - - %s", self.client_address[0], format % args)


handler = Handler
