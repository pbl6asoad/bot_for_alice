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
#    На Vercel .env файл НЕ подхватывается автоматически, там переменные задаются в UI.
#    Но локально (или на VPS) удобно иметь .env рядом — этот код его прочитает.
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
        # Если .env битый — просто не падаем, продолжим с переменными окружения
        logger.exception("Failed to load .env from %s", path)
        pass


load_dotenv()

# ----------------------------
# 2) Настройки из окружения
# ----------------------------
BOT_TOKEN = os.environ["BOT_TOKEN"]
FAMILY_CHAT_ID = int(os.environ["FAMILY_CHAT_ID"])
TG_SECRET = os.environ.get("TG_SECRET", "").strip()

# Простейший маппинг имён из env:
# NAME_ALIASES=илье:Илья,веронике:Вероника,...
RAW_ALIASES = os.environ.get("NAME_ALIASES", "").strip()


def parse_aliases(raw: str) -> dict:
    """
    Превращает строку вида:
      "илье:Илья,веронике:Вероника"
    в словарь:
      {"илье": "Илья", "веронике": "Вероника"}
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


def normalize_text(s: str) -> str:
    """
    Нормализация для сравнения:
    - trim
    - lowercase
    - ё -> е
    """
    return (s or "").strip().lower().replace("ё", "е")


NAME_ALIASES = parse_aliases(RAW_ALIASES)

# ----------------------------
# 3) Telegram API helper
# ----------------------------
def tg_api(method: str, payload: dict) -> dict:
    """
    Вызов Telegram Bot API стандартной библиотекой (без requests).
    Возвращает распарсенный JSON ответ.
    """
    logger.info("Calling Telegram API method %s", method)
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/{method}"
    data = urllib.parse.urlencode(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:
        raw = resp.read().decode("utf-8")
    try:
        result = json.loads(raw)
        if not result.get("ok", False):
            logger.warning("Telegram API method %s returned error: %s", method, result.get("description"))
        else:
            logger.debug("Telegram API method %s succeeded", method)
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
# Поддерживаем варианты:
# - "передай илье купи хлеб"
# - "алиса передай веронике: купи хлеб"
# - "алиса, передай коле что я дома"
#
# Логика:
# 1) опционально убираем "алиса" в начале
# 2) ищем "передай <кому> <текст>"
# 3) если текст начинается с "что " — убираем "что"
CMD_RE = re.compile(r"^(?:алиса[\s,:\-]*)?(?:передай|попроси)\s+(\S+)\s+(.+)$", re.IGNORECASE)



def canonical_name(raw_name: str) -> str:
    """
    Приводим имя к красивому виду через NAME_ALIASES,
    иначе просто капитализируем первую букву.
    """
    key = normalize_text(raw_name)
    if key in NAME_ALIASES:
        return NAME_ALIASES[key]
    # fallback: "илье" -> "Илье"
    n = (raw_name or "").strip()
    return n[:1].upper() + n[1:] if n else n


def parse_pereday(text: str):
    """
    Возвращает (to_name, message) или None.
    """
    t = (text or "").strip()
    if not t:
        logger.debug("Empty text received for parsing")
        return None

    m = CMD_RE.match(t)
    if not m:
        logger.debug("Text did not match command pattern: %s", text)
        return None

    to_raw = m.group(1).strip()
    msg = m.group(2).strip()

    # Уберём ведущие двоеточия/тире после имени (если попало)
    msg = re.sub(r"^[\s:\-]+", "", msg).strip()

    # Частый вариант: "передай илье что я дома"
    if normalize_text(msg).startswith("что "):
        msg = msg.split(" ", 1)[1].strip()

    if not to_raw or not msg:
        return None
    parsed_to = canonical_name(to_raw)
    logger.info("Parsed forward command to=%s", parsed_to)
    return parsed_to, msg


def format_out(to_name: str, msg: str) -> str:
    return f"Для {to_name}\n{msg.strip()}"


# ----------------------------
# 5) Обработчик Webhook для Vercel
#    Vercel вызывает Handler на /api/telegram (POST).
# ----------------------------
class Handler(BaseHTTPRequestHandler):
    def _ok(self):
        self.send_response(200)
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
        self._ok()

    def do_POST(self):
        logger.info("Received POST from %s", self.client_address)
        # 1) Проверяем secret_token (если задан)
        # Telegram присылает его в заголовке X-Telegram-Bot-Api-Secret-Token,
        # когда ты установишь webhook с параметром secret_token.
        if TG_SECRET:
            got = self.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
            if got != TG_SECRET:
                logger.warning("Unauthorized POST: bad secret token from %s", self.client_address)
                self._json(401, {"ok": False, "error": "unauthorized"})
                return

        # 2) Читаем update (JSON)
        length = int(self.headers.get("content-length", 0))
        raw = self.rfile.read(length) if length > 0 else b"{}"
        logger.debug("Received raw update bytes: %d", len(raw))
        try:
            content_type = self.headers.get("Content-Type", "")
            charset = None
            if "charset=" in content_type:
                charset = content_type.split("charset=", 1)[1].split(";", 1)[0].strip()
            encodings = [charset] if charset else []
            encodings.extend(["utf-8", "cp1251", "latin-1"])

            update = None
            last_error = None
            for enc in encodings:
                try:
                    raw_text = raw.decode(enc)
                    update = json.loads(raw_text)
                    if enc != encodings[0]:
                        logger.info("Decoded body using fallback encoding %s", enc)
                    break
                except Exception as e:
                    last_error = e
                    continue

            if update is None:
                logger.error(
                    "Failed to decode incoming update body; tried encodings %s; last_error=%s",
                    encodings,
                    last_error,
                )
                self._json(400, {"ok": False, "error": "invalid json"})
                return
        except Exception:
            logger.exception("Failed to decode incoming update body")
            self._json(400, {"ok": False, "error": "invalid json"})
            return

        # 3) Если бота добавили в чужой чат — выйти (приватность)
        # Это приходит как update.my_chat_member
        my_chat_member = update.get("my_chat_member")
        if isinstance(my_chat_member, dict):
            chat = my_chat_member.get("chat") or {}
            chat_id = chat.get("id")
            if isinstance(chat_id, int) and chat_id != FAMILY_CHAT_ID:
                # Попробуем выйти. Даже если не получится — молча ответим 200.
                tg_leave_chat(chat_id)
                logger.info("Left chat_id=%s after my_chat_member update", chat_id)
            else:
                logger.debug("Received my_chat_member update for family chat_id=%s", chat_id)
            self._ok()
            return

        # 4) Обычное сообщение (update.message / edited_message)
        message = update.get("message") or update.get("edited_message") or {}
        chat = message.get("chat") or {}
        chat_id = chat.get("id")
        text = message.get("text") or ""

        # Строго работаем только в вашем семейном чате
        if chat_id != FAMILY_CHAT_ID:
            logger.info("Ignoring message from unexpected chat_id=%s", chat_id)
            self._ok()
            return

        parsed = parse_pereday(text)
        if parsed:
            to_name, msg = parsed
            tg_send_message(FAMILY_CHAT_ID, format_out(to_name, msg))
            logger.info("Forwarded message to %s", to_name)
        else:
            logger.debug("No command parsed from message: %s", text)

        self._ok()

    def log_message(self, format, *args):
        logger.info("%s - - %s", self.client_address[0], format % args)


# Vercel ищет переменную handler
handler = Handler
