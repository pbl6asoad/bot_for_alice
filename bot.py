import os
import json
import asyncio
from typing import Optional, Dict

from aiohttp import web
from aiogram import Bot, Dispatcher, F
from aiogram.filters import Command
from aiogram.types import Message, ChatMemberUpdated

DATA_FILE = "bot_state.json"


ALLOWED_CHAT_ID = int(os.getenv("ALLOWED_CHAT_ID", "0"))  # ваш семейный чат
ADMIN_USER_IDS = {int(x) for x in os.getenv("ADMIN_USER_IDS", "").split(",") if x.strip()}

@dp.my_chat_member()
async def on_my_chat_member(update: ChatMemberUpdated):
    if ALLOWED_CHAT_ID and update.chat.id != ALLOWED_CHAT_ID:
        await bot.leave_chat(update.chat.id)  # leaveChat :contentReference[oaicite:3]{index=3}

# 2) Любые сообщения не из разрешённого чата — игнор
@dp.message()
async def guard_all_messages(message: Message):
    if ALLOWED_CHAT_ID and message.chat.id != ALLOWED_CHAT_ID:
        return

def load_state() -> Dict:
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_state(state: Dict) -> None:
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)

def norm_name(s: str) -> str:
    return s.strip().lower().replace("ё", "е")

# Пример маппинга: можешь расширять как хочешь
NAME_ALIASES = {
    "илья": "Илья",
    "иле": "Илья",
    "илье": "Илья",
    "вероника": "Вероника",
    "веронике": "Вероника",
    "коля": "Коля",
    "коле": "Коля",
    "николай": "Коля",
}

def canonical_name(raw: str) -> str:
    key = norm_name(raw)
    return NAME_ALIASES.get(key, raw.strip().capitalize())

def format_message(to_name: str, text: str) -> str:
    to_name = canonical_name(to_name)
    text = text.strip()
    return f"Для {to_name}\n{text}"

async def main():
    token = os.getenv("BOT_TOKEN")
    if not token:
        raise RuntimeError("Нужно задать BOT_TOKEN в переменных окружения")

    secret = os.getenv("RELAY_SECRET", "change-me")
    port = int(os.getenv("PORT", "8080"))

    state = load_state()
    bot = Bot(token=token)
    dp = Dispatcher()

    # Команда, чтобы бот запомнил текущий чат как "семейный"
    @dp.message(Command("setchat"))
    async def setchat(m: Message):
        state["chat_id"] = m.chat.id
        save_state(state)
        await m.answer(f"Ок! Запомнил этот чат для пересылок. chat_id={m.chat.id}")

    # Быстрый ручной тест прямо из чата:
    # /relay Илья Привет, перезвони пожалуйста
    @dp.message(Command("relay"))
    async def relay_cmd(m: Message):
        parts = (m.text or "").split(maxsplit=2)
        if len(parts) < 3:
            await m.answer("Формат: /relay ИМЯ ТЕКСТ")
            return
        to_name, text = parts[1], parts[2]
        await m.answer(format_message(to_name, text))

    # HTTP endpoint, который будет дергать твой сервис/навык Алисы
    # POST /relay  JSON: {"to":"Илья","text":"..."}
    async def relay_http(request: web.Request) -> web.Response:
        # простая защита
        if request.headers.get("X-Relay-Secret") != secret:
            return web.json_response({"ok": False, "error": "unauthorized"}, status=401)

        data = await request.json()
        to_name = str(data.get("to", "")).strip()
        text = str(data.get("text", "")).strip()

        if not to_name or not text:
            return web.json_response({"ok": False, "error": "to/text required"}, status=400)

        chat_id = state.get("chat_id")
        if not chat_id:
            return web.json_response({"ok": False, "error": "chat_id not set. Run /setchat in target group."}, status=400)

        msg = format_message(to_name, text)
        await bot.send_message(chat_id=chat_id, text=msg)
        return web.json_response({"ok": True})

    app = web.Application()
    app.router.add_post("/relay", relay_http)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host="0.0.0.0", port=port)
    await site.start()

    print(f"HTTP relay listening on :{port} (POST /relay)")
    print("Telegram bot polling started")

    # запускаем polling параллельно с HTTP сервером
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
