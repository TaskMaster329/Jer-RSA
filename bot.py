import asyncio
import redis
from aiogram import Bot, Dispatcher, F, types
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton

BOT_TOKEN ="8669371108:AAF5PzZK6vafu8-rebEh7_UJfMjWjTYzjq0"
CHAT_ID = "1016046994"
bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()
r = redis.Redis(host="localhost", port=6379, db=0)


def kb(session_id):
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="✔ Approve", callback_data=f"allow:{session_id}"),
            InlineKeyboardButton(text="✖ Deny", callback_data=f"deny:{session_id}")
        ]
    ])


async def send_approval(user, ip, session_id):
    await bot.send_message(
        CHAT_ID,
        f"🔐 SSH Login\nUser: {user}\nIP: {ip}\nSession: {session_id}",
        reply_markup=kb(session_id)
    )


@dp.callback_query(F.data.startswith("allow:"))
async def allow(cb: types.CallbackQuery):
    session_id = cb.data.split(":")[1]
    r.setex(f"mfa:{session_id}", 120, "allow")
    await cb.answer("Approved ✔")


@dp.callback_query(F.data.startswith("deny:"))
async def deny(cb: types.CallbackQuery):
    session_id = cb.data.split(":")[1]
    r.setex(f"mfa:{session_id}", 120, "deny")
    await cb.answer("Denied ❌")


async def main():
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
