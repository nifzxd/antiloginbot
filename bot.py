from __future__ import annotations

import asyncio
import dataclasses
import html
import json
import io
import logging
import os
import re
import time
from contextlib import suppress
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

import qrcode
from telethon import TelegramClient, events, functions
from telethon.errors import (
    AuthKeyError,
    FloodWaitError,
    PasswordHashInvalidError,
    PhoneCodeExpiredError,
    PhoneCodeInvalidError,
    PhoneNumberInvalidError,
    SessionPasswordNeededError,
    UserDeactivatedBanError,
    UserDeactivatedError,
)
from telethon.sessions import StringSession

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, InputMediaPhoto, Update
from telegram.constants import ParseMode
from telegram.error import BadRequest
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)
from telegram.request import HTTPXRequest


CONFIG_FILE = "config.json"
ACCOUNTS_FILE = "db/accounts.json"
LOG_DIR = "logs"
PHONE_REGEX = re.compile(r"^\+\d{7,15}$")
CODE_REGEX = re.compile(r"^\d{4,7}$")
OTP_CODE_REGEX = re.compile(r"\b\d{5}\b")
TELEGRAM_SERVICE_ID = 777000
QR_MAX_REFRESHES = 6
HEALTH_CHECK_INTERVAL_SECONDS = 300
BACKUP_RETENTION_COUNT = 5
INVALID_SESSION_ERRORS = (AuthKeyError, UserDeactivatedError, UserDeactivatedBanError)


class ConsoleFormatter(logging.Formatter):
    COLORS = {
        logging.DEBUG: "\033[90m",
        logging.INFO: "\033[36m",
        logging.WARNING: "\033[33m",
        logging.ERROR: "\033[31m",
        logging.CRITICAL: "\033[41m",
    }
    RESET = "\033[0m"
    GREY = "\033[90m"

    def format(self, record):
        color = self.COLORS.get(record.levelno, "")
        time_str = self.formatTime(record, "%H:%M:%S")
        level = f"{color}{record.levelname:<8}{self.RESET}"
        return f"{self.GREY}{time_str}{self.RESET}  {level}  {record.getMessage()}"


def setup_logging() -> logging.Logger:
    Path(LOG_DIR).mkdir(exist_ok=True)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(ConsoleFormatter())

    file_handler = RotatingFileHandler(
        Path(LOG_DIR) / "anti_login.log",
        maxBytes=5 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))

    logging.basicConfig(level=logging.INFO, handlers=[console_handler, file_handler], force=True)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("telethon").setLevel(logging.WARNING)
    return logging.getLogger("anti_login")


logger = setup_logging()


@dataclasses.dataclass(frozen=True)
class Config:
    api_id: int
    api_hash: str
    bot_token: str
    forward_channel: Optional[str]
    admin_ids: frozenset
    allowed_users: frozenset

    @property
    def authorized_users(self) -> frozenset:
        return self.admin_ids | self.allowed_users


def _to_int_set(values) -> frozenset:
    result = set()
    for value in values or []:
        try:
            result.add(int(value))
        except (TypeError, ValueError):
            logger.warning("Ignoring invalid id in config.json: %r", value)
    return frozenset(result)


def load_config(path: Path) -> Optional[Config]:
    if not path.exists():
        sample = {
            "api_id": 123456,
            "api_hash": "your_hash",
            "bot_token": "your_token",
            "forward_channel": "@channel",
            "admin_ids": [123456789],
            "allowed_users": [],
        }
        path.write_text(json.dumps(sample, indent=2))
        logger.warning("%s not found. A sample has been created — fill it in and restart.", path)
        return None

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        logger.error("Failed to read %s: %s", path, e)
        return None

    try:
        api_id = int(raw.get("api_id", 0))
    except (TypeError, ValueError):
        api_id = 0

    api_hash = raw.get("api_hash")
    bot_token = raw.get("bot_token")
    forward_channel = raw.get("forward_channel") or None

    if not api_id or not api_hash or not bot_token:
        logger.error("api_id, api_hash and bot_token are required in config.json")
        return None

    return Config(
        api_id=api_id,
        api_hash=api_hash,
        bot_token=bot_token,
        forward_channel=forward_channel,
        admin_ids=_to_int_set(raw.get("admin_ids")),
        allowed_users=_to_int_set(raw.get("allowed_users")),
    )


def mask_phone(phone: str) -> str:
    digits = phone.lstrip("+")
    if len(digits) <= 6:
        return "+" + digits[0] + "*" * (len(digits) - 1)
    visible_start, visible_end = 3, 2
    masked = "*" * (len(digits) - visible_start - visible_end)
    return f"+{digits[:visible_start]}{masked}{digits[-visible_end:]}"


def normalize_phone(raw: str) -> str:
    digits = re.sub(r"\D", "", raw)
    return "+" + digits


@dataclasses.dataclass
class AccountRecord:
    phone: str
    session_str: str
    anti_login: bool = False
    created_at: str = dataclasses.field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = dataclasses.field(default_factory=lambda: datetime.utcnow().isoformat())
    invalidated_codes: int = 0

    def touch(self):
        self.updated_at = datetime.utcnow().isoformat()

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @staticmethod
    def from_dict(phone: str, data: dict) -> "AccountRecord":
        return AccountRecord(
            phone=phone,
            session_str=str(data["session_str"]),
            anti_login=bool(data.get("anti_login", False)),
            created_at=str(data.get("created_at") or datetime.utcnow().isoformat()),
            updated_at=str(data.get("updated_at") or datetime.utcnow().isoformat()),
            invalidated_codes=int(data.get("invalidated_codes", 0) or 0),
        )


def validate_account_record(phone: str, data) -> Optional[str]:
    if not PHONE_REGEX.match(phone):
        return f"invalid phone format: {phone}"
    if not isinstance(data, dict):
        return "record is not a JSON object"
    session_str = data.get("session_str")
    if not session_str or not isinstance(session_str, str):
        return "missing or empty session_str"
    return None


class AccountDatabase:
    def __init__(self, path: Path, backup_count: int = BACKUP_RETENTION_COUNT):
        self.path = path
        self.backup_dir = path.parent / "backups"
        self.backup_count = backup_count
        self._lock = asyncio.Lock()
        self._records: dict[str, AccountRecord] = {}

    def load(self) -> list[str]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        raw = self._read_json_with_recovery()
        rejected = []
        records: dict[str, AccountRecord] = {}
        for phone, data in raw.items():
            error = validate_account_record(phone, data)
            if error:
                logger.warning("Rejecting corrupt account record %s: %s", phone, error)
                rejected.append(phone)
                continue
            records[phone] = AccountRecord.from_dict(phone, data)
        self._records = records
        return rejected

    def _read_json_with_recovery(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            content = self.path.read_text(encoding="utf-8")
            if not content.strip():
                return {}
            return json.loads(content)
        except (json.JSONDecodeError, OSError) as e:
            logger.error("accounts.json is corrupt (%s). Attempting recovery from backup.", e)
            return self._recover_from_backup()

    def _recover_from_backup(self) -> dict:
        backups = sorted(self.backup_dir.glob("accounts_*.json"), reverse=True)
        for backup in backups:
            try:
                data = json.loads(backup.read_text(encoding="utf-8"))
                logger.warning("Recovered account database from backup: %s", backup.name)
                return data
            except (json.JSONDecodeError, OSError):
                continue
        logger.error("No usable backup found. Starting with an empty account database.")
        return {}

    def get(self, phone: str) -> Optional[AccountRecord]:
        return self._records.get(phone)

    def all(self) -> dict:
        return dict(self._records)

    def __contains__(self, phone: str) -> bool:
        return phone in self._records

    async def upsert(self, record: AccountRecord):
        async with self._lock:
            record.touch()
            self._records[record.phone] = record
            await self._save_locked()

    async def remove(self, phone: str) -> bool:
        async with self._lock:
            if phone not in self._records:
                return False
            del self._records[phone]
            await self._save_locked()
            return True

    async def _save_locked(self):
        data = {phone: record.to_dict() for phone, record in self._records.items()}
        await asyncio.to_thread(self._write_atomic, data)

    def _write_atomic(self, data: dict):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self.path.with_suffix(".tmp")
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, self.path)
        self._rotate_backup(data)

    def _rotate_backup(self, data: dict):
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.utcnow().strftime("%Y%m%dT%H%M%S%f")
        backup_path = self.backup_dir / f"accounts_{stamp}.json"
        with suppress(Exception):
            backup_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        backups = sorted(self.backup_dir.glob("accounts_*.json"))
        for stale in backups[:-self.backup_count]:
            with suppress(Exception):
                stale.unlink()


class SessionManager:
    def __init__(self, config: Config, database: AccountDatabase):
        self.config = config
        self.database = database
        self.clients: dict[str, TelegramClient] = {}
        self.tasks: list[asyncio.Task] = []
        self.bot_app: Optional[Application] = None
        self._reconnect_delays: dict[str, float] = {}

    def is_protected(self, phone: str) -> bool:
        record = self.database.get(phone)
        return bool(record and record.anti_login)

    def phones(self) -> list:
        return list(self.database.all().keys())

    def track(self, task: asyncio.Task):
        self.tasks[:] = [t for t in self.tasks if not t.done()]
        self.tasks.append(task)

    async def load_all(self):
        rejected = self.database.load()
        for phone in rejected:
            logger.info("Discarded unrecoverable account record: %s", phone)

        sem = asyncio.Semaphore(5)

        async def connect(phone: str, record: AccountRecord):
            async with sem:
                await self._connect_existing(phone, record)

        records = list(self.database.all().items())
        if records:
            await asyncio.gather(*(connect(p, r) for p, r in records))

    async def _connect_existing(self, phone: str, record: AccountRecord):
        try:
            client = TelegramClient(StringSession(record.session_str), self.config.api_id, self.config.api_hash)
            await client.start()
            if not await client.is_user_authorized():
                raise AuthKeyError("session no longer authorized")
            me = await client.get_me()
            self.clients[phone] = client
            self._setup_otp_guard(phone, client)
            self.track(asyncio.create_task(self._supervise_client(phone, client)))
            logger.info("Account loaded: %s (%s)", phone, me.first_name)
        except INVALID_SESSION_ERRORS as e:
            logger.error("Session for %s is no longer valid (%s). Removing from database.", phone, e)
            await self.database.remove(phone)
        except Exception as e:
            logger.error("Failed to load account %s: %s. Will retry via health check.", phone, e)

    async def _supervise_client(self, phone: str, client: TelegramClient):
        try:
            await client.run_until_disconnected()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning("Client task for %s ended unexpectedly: %s", phone, e)

    async def add_account(self, phone: str, client: TelegramClient) -> bool:
        if phone in self.database:
            return False
        record = AccountRecord(phone=phone, session_str=client.session.save(), anti_login=False)
        await self.database.upsert(record)
        self.clients[phone] = client
        self._setup_otp_guard(phone, client)
        self.track(asyncio.create_task(self._supervise_client(phone, client)))
        logger.info("Account added: %s", phone)
        return True

    async def remove_account(self, phone: str) -> bool:
        client = self.clients.pop(phone, None)
        if client:
            with suppress(Exception):
                await client.disconnect()
        return await self.database.remove(phone)

    async def toggle_anti_login(self, phone: str) -> bool:
        record = self.database.get(phone)
        if not record:
            return False
        record.anti_login = not record.anti_login
        await self.database.upsert(record)
        logger.info("Anti-Login %s -> %s", phone, "ENABLED" if record.anti_login else "DISABLED")
        return True

    async def reconnect(self, phone: str) -> bool:
        record = self.database.get(phone)
        if not record:
            return False
        old_client = self.clients.pop(phone, None)
        if old_client:
            with suppress(Exception):
                await old_client.disconnect()
        try:
            client = TelegramClient(StringSession(record.session_str), self.config.api_id, self.config.api_hash)
            await client.start()
            if not await client.is_user_authorized():
                raise AuthKeyError("session no longer authorized")
            self.clients[phone] = client
            self._setup_otp_guard(phone, client)
            self.track(asyncio.create_task(self._supervise_client(phone, client)))
            self._reconnect_delays.pop(phone, None)
            logger.info("Reconnected: %s", phone)
            return True
        except INVALID_SESSION_ERRORS as e:
            logger.error("Session for %s is invalid during reconnect (%s). Removing from database.", phone, e)
            await self.database.remove(phone)
            await notify_admins_session_removed(self.bot_app, self.config, phone, str(e))
            return False
        except FloodWaitError as e:
            logger.warning("Reconnect for %s hit flood wait: %ds", phone, e.seconds)
            self._reconnect_delays[phone] = time.monotonic() + e.seconds
            return False
        except Exception as e:
            logger.error("Failed to reconnect %s: %s", phone, e)
            return False

    async def reconnect_all(self):
        for phone in self.phones():
            await self.reconnect(phone)

    async def health_check_loop(self, interval_seconds: int = HEALTH_CHECK_INTERVAL_SECONDS):
        while True:
            await asyncio.sleep(interval_seconds)
            for phone in self.phones():
                with suppress(Exception):
                    await self._health_check_one(phone)

    async def _health_check_one(self, phone: str):
        record = self.database.get(phone)
        if not record:
            return
        delay_until = self._reconnect_delays.get(phone)
        if delay_until and time.monotonic() < delay_until:
            return

        client = self.clients.get(phone)
        if client and client.is_connected():
            try:
                if not await client.is_user_authorized():
                    raise AuthKeyError("session no longer authorized")
                return
            except INVALID_SESSION_ERRORS as e:
                logger.error("Detected invalid session for %s (%s). Removing.", phone, e)
                with suppress(Exception):
                    await client.disconnect()
                self.clients.pop(phone, None)
                await self.database.remove(phone)
                await notify_admins_session_removed(self.bot_app, self.config, phone, str(e))
                return
            except Exception:
                return

        logger.info("Client for %s appears disconnected. Attempting reconnect.", phone)
        await self.reconnect(phone)

    def _setup_otp_guard(self, phone: str, client: TelegramClient):
        # Guard against installing the handler twice for the same client,
        # which would invalidate each OTP code twice.
        if getattr(client, "_otp_guard_installed", False):
            return
        try:
            setattr(client, "_otp_guard_installed", True)
        except Exception:
            pass

        @client.on(events.NewMessage(from_users=[TELEGRAM_SERVICE_ID]))
        async def handle_otp(event):
            try:
                await self._handle_otp_event(phone, event)
            except Exception as e:
                logger.error("Error while handling OTP event for %s: %s", phone, e)

    async def _handle_otp_event(self, phone: str, event):
        if not self.is_protected(phone):
            return
        match = OTP_CODE_REGEX.search(event.message.text or "")
        if not match:
            return
        code = match.group(0)
        client = self.clients.get(phone)
        if not client:
            return
        try:
            await client(functions.account.InvalidateSignInCodesRequest(codes=[code]))
            logger.warning("Login code %s for %s was invalidated.", code, phone)
        except Exception as e:
            logger.error("Failed to invalidate code for %s: %s", phone, e)
            return

        record = self.database.get(phone)
        if not record:
            return
        record.invalidated_codes += 1
        await self.database.upsert(record)

        if self.config.forward_channel:
            await post_alert_to_channel(self.bot_app, self.config, phone)
        await notify_admins_login_attempt(self.bot_app, self.config, phone)

    async def shutdown(self):
        for task in self.tasks:
            task.cancel()
        for client in list(self.clients.values()):
            with suppress(Exception):
                await client.disconnect()
        logger.info("All account connections closed.")


async def post_alert_to_channel(bot_app: Optional[Application], config: Config, phone: str):
    if not bot_app or not config.forward_channel:
        return
    text = (
        "⚠️ Unauthorized login attempt detected\n"
        f"Account: {mask_phone(phone)}\n"
        f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        "The login code was automatically invalidated."
    )
    try:
        await bot_app.bot.send_message(config.forward_channel, text)
    except Exception as e:
        logger.error("Failed to post alert to channel: %s", e)


async def notify_admins_login_attempt(bot_app: Optional[Application], config: Config, phone: str):
    if not bot_app:
        return
    text = (
        "🚨 <b>Login Attempt Detected</b>\n"
        f"Account: <code>{html.escape(phone)}</code>\n"
        f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        "The login code was automatically invalidated."
    )
    for admin_id in config.admin_ids:
        with suppress(Exception):
            await bot_app.bot.send_message(admin_id, text, parse_mode=ParseMode.HTML)


async def notify_admins_session_removed(bot_app: Optional[Application], config: Config, phone: str, reason: str):
    if not bot_app:
        return
    text = (
        "🧹 <b>Session Removed</b>\n"
        f"Account: <code>{html.escape(phone)}</code>\n"
        f"Reason: {html.escape(reason)}\n"
        "This account was disconnected and cleaned up from the database. Re-add it if needed."
    )
    for admin_id in config.admin_ids:
        with suppress(Exception):
            await bot_app.bot.send_message(admin_id, text, parse_mode=ParseMode.HTML)


_config: Optional[Config] = None
_session_manager: Optional[SessionManager] = None
user_sessions: dict = {}


def is_authorized(user_id: int) -> bool:
    return bool(_config) and user_id in _config.authorized_users


async def render(context, chat_id: int, message_id: int, text: str, keyboard=None):
    markup = InlineKeyboardMarkup(keyboard) if keyboard else None
    try:
        await context.bot.edit_message_text(
            chat_id=chat_id,
            message_id=message_id,
            text=text,
            parse_mode=ParseMode.HTML,
            reply_markup=markup,
        )
        return
    except BadRequest as e:
        if "message is not modified" in str(e).lower():
            return
        logger.warning("HTML parse failed, retrying as plain text: %s", e)

    # Fallback: strip HTML tags and unescape entities before sending as plain text
    plain = re.sub(r"<[^>]+>", "", text)
    plain = html.unescape(plain)
    try:
        await context.bot.edit_message_text(
            chat_id=chat_id,
            message_id=message_id,
            text=plain,
            reply_markup=markup,
        )
    except BadRequest as e:
        if "message is not modified" not in str(e).lower():
            logger.error("Failed to edit message: %s", e)


def main_menu_keyboard():
    return [
        [
            InlineKeyboardButton("➕ Add Account", callback_data="add_acc"),
            InlineKeyboardButton("📋 Account List", callback_data="list_acc"),
        ],
        [
            InlineKeyboardButton("🔄 Reconnect All", callback_data="reconnect_all"),
        ],
    ]


async def show_main_menu(context, chat_id, message_id):
    await render(context, chat_id, message_id, "🤖 <b>Anti-Login Bot</b>\nManage your protected accounts.", main_menu_keyboard())


async def list_accounts_view(context, chat_id, message_id):
    accounts = _session_manager.database.all()
    if not accounts:
        keyboard = [[InlineKeyboardButton("🔙 Back", callback_data="menu")]]
        await render(context, chat_id, message_id, "📋 <b>Account List</b>\n\nNo accounts registered yet.", keyboard)
        return

    keyboard = [
        [
            InlineKeyboardButton(
                f"{'🔒' if record.anti_login else '🔓'} {phone}",
                callback_data=f"acc_{phone}",
            )
        ]
        for phone, record in accounts.items()
    ]
    keyboard.append([InlineKeyboardButton("🔙 Back", callback_data="menu")])

    await render(context, chat_id, message_id, "📋 <b>Account List</b>", keyboard)


async def account_detail_view(context, chat_id, message_id, phone, banner: str = ""):
    record = _session_manager.database.get(phone)
    if not record:
        await list_accounts_view(context, chat_id, message_id)
        return
    status = "🔒 ENABLED" if record.anti_login else "🔓 DISABLED"
    text = (
        f"{html.escape(banner)}📱 <b>{html.escape(phone)}</b>\n"
        f"Anti-Login status: <b>{status}</b>\n"
        f"Codes invalidated so far: {record.invalidated_codes}"
    )
    toggle_label = "🔓 Disable" if record.anti_login else "🔒 Enable"
    keyboard = [
        [InlineKeyboardButton(toggle_label, callback_data=f"toggle_{phone}")],
        [InlineKeyboardButton("🗑 Remove Account", callback_data=f"del_{phone}")],
        [InlineKeyboardButton("🔙 Back", callback_data="list_acc")],
    ]
    await render(context, chat_id, message_id, text, keyboard)


async def delete_confirm_view(context, chat_id, message_id, phone):
    if phone not in _session_manager.database:
        await list_accounts_view(context, chat_id, message_id)
        return
    keyboard = [
        [
            InlineKeyboardButton("✅ Yes, Remove", callback_data=f"delconfirm_{phone}"),
            InlineKeyboardButton("❌ Cancel", callback_data=f"acc_{phone}"),
        ]
    ]
    await render(context, chat_id, message_id, f"⚠️ Remove account <code>{html.escape(phone)}</code>?", keyboard)


def cancel_keyboard():
    return [[InlineKeyboardButton("❌ Cancel", callback_data="cancel_add")]]


def add_method_keyboard():
    return [
        [InlineKeyboardButton("📱 Phone Number", callback_data="add_phone")],
        [InlineKeyboardButton("🔲 QR Code", callback_data="add_qr")],
        [InlineKeyboardButton("🔙 Back", callback_data="menu")],
    ]


async def cleanup_session_client(session: dict):
    client = session.get("client")
    if client:
        with suppress(Exception):
            await client.disconnect()


async def cleanup_qr_message(context, session: dict):
    qr_msg_id = session.get("qr_msg_id")
    if qr_msg_id:
        with suppress(Exception):
            await context.bot.delete_message(session["chat_id"], qr_msg_id)


async def reset_user_flow(context, user_id: int):
    session = user_sessions.pop(user_id, None)
    if not session:
        return
    await cleanup_qr_message(context, session)
    await cleanup_session_client(session)


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not is_authorized(user_id):
        await update.message.reply_text("⛔ Unauthorized")
        return

    await reset_user_flow(context, user_id)

    message = await update.message.reply_text(
        "🤖 <b>Anti-Login Bot</b>\nManage your protected accounts.",
        parse_mode=ParseMode.HTML,
        reply_markup=InlineKeyboardMarkup(main_menu_keyboard()),
    )
    user_sessions[user_id] = {
        "chat_id": message.chat_id,
        "control_msg_id": message.message_id,
    }


def generate_qr_image(url: str) -> io.BytesIO:
    img = qrcode.make(url)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    buf.seek(0)
    return buf


async def refresh_qr_photo(context, session: dict, qr_login) -> bool:
    try:
        buf = generate_qr_image(qr_login.url)
    except Exception as e:
        logger.error("Failed to regenerate QR image: %s", e)
        return False
    try:
        await context.bot.edit_message_media(
            chat_id=session["chat_id"],
            message_id=session["qr_msg_id"],
            media=InputMediaPhoto(
                buf,
                caption="🔲 Scan this QR code from Telegram on your phone:\nSettings → Devices → Link Desktop Device\n\n♻️ Code refreshed — please scan the latest one.",
            ),
        )
        return True
    except Exception as e:
        logger.error("Failed to refresh QR image: %s", e)
        return False


async def start_qr_login(context, chat_id, message_id, user_id):
    client = TelegramClient(StringSession(), _config.api_id, _config.api_hash)
    await client.connect()
    qr_login = await client.qr_login()

    try:
        buf = generate_qr_image(qr_login.url)
    except Exception as e:
        logger.error("Failed to generate QR image: %s", e)
        with suppress(Exception):
            await client.disconnect()
        await render(
            context, chat_id, message_id,
            "❌ QR code generation failed (missing Pillow?). Install it with:\n<code>pip install \"qrcode[pil]\"</code>\n\nOr use the Phone Number method instead.",
            add_method_keyboard(),
        )
        return

    sent = await context.bot.send_photo(
        chat_id,
        buf,
        caption="🔲 Scan this QR code from Telegram on your phone:\nSettings → Devices → Link Desktop Device",
    )

    user_sessions[user_id] = {
        "step": "wait_qr",
        "client": client,
        "qr_login": qr_login,
        "chat_id": chat_id,
        "control_msg_id": message_id,
        "qr_msg_id": sent.message_id,
    }
    await render(context, chat_id, message_id, "⏳ Waiting for QR scan...", cancel_keyboard())

    _session_manager.track(asyncio.create_task(watch_qr_login(context, user_id)))


async def watch_qr_login(context, user_id):
    session = user_sessions.get(user_id)
    if not session or session.get("step") != "wait_qr":
        return
    client = session["client"]
    chat_id = session["chat_id"]
    message_id = session["control_msg_id"]

    for attempt in range(QR_MAX_REFRESHES):
        if user_sessions.get(user_id) is not session:
            return
        qr_login = session["qr_login"]
        try:
            await qr_login.wait()
            break
        except SessionPasswordNeededError:
            if user_sessions.get(user_id) is session:
                session["step"] = "wait_password"
                await render(context, chat_id, message_id, "🔐 This account has 2FA enabled. Enter the password:", cancel_keyboard())
            return
        except asyncio.TimeoutError:
            if user_sessions.get(user_id) is not session:
                return
            if attempt == QR_MAX_REFRESHES - 1:
                await cleanup_qr_message(context, session)
                user_sessions.pop(user_id, None)
                await render(
                    context, chat_id, message_id,
                    "⌛ QR code expired.",
                    [
                        [
                            InlineKeyboardButton("🔄 Retry", callback_data="add_qr"),
                            InlineKeyboardButton("🔙 Menu", callback_data="menu"),
                        ]
                    ],
                )
                with suppress(Exception):
                    await client.disconnect()
                return
            try:
                await qr_login.recreate()
            except Exception as e:
                logger.error("Failed to recreate QR token: %s", e)
                await cleanup_qr_message(context, session)
                user_sessions.pop(user_id, None)
                await render(context, chat_id, message_id, f"❌ QR login failed: {html.escape(str(e))}", [
                    [InlineKeyboardButton("🔙 Menu", callback_data="menu")]
                ])
                with suppress(Exception):
                    await client.disconnect()
                return
            await refresh_qr_photo(context, session, qr_login)
            continue
        except Exception as e:
            logger.error("QR login failed: %s", e)
            if user_sessions.get(user_id) is session:
                await cleanup_qr_message(context, session)
                user_sessions.pop(user_id, None)
                await render(context, chat_id, message_id, f"❌ QR login failed: {html.escape(str(e))}", [
                    [InlineKeyboardButton("🔙 Menu", callback_data="menu")]
                ])
            with suppress(Exception):
                await client.disconnect()
            return

    me = await client.get_me()
    phone = normalize_phone(me.phone) if me.phone else f"+id{me.id}"
    await cleanup_qr_message(context, session)
    await finish_add_account(context, chat_id, message_id, user_id, phone, client)


async def message_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not is_authorized(user_id):
        return
    session = user_sessions.get(user_id)

    # No active input flow: delete the stray message so sensitive input
    # (codes, passwords) does not linger in the chat history.
    if not session or "step" not in session:
        with suppress(Exception):
            await context.bot.delete_message(update.effective_chat.id, update.message.message_id)
        return

    text = (update.message.text or "").strip()
    chat_id = session["chat_id"]
    message_id = session["control_msg_id"]

    with suppress(Exception):
        await context.bot.delete_message(chat_id, update.message.message_id)

    if not text:
        await render(context, chat_id, message_id, "❌ Empty input is not allowed. Please try again.", cancel_keyboard())
        return

    step = session["step"]

    if step == "wait_phone":
        if not PHONE_REGEX.match(text):
            await render(context, chat_id, message_id, "❌ Invalid format. Use <code>+&lt;country code&gt;&lt;number&gt;</code>, digits only.", cancel_keyboard())
            return
        try:
            client = TelegramClient(StringSession(), _config.api_id, _config.api_hash)
            await client.connect()
            await client.send_code_request(text)
            session.update({"step": "wait_code", "phone": text, "client": client})
            await render(context, chat_id, message_id, f"📲 Code sent to <code>{html.escape(text)}</code>.\nEnter the code:", cancel_keyboard())
        except PhoneNumberInvalidError:
            await render(context, chat_id, message_id, "❌ Invalid phone number.", cancel_keyboard())
        except FloodWaitError as e:
            await render(context, chat_id, message_id, f"⏳ Please wait {e.seconds} seconds and try again.", cancel_keyboard())
        except Exception as e:
            await render(context, chat_id, message_id, f"❌ Error: {html.escape(str(e))}", cancel_keyboard())

    elif step == "wait_code":
        if not CODE_REGEX.match(text):
            await render(context, chat_id, message_id, "❌ The code must be numeric only. Try again:", cancel_keyboard())
            return
        phone, client = session["phone"], session["client"]
        try:
            await client.sign_in(phone, text)
            await finish_add_account(context, chat_id, message_id, user_id, phone, client)
        except SessionPasswordNeededError:
            session["step"] = "wait_password"
            await render(context, chat_id, message_id, "🔐 This account has 2FA enabled. Enter the password:", cancel_keyboard())
        except PhoneCodeInvalidError:
            await render(context, chat_id, message_id, "❌ Invalid code, try again:", cancel_keyboard())
        except PhoneCodeExpiredError:
            await cleanup_session_client(session)
            user_sessions.pop(user_id, None)
            await render(context, chat_id, message_id, "❌ Code expired. Please start over.", [[InlineKeyboardButton("🔙 Menu", callback_data="menu")]])
        except FloodWaitError as e:
            await render(context, chat_id, message_id, f"⏳ Please wait {e.seconds} seconds and try again.", cancel_keyboard())
        except Exception as e:
            await render(context, chat_id, message_id, f"❌ Error: {html.escape(str(e))}", cancel_keyboard())

    elif step == "wait_password":
        client = session["client"]
        phone = session.get("phone")
        try:
            await client.sign_in(password=text)
            if not phone:
                me = await client.get_me()
                phone = normalize_phone(me.phone) if me.phone else f"+id{me.id}"
            await cleanup_qr_message(context, session)
            await finish_add_account(context, chat_id, message_id, user_id, phone, client)
        except PasswordHashInvalidError:
            await render(context, chat_id, message_id, "❌ Incorrect password. Please try again:", cancel_keyboard())
        except Exception as e:
            await render(context, chat_id, message_id, f"❌ Login failed: {html.escape(str(e))}", cancel_keyboard())


async def finish_add_account(context, chat_id, message_id, user_id, phone, client):
    success = await _session_manager.add_account(phone, client)
    user_sessions.pop(user_id, None)
    if success:
        await account_detail_view(context, chat_id, message_id, phone, banner="✅ Account added successfully!\n\n")
    else:
        with suppress(Exception):
            await client.disconnect()
        await render(
            context, chat_id, message_id,
            "❌ Account already exists or failed to add.",
            [[InlineKeyboardButton("🔙 Menu", callback_data="menu")]],
        )


async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user_id = update.effective_user.id
    chat_id = query.message.chat_id
    message_id = query.message.message_id

    if not is_authorized(user_id):
        await render(context, chat_id, message_id, "⛔ Unauthorized")
        return

    data = query.data

    # Any button press cancels the currently running input flow
    # (phone / code / password / qr) so state cannot leak between actions.
    await reset_user_flow(context, user_id)
    user_sessions[user_id] = {"chat_id": chat_id, "control_msg_id": message_id}

    if data == "menu":
        await show_main_menu(context, chat_id, message_id)

    elif data == "add_acc":
        await render(context, chat_id, message_id, "Choose an account addition method:", add_method_keyboard())

    elif data == "add_phone":
        user_sessions[user_id]["step"] = "wait_phone"
        await render(
            context, chat_id, message_id,
            "📱 Send the phone number with country code:\n<code>+15551234567</code>",
            cancel_keyboard(),
        )

    elif data == "add_qr":
        await start_qr_login(context, chat_id, message_id, user_id)

    elif data == "cancel_add":
        await show_main_menu(context, chat_id, message_id)

    elif data == "list_acc":
        await list_accounts_view(context, chat_id, message_id)

    elif data.startswith("acc_"):
        await account_detail_view(context, chat_id, message_id, data[len("acc_"):])

    elif data.startswith("toggle_"):
        phone = data[len("toggle_"):]
        await _session_manager.toggle_anti_login(phone)
        await account_detail_view(context, chat_id, message_id, phone)

    elif data.startswith("delconfirm_"):
        phone = data[len("delconfirm_"):]
        await _session_manager.remove_account(phone)
        await list_accounts_view(context, chat_id, message_id)

    elif data.startswith("del_"):
        await delete_confirm_view(context, chat_id, message_id, data[len("del_"):])

    elif data == "reconnect_all":
        await render(context, chat_id, message_id, "🔄 Reconnecting all accounts in background...")
        _session_manager.track(asyncio.create_task(_session_manager.reconnect_all()))
        await show_main_menu(context, chat_id, message_id)


async def error_handler(update, context: ContextTypes.DEFAULT_TYPE):
    logger.error("Update %s caused error: %s", update, context.error)


def make_post_init(session_manager: SessionManager):
    async def post_init(application: Application):
        await session_manager.load_all()
        session_manager.track(asyncio.create_task(session_manager.health_check_loop()))
        me = await application.bot.get_me()
        banner = (
            "\n" + "=" * 46 + "\n"
            f"  Anti-Login Bot running as @{me.username}\n"
            f"  Protected accounts : {len(session_manager.phones())}\n"
            f"  Registered admins  : {len(session_manager.config.admin_ids)}\n"
            + "=" * 46
        )
        logger.info(banner)
    return post_init


def make_post_shutdown(session_manager: SessionManager):
    async def post_shutdown(application: Application):
        await session_manager.shutdown()
    return post_shutdown


def main():
    global _config, _session_manager

    config = load_config(Path(CONFIG_FILE))
    if config is None:
        return
    _config = config

    if not config.admin_ids:
        logger.warning("No admin_ids configured — login alerts will not be delivered to anyone.")

    database = AccountDatabase(Path(ACCOUNTS_FILE))
    session_manager = SessionManager(config, database)
    _session_manager = session_manager

    request = HTTPXRequest(connection_pool_size=8)
    bot_app = (
        Application.builder()
        .token(config.bot_token)
        .request(request)
        .post_init(make_post_init(session_manager))
        .post_shutdown(make_post_shutdown(session_manager))
        .build()
    )
    session_manager.bot_app = bot_app

    bot_app.add_handler(CommandHandler("start", start_command))
    bot_app.add_handler(CallbackQueryHandler(button_callback))
    bot_app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, message_handler))
    bot_app.add_error_handler(error_handler)

    logger.info("Starting bot...")
    bot_app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()