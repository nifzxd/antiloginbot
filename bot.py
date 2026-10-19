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
import uuid
import weakref
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
BACKUP_MIN_INTERVAL_SECONDS = 60
USER_SESSION_SWEEP_INTERVAL = 3600
USER_SESSION_IDLE_TIMEOUT = 3600
ACCOUNTS_PER_PAGE = 20
OTP_SESSION_SWEEP_DELAY_SECONDS = 4
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
    trust_fingerprint: bool = True

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
            "trust_fingerprint": True,
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
    trust_fingerprint = bool(raw.get("trust_fingerprint", True))

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
        trust_fingerprint=trust_fingerprint,
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
    whitelisted_sessions: list = dataclasses.field(default_factory=list)
    trusted_fingerprints: list = dataclasses.field(default_factory=list)
    whitelist_initialized: bool = False

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
            whitelisted_sessions=list(data.get("whitelisted_sessions", []) or []),
            trusted_fingerprints=list(data.get("trusted_fingerprints", []) or []),
            whitelist_initialized=bool(data.get("whitelist_initialized", False)),
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


def _session_fingerprint(auth) -> str:
    return f"{auth.device_model or '?'}|{auth.platform or '?'}|{auth.app_name or '?'}"


def _format_session(auth, prefix: str = "") -> str:
    created = auth.date_created.strftime("%Y-%m-%d %H:%M") if auth.date_created else "?"
    return (
        f"{prefix}<b>{html.escape(auth.device_model or '?')}</b> "
        f"({html.escape(auth.platform or '?')})\n"
        f"   App: {html.escape(auth.app_name or '?')} {html.escape(auth.app_version or '')}\n"
        f"   Location: {html.escape(auth.country or '?')}, {html.escape(auth.region or '?')}\n"
        f"   IP: {html.escape(auth.ip or '?')}\n"
        f"   Created: {created}\n"
    )


class AccountDatabase:
    def __init__(self, path: Path, backup_count: int = BACKUP_RETENTION_COUNT):
        self.path = path
        self.backup_dir = path.parent / "backups"
        self.backup_count = backup_count
        self._lock = asyncio.Lock()
        self._records: dict[str, AccountRecord] = {}
        self._last_backup: float = 0.0

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

        if rejected:
            cleaned = {p: r.to_dict() for p, r in self._records.items()}
            with suppress(Exception):
                self._write_atomic(cleaned)

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

    def redact_phone_from_backups(self, phone: str):
        if not self.backup_dir.exists():
            return
        for backup in self.backup_dir.glob("accounts_*.json"):
            try:
                data = json.loads(backup.read_text(encoding="utf-8"))
                if phone in data:
                    del data[phone]
                    backup.write_text(
                        json.dumps(data, indent=2, ensure_ascii=False),
                        encoding="utf-8",
                    )
                    logger.info("Redacted %s from backup %s", phone, backup.name)
            except Exception as e:
                logger.debug("Could not redact backup %s: %s", backup.name, e)

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
        now = time.monotonic()
        if now - self._last_backup < BACKUP_MIN_INTERVAL_SECONDS:
            return
        self._last_backup = now

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
        self._reconnect_locks: dict[str, asyncio.Lock] = {}
        self._guarded_clients: weakref.WeakSet = weakref.WeakSet()
        self._ui_sessions: dict[str, tuple] = {}
        self._pending_fingerprints: dict[str, tuple] = {}

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
        # [FIX #5] Use connect() + is_user_authorized() instead of start().
        # start() can hang in headless environments (Docker) because it tries
        # to read a phone number from stdin when the session is invalid.
        client = TelegramClient(StringSession(record.session_str), self.config.api_id, self.config.api_hash)
        try:
            await client.connect()
            if not await client.is_user_authorized():
                raise AuthKeyError("session no longer authorized")
            me = await client.get_me()
            self.clients[phone] = client
            self._setup_otp_guard(phone, client)
            self.track(asyncio.create_task(self._supervise_client(phone, client)))
            await self._ensure_whitelist_initialized(phone, client)
            logger.info("Account loaded: %s (%s)", phone, me.first_name)
        except INVALID_SESSION_ERRORS as e:
            logger.error("Session for %s is no longer valid (%s). Removing from database.", phone, e)
            with suppress(Exception):
                await client.disconnect()
            await self.database.remove(phone)
            # [FIX #7] Also scrub backups so the dead session string cannot be reused.
            await asyncio.to_thread(self.database.redact_phone_from_backups, phone)
            await notify_admins_session_removed(self.bot_app, self.config, phone, str(e))
        except Exception as e:
            logger.error("Failed to load account %s: %s. Will retry via health check.", phone, e)
            with suppress(Exception):
                await client.disconnect()

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
        # [FIX #3] On failure, roll back state and remove the client from the
        # registry so finish_add_account can safely LogOut without leaving a
        # dangling entry.
        try:
            await self.database.upsert(record)
            self.clients[phone] = client
            self._setup_otp_guard(phone, client)
            self.track(asyncio.create_task(self._supervise_client(phone, client)))
            await self._ensure_whitelist_initialized(phone, client)
        except Exception as e:
            logger.error("add_account failed for %s: %s", phone, e)
            self.clients.pop(phone, None)
            with suppress(Exception):
                await self.database.remove(phone)
            raise
        logger.info("Account added: %s", phone)
        return True

    async def remove_account(self, phone: str) -> bool:
        client = self.clients.pop(phone, None)
        logged_out = False
        if client:
            try:
                await client(functions.auth.LogOutRequest())
                logged_out = True
                logger.info("Logged out bot session for %s on Telegram servers", phone)
            except Exception as e:
                logger.warning(
                    "Could not log out bot session for %s (%s) — session may still "
                    "be valid server-side; scrubbing backups anyway.",
                    phone, e,
                )
            with suppress(Exception):
                await client.disconnect()

        removed = await self.database.remove(phone)
        if removed:
            await asyncio.to_thread(self.database.redact_phone_from_backups, phone)
            logger.info(
                "Removed account %s (logged_out=%s, backups scrubbed)",
                phone, logged_out,
            )
        return removed

    async def toggle_anti_login(self, phone: str) -> bool:
        record = self.database.get(phone)
        if not record:
            return False
        record.anti_login = not record.anti_login
        await self.database.upsert(record)
        logger.info("Anti-Login %s -> %s", phone, "ENABLED" if record.anti_login else "DISABLED")
        return True

    async def reconnect(self, phone: str) -> bool:
        lock = self._reconnect_locks.setdefault(phone, asyncio.Lock())
        async with lock:
            record = self.database.get(phone)
            if not record:
                return False

            existing = self.clients.get(phone)
            if existing and existing.is_connected():
                try:
                    if await existing.is_user_authorized():
                        return True
                except Exception:
                    pass

            old_client = self.clients.pop(phone, None)
            if old_client:
                with suppress(Exception):
                    await old_client.disconnect()

            # [FIX #5] connect() + explicit auth check, no interactive start().
            client = TelegramClient(StringSession(record.session_str), self.config.api_id, self.config.api_hash)
            try:
                await client.connect()
                if not await client.is_user_authorized():
                    raise AuthKeyError("session no longer authorized")
                self.clients[phone] = client
                self._setup_otp_guard(phone, client)
                self.track(asyncio.create_task(self._supervise_client(phone, client)))
                await self._ensure_whitelist_initialized(phone, client)
                self._reconnect_delays.pop(phone, None)
                logger.info("Reconnected: %s", phone)
                return True
            except INVALID_SESSION_ERRORS as e:
                logger.error("Session for %s is invalid during reconnect (%s). Removing.", phone, e)
                with suppress(Exception):
                    await client.disconnect()
                await self.database.remove(phone)
                await asyncio.to_thread(self.database.redact_phone_from_backups, phone)
                await notify_admins_session_removed(self.bot_app, self.config, phone, str(e))
                return False
            except FloodWaitError as e:
                logger.warning("Reconnect for %s hit flood wait: %ds", phone, e.seconds)
                with suppress(Exception):
                    await client.disconnect()
                self._reconnect_delays[phone] = time.monotonic() + e.seconds
                return False
            except Exception as e:
                logger.error("Failed to reconnect %s: %s", phone, e)
                with suppress(Exception):
                    await client.disconnect()
                return False

    async def reconnect_all(self):
        for phone in self.phones():
            delay_until = self._reconnect_delays.get(phone)
            if delay_until and time.monotonic() < delay_until:
                continue
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
                with suppress(Exception):
                    await self.check_sessions(phone, source="health_check")
                return
            except INVALID_SESSION_ERRORS as e:
                logger.error("Detected invalid session for %s (%s). Removing.", phone, e)
                with suppress(Exception):
                    await client.disconnect()
                self.clients.pop(phone, None)
                await self.database.remove(phone)
                await asyncio.to_thread(self.database.redact_phone_from_backups, phone)
                await notify_admins_session_removed(self.bot_app, self.config, phone, str(e))
                return
            except Exception:
                return

        logger.info("Client for %s appears disconnected. Attempting reconnect.", phone)
        await self.reconnect(phone)

    def _setup_otp_guard(self, phone: str, client: TelegramClient):
        if client in self._guarded_clients:
            return
        self._guarded_clients.add(client)

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

        self.track(asyncio.create_task(
            self._delayed_session_sweep(phone, delay=OTP_SESSION_SWEEP_DELAY_SECONDS, source="otp_event")
        ))

        if self.config.forward_channel:
            await post_alert_to_channel(self.bot_app, self.config, phone)
        await notify_admins_login_attempt(self.bot_app, self.config, phone)

    def _whitelist_session(self, record: AccountRecord, auth, source: str = "manual") -> None:
        entry = {
            "hash": auth.hash,
            "device_model": auth.device_model,
            "platform": auth.platform,
            "app_name": auth.app_name,
            "app_version": auth.app_version,
            "country": auth.country,
            "region": auth.region,
            "ip": auth.ip,
            "date_created": auth.date_created.isoformat() if auth.date_created else None,
            "trusted_at": datetime.utcnow().isoformat(),
            "source": source,
        }
        record.whitelisted_sessions = [
            e for e in record.whitelisted_sessions if e.get("hash") != auth.hash
        ]
        record.whitelisted_sessions.append(entry)

        fp = _session_fingerprint(auth)
        if fp not in record.trusted_fingerprints:
            record.trusted_fingerprints.append(fp)

    def _is_trusted(self, record: AccountRecord, auth) -> bool:
        if auth.current:
            return True
        if any(e.get("hash") == auth.hash for e in record.whitelisted_sessions):
            return True
        if self.config.trust_fingerprint and _session_fingerprint(auth) in record.trusted_fingerprints:
            return True
        return False

    async def _kill_session(self, client, auth, phone: str) -> bool:
        try:
            await client(functions.account.ResetAuthorizationRequest(hash=auth.hash))
            logger.warning(
                "Killed session for %s: %s / %s (%s)",
                phone, auth.device_model, auth.platform, auth.country,
            )
            return True
        except Exception as e:
            logger.info("Could not kill session for %s (hash=%s): %s", phone, auth.hash, e)
            return False

    async def _ensure_whitelist_initialized(self, phone: str, client: TelegramClient) -> bool:
        """Returns True if the record has a valid baseline after this call."""
        record = self.database.get(phone)
        if not record:
            return False
        if record.whitelist_initialized:
            return True
        try:
            result = await client(functions.account.GetAuthorizationsRequest())
        except Exception as e:
            logger.error("Failed to fetch authorizations for baseline %s: %s", phone, e)
            return False

        for auth in result.authorizations:
            self._whitelist_session(record, auth, source="baseline")

        record.whitelist_initialized = True
        await self.database.upsert(record)
        logger.info(
            "Baseline whitelist for %s: %d session(s) trusted",
            phone, len(result.authorizations),
        )
        return True

    async def check_sessions(self, phone: str, source: str) -> list:
        record = self.database.get(phone)
        client = self.clients.get(phone)
        if not record or not client:
            return []

        # [FIX #1] CRITICAL: never sweep without a baseline. If the baseline
        # failed during add/connect (e.g. network blip), retry here. If it
        # still fails, skip the sweep entirely rather than killing every
        # legitimate device on the account.
        if not record.whitelist_initialized:
            ok = await self._ensure_whitelist_initialized(phone, client)
            if not ok:
                logger.warning(
                    "Skipping session sweep for %s (%s): baseline not initialized",
                    phone, source,
                )
                return []

        try:
            result = await client(functions.account.GetAuthorizationsRequest())
        except Exception as e:
            logger.error("Failed to fetch authorizations for %s: %s", phone, e)
            return []

        killed = []
        changed = False

        for auth in result.authorizations:
            if self._is_trusted(record, auth):
                if not any(e.get("hash") == auth.hash for e in record.whitelisted_sessions):
                    self._whitelist_session(record, auth, source="fingerprint_auto")
                    changed = True
                continue

            if auth.current:
                logger.error("Refusing to kill current session for %s", phone)
                continue

            if await self._kill_session(client, auth, phone):
                killed.append(auth)

        if changed:
            await self.database.upsert(record)

        if killed:
            await notify_admins_session_killed(self.bot_app, self.config, phone, killed, source)

        return killed

    async def _delayed_session_sweep(self, phone: str, delay: float, source: str):
        await asyncio.sleep(delay)
        with suppress(Exception):
            await self.check_sessions(phone, source=source)

    async def shutdown(self):
        for task in self.tasks:
            task.cancel()
        if self.tasks:
            await asyncio.gather(*self.tasks, return_exceptions=True)
        self.tasks.clear()

        for client in list(self.clients.values()):
            with suppress(Exception):
                await client.disconnect()
        self.clients.clear()
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


async def _broadcast_to_admins(bot_app: Optional[Application], config: Config, text: str, markup=None):
    if not bot_app or not config.admin_ids:
        return

    async def send(aid):
        with suppress(Exception):
            await bot_app.bot.send_message(
                aid, text, parse_mode=ParseMode.HTML, reply_markup=markup,
            )

    await asyncio.gather(*(send(a) for a in config.admin_ids))


async def notify_admins_login_attempt(bot_app: Optional[Application], config: Config, phone: str):
    text = (
        "🚨 <b>Login Attempt Detected</b>\n"
        f"Account: <code>{html.escape(phone)}</code>\n"
        f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        "The login code was automatically invalidated."
    )
    await _broadcast_to_admins(bot_app, config, text)


async def notify_admins_session_removed(bot_app: Optional[Application], config: Config, phone: str, reason: str):
    text = (
        "🧹 <b>Session Removed</b>\n"
        f"Account: <code>{html.escape(phone)}</code>\n"
        f"Reason: {html.escape(reason)}\n"
        "This account was disconnected and cleaned up from the database. Re-add it if needed."
    )
    await _broadcast_to_admins(bot_app, config, text)


async def notify_admins_session_killed(
    bot_app: Optional[Application], config: Config,
    phone: str, killed_sessions, source: str,
):
    if not bot_app or not config.admin_ids:
        return

    lines = [
        "🔪 <b>Unauthorized Session Killed</b>",
        f"Account: <code>{html.escape(phone)}</code>",
        f"Trigger: <i>{html.escape(source)}</i>",
        "",
    ]
    for auth in killed_sessions:
        lines.append(_format_session(auth, prefix="• "))

    keyboard_rows = []
    if _session_manager:
        for auth in killed_sessions:
            fp = _session_fingerprint(auth)
            short = uuid.uuid4().hex[:10]
            _session_manager._pending_fingerprints[short] = (phone, fp)
            label = f"✅ Trust {auth.device_model or 'device'}"
            keyboard_rows.append([InlineKeyboardButton(label, callback_data=f"trustfp_{short}")])

    markup = InlineKeyboardMarkup(keyboard_rows) if keyboard_rows else None
    await _broadcast_to_admins(bot_app, config, "\n".join(lines), markup=markup)


_config: Optional[Config] = None
_session_manager: Optional[SessionManager] = None
user_sessions: dict = {}


def is_authorized(user_id: int) -> bool:
    return bool(_config) and user_id in _config.authorized_users


async def _safe_answer(query, text: Optional[str] = None, show_alert: bool = False):
    # [FIX #2] Telegram allows only ONE answer per callback query. Second call
    # raises BadRequest. We track per-query answered state via an attribute so
    # that any branch can call this idempotently and the toast is shown exactly
    # once with whichever text was supplied first.
    if getattr(query, "_safe_answered", False):
        return
    try:
        query._safe_answered = True
    except AttributeError:
        pass
    try:
        await query.answer(text=text, show_alert=show_alert)
    except BadRequest as e:
        logger.debug("answer() suppressed: %s", e)


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


async def list_accounts_view(context, chat_id, message_id, page: int = 0):
    # [FIX #6] Sort by phone for stable ordering across add/remove cycles.
    accounts = sorted(_session_manager.database.all().items(), key=lambda kv: kv[0])
    if not accounts:
        keyboard = [[InlineKeyboardButton("🔙 Back", callback_data="menu")]]
        await render(context, chat_id, message_id, "📋 <b>Account List</b>\n\nNo accounts registered yet.", keyboard)
        return

    total_pages = max(1, (len(accounts) + ACCOUNTS_PER_PAGE - 1) // ACCOUNTS_PER_PAGE)
    page = max(0, min(page, total_pages - 1))
    start = page * ACCOUNTS_PER_PAGE
    end = start + ACCOUNTS_PER_PAGE
    chunk = accounts[start:end]

    keyboard = []
    for phone, record in chunk:
        keyboard.append([
            InlineKeyboardButton(
                f"{'🔒' if record.anti_login else '🔓'} {phone}",
                callback_data=f"acc_{phone}",
            )
        ])

    nav_row = []
    if page > 0:
        nav_row.append(InlineKeyboardButton("⬅️ Prev", callback_data=f"list_acc_{page - 1}"))
    if page < total_pages - 1:
        nav_row.append(InlineKeyboardButton("Next ➡️", callback_data=f"list_acc_{page + 1}"))
    if nav_row:
        keyboard.append(nav_row)
    keyboard.append([InlineKeyboardButton("🔙 Back", callback_data="menu")])

    header = f"📋 <b>Account List</b> (page {page + 1}/{total_pages})"
    await render(context, chat_id, message_id, header, keyboard)


async def account_detail_view(context, chat_id, message_id, phone, banner: str = ""):
    record = _session_manager.database.get(phone)
    if not record:
        await list_accounts_view(context, chat_id, message_id)
        return
    status = "🔒 ENABLED" if record.anti_login else "🔓 DISABLED"
    text = (
        f"{html.escape(banner)}📱 <b>{html.escape(phone)}</b>\n"
        f"Anti-Login status: <b>{status}</b>\n"
        f"Codes invalidated so far: {record.invalidated_codes}\n"
        f"Whitelisted sessions: <b>{len(record.whitelisted_sessions)}</b>"
    )
    toggle_label = "🔓 Disable" if record.anti_login else "🔒 Enable"
    keyboard = [
        [InlineKeyboardButton(toggle_label, callback_data=f"toggle_{phone}")],
        [InlineKeyboardButton("🔐 Sessions", callback_data=f"sessions_{phone}")],
        [InlineKeyboardButton("🗑 Remove Account", callback_data=f"del_{phone}")],
        [InlineKeyboardButton("🔙 Back", callback_data="list_acc")],
    ]
    await render(context, chat_id, message_id, text, keyboard)


async def sessions_view(context, chat_id, message_id, phone):
    record = _session_manager.database.get(phone)
    client = _session_manager.clients.get(phone)
    if not record:
        await list_accounts_view(context, chat_id, message_id)
        return
    if not client:
        await render(
            context, chat_id, message_id,
            f"⚠️ Client for <code>{html.escape(phone)}</code> is not connected.",
            [[InlineKeyboardButton("🔙 Back", callback_data=f"acc_{phone}")]],
        )
        return

    try:
        result = await client(functions.account.GetAuthorizationsRequest())
    except Exception as e:
        await render(
            context, chat_id, message_id,
            f"❌ Failed to fetch sessions: {html.escape(str(e))}",
            [[InlineKeyboardButton("🔙 Back", callback_data=f"acc_{phone}")]],
        )
        return

    lines = [f"🔐 <b>Sessions for {html.escape(phone)}</b>\n"]
    keyboard_rows = []
    for auth in result.authorizations:
        trusted = _session_manager._is_trusted(record, auth)
        tag = "🟢" if trusted else "🔴"
        me_tag = " <i>(bot)</i>" if auth.current else ""
        lines.append(f"{tag}{me_tag}\n{_format_session(auth)}")

        if not auth.current:
            short = uuid.uuid4().hex[:10]
            _session_manager._ui_sessions[short] = (phone, auth.hash)
            if trusted:
                keyboard_rows.append([
                    InlineKeyboardButton(
                        f"🚫 Revoke {auth.device_model or 'device'}",
                        callback_data=f"sess_revoke_{short}",
                    )
                ])
            else:
                keyboard_rows.append([
                    InlineKeyboardButton(
                        f"✅ Trust {auth.device_model or 'device'}",
                        callback_data=f"sess_trust_{short}",
                    )
                ])

    keyboard_rows.append([InlineKeyboardButton("🔄 Refresh", callback_data=f"sessions_{phone}")])
    keyboard_rows.append([InlineKeyboardButton("🔙 Back", callback_data=f"acc_{phone}")])
    await render(context, chat_id, message_id, "\n".join(lines), keyboard_rows)


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


async def cleanup_qr_message(bot, session: dict):
    qr_msg_id = session.get("qr_msg_id")
    if qr_msg_id and bot:
        with suppress(Exception):
            await bot.delete_message(session["chat_id"], qr_msg_id)


async def reset_user_flow(context, user_id: int):
    session = user_sessions.pop(user_id, None)
    if not session:
        return
    await cleanup_qr_message(context.bot, session)
    await cleanup_session_client(session)


def _new_session(chat_id: int, message_id: int, **extra) -> dict:
    base = {
        "chat_id": chat_id,
        "control_msg_id": message_id,
        "created_at": time.monotonic(),
    }
    base.update(extra)
    return base


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
    user_sessions[user_id] = _new_session(message.chat_id, message.message_id)


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
    try:
        await client.connect()
        qr_login = await client.qr_login()
    except Exception as e:
        logger.error("QR login setup failed: %s", e)
        with suppress(Exception):
            await client.disconnect()
        await render(context, chat_id, message_id, f"❌ QR login failed: {html.escape(str(e))}", add_method_keyboard())
        return

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

    try:
        sent = await context.bot.send_photo(
            chat_id,
            buf,
            caption="🔲 Scan this QR code from Telegram on your phone:\nSettings → Devices → Link Desktop Device",
        )
    except Exception as e:
        logger.error("Failed to send QR photo: %s", e)
        with suppress(Exception):
            await client.disconnect()
        await render(context, chat_id, message_id, f"❌ Failed to send QR image: {html.escape(str(e))}", add_method_keyboard())
        return

    user_sessions[user_id] = _new_session(
        chat_id,
        message_id,
        step="wait_qr",
        client=client,
        qr_login=qr_login,
        qr_msg_id=sent.message_id,
    )
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
                await cleanup_qr_message(context.bot, session)
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
                await cleanup_qr_message(context.bot, session)
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
                await cleanup_qr_message(context.bot, session)
                user_sessions.pop(user_id, None)
                await render(context, chat_id, message_id, f"❌ QR login failed: {html.escape(str(e))}", [
                    [InlineKeyboardButton("🔙 Menu", callback_data="menu")]
                ])
            with suppress(Exception):
                await client.disconnect()
            return

    # [FIX #4] get_me() can throw if the network drops right after a successful
    # scan. Wrap it so the client is always disconnected on failure and the
    # user is not left stuck with a dangling QR session.
    try:
        me = await client.get_me()
    except Exception as e:
        logger.error("QR login: get_me failed: %s", e)
        await cleanup_qr_message(context.bot, session)
        user_sessions.pop(user_id, None)
        with suppress(Exception):
            await client.disconnect()
        await render(
            context, chat_id, message_id,
            f"❌ Could not fetch account info: {html.escape(str(e))}",
            [[InlineKeyboardButton("🔙 Menu", callback_data="menu")]],
        )
        return

    # Race guard: user navigated away while get_me was running.
    if user_sessions.get(user_id) is not session:
        with suppress(Exception):
            await client.disconnect()
        return

    phone = normalize_phone(me.phone) if me.phone else f"+id{me.id}"
    await cleanup_qr_message(context.bot, session)
    await finish_add_account(context, chat_id, message_id, user_id, phone, client)


async def user_session_sweeper(bot):
    while True:
        await asyncio.sleep(USER_SESSION_SWEEP_INTERVAL)
        now = time.monotonic()
        stale = []
        for uid, sess in list(user_sessions.items()):
            if "step" in sess:
                continue
            created = sess.get("created_at", now)
            if now - created > USER_SESSION_IDLE_TIMEOUT:
                stale.append(uid)
        for uid in stale:
            sess = user_sessions.pop(uid, None)
            if sess:
                await cleanup_qr_message(bot, sess)
                await cleanup_session_client(sess)
        if stale:
            logger.info("Swept %d idle user sessions", len(stale))

        if _session_manager:
            if len(_session_manager._ui_sessions) > 500:
                _session_manager._ui_sessions.clear()
            if len(_session_manager._pending_fingerprints) > 500:
                _session_manager._pending_fingerprints.clear()


async def message_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not is_authorized(user_id):
        return
    session = user_sessions.get(user_id)

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
            await cleanup_qr_message(context.bot, session)
            await finish_add_account(context, chat_id, message_id, user_id, phone, client)
        except PasswordHashInvalidError:
            await render(context, chat_id, message_id, "❌ Incorrect password. Please try again:", cancel_keyboard())
        except Exception as e:
            await render(context, chat_id, message_id, f"❌ Login failed: {html.escape(str(e))}", cancel_keyboard())


async def finish_add_account(context, chat_id, message_id, user_id, phone, client):
    # [FIX #3] If add_account fails (duplicate phone, DB error), the newly
    # created Telegram session must be logged out. Plain disconnect() leaves
    # the session valid server-side, causing orphan "bot" entries.
    try:
        success = await _session_manager.add_account(phone, client)
    except Exception as e:
        logger.error("finish_add_account: add_account failed for %s: %s", phone, e)
        success = False

    user_sessions.pop(user_id, None)

    if success:
        await account_detail_view(context, chat_id, message_id, phone, banner="✅ Account added successfully!\n\n")
        return

    # Failure path: log out the just-created session so it doesn't linger.
    with suppress(Exception):
        await client(functions.auth.LogOutRequest())
    with suppress(Exception):
        await client.disconnect()
    await render(
        context, chat_id, message_id,
        "❌ Account already exists or failed to add.",
        [[InlineKeyboardButton("🔙 Menu", callback_data="menu")]],
    )


async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    user_id = update.effective_user.id
    chat_id = query.message.chat_id
    message_id = query.message.message_id

    if not is_authorized(user_id):
        await _safe_answer(query)
        await render(context, chat_id, message_id, "⛔ Unauthorized")
        return

    data = query.data

    try:
        await reset_user_flow(context, user_id)
        user_sessions[user_id] = _new_session(chat_id, message_id)

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
            await list_accounts_view(context, chat_id, message_id, page=0)

        elif data.startswith("list_acc_"):
            try:
                page = int(data[len("list_acc_"):])
            except ValueError:
                page = 0
            await list_accounts_view(context, chat_id, message_id, page=page)

        elif data.startswith("acc_"):
            await account_detail_view(context, chat_id, message_id, data[len("acc_"):])

        elif data.startswith("toggle_"):
            phone = data[len("toggle_"):]
            await _session_manager.toggle_anti_login(phone)
            await account_detail_view(context, chat_id, message_id, phone)

        elif data.startswith("delconfirm_"):
            phone = data[len("delconfirm_"):]
            ok = await _session_manager.remove_account(phone)
            if ok:
                await render(
                    context, chat_id, message_id,
                    f"✅ Account <code>{html.escape(phone)}</code> removed and session logged out.",
                    [[InlineKeyboardButton("🔙 Back", callback_data="list_acc")]],
                )
            else:
                await render(
                    context, chat_id, message_id,
                    f"⚠️ Account <code>{html.escape(phone)}</code> was not found in the database.",
                    [[InlineKeyboardButton("🔙 Back", callback_data="list_acc")]],
                )

        elif data.startswith("del_"):
            await delete_confirm_view(context, chat_id, message_id, data[len("del_"):])

        elif data == "reconnect_all":
            await render(context, chat_id, message_id, "🔄 Reconnecting all accounts in background...")
            _session_manager.track(asyncio.create_task(_session_manager.reconnect_all()))
            await show_main_menu(context, chat_id, message_id)

        elif data.startswith("sessions_"):
            await sessions_view(context, chat_id, message_id, data[len("sessions_"):])

        elif data.startswith("sess_trust_"):
            short = data[len("sess_trust_"):]
            key = _session_manager._ui_sessions.pop(short, None)
            if not key:
                await _safe_answer(query, "Expired — reopen Sessions")
                return
            phone, hash_val = key
            record = _session_manager.database.get(phone)
            client = _session_manager.clients.get(phone)
            if not record or not client:
                await _safe_answer(query, "Account unavailable")
                return
            try:
                result = await client(functions.account.GetAuthorizationsRequest())
                for auth in result.authorizations:
                    if auth.hash == hash_val:
                        _session_manager._whitelist_session(record, auth, source="admin_ui")
                        await _session_manager.database.upsert(record)
                        await _safe_answer(query, "Session trusted")
                        await sessions_view(context, chat_id, message_id, phone)
                        return
            except Exception as e:
                logger.error("Failed to trust session: %s", e)
            await _safe_answer(query, "Failed to trust")

        elif data.startswith("sess_revoke_"):
            short = data[len("sess_revoke_"):]
            key = _session_manager._ui_sessions.pop(short, None)
            if not key:
                await _safe_answer(query, "Expired — reopen Sessions")
                return
            phone, hash_val = key
            record = _session_manager.database.get(phone)
            client = _session_manager.clients.get(phone)
            if not record or not client:
                await _safe_answer(query, "Account unavailable")
                return
            try:
                result = await client(functions.account.GetAuthorizationsRequest())
                for auth in result.authorizations:
                    if auth.hash == hash_val:
                        if auth.current:
                            await _safe_answer(query, "Refusing to revoke current session")
                            return
                        await client(functions.account.ResetAuthorizationRequest(hash=auth.hash))
                        record.whitelisted_sessions = [
                            e for e in record.whitelisted_sessions if e.get("hash") != auth.hash
                        ]
                        await _session_manager.database.upsert(record)
                        logger.warning("Manually revoked session for %s", phone)
                        await _safe_answer(query, "Revoked")
                        await sessions_view(context, chat_id, message_id, phone)
                        return
            except Exception as e:
                logger.error("Failed to revoke session: %s", e)
            await _safe_answer(query, "Failed to revoke")

        elif data.startswith("trustfp_"):
            short = data[len("trustfp_"):]
            entry = _session_manager._pending_fingerprints.pop(short, None)
            if not entry:
                await _safe_answer(query, "Expired")
                return
            phone, fp = entry
            record = _session_manager.database.get(phone)
            if not record:
                await _safe_answer(query, "Account not found")
                return
            if fp not in record.trusted_fingerprints:
                record.trusted_fingerprints.append(fp)
                await _session_manager.database.upsert(record)
            await _safe_answer(query, "Device trusted — user can now re-login")
            with suppress(Exception):
                await query.edit_message_text(
                    f"✅ Trusted device type:\n<code>{html.escape(fp)}</code>\n\n"
                    f"User from this device can log in again.",
                    parse_mode=ParseMode.HTML,
                )
    finally:
        # [FIX #2] Ensure the callback query is always answered, even if the
        # branch above returned without answering explicitly. Any explicit
        # answer earlier already set the flag, so this is a no-op in that case.
        await _safe_answer(query)


async def error_handler(update, context: ContextTypes.DEFAULT_TYPE):
    logger.error("Update %s caused error: %s", update, context.error)


def make_post_init(session_manager: SessionManager):
    async def post_init(application: Application):
        await session_manager.load_all()
        session_manager.track(asyncio.create_task(session_manager.health_check_loop()))
        session_manager.track(asyncio.create_task(user_session_sweeper(application.bot)))
        me = await application.bot.get_me()
        banner = (
            "\n" + "=" * 46 + "\n"
            f"  Anti-Login Bot running as @{me.username}\n"
            f"  Protected accounts : {len(session_manager.phones())}\n"
            f"  Registered admins  : {len(session_manager.config.admin_ids)}\n"
            f"  Strict fingerprint : {'OFF' if session_manager.config.trust_fingerprint else 'ON (hash-only)'}\n"
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

    if not config.trust_fingerprint:
        logger.info("Strict mode: fingerprint auto-trust is DISABLED (hash whitelist only).")

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
    try:
        bot_app.run_polling(allowed_updates=Update.ALL_TYPES)
    except Exception as e:
        logger.exception("Bot terminated with error: %s", e)
        raise


if __name__ == "__main__":
    main()