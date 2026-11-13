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
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

import qrcode
from telethon import TelegramClient, events, functions
from telethon.tl import types
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
from telegram.error import BadRequest, TimedOut, NetworkError
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


def _utcnow() -> datetime:
    """Naive UTC datetime — replacement for deprecated datetime.utcnow()."""
    return datetime.now(timezone.utc).replace(tzinfo=None)

# [FIX #1] Accept +id... identifiers (QR accounts without phone).
PHONE_REGEX = re.compile(r"^(?:\+\d{7,15}|\+id\d+)$")
CODE_REGEX = re.compile(r"^\d{4,7}$")

# [VALID #1] OTP extraction — structured keyword match first, then
# single-candidate fallback. Supports 5-6 digit codes (Telegram now
# uses both, and some locales already use 6 digits).
OTP_CODE_KEYWORD_RE = re.compile(
    r"(?i)(?:login code|kode|verifikasi|verification code|code)[^\d]{0,30}(\d{5,6})"
)
OTP_CODE_ANY_RE = re.compile(r"\b\d{5,6}\b")

TELEGRAM_SERVICE_ID = 777000
QR_MAX_REFRESHES = 6
HEALTH_CHECK_INTERVAL_SECONDS = 300
BACKUP_RETENTION_COUNT = 1
BACKUP_MIN_INTERVAL_SECONDS = 60
USER_SESSION_SWEEP_INTERVAL = 3600
USER_SESSION_IDLE_TIMEOUT = 3600
STEP_TIMEOUT_SECONDS = 900
ACCOUNTS_PER_PAGE = 10
OTP_SESSION_SWEEP_DELAY_SECONDS = 4
ADD_COOLDOWN_SECONDS = 120
UI_CACHE_TTL_SECONDS = 1800
INVALID_SESSION_ERRORS = (AuthKeyError, UserDeactivatedError, UserDeactivatedBanError)


def _extract_otp_code(text: str) -> Optional[str]:
    """[VALID #1] Extract the OTP from a Telegram service message.
    Returns None if the message is ambiguous or has no candidate."""
    if not text:
        return None
    m = OTP_CODE_KEYWORD_RE.search(text)
    if m:
        return m.group(1)
    candidates = OTP_CODE_ANY_RE.findall(text)
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        logger.warning(
            "OTP message ambiguous (%d candidates), skipping: %r",
            len(candidates), text[:200],
        )
    return None


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

    audit = logging.getLogger("audit")
    audit_path = Path(LOG_DIR) / "audit.log"
    if not any(
        isinstance(h, RotatingFileHandler) and Path(h.baseFilename) == audit_path
        for h in audit.handlers
    ):
        ah = RotatingFileHandler(audit_path, maxBytes=10 * 1024 * 1024, backupCount=10, encoding="utf-8")
        ah.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        audit.addHandler(ah)
    audit.setLevel(logging.INFO)
    audit.propagate = False

    return logging.getLogger("anti_login")


logger = setup_logging()
audit_logger = logging.getLogger("audit")


@dataclasses.dataclass(frozen=True)
class Config:
    api_id: int
    api_hash: str
    bot_token: str
    admin_ids: frozenset


def _to_int_set(values) -> frozenset:
    result = set()
    for value in values or []:
        # [VALID #6] Reject bools (True/False are ints in Python).
        if isinstance(value, bool):
            logger.warning("Ignoring bool id in config.json: %r", value)
            continue
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
            "admin_ids": [123456789],
        }
        path.write_text(json.dumps(sample, indent=2))
        logger.warning("%s not found. A sample has been created — fill it in and restart.", path)
        return None

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        logger.error("Failed to read %s: %s", path, e)
        return None

    if not isinstance(raw, dict):
        logger.error("config.json must be a JSON object")
        return None

    # [VALID #6] api_id validation
    raw_api_id = raw.get("api_id")
    if isinstance(raw_api_id, bool):
        logger.error("api_id must be an integer, not bool")
        return None
    try:
        api_id = int(raw_api_id)
    except (TypeError, ValueError):
        logger.error("api_id must be an integer, got %r", raw_api_id)
        return None
    if not (1 <= api_id <= 10_000_000_000):
        logger.error("api_id out of plausible range: %s", api_id)
        return None

    # [VALID #6] api_hash validation
    api_hash = raw.get("api_hash")
    if not isinstance(api_hash, str) or not re.fullmatch(r"[0-9a-fA-F]{32}", api_hash):
        logger.error("api_hash must be a 32-char hex string")
        return None
    if "your_hash" in api_hash.lower():
        logger.error("api_hash still sample value — change it first")
        return None

    # [VALID #6] bot_token validation
    bot_token = raw.get("bot_token")
    if not isinstance(bot_token, str) or not re.fullmatch(r"\d+:[A-Za-z0-9_-]{30,50}", bot_token):
        logger.error("bot_token format invalid (expected '<id>:<secret>')")
        return None
    if "your_token" in bot_token.lower():
        logger.error("bot_token still sample value — change it first")
        return None

    return Config(
        api_id=api_id,
        api_hash=api_hash,
        bot_token=bot_token,
        admin_ids=_to_int_set(raw.get("admin_ids")),
    )


def normalize_phone(raw: str) -> str:
    # [VALID #8] Preserve +id... identifiers
    if raw.startswith("+id"):
        return raw
    return "+" + re.sub(r"\D", "", raw)


@dataclasses.dataclass
class AccountRecord:
    phone: str
    session_str: str
    anti_login: bool = False
    created_at: str = dataclasses.field(default_factory=lambda: _utcnow().isoformat())
    updated_at: str = dataclasses.field(default_factory=lambda: _utcnow().isoformat())
    invalidated_codes: int = 0
    whitelisted_sessions: list = dataclasses.field(default_factory=list)
    whitelist_initialized: bool = False

    def touch(self):
        self.updated_at = _utcnow().isoformat()

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @staticmethod
    def from_dict(phone: str, data: dict) -> "AccountRecord":
        return AccountRecord(
            phone=phone,
            session_str=str(data["session_str"]),
            anti_login=bool(data.get("anti_login", False)),
            created_at=str(data.get("created_at") or _utcnow().isoformat()),
            updated_at=str(data.get("updated_at") or _utcnow().isoformat()),
            invalidated_codes=int(data.get("invalidated_codes", 0) or 0),
            whitelisted_sessions=list(data.get("whitelisted_sessions", []) or []),
            whitelist_initialized=bool(data.get("whitelist_initialized", False)),
        )


def validate_account_record(phone: str, data) -> Optional[str]:
    # [VALID #2] + [VALID #12] Full record validation — prevents load() crash
    if not PHONE_REGEX.match(phone):
        return f"invalid phone format: {phone}"
    if not isinstance(data, dict):
        return "record is not a JSON object"
    session_str = data.get("session_str")
    if not isinstance(session_str, str) or not session_str.strip():
        return "missing or empty session_str"
    # [VALID #2] Ensure invalidated_codes is numeric
    try:
        int(data.get("invalidated_codes", 0) or 0)
    except (TypeError, ValueError):
        return "invalidated_codes is not numeric"
    # [VALID #2] Ensure whitelisted_sessions is a list
    if not isinstance(data.get("whitelisted_sessions", []), list):
        return "whitelisted_sessions is not a list"
    if not isinstance(data.get("anti_login", False), bool):
        return "anti_login is not a bool"
    if not isinstance(data.get("whitelist_initialized", False), bool):
        return "whitelist_initialized is not a bool"
    return None


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
            try:
                records[phone] = AccountRecord.from_dict(phone, data)
            except Exception as e:
                # [VALID #2] Never let a single bad record crash startup
                logger.error("Failed to parse record %s: %s", phone, e)
                rejected.append(phone)
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
            data = json.loads(content)
            if not isinstance(data, dict):
                raise json.JSONDecodeError("top-level is not an object", content, 0)
            return data
        except (json.JSONDecodeError, OSError) as e:
            logger.error("accounts.json is corrupt (%s). Attempting recovery from backup.", e)
            return self._recover_from_backup()

    def _recover_from_backup(self) -> dict:
        backups = sorted(self.backup_dir.glob("accounts_*.json"), reverse=True)
        for backup in backups:
            try:
                data = json.loads(backup.read_text(encoding="utf-8"))
                # [VALID #16] Validate structure before accepting backup
                if not isinstance(data, dict):
                    logger.warning("Backup %s is not a dict, skip", backup.name)
                    continue
                if not all(PHONE_REGEX.match(k) for k in data.keys() if isinstance(k, str)):
                    logger.warning("Backup %s has invalid keys, skip", backup.name)
                    continue
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

    async def mutate(self, phone: str, fn) -> Optional[AccountRecord]:
        async with self._lock:
            record = self._records.get(phone)
            if record is None:
                return None
            fn(record)
            record.touch()
            await self._save_locked()
            return record

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
                # [VALID #10] Guard against non-dict backups
                if not isinstance(data, dict):
                    logger.warning("Backup %s not a dict, skip redact", backup.name)
                    continue
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
        stamp = _utcnow().strftime("%Y%m%dT%H%M%S%f")
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
        # [VALID #11] Detect corrupt session_str early
        try:
            session = StringSession(record.session_str)
        except (ValueError, TypeError) as e:
            logger.error("Corrupt session_str for %s (%s). Removing.", phone, e)
            await self.database.remove(phone)
            await asyncio.to_thread(self.database.redact_phone_from_backups, phone)
            return

        client = TelegramClient(session, self.config.api_id, self.config.api_hash)
        try:
            await client.connect()
            if not await client.is_user_authorized():
                raise AuthKeyError("session no longer authorized")
            # [VALID #5] Guard against get_me() returning None
            me = await client.get_me()
            if me is None:
                raise AuthKeyError("get_me returned None — session likely invalid")
            self.clients[phone] = client
            try:
                self._setup_otp_guard(phone, client)
                self.track(asyncio.create_task(self._supervise_client(phone, client)))
                await self._ensure_whitelist_initialized(phone, client)
            except Exception:
                self.clients.pop(phone, None)
                raise
            logger.info("Account loaded: %s (%s)", phone, me.first_name)
        except INVALID_SESSION_ERRORS as e:
            logger.error("Session for %s is no longer valid (%s). Removing from database.", phone, e)
            with suppress(Exception):
                await client.disconnect()
            self.clients.pop(phone, None)
            await self.database.remove(phone)
            await asyncio.to_thread(self.database.redact_phone_from_backups, phone)
            await notify_admins_session_removed(self.bot_app, self.config, phone, str(e))
        except Exception as e:
            self.clients.pop(phone, None)
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
        try:
            await self.database.upsert(record)
            self.clients[phone] = client
            try:
                self._setup_otp_guard(phone, client)
                self.track(asyncio.create_task(self._supervise_client(phone, client)))
                await self._ensure_whitelist_initialized(phone, client)
            except Exception:
                self.clients.pop(phone, None)
                raise
        except Exception as e:
            logger.error("add_account failed for %s: %s", phone, e)
            self.clients.pop(phone, None)
            with suppress(Exception):
                await self.database.remove(phone)
            raise
        logger.info("Account added: %s", phone)
        audit_logger.info("account_added phone=%s", phone)
        return True

    async def remove_account(self, phone: str) -> bool:
        client = self.clients.get(phone)
        logged_out = False
        if client:
            for attempt in range(3):
                try:
                    await client(functions.auth.LogOutRequest())
                    logged_out = True
                    audit_logger.info("account_logout phone=%s attempt=%d", phone, attempt + 1)
                    break
                except Exception as e:
                    if attempt < 2:
                        logger.info("Logout retry for %s (attempt %d): %s", phone, attempt + 2, e)
                        await asyncio.sleep(2 ** attempt)
                        continue
                    logger.error("Logout FAILED for %s after retries: %s", phone, e)
                    await _broadcast_to_admins(
                        self.bot_app, self.config,
                        f"⚠️ <b>Logout fail</b> for <code>{html.escape(phone)}</code>.\n"
                        f"Session may still be active on Telegram. Try <b>Remove Account</b> again later.",
                    )
                    with suppress(Exception):
                        await client.disconnect()
                    return False
            self.clients.pop(phone, None)
            with suppress(Exception):
                await client.disconnect()

        removed = await self.database.remove(phone)
        if removed:
            await asyncio.to_thread(self.database.redact_phone_from_backups, phone)
            audit_logger.info("account_removed phone=%s logged_out=%s", phone, logged_out)
            logger.info("Removed account %s (logged_out=%s, backups scrubbed)", phone, logged_out)
        return removed

    async def toggle_anti_login(self, phone: str) -> bool:
        def _toggle(r: AccountRecord):
            r.anti_login = not r.anti_login

        record = await self.database.mutate(phone, _toggle)
        if record is None:
            return False
        logger.info("Anti-Login %s -> %s", phone, "ENABLED" if record.anti_login else "DISABLED")
        audit_logger.info("anti_login_toggle phone=%s state=%s", phone, record.anti_login)
        return True

    async def reset_baseline(self, phone: str) -> bool:
        client = self.clients.get(phone)
        if not client:
            return False

        def _reset(r: AccountRecord):
            r.whitelist_initialized = False
            r.whitelisted_sessions = []

        await self.database.mutate(phone, _reset)
        ok = await self._ensure_whitelist_initialized(phone, client)
        audit_logger.info("baseline_reset phone=%s ok=%s", phone, ok)
        return ok

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

            # [VALID #11] Detect corrupt session_str early
            try:
                session = StringSession(record.session_str)
            except (ValueError, TypeError) as e:
                logger.error("Corrupt session_str for %s during reconnect (%s). Removing.", phone, e)
                await self.database.remove(phone)
                await asyncio.to_thread(self.database.redact_phone_from_backups, phone)
                return False

            client = TelegramClient(session, self.config.api_id, self.config.api_hash)
            try:
                await client.connect()
                if not await client.is_user_authorized():
                    raise AuthKeyError("session no longer authorized")
                # [VALID #5] Guard get_me() None
                me = await client.get_me()
                if me is None:
                    raise AuthKeyError("get_me returned None — session likely invalid")
                self.clients[phone] = client
                try:
                    self._setup_otp_guard(phone, client)
                    self.track(asyncio.create_task(self._supervise_client(phone, client)))
                    await self._ensure_whitelist_initialized(phone, client)
                except Exception:
                    self.clients.pop(phone, None)
                    raise
                self._reconnect_delays.pop(phone, None)
                logger.info("Reconnected: %s", phone)
                return True
            except INVALID_SESSION_ERRORS as e:
                logger.error("Session for %s is invalid during reconnect (%s). Removing.", phone, e)
                with suppress(Exception):
                    await client.disconnect()
                self.clients.pop(phone, None)
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
        # [VALID #1] Use robust extraction; skip ambiguous messages
        code = _extract_otp_code(event.message.text or "")
        if not code:
            return
        client = self.clients.get(phone)
        if not client:
            return
        try:
            await client(functions.account.InvalidateSignInCodesRequest(codes=[code]))
            logger.warning("Login code %s for %s was invalidated.", code, phone)
            audit_logger.warning("otp_invalidated phone=%s code=%s", phone, code)
        except Exception as e:
            logger.error("Failed to invalidate code for %s: %s", phone, e)
            return

        def _inc(r: AccountRecord):
            r.invalidated_codes += 1

        record = await self.database.mutate(phone, _inc)
        if record is None:
            return

        self.track(asyncio.create_task(
            self._delayed_session_sweep(phone, delay=OTP_SESSION_SWEEP_DELAY_SECONDS, source="otp_event")
        ))

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
            "trusted_at": _utcnow().isoformat(),
            "source": source,
        }
        record.whitelisted_sessions = [
            e for e in record.whitelisted_sessions if e.get("hash") != auth.hash
        ]
        record.whitelisted_sessions.append(entry)

    def _is_trusted(self, record: AccountRecord, auth) -> bool:
        if auth.current:
            return True
        return any(e.get("hash") == auth.hash for e in record.whitelisted_sessions)

    async def _kill_session(self, client, auth, phone: str) -> bool:
        try:
            await client(functions.account.ResetAuthorizationRequest(hash=auth.hash))
            logger.warning(
                "Killed session for %s: %s / %s (%s)",
                phone, auth.device_model, auth.platform, auth.country,
            )
            audit_logger.warning(
                "session_killed phone=%s device=%s platform=%s ip=%s",
                phone, auth.device_model, auth.platform, auth.ip,
            )
            return True
        except Exception as e:
            logger.info("Could not kill session for %s (hash=%s): %s", phone, auth.hash, e)
            return False

    async def _ensure_whitelist_initialized(self, phone: str, client: TelegramClient) -> bool:
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

        def _apply(r: AccountRecord):
            for auth in result.authorizations:
                self._whitelist_session(r, auth, source="baseline")
            r.whitelist_initialized = True

        record = await self.database.mutate(phone, _apply)
        if record is None:
            return False
        logger.info("Baseline whitelist for %s: %d session(s) trusted", phone, len(result.authorizations))
        audit_logger.info("baseline_init phone=%s count=%d", phone, len(result.authorizations))
        return True

    async def check_sessions(self, phone: str, source: str) -> list:
        record = self.database.get(phone)
        client = self.clients.get(phone)
        if not record or not client:
            return []

        if not record.whitelist_initialized:
            ok = await self._ensure_whitelist_initialized(phone, client)
            if not ok:
                logger.warning(
                    "Skipping session sweep for %s (%s): baseline not initialized", phone, source,
                )
                await _broadcast_to_admins(
                    self.bot_app, self.config,
                    f"⚠️ <b>Baseline not ready</b> for <code>{html.escape(phone)}</code>\n"
                    f"Anti-login can't sweep session (<i>{html.escape(source)}</i>).\n"
                    f"Use the button <b>Reset Baseline</b>.",
                )
                return []
            record = self.database.get(phone)
            if not record:
                return []

        try:
            result = await client(functions.account.GetAuthorizationsRequest())
        except Exception as e:
            logger.error("Failed to fetch authorizations for %s: %s", phone, e)
            return []

        to_kill = []
        for auth in result.authorizations:
            if self._is_trusted(record, auth):
                continue
            if auth.current:
                logger.error("Refusing to kill current session for %s", phone)
                continue
            to_kill.append(auth)

        killed = []
        for auth in to_kill:
            if await self._kill_session(client, auth, phone):
                killed.append(auth)

        if killed:
            def _apply(r: AccountRecord):
                killed_hashes = {a.hash for a in killed}
                r.whitelisted_sessions = [
                    e for e in r.whitelisted_sessions if e.get("hash") not in killed_hashes
                ]
            await self.database.mutate(phone, _apply)
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

    await _broadcast_to_admins(bot_app, config, "\n".join(lines))


_config: Optional[Config] = None
_session_manager: Optional[SessionManager] = None
user_sessions: dict = {}
_add_cooldown: dict[int, float] = {}


def is_authorized(user_id: int) -> bool:
    return bool(_config) and user_id in _config.admin_ids


def _check_add_cooldown(user_id: int) -> Optional[str]:
    last = _add_cooldown.get(user_id, 0.0)
    delta = time.monotonic() - last
    if delta < ADD_COOLDOWN_SECONDS:
        return f"⏳ Wait {int(ADD_COOLDOWN_SECONDS - delta + 1)} seconds before adding another account."
    return None


def _bump_control_message(chat_id: int, old_id: int, new_id: int):
    for sess in user_sessions.values():
        if sess.get("chat_id") == chat_id and sess.get("control_msg_id") == old_id:
            sess["control_msg_id"] = new_id


async def _safe_answer(query, text: Optional[str] = None, show_alert: bool = False):
    if query is None:
        return
    if getattr(query, "_safe_answered", False):
        return
    try:
        query._safe_answered = True
    except AttributeError:
        pass
    try:
        await query.answer(text=text, show_alert=show_alert)
    except (BadRequest, TimedOut, NetworkError) as e:
        logger.debug("answer() suppressed: %s", e)


def _validate_keyboard(keyboard) -> None:
    """[VALID #13] Warn if any callback_data exceeds Telegram's 64-byte limit."""
    if not keyboard:
        return
    for row in keyboard:
        for btn in row:
            cb = getattr(btn, "callback_data", None)
            if isinstance(cb, str):
                encoded = cb.encode("utf-8")
                if len(encoded) > 64:
                    logger.error(
                        "callback_data exceeds 64 bytes (%d): %r", len(encoded), cb,
                    )


async def render(context, chat_id: int, message_id: int, text: str, keyboard=None) -> int:
    _validate_keyboard(keyboard)
    markup = InlineKeyboardMarkup(keyboard) if keyboard else None
    try:
        await context.bot.edit_message_text(
            chat_id=chat_id,
            message_id=message_id,
            text=text,
            parse_mode=ParseMode.HTML,
            reply_markup=markup,
        )
        return message_id
    except BadRequest as e:
        err = str(e).lower()
        if "message is not modified" in err:
            return message_id
        if "message to edit not found" in err or "message can't be edited" in err:
            logger.info("Control message %s missing; sending fresh message", message_id)
            msg = await context.bot.send_message(
                chat_id, text, parse_mode=ParseMode.HTML, reply_markup=markup,
            )
            _bump_control_message(chat_id, message_id, msg.message_id)
            return msg.message_id
        logger.warning("HTML parse failed, retrying as plain text: %s", e)

    plain = html.unescape(re.sub(r"<[^>]+>", "", text))
    try:
        await context.bot.edit_message_text(
            chat_id=chat_id, message_id=message_id, text=plain, reply_markup=markup,
        )
        return message_id
    except BadRequest as e:
        err = str(e).lower()
        if "message is not modified" in err:
            return message_id
        if "message to edit not found" in err or "message can't be edited" in err:
            msg = await context.bot.send_message(chat_id, plain, reply_markup=markup)
            _bump_control_message(chat_id, message_id, msg.message_id)
            return msg.message_id
        logger.error("Failed to edit message: %s", e)
        return message_id


def main_menu_keyboard():
    return [
        [
            InlineKeyboardButton("➕ Add Account", callback_data="add_acc", style="primary"),
            InlineKeyboardButton("📋 Account List", callback_data="list_acc", style="success"),
        ],
        [
            InlineKeyboardButton("📊 Stats", callback_data="stats", style="primary"),
            InlineKeyboardButton("🔄 Reconnect All", callback_data="reconnect_all", style="danger"),
        ],
    ]


async def show_main_menu(context, chat_id, message_id):
    await render(
        context, chat_id, message_id,
        "🛡️ <b>Welcome to Anti-Login Bot</b>\nSecurely manage and monitor your protected accounts.\n\n👨‍💻 Developer: @nifzz",
        main_menu_keyboard(),
    )


def _account_sort_key(kv):
    phone = kv[0]
    return (1 if phone.startswith("+id") else 0, phone)


async def list_accounts_view(context, chat_id, message_id, page: int = 0, filter_q: str = ""):
    accounts = sorted(_session_manager.database.all().items(), key=_account_sort_key)
    if filter_q:
        accounts = [(p, r) for p, r in accounts if filter_q in p]

    if not accounts:
        keyboard = [[InlineKeyboardButton("🔙 Back", callback_data="menu", style="primary")]]
        msg = "📋 <b>Account List</b>\n\nNo accounts" + (f" matching <code>{html.escape(filter_q)}</code>." if filter_q else " registered yet.")
        await render(context, chat_id, message_id, msg, keyboard)
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
                style="success" if record.anti_login else "danger",
            )
        ])

    nav_row = []
    if page > 0:
        nav_row.append(InlineKeyboardButton("⬅️ Prev", callback_data=f"list_acc_{page - 1}", style="primary"))
    if page < total_pages - 1:
        nav_row.append(InlineKeyboardButton("Next ➡️", callback_data=f"list_acc_{page + 1}", style="primary"))
    if nav_row:
        keyboard.append(nav_row)
    keyboard.append([InlineKeyboardButton("🔙 Back", callback_data="menu", style="primary")])

    header = f"📋 <b>Account List</b> (page {page + 1}/{total_pages})"
    if filter_q:
        header += f"\n🔍 Filter: <code>{html.escape(filter_q)}</code>"
    await render(context, chat_id, message_id, header, keyboard)


async def account_detail_view(context, chat_id, message_id, phone, banner: str = ""):
    record = _session_manager.database.get(phone)
    if not record:
        await list_accounts_view(context, chat_id, message_id)
        return
    status = "🔒 ENABLED" if record.anti_login else "🔓 DISABLED"
    baseline = "✅ ready" if record.whitelist_initialized else "⚠️ not initialized"
    text = (
        f"{html.escape(banner)}📱 <b>{html.escape(phone)}</b>\n"
        f"Anti-Login status: <b>{status}</b>\n"
        f"Codes invalidated so far: {record.invalidated_codes}\n"
        f"Whitelisted sessions: <b>{len(record.whitelisted_sessions)}</b>\n"
        f"Baseline: {baseline}"
    )
    toggle_label = "🔓 Disable" if record.anti_login else "🔒 Enable"
    toggle_style = "danger" if record.anti_login else "success"
    keyboard = [
        [InlineKeyboardButton(toggle_label, callback_data=f"toggle_{phone}", style=toggle_style)],
        [InlineKeyboardButton("🔐 Sessions", callback_data=f"sessions_{phone}", style="primary")],
        [InlineKeyboardButton("♻️ Reset Baseline", callback_data=f"resetbase_{phone}", style="primary")],
        [InlineKeyboardButton("🗑 Remove Account", callback_data=f"del_{phone}", style="danger")],
        [InlineKeyboardButton("🔙 Back", callback_data="list_acc", style="primary")],
    ]
    await render(context, chat_id, message_id, text, keyboard)


async def sessions_view(context, chat_id, message_id, phone, banner: str = ""):
    record = _session_manager.database.get(phone)
    client = _session_manager.clients.get(phone)
    if not record:
        await list_accounts_view(context, chat_id, message_id)
        return
    if not client:
        await render(
            context, chat_id, message_id,
            f"{banner}⚠️ Client for <code>{html.escape(phone)}</code> is not connected.",
            [[InlineKeyboardButton("🔙 Back", callback_data=f"acc_{phone}", style="primary")]],
        )
        return

    try:
        result = await client(functions.account.GetAuthorizationsRequest())
    except Exception as e:
        await render(
            context, chat_id, message_id,
            f"{banner}❌ Failed to fetch sessions: {html.escape(str(e))}",
            [[InlineKeyboardButton("🔙 Back", callback_data=f"acc_{phone}", style="primary")]],
        )
        return

    lines = [f"{banner}🔐 <b>Sessions for {html.escape(phone)}</b>\n"]
    keyboard_rows = []
    for auth in result.authorizations:
        trusted = _session_manager._is_trusted(record, auth)
        tag = "🟢" if trusted else "🔴"
        me_tag = " <i>(bot)</i>" if auth.current else ""
        lines.append(f"{tag}{me_tag}\n{_format_session(auth)}")

        if not auth.current:
            short = uuid.uuid4().hex[:10]
            _session_manager._ui_sessions[short] = (phone, auth.hash, time.monotonic())
            device = auth.device_model or "device"
            row = []
            if not trusted:
                row.append(InlineKeyboardButton(
                    f"✅ Trust {device}",
                    callback_data=f"sess_trust_{short}",
                    style="success",
                ))
            row.append(InlineKeyboardButton(
                f"🚪 Logout {device}",
                callback_data=f"revokeconfirm_{short}",
                style="danger",
            ))
            keyboard_rows.append(row)

    keyboard_rows.append([InlineKeyboardButton("🔄 Refresh", callback_data=f"sessions_{phone}", style="primary")])
    keyboard_rows.append([InlineKeyboardButton("🔙 Back", callback_data=f"acc_{phone}", style="primary")])
    await render(context, chat_id, message_id, "\n".join(lines), keyboard_rows)


async def delete_confirm_view(context, chat_id, message_id, phone):
    if phone not in _session_manager.database:
        await list_accounts_view(context, chat_id, message_id)
        return
    keyboard = [
        [
            InlineKeyboardButton("✅ Yes, Remove", callback_data=f"delconfirm_{phone}", style="danger"),
            InlineKeyboardButton("❌ Cancel", callback_data=f"acc_{phone}", style="primary"),
        ]
    ]
    await render(context, chat_id, message_id, f"⚠️ Remove account <code>{html.escape(phone)}</code>?", keyboard)


def cancel_keyboard():
    return [[InlineKeyboardButton("❌ Cancel", callback_data="cancel_add", style="danger")]]


def add_method_keyboard():
    return [
        [InlineKeyboardButton("📱 Phone Number", callback_data="add_phone", style="primary")],
        [InlineKeyboardButton("🔲 QR Code", callback_data="add_qr", style="primary")],
        [InlineKeyboardButton("🔙 Back", callback_data="menu", style="primary")],
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
    # [VALID #7] Defensive against channel posts
    if update.effective_user is None or update.message is None:
        return
    user_id = update.effective_user.id
    if not is_authorized(user_id):
        await update.message.reply_text("⛔ Unauthorized")
        return

    await reset_user_flow(context, user_id)

    message = await update.message.reply_text(
        "🛡️ <b>Welcome to Anti-Login Bot</b>\nSecurely manage and monitor your protected accounts.\n\n👨‍💻 Developer: @nifzz",
        parse_mode=ParseMode.HTML,
        reply_markup=InlineKeyboardMarkup(main_menu_keyboard()),
    )
    user_sessions[user_id] = _new_session(message.chat_id, message.message_id)


async def cancel_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # [VALID #7] Defensive against channel posts
    if update.effective_user is None or update.message is None:
        return
    user_id = update.effective_user.id
    if not is_authorized(user_id):
        return
    await reset_user_flow(context, user_id)
    msg = await update.message.reply_text(
        "✅ Canceled.",
        reply_markup=InlineKeyboardMarkup(main_menu_keyboard()),
    )
    user_sessions[user_id] = _new_session(msg.chat_id, msg.message_id)


def generate_qr_image(url: str) -> io.BytesIO:
    img = qrcode.make(url)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    buf.seek(0)
    return buf


async def _refresh_qr_token(client, qr_login):
    resp = await client(functions.auth.ExportLoginTokenRequest(
        _config.api_id, _config.api_hash, []
    ))
    if isinstance(resp, types.auth.LoginTokenMigrateTo):
        # [VALID #9] Guard against missing private API
        if not hasattr(client, "_switch_dc"):
            logger.error("Telethon private _switch_dc missing — cannot migrate DC")
            raise RuntimeError("Telethon API changed: _switch_dc not available")
        await client._switch_dc(resp.dc_id)
        resp = await client(functions.auth.ImportLoginTokenRequest(resp.token))
    qr_login._resp = resp
    return resp


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
                            InlineKeyboardButton("🔄 Retry", callback_data="add_qr", style="primary"),
                            InlineKeyboardButton("🔙 Menu", callback_data="menu"),
                        ]
                    ],
                )
                with suppress(Exception):
                    await client.disconnect()
                return
            try:
                await _refresh_qr_token(client, qr_login)
            except SessionPasswordNeededError:
                if user_sessions.get(user_id) is session:
                    session["step"] = "wait_password"
                    await cleanup_qr_message(context.bot, session)
                    await render(
                        context, chat_id, message_id,
                        "🔐 This account has 2FA enabled. Enter the password:",
                        cancel_keyboard(),
                    )
                return
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

    if me is None:
        # [VALID #5] Guard None
        logger.error("QR login: get_me returned None")
        await cleanup_qr_message(context.bot, session)
        user_sessions.pop(user_id, None)
        with suppress(Exception):
            await client.disconnect()
        await render(
            context, chat_id, message_id,
            "❌ Could not fetch account info.",
            [[InlineKeyboardButton("🔙 Menu", callback_data="menu")]],
        )
        return

    if user_sessions.get(user_id) is not session:
        with suppress(Exception):
            await client.disconnect()
        return

    # [VALID #8] normalize_phone preserves +id
    phone = normalize_phone(me.phone) if me.phone else f"+id{me.id}"
    await cleanup_qr_message(context.bot, session)
    _add_cooldown[user_id] = time.monotonic()
    await finish_add_account(context, chat_id, message_id, user_id, phone, client)


async def user_session_sweeper(bot):
    while True:
        await asyncio.sleep(USER_SESSION_SWEEP_INTERVAL)
        now = time.monotonic()
        stale = []
        for uid, sess in list(user_sessions.items()):
            created = sess.get("created_at", now)
            has_step = "step" in sess
            timeout = STEP_TIMEOUT_SECONDS if has_step else USER_SESSION_IDLE_TIMEOUT
            if now - created > timeout:
                stale.append(uid)

        for uid in stale:
            sess = user_sessions.pop(uid, None)
            if sess:
                await cleanup_qr_message(bot, sess)
                await cleanup_session_client(sess)
        if stale:
            logger.info("Swept %d idle user session(s)", len(stale))

        if _session_manager:
            cutoff = time.monotonic() - UI_CACHE_TTL_SECONDS
            _session_manager._ui_sessions = {
                k: v for k, v in _session_manager._ui_sessions.items()
                if len(v) >= 3 and v[2] > cutoff
            }


async def message_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # [VALID #7] Defensive against channel posts / None
    if update.effective_user is None or update.message is None:
        return
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
        if not PHONE_REGEX.match(text) or text.startswith("+id"):
            await render(context, chat_id, message_id, "❌ Invalid format. Use <code>+&lt;country code&gt;&lt;number&gt;</code>, digits only.", cancel_keyboard())
            return
        # [VALID #15] Prevent wasting an OTP on an already-registered number
        if text in _session_manager.database:
            await render(
                context, chat_id, message_id,
                f"⚠️ Account <code>{html.escape(text)}</code> already registered.",
                cancel_keyboard(),
            )
            return
        client = TelegramClient(StringSession(), _config.api_id, _config.api_hash)
        try:
            await client.connect()
            await client.send_code_request(text)
        except PhoneNumberInvalidError:
            with suppress(Exception):
                await client.disconnect()
            await render(context, chat_id, message_id, "❌ Invalid phone number.", cancel_keyboard())
            return
        except FloodWaitError as e:
            with suppress(Exception):
                await client.disconnect()
            await render(context, chat_id, message_id, f"⏳ Please wait {e.seconds} seconds and try again.", cancel_keyboard())
            return
        except Exception as e:
            with suppress(Exception):
                await client.disconnect()
            await render(context, chat_id, message_id, f"❌ Error: {html.escape(str(e))}", cancel_keyboard())
            return
        session.update({"step": "wait_code", "phone": text, "client": client})
        _add_cooldown[user_id] = time.monotonic()
        await render(
            context, chat_id, message_id,
            f"📲 Code sent to <code>{html.escape(text)}</code>.\n"
            "Enter the code (e.g. <code>12345</code> or <code>1 2 3 4 5</code>):",
            cancel_keyboard(),
        )

    elif step == "wait_code":
        code = re.sub(r"\D", "", text)
        if not CODE_REGEX.match(code):
            await render(
                context, chat_id, message_id,
                "❌ The code must be numeric only. Try again\n"
                "(<code>12345</code> or <code>1 2 3 4 5</code>):",
                cancel_keyboard(),
            )
            return
        phone, client = session["phone"], session["client"]
        try:
            await client.sign_in(phone, code)
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
                if me is None:
                    raise RuntimeError("get_me returned None")
                phone = normalize_phone(me.phone) if me.phone else f"+id{me.id}"
            await cleanup_qr_message(context.bot, session)
            await finish_add_account(context, chat_id, message_id, user_id, phone, client)
        except PasswordHashInvalidError:
            await render(context, chat_id, message_id, "❌ Incorrect password. Please try again:", cancel_keyboard())
        except Exception as e:
            logger.error("Password login failed for %s: %s", phone, e)
            await cleanup_qr_message(context.bot, session)
            user_sessions.pop(user_id, None)
            with suppress(Exception):
                await client.disconnect()
            await render(
                context, chat_id, message_id,
                f"❌ Login failed: {html.escape(str(e))}",
                [[InlineKeyboardButton("🔙 Menu", callback_data="menu")]],
            )


async def finish_add_account(context, chat_id, message_id, user_id, phone, client):
    if not PHONE_REGEX.match(phone):
        logger.error("Refusing to add account with invalid identifier: %r", phone)
        with suppress(Exception):
            await client(functions.auth.LogOutRequest())
        with suppress(Exception):
            await client.disconnect()
        user_sessions.pop(user_id, None)
        await render(
            context, chat_id, message_id,
            f"❌ Invalid account identifier: <code>{html.escape(phone)}</code>",
            [[InlineKeyboardButton("🔙 Menu", callback_data="menu")]],
        )
        return

    try:
        success = await _session_manager.add_account(phone, client)
    except Exception as e:
        logger.error("finish_add_account: add_account failed for %s: %s", phone, e)
        success = False

    user_sessions.pop(user_id, None)

    if success:
        await account_detail_view(context, chat_id, message_id, phone, banner="✅ Account added successfully!\n\n")
        return

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
    # [VALID #3] + [VALID #7] Guard against None message / user
    if update.effective_user is None:
        return
    if query is None:
        return
    if query.message is None or not hasattr(query.message, "chat_id"):
        await _safe_answer(query, "Message expired — send /start again")
        return

    user_id = update.effective_user.id
    chat_id = query.message.chat_id
    message_id = query.message.message_id

    if not is_authorized(user_id):
        await _safe_answer(query)
        await render(context, chat_id, message_id, "⛔ Unauthorized")
        return

    data = query.data

    # ===== PRE-ACK CHECKS (cepat, butuh show_alert) =====
    if data in ("add_acc", "add_phone", "add_qr"):
        cd = _check_add_cooldown(user_id)
        if cd:
            await _safe_answer(query, cd, show_alert=True)
            if data == "add_acc":
                await show_main_menu(context, chat_id, message_id)
            else:
                await render(context, chat_id, message_id,
                             "Choose an account addition method:", add_method_keyboard())
            return

    _session_op = None  # (kind, phone, hash, short)
    if data.startswith("sess_trust_"):
        short = data[len("sess_trust_"):]
        entry = _session_manager._ui_sessions.pop(short, None)
        if not entry or len(entry) < 2:
            await _safe_answer(query, "Expired — reopen Sessions")
            return
        phone, hash_val = entry[0], entry[1]
        if not _session_manager.database.get(phone) or not _session_manager.clients.get(phone):
            await _safe_answer(query, "Account unavailable")
            return
        _session_op = ("trust", phone, hash_val, None)
    elif data.startswith("sess_revoke_"):
        short = data[len("sess_revoke_"):]
        entry = _session_manager._ui_sessions.pop(short, None)
        if not entry or len(entry) < 2:
            await _safe_answer(query, "Expired — reopen Sessions")
            return
        phone, hash_val = entry[0], entry[1]
        if not _session_manager.database.get(phone) or not _session_manager.clients.get(phone):
            await _safe_answer(query, "Account unavailable")
            return
        _session_op = ("revoke", phone, hash_val, None)
    elif data.startswith("revokeconfirm_"):
        short = data[len("revokeconfirm_"):]
        entry = _session_manager._ui_sessions.get(short)
        if not entry or len(entry) < 2:
            await _safe_answer(query, "Expired — reopen Sessions")
            return
        phone, hash_val = entry[0], entry[1]
        if not _session_manager.clients.get(phone):
            await _safe_answer(query, "Account unavailable")
            return
        _session_op = ("confirm", phone, hash_val, short)

    # ===== ACK SEKARANG — hentikan spinner, cegah TimedOut =====
    await _safe_answer(query)

    try:
        await reset_user_flow(context, user_id)
        user_sessions[user_id] = _new_session(chat_id, message_id)

        # === Operasi sesi (trust / revoke / confirm) ===
        if _session_op is not None:
            kind, phone, hash_val, short = _session_op
            client = _session_manager.clients.get(phone)
            if not client:
                await list_accounts_view(context, chat_id, message_id)
                return
            try:
                result = await client(functions.account.GetAuthorizationsRequest())
            except Exception as e:
                logger.error("Failed to load sessions for %s (%s): %s", phone, kind, e)
                await sessions_view(context, chat_id, message_id, phone,
                                    banner=f"❌ Failed to load sessions: {html.escape(str(e))}\n\n")
                return

            if kind == "trust":
                matched = next((a for a in result.authorizations if a.hash == hash_val), None)
                if matched is None:
                    await sessions_view(context, chat_id, message_id, phone,
                                        banner="⚠️ Session not found (may already be gone).\n\n")
                    return
                def _trust(r):
                    _session_manager._whitelist_session(r, matched, source="admin_ui")
                await _session_manager.database.mutate(phone, _trust)
                audit_logger.info("session_trusted_manual phone=%s hash=%s", phone, matched.hash)
                await sessions_view(context, chat_id, message_id, phone,
                                    banner="✅ Session trusted.\n\n")

            elif kind == "revoke":
                matched = next((a for a in result.authorizations if a.hash == hash_val), None)
                if matched is None:
                    await sessions_view(context, chat_id, message_id, phone,
                                        banner="⚠️ Session not found (may already be gone).\n\n")
                    return
                if matched.current:
                    await sessions_view(context, chat_id, message_id, phone,
                                        banner="⚠️ Refusing to revoke the current session.\n\n")
                    return
                try:
                    await client(functions.account.ResetAuthorizationRequest(hash=matched.hash))
                    def _drop(r):
                        r.whitelisted_sessions = [
                            e for e in r.whitelisted_sessions if e.get("hash") != matched.hash
                        ]
                    await _session_manager.database.mutate(phone, _drop)
                    audit_logger.warning("session_revoked_manual phone=%s hash=%s", phone, matched.hash)
                    logger.warning("Manually revoked session for %s", phone)
                    await sessions_view(context, chat_id, message_id, phone,
                                        banner="✅ Session revoked.\n\n")
                except Exception as e:
                    logger.error("Failed to revoke session for %s: %s", phone, e)
                    await sessions_view(context, chat_id, message_id, phone,
                                        banner=f"❌ Failed to revoke: {html.escape(str(e))}\n\n")

            elif kind == "confirm":
                target = next((a for a in result.authorizations if a.hash == hash_val), None)
                if target is None:
                    await sessions_view(context, chat_id, message_id, phone,
                                        banner="⚠️ Session not found.\n\n")
                    return
                if target.current:
                    await sessions_view(context, chat_id, message_id, phone,
                                        banner="⚠️ Refusing to logout the current session.\n\n")
                    return
                keyboard = [[
                    InlineKeyboardButton("✅ Yes, Logout",
                                         callback_data=f"sess_revoke_{short}", style="danger"),
                    InlineKeyboardButton("❌ Cancel",
                                         callback_data=f"sessions_{phone}", style="primary"),
                ]]
                await render(
                    context, chat_id, message_id,
                    f"⚠️ <b>Logout this session?</b>\n\n"
                    f"Account: <code>{html.escape(phone)}</code>\n\n"
                    f"{_format_session(target)}"
                    f"\nThis session will be <b>terminated immediately on Telegram's servers</b>.\n"
                    f"The device will need to log in again.\n\n"
                    f"<b>This action cannot be undone.</b>",
                    keyboard,
                )
            return

        # === Dispatch normal ===
        if data == "menu":
            await show_main_menu(context, chat_id, message_id)

        elif data == "stats":
            db = _session_manager.database.all()
            total = len(db)
            protected = sum(1 for r in db.values() if r.anti_login)
            codes = sum(r.invalidated_codes for r in db.values())
            sessions_count = sum(len(r.whitelisted_sessions) for r in db.values())
            no_baseline = sum(1 for r in db.values() if not r.whitelist_initialized)
            connected = sum(1 for p in db if p in _session_manager.clients)
            text = (
                "📊 <b>Stats</b>\n"
                f"Accounts         : <b>{total}</b>\n"
                f"Connected        : {connected}\n"
                f"Protected        : {protected}\n"
                f"Codes invalid    : {codes}\n"
                f"Whitelisted      : {sessions_count}\n"
                f"⚠️ No baseline  : {no_baseline}"
            )
            await render(context, chat_id, message_id, text, [[InlineKeyboardButton("🔙 Back", callback_data="menu", style="primary")]])

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

        elif data.startswith("resetbase_"):
            phone = data[len("resetbase_"):]
            ok = await _session_manager.reset_baseline(phone)
            banner = "✅ Baseline in-reset.\n\n" if ok else "❌ Reset baseline failed.\n\n"
            await account_detail_view(context, chat_id, message_id, phone, banner=banner)

        elif data.startswith("delconfirm_"):
            phone = data[len("delconfirm_"):]
            ok = await _session_manager.remove_account(phone)
            if ok:
                await render(
                    context, chat_id, message_id,
                    f"✅ Account <code>{html.escape(phone)}</code> removed and session logged out.",
                    [[InlineKeyboardButton("🔙 Back", callback_data="list_acc", style="primary")]],
                )
            else:
                await render(
                    context, chat_id, message_id,
                    f"⚠️ Account <code>{html.escape(phone)}</code> could not be fully removed "
                    f"(logout may have failed). Try again or check the log.",
                    [[InlineKeyboardButton("🔙 Back", callback_data="list_acc", style="primary")]],
                )

        elif data.startswith("del_"):
            await delete_confirm_view(context, chat_id, message_id, data[len("del_"):])

        elif data == "reconnect_all":
            await render(context, chat_id, message_id, "🔄 Reconnecting all accounts in background...")
            _session_manager.track(asyncio.create_task(_session_manager.reconnect_all()))
            await show_main_menu(context, chat_id, message_id)

        elif data.startswith("sessions_"):
            await sessions_view(context, chat_id, message_id, data[len("sessions_"):])

        # Catatan: sess_trust_ / sess_revoke_ / revokeconfirm_ sudah
        # ditangani di atas via _session_op, jadi TIDAK masuk sini lagi.

    finally:
        await _safe_answer(query)  # no-op kalau sudah di-ack


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
    bot_app.add_handler(CommandHandler("cancel", cancel_command))
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