"""Модуль безопасной отправки диагностических логов разработчику.
Работает строго на стандартной библиотеке Python (urllib.request, ssl, json).
Поддерживает автоматический санитайзинг персональных данных (маскировка путей пользователей),
сбор системного контекста (Windows, TTL, прокси) и доставку через Telegram Bot API и Discord Webhook.
"""

import os
import re
import ssl
import json
import time
import uuid
import platform
import logging
import urllib.request
import urllib.error
from typing import Tuple, Optional, Dict, Any

try:
    from Floweryguard.logger import get_current_log_path, _get_app_version
    from Floweryguard.ttl_fix import is_admin, TTLManager
    from Floweryguard.quic_block import QUICBlocker
    from Floweryguard.system_proxy import SystemProxyManager
except ImportError:
    from flowguard.logger import get_current_log_path, _get_app_version
    from flowguard.ttl_fix import is_admin, TTLManager
    from flowguard.quic_block import QUICBlocker
    from flowguard.system_proxy import SystemProxyManager

logger = logging.getLogger("Flowery.LogSender")


# Регулярные выражения для санитайзинга конфиденциальных данных
USER_PATH_RE = re.compile(r"([A-Za-z]:\\Users\\)([^\s\\/\"':]+)", re.IGNORECASE)
HOME_PATH_RE = re.compile(r"(/home/|/Users/)([^\s\\/\"':]+)", re.IGNORECASE)
IP_RE = re.compile(r"\b(?!(?:127\.0\.0\.1|0\.0\.0\.0|1\.1\.1\.1|8\.8\.8\.8|9\.9\.9\.9|149\.112\.112\.112))\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


def sanitize_text(text: str) -> str:
    """Удаляет персональные пути Windows/Linux и личные IP-адреса из текста лога."""
    # Маскируем имена пользователей Windows (C:\Users\Ivan -> C:\Users\[USER])
    sanitized = USER_PATH_RE.sub(r"\1[USER]", text)
    sanitized = HOME_PATH_RE.sub(r"\1[USER]", sanitized)
    # Маскируем личные IP-адреса пользователей, сохраняя известные публичные DNS и localhost
    sanitized = IP_RE.sub("[IP_REDACTED]", sanitized)
    return sanitized


def collect_system_snapshot(config=None) -> Dict[str, Any]:
    """Собирает системные метаданные для диагностического отчёта."""
    v4_ttl, v6_ttl = None, None
    try:
        ttl_mgr = TTLManager()
        v4_ttl, v6_ttl = ttl_mgr.get_current_ttl()
    except Exception as e:
        logger.debug("Failed to read current TTL for snapshot: %s", e)

    quic_rule = False
    try:
        quic_rule = QUICBlocker().is_rule_present()
    except Exception as e:
        logger.debug("Failed to check QUIC rule for snapshot: %s", e)

    proxy_enabled = False
    proxy_server = ""
    try:
        proxy_enabled, proxy_server, _ = SystemProxyManager().get_current_settings()
    except Exception as e:
        logger.debug("Failed to check proxy settings for snapshot: %s", e)

    active_profile = "default"
    active_strategy = "auto"
    if config:
        active_profile = getattr(config, "active_profile_name", "unknown")
        active_strategy = getattr(config, "default_strategy", "auto")

    return {
        "flowery_version": _get_app_version(),
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "is_admin": is_admin(),
        "ipv4_ttl": v4_ttl or "default",
        "ipv6_ttl": v6_ttl or "default",
        "quic_blocked": quic_rule,
        "proxy_enabled": proxy_enabled,
        "proxy_server": proxy_server,
        "active_profile": active_profile,
        "active_strategy": active_strategy,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


def build_multipart_payload(fields: Dict[str, str], files: Dict[str, Tuple[str, bytes]]) -> Tuple[bytes, str]:
    """Формирует multipart/form-data тело запроса без сторонних зависимостей (RFC 2046)."""
    boundary = f"----WebKitFormBoundary{uuid.uuid4().hex}"
    body = bytearray()

    # Обычные текстовые поля
    for key, value in fields.items():
        body.extend(f"--{boundary}\r\n".encode("utf-8"))
        body.extend(f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode("utf-8"))
        body.extend(f"{value}\r\n".encode("utf-8"))

    # Файлы
    for field_name, (filename, file_bytes) in files.items():
        body.extend(f"--{boundary}\r\n".encode("utf-8"))
        body.extend(f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'.encode("utf-8"))
        body.extend(b"Content-Type: text/plain; charset=utf-8\r\n\r\n")
        body.extend(file_bytes)
        body.extend(b"\r\n")

    body.extend(f"--{boundary}--\r\n".encode("utf-8"))
    content_type = f"multipart/form-data; boundary={boundary}"
    return bytes(body), content_type


class LogSender:
    """Управление формированием и отправкой логов разработчику."""

    def __init__(self, config=None):
        self.config = config

    def prepare_sanitized_report(self, user_comment: str = "") -> Tuple[str, bytes]:
        """Подготавливает финальный текст отчёта с системным заголовком и анонимизированным логом."""
        snap = collect_system_snapshot(self.config)
        header_lines = [
            "=" * 70,
            f"FLOWERY (GLUE) v{snap['flowery_version']} — ДИАГНОСТИЧЕСКИЙ ОТЧЁТ",
            "=" * 70,
            f"Время отправки:       {snap['timestamp']}",
            f"ОС / Платформа:       {snap['platform']}",
            f"Python:               {snap['python_version']}",
            f"Права Администратора: {'ДА' if snap['is_admin'] else 'НЕТ'}",
            f"DefaultTTL (v4 / v6): {snap['ipv4_ttl']} / {snap['ipv6_ttl']}",
            f"Блокировка QUIC:      {'АКТИВНА' if snap['quic_blocked'] else 'ВЫКЛЮЧЕНА'}",
            f"Системный прокси:     {'ВКЛ' if snap['proxy_enabled'] else 'ВЫКЛ'} ({snap['proxy_server']})",
            f"Активный профиль:     {snap['active_profile']}",
            f"Стратегия обхода:     {snap['active_strategy']}",
        ]
        if user_comment:
            header_lines.extend([
                "-" * 70,
                f"КОММЕНТАРИЙ ПОЛЬЗОВАТЕЛЯ:",
                user_comment.strip(),
            ])
        header_lines.extend([
            "=" * 70,
            "ПОСЛЕДНИЕ СОБЫТИЯ СЕССИИ (АНАЛИЗ И ОШИБКИ):",
            "=" * 70,
            "",
        ])

        # Читаем текущий лог-файл
        log_path = get_current_log_path()
        log_content = ""
        if os.path.exists(log_path):
            try:
                with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                    log_content = f.read()
            except Exception as e:
                log_content = f"[!] Ошибка чтения файла лога: {e}"
        else:
            log_content = "[i] Файл сессии пуст или ещё не создан на диске."

        # Санитайзинг
        sanitized_log = sanitize_text(log_content)

        full_report = "\n".join(header_lines) + sanitized_log
        filename = f"Flowery_Report_{time.strftime('%Y%m%d_%H%M%S')}.txt"
        return filename, full_report.encode("utf-8")

    def _open_url(self, req: urllib.request.Request, timeout: float = 12.0) -> bytes:
        """Выполняет HTTP запрос, сначала пробуя локальный прокси Flowery, а затем напрямую."""
        # 1. Сначала пробуем через локальный прокси Flowery если запущен (для обхода блокировки api.telegram.org)
        proxy_port = 8118
        if self.config:
            try:
                proxy_port = getattr(self.config, "listen_port", 8118)
            except Exception as e:
                logger.debug("Failed reading listen_port from config: %s", e)
        proxy_url = f"http://127.0.0.1:{proxy_port}"
        ssl_ctx = ssl._create_unverified_context()
        proxy_handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
        opener_proxy = urllib.request.build_opener(proxy_handler, urllib.request.HTTPSHandler(context=ssl_ctx))

        try:
            with opener_proxy.open(req, timeout=timeout) as resp:
                return resp.read()
        except Exception as e:
            logger.debug("Opening URL via proxy %s failed, falling back to direct: %s", proxy_url, e)

        # 2. Если прокси недоступен, пробуем напрямую
        direct_opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl_ctx))
        with direct_opener.open(req, timeout=timeout) as resp:
            return resp.read()

    def send_to_telegram(
        self,
        bot_token: str,
        chat_id: str,
        filename: str,
        file_bytes: bytes,
        caption: str = ""
    ) -> Tuple[bool, str]:
        """Отправляет документ в Telegram чат через Bot API (sendDocument)."""
        if not bot_token or not chat_id:
            return False, "Не указан bot_token или chat_id для Telegram"

        url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
        fields = {
            "chat_id": str(chat_id),
            "caption": caption[:1024],
        }
        files = {
            "document": (filename, file_bytes)
        }

        body, content_type = build_multipart_payload(fields, files)
        req = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": content_type,
                "User-Agent": f"Flowery/{_get_app_version()}"
            }
        )

        try:
            resp_bytes = self._open_url(req, timeout=15.0)
            res_json = json.loads(resp_bytes.decode("utf-8", errors="replace"))
            if res_json.get("ok"):
                return True, "Лог успешно доставлен разработчику в Telegram!"
            else:
                desc = res_json.get("description", "Неизвестная ошибка Telegram API")
                return False, f"Telegram API: {desc}"
        except urllib.error.HTTPError as he:
            err_body = he.read().decode("utf-8", errors="ignore")
            try:
                ej = json.loads(err_body)
                return False, f"Telegram API HTTP {he.code}: {ej.get('description', err_body)}"
            except Exception:
                return False, f"Telegram API HTTP {he.code}: {err_body[:200]}"
        except Exception as e:
            return False, f"Ошибка сети при отправке: {e}"

    def auto_detect_telegram_chat_id(self, bot_token: str) -> Optional[str]:
        """Пытается определить chat_id из последних входящих сообщений боту (/getUpdates)."""
        if not bot_token:
            return None
        url = f"https://api.telegram.org/bot{bot_token}/getUpdates"
        req = urllib.request.Request(url, headers={"User-Agent": "Flowery/1.2"})
        try:
            resp_bytes = self._open_url(req, timeout=8.0)
            data = json.loads(resp_bytes.decode("utf-8", errors="replace"))
            if data.get("ok") and data.get("result"):
                for upd in reversed(data["result"]):
                    msg = upd.get("message") or upd.get("channel_post") or upd.get("my_chat_member", {}).get("chat")
                    if msg:
                        chat = msg.get("chat") if "chat" in msg else msg
                        if chat and "id" in chat:
                            return str(chat["id"])
        except Exception as e:
            logger.debug("auto_detect_telegram_chat_id encountered exception: %s", e)
        return None

    def send_to_gateway(
        self,
        gateway_url: str,
        filename: str,
        file_bytes: bytes,
        caption: str = ""
    ) -> Tuple[bool, str]:
        """Отправляет отчёт через защищённый сервер-шлюз (Cloudflare Worker).
        Токен бота хранится на стороне сервера, клиенту он не передаётся.
        """
        if not gateway_url or "YOUR-NAME" in gateway_url:
            return False, (
                "Адрес сервера-шлюза ещё не настроен!\n"
                "Разверните шлюз по инструкции relay/README.md и укажите\n"
                "report_gateway_url в секции [support] файла config.ini."
            )

        payload = {
            "filename": filename,
            "caption": caption,
            "content": file_bytes.decode("utf-8", errors="replace"),
        }
        body_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")

        req = urllib.request.Request(
            gateway_url,
            data=body_bytes,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": f"Flowery/{_get_app_version()}"
            }
        )

        try:
            resp_bytes = self._open_url(req, timeout=15.0)
            res_json = json.loads(resp_bytes.decode("utf-8", errors="replace"))
            if res_json.get("ok"):
                return True, "Лог успешно передан на сервер-шлюз и доставлен разработчику в Telegram!"
            else:
                err_msg = res_json.get("error", "Неизвестный ответ шлюза")
                return False, f"Сервер-шлюз: {err_msg}"
        except urllib.error.HTTPError as he:
            err_body = he.read().decode("utf-8", errors="ignore")
            try:
                ej = json.loads(err_body)
                return False, f"Шлюз HTTP {he.code}: {ej.get('error', err_body)}"
            except Exception:
                return False, f"Шлюз HTTP {he.code}: {err_body[:200]}"
        except Exception as e:
            return False, f"Ошибка соединения со шлюзом: {e}"

    def send_report(self, user_comment: str = "") -> Tuple[bool, str]:
        """Единый метод отправки отчёта разработчику с авто-выбором транспорта."""
        filename, file_bytes = self.prepare_sanitized_report(user_comment)
        snap = collect_system_snapshot(self.config)

        caption = (
            f"🌸 Flowery v{snap['flowery_version']} Диагностический отчёт\n"
            f"🖥 ОС: {snap['platform'][:40]}\n"
            f"⚙️ Профиль: {snap['active_profile']} | TTL: {snap['ipv4_ttl']}\n"
            f"🔒 QUIC: {snap['quic_blocked']} | Proxy: {snap['proxy_enabled']}"
        )
        if user_comment:
            caption += f"\n💬 Комментарий: {user_comment[:200]}"

        # Читаем параметры из конфигурации
        gateway_url = ""
        bot_token = ""
        chat_id = ""
        discord_url = ""
        transport = "gateway"

        if self.config:
            transport = self.config.get_str("support", "report_transport") or "gateway"
            gateway_url = self.config.get_str("support", "report_gateway_url")
            bot_token = self.config.get_str("support", "telegram_bot_token")
            chat_id = self.config.get_str("support", "telegram_chat_id")
            discord_url = self.config.get_str("support", "discord_webhook_url")

        # Чтение из переменных окружения при отсутствии в config.ini
        if not gateway_url:
            gateway_url = os.environ.get("FLOWERY_GATEWAY_URL", "").strip()
        if not bot_token:
            bot_token = os.environ.get("FLOWERY_TELEGRAM_BOT_TOKEN", "").strip()
        if not chat_id:
            chat_id = os.environ.get("FLOWERY_TELEGRAM_CHAT_ID", "").strip()
        if not discord_url:
            discord_url = os.environ.get("FLOWERY_DISCORD_WEBHOOK_URL", "").strip()

        # 1. Защищённый шлюз (Cloudflare Worker Relay) — основной безопасный способ
        if transport == "gateway" or (gateway_url and not bot_token):
            if gateway_url and "YOUR-NAME" not in gateway_url:
                return self.send_to_gateway(gateway_url, filename, file_bytes, caption)
            elif not bot_token and not discord_url:
                return False, (
                    "Сервер-шлюз ещё не привязан к вашему аккаунту Cloudflare!\n"
                    "Разверните бесплатный шлюз по инструкции relay/README.md и укажите\n"
                    "адрес в config.ini: report_gateway_url = https://ваш-воркер.workers.dev/report"
                )

        if transport == "discord" and discord_url:
            # Discord Webhook отправка
            fields = {"content": caption}
            files = {"file": (filename, file_bytes)}
            body, ctype = build_multipart_payload(fields, files)
            req = urllib.request.Request(discord_url, data=body, headers={"Content-Type": ctype})
            try:
                self._open_url(req, timeout=15.0)
                return True, "Лог успешно отправлен в Discord разработчика!"
            except Exception as e:
                return False, f"Ошибка Discord Webhook: {e}"

        # По умолчанию — Telegram
        if not chat_id:
            chat_id = self.auto_detect_telegram_chat_id(bot_token)
            if chat_id and self.config:
                try:
                    self.config.set_value("support", "telegram_chat_id", chat_id)
                    self.config.save()
                except Exception as e:
                    logger.warning("Failed to auto-save detected telegram_chat_id to config: %s", e)

        if not chat_id:
            return False, (
                "Не удалось определить Telegram chat_id!\n"
                "Откройте вашего бота в Telegram и отправьте ему сообщение /start, "
                "или укажите telegram_chat_id в файле config.ini."
            )

        return self.send_to_telegram(bot_token, chat_id, filename, file_bytes, caption)
