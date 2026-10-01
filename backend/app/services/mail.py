"""Outbound email. Production delivers over SMTP; tests inject InMemoryMailService instead."""

import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Protocol

from app.core.config import get_settings

SMTP_TIMEOUT_SECONDS = 15
SMTPS_PORT = 465


@dataclass(frozen=True)
class MailMessage:
    to: str
    subject: str
    body: str


class MailService(Protocol):
    def send(self, message: MailMessage) -> None: ...


class SmtpMailService:
    """Sends plain-text mail over an encrypted SMTP connection (implicit TLS on 465, STARTTLS otherwise)."""

    def __init__(self, host: str, port: int, sender: str, username: str | None, password: str | None) -> None:
        self._host = host
        self._port = port
        self._sender = sender
        self._username = username
        self._password = password

    def send(self, message: MailMessage) -> None:
        email = EmailMessage()
        email["From"] = self._sender
        email["To"] = message.to
        email["Subject"] = message.subject
        email.set_content(message.body)

        context = ssl.create_default_context()
        if self._port == SMTPS_PORT:
            with smtplib.SMTP_SSL(self._host, self._port, timeout=SMTP_TIMEOUT_SECONDS, context=context) as smtp:
                self._deliver(smtp, email)
        else:
            with smtplib.SMTP(self._host, self._port, timeout=SMTP_TIMEOUT_SECONDS) as smtp:
                # Refuse to send credentials or reset links over an unencrypted connection.
                smtp.starttls(context=context)
                self._deliver(smtp, email)

    def _deliver(self, smtp: smtplib.SMTP, email: EmailMessage) -> None:
        if self._username:
            smtp.login(self._username, self._password or "")
        smtp.send_message(email)


class InMemoryMailService:
    """Collects messages instead of sending them; used by tests."""

    def __init__(self) -> None:
        self.outbox: list[MailMessage] = []

    def send(self, message: MailMessage) -> None:
        self.outbox.append(message)


def get_mail_service() -> MailService | None:
    """FastAPI dependency: the configured SMTP service, or None when email delivery is not configured."""
    settings = get_settings()
    if not settings.email_host or not settings.email_from:
        return None
    return SmtpMailService(
        host=settings.email_host,
        port=settings.email_port,
        sender=settings.email_from,
        username=settings.email_username or None,
        password=settings.email_password.get_secret_value() if settings.email_password else None,
    )
