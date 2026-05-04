from __future__ import annotations

import asyncio
import base64
import json
import re
import secrets
from datetime import datetime, timedelta, timezone
from html import unescape
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import httpx
from pydantic import BaseModel, Field

from app.config import Settings
from app.models import GmailConnectionStatus, GmailMessagePreview, InputBundle

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1/users/me"
GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
STATE_COOKIE_NAME = "gmail_oauth_state"


class GmailIntegrationError(RuntimeError):
    """Raised when Gmail integration cannot complete a request."""


class StoredGmailToken(BaseModel):
    access_token: str
    refresh_token: str | None = None
    token_type: str = "Bearer"
    expires_at: datetime | None = None
    scope: str | None = None
    email_address: str | None = None
    history_id: str | None = None
    watch_expiration: datetime | None = None
    last_sync_at: datetime | None = None
    connected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class GmailTokenStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self) -> StoredGmailToken | None:
        if not self.path.exists():
            return None
        with self.path.open("r", encoding="utf-8") as handle:
            return StoredGmailToken.model_validate(json.load(handle))

    def save(self, token: StoredGmailToken) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("w", encoding="utf-8") as handle:
            json.dump(token.model_dump(mode="json"), handle, indent=2)

    def clear(self) -> None:
        if self.path.exists():
            self.path.unlink()


def _extract_header(headers: list[dict[str, str]], name: str) -> str:
    target = name.lower()
    for header in headers:
        if header.get("name", "").lower() == target:
            return header.get("value", "")
    return ""


def _decode_base64url(value: str | None) -> str:
    if not value:
        return ""
    padding = "=" * (-len(value) % 4)
    decoded = base64.urlsafe_b64decode(value + padding)
    return decoded.decode("utf-8", errors="replace")


def _strip_html(content: str) -> str:
    text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", content)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = unescape(text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _extract_body_text(payload: dict[str, Any] | None) -> str:
    if not payload:
        return ""

    mime_type = payload.get("mimeType", "")
    body_data = _decode_base64url(payload.get("body", {}).get("data"))
    if mime_type == "text/plain" and body_data:
        return body_data.strip()
    if mime_type == "text/html" and body_data:
        return _strip_html(body_data)

    parts = payload.get("parts", []) or []
    plain_parts: list[str] = []
    html_parts: list[str] = []

    def walk(part: dict[str, Any]) -> None:
        part_mime = part.get("mimeType", "")
        decoded = _decode_base64url(part.get("body", {}).get("data"))
        if part_mime == "text/plain" and decoded:
            plain_parts.append(decoded.strip())
        elif part_mime == "text/html" and decoded:
            html_parts.append(_strip_html(decoded))
        for child in part.get("parts", []) or []:
            walk(child)

    for part in parts:
        walk(part)

    if plain_parts:
        return "\n\n".join(piece for piece in plain_parts if piece)
    if html_parts:
        return "\n\n".join(piece for piece in html_parts if piece)
    if body_data:
        return body_data.strip()
    return ""


def _to_datetime_from_epoch_seconds(value: float | int | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromtimestamp(float(value), tz=timezone.utc)


def _to_datetime_from_epoch_millis(value: str | int | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromtimestamp(int(value) / 1000, tz=timezone.utc)


class GmailService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.token_store = GmailTokenStore(settings.gmail_token_store_path)

    def is_configured(self) -> bool:
        return self.settings.gmail_is_configured

    def generate_oauth_state(self) -> str:
        return secrets.token_urlsafe(24)

    def build_auth_url(self, state: str) -> str:
        if not self.is_configured():
            raise GmailIntegrationError("Gmail OAuth is not configured.")

        query = urlencode(
            {
                "client_id": self.settings.gmail_client_id,
                "redirect_uri": self.settings.effective_gmail_redirect_uri,
                "response_type": "code",
                "scope": GMAIL_SCOPE,
                "access_type": "offline",
                "include_granted_scopes": "true",
                "prompt": "consent",
                "state": state,
            }
        )
        return f"{AUTH_URL}?{query}"

    async def get_status(self) -> GmailConnectionStatus:
        if not self.is_configured():
            return GmailConnectionStatus(
                configured=False,
                connected=False,
                detail="Add Gmail OAuth credentials to enable live inbox ingestion.",
            )

        token = self.token_store.load()
        if token is None:
            return GmailConnectionStatus(
                configured=True,
                connected=False,
                detail="Gmail is configured, but this app is not yet connected to a mailbox.",
            )

        return GmailConnectionStatus(
            configured=True,
            connected=True,
            email_address=token.email_address,
            last_sync_at=token.last_sync_at,
            watch_expiration=token.watch_expiration,
            detail="Connected to Gmail and ready to fetch live inbox messages.",
        )

    async def exchange_code(self, code: str) -> GmailConnectionStatus:
        existing = self.token_store.load()
        payload = {
            "code": code,
            "client_id": self.settings.gmail_client_id,
            "client_secret": self.settings.gmail_client_secret,
            "redirect_uri": self.settings.effective_gmail_redirect_uri,
            "grant_type": "authorization_code",
        }

        async with httpx.AsyncClient(timeout=self.settings.default_timeout_seconds) as client:
            response = await client.post(TOKEN_URL, data=payload)
            response.raise_for_status()
        token_payload = response.json()

        stored = self._build_stored_token(token_payload, existing=existing)
        profile = await self._fetch_profile(stored)
        stored.email_address = profile.get("emailAddress")
        stored.history_id = profile.get("historyId")
        stored.last_sync_at = datetime.now(timezone.utc)
        self.token_store.save(stored)
        return await self.get_status()

    async def list_messages(self, max_results: int | None = None, query: str | None = None) -> list[GmailMessagePreview]:
        token = await self._ensure_valid_token()
        params = {
            "maxResults": max_results or self.settings.gmail_poll_max_results,
            "q": query or self.settings.gmail_poll_query,
            "labelIds": "INBOX",
        }
        headers = {"Authorization": f"Bearer {token.access_token}"}

        async with httpx.AsyncClient(timeout=self.settings.default_timeout_seconds) as client:
            response = await client.get(f"{GMAIL_API_BASE}/messages", params=params, headers=headers)
            response.raise_for_status()
            data = response.json()
            message_refs = data.get("messages", []) or []
            previews = await asyncio.gather(
                *(self._fetch_message_preview(client, headers, item["id"]) for item in message_refs)
            )

        token.last_sync_at = datetime.now(timezone.utc)
        self.token_store.save(token)
        return previews

    async def get_message_preview(self, message_id: str) -> GmailMessagePreview:
        token = await self._ensure_valid_token()
        headers = {"Authorization": f"Bearer {token.access_token}"}
        async with httpx.AsyncClient(timeout=self.settings.default_timeout_seconds) as client:
            preview = await self._fetch_message_preview(client, headers, message_id)
        token.last_sync_at = datetime.now(timezone.utc)
        self.token_store.save(token)
        return preview

    async def build_input_bundle_from_message(self, message_id: str) -> InputBundle:
        preview = await self.get_message_preview(message_id)
        metadata_lines = [
            f"Gmail message id: {preview.id}",
            f"Thread id: {preview.thread_id}",
            f"Labels: {', '.join(preview.label_ids) or 'none'}",
            f"Unread: {'yes' if preview.is_unread else 'no'}",
        ]
        return InputBundle(
            email_from=preview.from_address,
            email_subject=preview.subject,
            email_body=preview.body_text or preview.snippet,
            external_source_label="Gmail metadata",
            external_source_ref=preview.id,
            external_data="\n".join(metadata_lines),
            business_goal="Review the incoming Gmail message and decide the safest next action.",
        )

    def disconnect(self) -> None:
        self.token_store.clear()

    async def _fetch_profile(self, token: StoredGmailToken) -> dict[str, Any]:
        headers = {"Authorization": f"Bearer {token.access_token}"}
        async with httpx.AsyncClient(timeout=self.settings.default_timeout_seconds) as client:
            response = await client.get(f"{GMAIL_API_BASE}/profile", headers=headers)
            response.raise_for_status()
            return response.json()

    async def _ensure_valid_token(self) -> StoredGmailToken:
        if not self.is_configured():
            raise GmailIntegrationError("Gmail OAuth is not configured.")

        token = self.token_store.load()
        if token is None:
            raise GmailIntegrationError("Connect Gmail before trying to fetch inbox messages.")

        expiry = token.expires_at
        if expiry and expiry > datetime.now(timezone.utc) + timedelta(seconds=60):
            return token
        if not token.refresh_token:
            raise GmailIntegrationError("Stored Gmail token is expired and has no refresh token.")
        return await self._refresh_token(token)

    async def _refresh_token(self, token: StoredGmailToken) -> StoredGmailToken:
        payload = {
            "client_id": self.settings.gmail_client_id,
            "client_secret": self.settings.gmail_client_secret,
            "refresh_token": token.refresh_token,
            "grant_type": "refresh_token",
        }
        async with httpx.AsyncClient(timeout=self.settings.default_timeout_seconds) as client:
            response = await client.post(TOKEN_URL, data=payload)
            response.raise_for_status()
        refreshed = self._build_stored_token(response.json(), existing=token)
        refreshed.email_address = token.email_address
        refreshed.history_id = token.history_id
        refreshed.watch_expiration = token.watch_expiration
        refreshed.last_sync_at = token.last_sync_at
        self.token_store.save(refreshed)
        return refreshed

    def _build_stored_token(
        self,
        payload: dict[str, Any],
        *,
        existing: StoredGmailToken | None,
    ) -> StoredGmailToken:
        expires_in = payload.get("expires_in")
        expires_at = None
        if expires_in is not None:
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=int(expires_in))

        refresh_token = payload.get("refresh_token")
        if not refresh_token and existing is not None:
            refresh_token = existing.refresh_token

        return StoredGmailToken(
            access_token=payload["access_token"],
            refresh_token=refresh_token,
            token_type=payload.get("token_type", "Bearer"),
            expires_at=expires_at,
            scope=payload.get("scope"),
            email_address=existing.email_address if existing else None,
            history_id=existing.history_id if existing else None,
            watch_expiration=existing.watch_expiration if existing else None,
            last_sync_at=existing.last_sync_at if existing else None,
            connected_at=existing.connected_at if existing else datetime.now(timezone.utc),
        )

    async def _fetch_message_preview(
        self,
        client: httpx.AsyncClient,
        headers: dict[str, str],
        message_id: str,
    ) -> GmailMessagePreview:
        response = await client.get(
            f"{GMAIL_API_BASE}/messages/{message_id}",
            params={"format": "full"},
            headers=headers,
        )
        response.raise_for_status()
        payload = response.json()
        headers_list = payload.get("payload", {}).get("headers", []) or []
        return GmailMessagePreview(
            id=payload["id"],
            thread_id=payload["threadId"],
            from_address=_extract_header(headers_list, "From"),
            subject=_extract_header(headers_list, "Subject"),
            snippet=payload.get("snippet", ""),
            received_at=_to_datetime_from_epoch_millis(payload.get("internalDate")),
            body_text=_extract_body_text(payload.get("payload")),
            label_ids=payload.get("labelIds", []) or [],
            is_unread="UNREAD" in (payload.get("labelIds", []) or []),
        )
