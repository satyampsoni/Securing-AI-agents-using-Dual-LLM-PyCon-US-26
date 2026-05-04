from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse

import httpx

from app.config import Settings
from app.models import (
    InputBundle,
    MCPAuthMode,
    MCPConnector,
    MCPConnectorInput,
    MCPConnectorSnapshot,
    MCPPromptPreview,
    MCPResourcePreview,
    MCPToolPreview,
)

MCP_PROTOCOL_VERSION = "2025-06-18"
MCP_STATE_COOKIE = "mcp_oauth_state"


class MCPConnectionError(RuntimeError):
    """Raised when an MCP server call fails."""


@dataclass
class MCPOAuthFlow:
    connector_id: str
    verifier: str
    state: str


class MCPConnectorStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def list(self) -> list[MCPConnector]:
        if not self.path.exists():
            return []
        with self.path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        return [MCPConnector.model_validate(item) for item in payload]

    def save_all(self, connectors: list[MCPConnector]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("w", encoding="utf-8") as handle:
            json.dump([item.model_dump(mode="json") for item in connectors], handle, indent=2)

    def upsert(self, connector: MCPConnector) -> MCPConnector:
        connectors = self.list()
        updated = False
        for idx, item in enumerate(connectors):
            if item.id == connector.id:
                connectors[idx] = connector
                updated = True
                break
        if not updated:
            connectors.append(connector)
        self.save_all(connectors)
        return connector

    def get(self, connector_id: str) -> MCPConnector:
        for connector in self.list():
            if connector.id == connector_id:
                return connector
        raise KeyError(f"Unknown connector id: {connector_id}")

    def delete(self, connector_id: str) -> None:
        connectors = [item for item in self.list() if item.id != connector_id]
        self.save_all(connectors)


def _canonical_server_uri(url: str) -> str:
    parsed = urlparse(url)
    cleaned = parsed._replace(fragment="", query="")
    normalized_path = cleaned.path or ""
    if normalized_path != "/" and normalized_path.endswith("/"):
        normalized_path = normalized_path[:-1]
    return urlunparse(
        (
            cleaned.scheme.lower(),
            cleaned.netloc.lower(),
            normalized_path,
            "",
            "",
            "",
        )
    )


def _resource_metadata_candidates(server_url: str) -> list[str]:
    parsed = urlparse(server_url)
    path = parsed.path.rstrip("/")
    candidates: list[str] = []
    if path:
        candidates.append(urlunparse((parsed.scheme, parsed.netloc, f"/.well-known/oauth-protected-resource{path}", "", "", "")))
    candidates.append(urlunparse((parsed.scheme, parsed.netloc, "/.well-known/oauth-protected-resource", "", "", "")))
    return candidates


def _authorization_metadata_candidates(auth_server_url: str) -> list[str]:
    parsed = urlparse(auth_server_url)
    base_path = parsed.path.rstrip("/")
    candidates = []
    if base_path:
        candidates.append(urlunparse((parsed.scheme, parsed.netloc, f"{base_path}/.well-known/oauth-authorization-server", "", "", "")))
    candidates.append(urlunparse((parsed.scheme, parsed.netloc, "/.well-known/oauth-authorization-server", "", "", "")))
    return candidates


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")


def _sse_json_messages(raw_text: str) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    event_data: list[str] = []
    for line in raw_text.splitlines():
        if line.startswith("data:"):
            event_data.append(line[5:].strip())
        elif not line.strip():
            if event_data:
                joined = "\n".join(event_data)
                try:
                    payload = json.loads(joined)
                except json.JSONDecodeError:
                    payload = None
                if isinstance(payload, dict):
                    messages.append(payload)
                event_data = []
    if event_data:
        joined = "\n".join(event_data)
        try:
            payload = json.loads(joined)
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, dict):
            messages.append(payload)
    return messages


class MCPRemoteClient:
    def __init__(self, settings: Settings, connector_store: MCPConnectorStore) -> None:
        self.settings = settings
        self.connector_store = connector_store
        self.oauth_flows: dict[str, MCPOAuthFlow] = {}

    async def list_connectors(self) -> list[MCPConnector]:
        return self.connector_store.list()

    async def save_connector(self, payload: MCPConnectorInput, connector_id: str | None = None) -> MCPConnector:
        if connector_id:
            connector = self.connector_store.get(connector_id)
            connector.name = payload.name
            connector.server_url = payload.server_url.rstrip("/")
            connector.auth_mode = payload.auth_mode
            connector.bearer_token = payload.bearer_token
        else:
            connector = MCPConnector(
                name=payload.name,
                server_url=payload.server_url.rstrip("/"),
                auth_mode=payload.auth_mode,
                bearer_token=payload.bearer_token,
            )
        await self._discover_server(connector)
        connector.last_error = None
        self.connector_store.upsert(connector)
        return connector

    async def delete_connector(self, connector_id: str) -> None:
        self.connector_store.delete(connector_id)

    async def refresh_snapshot(self, connector_id: str) -> MCPConnectorSnapshot:
        connector = self.connector_store.get(connector_id)
        return await self._snapshot(connector)

    async def list_snapshots(self) -> list[MCPConnectorSnapshot]:
        snapshots: list[MCPConnectorSnapshot] = []
        for connector in self.connector_store.list():
            try:
                snapshots.append(await self._snapshot(connector))
            except Exception as exc:
                snapshots.append(
                    MCPConnectorSnapshot(
                        connector_id=connector.id,
                        connected=False,
                        server_name=connector.discovered_name or connector.name,
                        auth_required=connector.auth_mode == MCPAuthMode.OAUTH,
                        error=str(exc),
                    )
                )
        return snapshots

    async def build_auth_url(self, connector_id: str) -> tuple[str, str]:
        connector = self.connector_store.get(connector_id)
        if connector.auth_mode != MCPAuthMode.OAUTH:
            raise MCPConnectionError("This connector is not configured for OAuth.")
        await self._ensure_oauth_metadata(connector)
        if not connector.authorization_endpoint:
            raise MCPConnectionError("Connector does not expose an authorization endpoint.")
        if not connector.client_id:
            await self._register_client(connector)

        verifier = secrets.token_urlsafe(48)
        state = secrets.token_urlsafe(24)
        self.oauth_flows[state] = MCPOAuthFlow(connector_id=connector.id, verifier=verifier, state=state)

        params = {
            "response_type": "code",
            "client_id": connector.client_id,
            "redirect_uri": f"{self.settings.app_base_url.rstrip('/')}/auth/mcp/callback",
            "scope": connector.scope or "",
            "code_challenge": _pkce_challenge(verifier),
            "code_challenge_method": "S256",
            "state": state,
            "resource": _canonical_server_uri(connector.server_url),
        }
        query = urlencode({key: value for key, value in params.items() if value is not None})
        return f"{connector.authorization_endpoint}?{query}", state

    async def complete_oauth(self, state: str, code: str) -> MCPConnector:
        flow = self.oauth_flows.pop(state, None)
        if flow is None:
            raise MCPConnectionError("Unknown or expired MCP OAuth state.")
        connector = self.connector_store.get(flow.connector_id)
        await self._ensure_oauth_metadata(connector)
        if not connector.token_endpoint or not connector.client_id:
            raise MCPConnectionError("Missing token endpoint or client registration.")

        data = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": connector.client_id,
            "redirect_uri": f"{self.settings.app_base_url.rstrip('/')}/auth/mcp/callback",
            "code_verifier": flow.verifier,
            "resource": _canonical_server_uri(connector.server_url),
        }
        if connector.client_secret:
            data["client_secret"] = connector.client_secret

        async with httpx.AsyncClient(timeout=self.settings.default_timeout_seconds) as client:
            response = await client.post(connector.token_endpoint, data=data)
            response.raise_for_status()
        token_payload = response.json()
        self._apply_token_payload(connector, token_payload)
        connector.last_connected_at = datetime.now(timezone.utc)
        connector.last_error = None
        self.connector_store.upsert(connector)
        return connector

    async def read_resource(self, connector_id: str, uri: str) -> dict[str, Any]:
        connector = self.connector_store.get(connector_id)
        session = await self._initialize_session(connector)
        payload = await self._request(
            connector,
            session,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "resources/read",
                "params": {"uri": uri},
            },
        )
        return payload["result"]

    async def call_tool(self, connector_id: str, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        connector = self.connector_store.get(connector_id)
        session = await self._initialize_session(connector)
        payload = await self._request(
            connector,
            session,
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": arguments},
            },
        )
        return payload["result"]

    async def build_input_bundle_from_resource(self, connector_id: str, uri: str) -> InputBundle:
        connector = self.connector_store.get(connector_id)
        result = await self.read_resource(connector_id, uri)
        contents = result.get("contents", []) or []
        text_parts: list[str] = []
        for item in contents:
            if "text" in item:
                text_parts.append(item["text"])
            elif "blob" in item:
                text_parts.append("[binary resource omitted]")
        body = "\n\n".join(part for part in text_parts if part).strip()
        return InputBundle(
            email_from=f"{connector.discovered_name or connector.name} resource",
            email_subject=uri,
            email_body=body or "No textual content returned.",
            external_source_label="MCP resource",
            external_source_ref=uri,
            external_data=json.dumps(result, indent=2),
            business_goal="Review the connector data and decide the safest next action.",
        )

    async def build_input_bundle_from_tool(
        self,
        connector_id: str,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> InputBundle:
        connector = self.connector_store.get(connector_id)
        result = await self.call_tool(connector_id, tool_name, arguments)
        text_parts: list[str] = []
        for item in result.get("content", []) or []:
            if item.get("type") == "text":
                text_parts.append(item.get("text", ""))
        tool_text = "\n\n".join(part for part in text_parts if part).strip()
        return InputBundle(
            email_from=f"{connector.discovered_name or connector.name} tool",
            email_subject=tool_name,
            email_body=tool_text or "Tool returned no text output.",
            external_source_label="MCP tool call",
            external_source_ref=tool_name,
            external_data=json.dumps(result, indent=2),
            business_goal="Review the connector tool result and decide the safest next action.",
        )

    async def _snapshot(self, connector: MCPConnector) -> MCPConnectorSnapshot:
        if connector.auth_mode == MCPAuthMode.OAUTH and not connector.access_token:
            return MCPConnectorSnapshot(
                connector_id=connector.id,
                connected=False,
                server_name=connector.discovered_name or connector.name,
                auth_required=True,
                auth_url=f"/auth/mcp/{connector.id}/start",
                error=connector.last_error,
            )

        session = await self._initialize_session(connector)
        resources = await self._list_resources(connector, session)
        tools = await self._list_tools(connector, session)
        prompts = await self._list_prompts(connector, session)
        self.connector_store.upsert(connector)
        return MCPConnectorSnapshot(
            connector_id=connector.id,
            connected=True,
            protocol_version=session["protocol_version"],
            server_name=session["server_info"].get("name"),
            server_title=session["server_info"].get("title"),
            server_version=session["server_info"].get("version"),
            instructions=session.get("instructions"),
            capabilities=session["capabilities"],
            resources=resources,
            tools=tools,
            prompts=prompts,
            last_refreshed_at=datetime.now(timezone.utc),
            auth_required=connector.auth_mode == MCPAuthMode.OAUTH,
            auth_url=f"/auth/mcp/{connector.id}/start" if connector.auth_mode == MCPAuthMode.OAUTH else None,
        )

    async def _list_resources(self, connector: MCPConnector, session: dict[str, Any]) -> list[MCPResourcePreview]:
        if "resources" not in session["capabilities"]:
            return []
        payload = await self._request(
            connector,
            session,
            {
                "jsonrpc": "2.0",
                "id": 11,
                "method": "resources/list",
                "params": {},
            },
        )
        resources = payload["result"].get("resources", []) or []
        return [
            MCPResourcePreview(
                uri=item["uri"],
                name=item.get("name") or item["uri"],
                title=item.get("title"),
                description=item.get("description"),
                mime_type=item.get("mimeType"),
            )
            for item in resources[:20]
        ]

    async def _list_tools(self, connector: MCPConnector, session: dict[str, Any]) -> list[MCPToolPreview]:
        if "tools" not in session["capabilities"]:
            return []
        payload = await self._request(
            connector,
            session,
            {
                "jsonrpc": "2.0",
                "id": 12,
                "method": "tools/list",
                "params": {},
            },
        )
        tools = payload["result"].get("tools", []) or []
        return [
            MCPToolPreview(
                name=item["name"],
                title=item.get("title"),
                description=item.get("description"),
                input_schema=item.get("inputSchema") or {},
            )
            for item in tools[:20]
        ]

    async def _list_prompts(self, connector: MCPConnector, session: dict[str, Any]) -> list[MCPPromptPreview]:
        if "prompts" not in session["capabilities"]:
            return []
        payload = await self._request(
            connector,
            session,
            {
                "jsonrpc": "2.0",
                "id": 13,
                "method": "prompts/list",
                "params": {},
            },
        )
        prompts = payload["result"].get("prompts", []) or []
        return [
            MCPPromptPreview(
                name=item["name"],
                title=item.get("title"),
                description=item.get("description"),
            )
            for item in prompts[:20]
        ]

    async def _discover_server(self, connector: MCPConnector) -> None:
        connector.server_url = connector.server_url.rstrip("/")
        try:
            async with httpx.AsyncClient(timeout=self.settings.default_timeout_seconds, follow_redirects=True) as client:
                parsed = urlparse(connector.server_url)
                discovery_url = f"{parsed.scheme}://{parsed.netloc}/.well-known/mcp.json"
                response = await client.get(discovery_url)
                if response.is_success:
                    data = response.json()
                    endpoint = data.get("endpoint")
                    if endpoint:
                        connector.server_url = endpoint.rstrip("/")
                    connector.discovered_name = data.get("name") or connector.discovered_name or connector.name
                    connector.description = data.get("description")
                    connector.icon_url = data.get("icon")
        except Exception:
            # Discovery is best-effort so users can still save or edit a connector while offline.
            pass
        if connector.auth_mode == MCPAuthMode.OAUTH:
            await self._ensure_oauth_metadata(connector)

    async def _ensure_oauth_metadata(self, connector: MCPConnector) -> None:
        if connector.authorization_endpoint and connector.token_endpoint:
            return
        async with httpx.AsyncClient(timeout=self.settings.default_timeout_seconds, follow_redirects=True) as client:
            resource_metadata = None
            for candidate in _resource_metadata_candidates(connector.server_url):
                response = await client.get(candidate)
                if response.is_success:
                    resource_metadata = response.json()
                    connector.resource_metadata_url = candidate
                    break
            if resource_metadata is None:
                raise MCPConnectionError("Unable to discover OAuth protected resource metadata for this MCP server.")
            authorization_servers = resource_metadata.get("authorization_servers") or []
            if not authorization_servers:
                raise MCPConnectionError("Protected resource metadata did not include authorization servers.")
            connector.authorization_server = authorization_servers[0]
            connector.scope = " ".join(resource_metadata.get("scopes_supported") or []) or connector.scope

            auth_metadata = None
            for candidate in _authorization_metadata_candidates(connector.authorization_server):
                response = await client.get(candidate)
                if response.is_success:
                    auth_metadata = response.json()
                    break
            if auth_metadata is None:
                raise MCPConnectionError("Unable to discover OAuth authorization server metadata.")
            connector.authorization_endpoint = auth_metadata.get("authorization_endpoint")
            connector.token_endpoint = auth_metadata.get("token_endpoint")
            connector.registration_endpoint = auth_metadata.get("registration_endpoint")

    async def _register_client(self, connector: MCPConnector) -> None:
        if not connector.registration_endpoint:
            raise MCPConnectionError(
                "This MCP authorization server does not advertise dynamic client registration. "
                "Manual client registration is not implemented in this demo."
            )
        payload = {
            "client_name": "Dual LLM Security Demo",
            "redirect_uris": [f"{self.settings.app_base_url.rstrip('/')}/auth/mcp/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "application_type": "web",
        }
        async with httpx.AsyncClient(timeout=self.settings.default_timeout_seconds) as client:
            response = await client.post(connector.registration_endpoint, json=payload)
            response.raise_for_status()
        registration = response.json()
        connector.client_id = registration.get("client_id")
        connector.client_secret = registration.get("client_secret")
        self.connector_store.upsert(connector)

    def _apply_token_payload(self, connector: MCPConnector, token_payload: dict[str, Any]) -> None:
        connector.access_token = token_payload.get("access_token")
        if token_payload.get("refresh_token"):
            connector.refresh_token = token_payload.get("refresh_token")
        expires_in = token_payload.get("expires_in")
        connector.token_expires_at = None
        if expires_in is not None:
            connector.token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=int(expires_in))

    async def _ensure_access_token(self, connector: MCPConnector) -> None:
        if connector.auth_mode == MCPAuthMode.NONE:
            return
        if connector.auth_mode == MCPAuthMode.BEARER:
            if not connector.bearer_token:
                raise MCPConnectionError("Bearer authentication requires a token.")
            return
        if connector.auth_mode != MCPAuthMode.OAUTH:
            return
        if connector.access_token and (connector.token_expires_at is None or connector.token_expires_at > datetime.now(timezone.utc) + timedelta(seconds=60)):
            return
        if not connector.refresh_token or not connector.token_endpoint or not connector.client_id:
            raise MCPConnectionError("OAuth token missing or expired. Reconnect this MCP server.")

        data = {
            "grant_type": "refresh_token",
            "refresh_token": connector.refresh_token,
            "client_id": connector.client_id,
            "resource": _canonical_server_uri(connector.server_url),
        }
        if connector.client_secret:
            data["client_secret"] = connector.client_secret
        async with httpx.AsyncClient(timeout=self.settings.default_timeout_seconds) as client:
            response = await client.post(connector.token_endpoint, data=data)
            response.raise_for_status()
        self._apply_token_payload(connector, response.json())
        self.connector_store.upsert(connector)

    async def _initialize_session(self, connector: MCPConnector) -> dict[str, Any]:
        await self._ensure_access_token(connector)
        initialize_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": "dual-llm-security-demo",
                    "title": "Dual LLM Security Demo",
                    "version": "0.1.0",
                },
            },
        }
        response = await self._post_jsonrpc(connector, initialize_request, protocol_version=None, session_id=None)
        result = response["payload"].get("result")
        if not result:
            raise MCPConnectionError("MCP server did not return an initialize result.")
        session = {
            "session_id": response["session_id"],
            "protocol_version": result.get("protocolVersion", MCP_PROTOCOL_VERSION),
            "capabilities": result.get("capabilities", {}),
            "server_info": result.get("serverInfo", {}),
            "instructions": result.get("instructions"),
        }
        await self._notify_initialized(connector, session)
        connector.last_connected_at = datetime.now(timezone.utc)
        connector.last_error = None
        return session

    async def _notify_initialized(self, connector: MCPConnector, session: dict[str, Any]) -> None:
        notification = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        await self._post_jsonrpc(
            connector,
            notification,
            protocol_version=session["protocol_version"],
            session_id=session["session_id"],
            expect_response=False,
        )

    async def _request(self, connector: MCPConnector, session: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        response = await self._post_jsonrpc(
            connector,
            payload,
            protocol_version=session["protocol_version"],
            session_id=session["session_id"],
        )
        body = response["payload"]
        if "error" in body:
            raise MCPConnectionError(body["error"].get("message", "MCP request failed."))
        return body

    async def _post_jsonrpc(
        self,
        connector: MCPConnector,
        payload: dict[str, Any],
        *,
        protocol_version: str | None,
        session_id: str | None,
        expect_response: bool = True,
    ) -> dict[str, Any]:
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }
        if protocol_version:
            headers["MCP-Protocol-Version"] = protocol_version
        if session_id:
            headers["Mcp-Session-Id"] = session_id
        if connector.auth_mode == MCPAuthMode.BEARER and connector.bearer_token:
            headers["Authorization"] = f"Bearer {connector.bearer_token}"
        if connector.auth_mode == MCPAuthMode.OAUTH and connector.access_token:
            headers["Authorization"] = f"Bearer {connector.access_token}"

        async with httpx.AsyncClient(timeout=self.settings.default_timeout_seconds, follow_redirects=True) as client:
            response = await client.post(connector.server_url, json=payload, headers=headers)
        if not expect_response:
            if response.status_code not in {200, 202}:
                raise MCPConnectionError(f"MCP notification failed with HTTP {response.status_code}.")
            return {"payload": {}, "session_id": response.headers.get("Mcp-Session-Id")}
        response.raise_for_status()
        session_header = response.headers.get("Mcp-Session-Id")
        content_type = response.headers.get("content-type", "")
        if "application/json" in content_type:
            body = response.json()
            return {"payload": body, "session_id": session_header}
        if "text/event-stream" in content_type:
            messages = _sse_json_messages(response.text)
            match_id = payload.get("id")
            for message in messages:
                if message.get("id") == match_id:
                    return {"payload": message, "session_id": session_header}
            raise MCPConnectionError("MCP SSE response did not include the expected JSON-RPC response.")
        raise MCPConnectionError(f"Unsupported MCP response content type: {content_type}")
