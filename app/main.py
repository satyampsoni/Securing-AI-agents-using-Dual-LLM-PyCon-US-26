from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.config import Settings, get_settings
from app.gmail import GmailIntegrationError, GmailService, STATE_COOKIE_NAME
from app.llm import build_llm_client
from app.mcp import MCPConnectionError, MCPConnectorStore, MCPRemoteClient, MCP_STATE_COOKIE
from app.models import MCPConnectorInput, MCPToolCallRequest, RunRequest, RuntimeConfig
from app.policy import PolicyEngine
from app.runner import ScenarioRunner
from app.scenarios import get_scenario, list_scenarios
from app.store import RunStore


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    app = FastAPI(title=settings.app_title)
    templates = Jinja2Templates(directory=str(Path("templates")))

    llm_client = build_llm_client(settings)
    policy_engine = PolicyEngine(settings)
    run_store = RunStore()
    gmail_service = GmailService(settings)
    connector_store = MCPConnectorStore(settings.mcp_connector_store_path)
    mcp_client = MCPRemoteClient(settings, connector_store)
    runner = ScenarioRunner(
        llm_client=llm_client,
        policy_engine=policy_engine,
        backend_name="live" if settings.use_live_models else "replay",
    )

    app.state.settings = settings
    app.state.store = run_store
    app.state.runner = runner
    app.state.gmail_service = gmail_service
    app.state.mcp_client = mcp_client

    app.mount("/static", StaticFiles(directory="static"), name="static")

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        gmail_status = await gmail_service.get_status()
        connectors = await mcp_client.list_connectors()
        return templates.TemplateResponse(
            request,
            "index.html",
            {
                "scenarios": [scenario.model_dump() for scenario in list_scenarios()],
                "default_runtime_config": RuntimeConfig().model_dump(),
                "gmail_status": gmail_status.model_dump(mode="json"),
                "mcp_connectors": [item.model_dump(mode="json") for item in connectors],
                "run_mode": settings.run_mode,
                "allow_sensitive_tools": settings.allow_sensitive_tools,
            },
        )

    @app.get("/api/scenarios")
    async def scenarios() -> list[dict]:
        return [scenario.model_dump() for scenario in list_scenarios()]

    @app.post("/api/run")
    async def run_scenario(payload: RunRequest) -> dict:
        try:
            scenario = get_scenario(payload.scenario_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

        trace = await app.state.runner.run(
            scenario,
            payload.mode,
            runtime_config=payload.runtime_config,
            input_override=payload.input_override,
        )
        app.state.store.save(trace)
        return trace.model_dump(mode="json")

    @app.get("/api/runs/{run_id}")
    async def get_run(run_id: str) -> dict:
        try:
            trace = app.state.store.get(run_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=f"Unknown run id: {run_id}") from exc
        return trace.model_dump(mode="json")

    @app.get("/api/gmail/status")
    async def gmail_status() -> dict:
        return (await gmail_service.get_status()).model_dump(mode="json")

    @app.get("/api/gmail/messages")
    async def gmail_messages(max_results: int | None = None, q: str | None = None) -> list[dict]:
        try:
            messages = await gmail_service.list_messages(max_results=max_results, query=q)
        except GmailIntegrationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"Gmail inbox sync failed: {exc}") from exc
        return [item.model_dump(mode="json") for item in messages]

    @app.get("/api/gmail/messages/{message_id}")
    async def gmail_message(message_id: str) -> dict:
        try:
            preview = await gmail_service.get_message_preview(message_id)
        except GmailIntegrationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"Failed to fetch Gmail message: {exc}") from exc
        return preview.model_dump(mode="json")

    @app.get("/api/gmail/messages/{message_id}/input")
    async def gmail_message_input(message_id: str) -> dict:
        try:
            bundle = await gmail_service.build_input_bundle_from_message(message_id)
        except GmailIntegrationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"Failed to build Gmail input bundle: {exc}") from exc
        return bundle.model_dump(mode="json")

    @app.post("/api/gmail/disconnect")
    async def gmail_disconnect() -> dict:
        gmail_service.disconnect()
        return {"ok": True}

    @app.get("/auth/gmail/start")
    async def gmail_auth_start() -> RedirectResponse:
        try:
            state = gmail_service.generate_oauth_state()
            auth_url = gmail_service.build_auth_url(state)
        except GmailIntegrationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

        response = RedirectResponse(url=auth_url, status_code=302)
        response.set_cookie(
            STATE_COOKIE_NAME,
            state,
            httponly=True,
            secure=settings.environment.lower() == "production",
            samesite="lax",
            max_age=600,
        )
        return response

    @app.get("/auth/gmail/callback")
    async def gmail_auth_callback(request: Request, code: str | None = None, state: str | None = None) -> RedirectResponse:
        expected_state = request.cookies.get(STATE_COOKIE_NAME)
        if not code:
            raise HTTPException(status_code=400, detail="Missing Gmail authorization code.")
        if not expected_state or expected_state != state:
            raise HTTPException(status_code=400, detail="Gmail OAuth state validation failed.")

        try:
            await gmail_service.exchange_code(code)
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"Gmail OAuth token exchange failed: {exc}") from exc

        response = RedirectResponse(url="/?gmail=connected", status_code=302)
        response.delete_cookie(STATE_COOKIE_NAME)
        return response

    @app.get("/api/mcp/connectors")
    async def list_mcp_connectors() -> list[dict]:
        connectors = await mcp_client.list_connectors()
        return [item.model_dump(mode="json") for item in connectors]

    @app.post("/api/mcp/connectors")
    async def create_mcp_connector(payload: MCPConnectorInput) -> dict:
        try:
            connector = await mcp_client.save_connector(payload)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Failed to save MCP connector: {exc}") from exc
        return connector.model_dump(mode="json")

    @app.post("/api/mcp/connectors/{connector_id}")
    async def update_mcp_connector(connector_id: str, payload: MCPConnectorInput) -> dict:
        try:
            connector = await mcp_client.save_connector(payload, connector_id=connector_id)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Failed to update MCP connector: {exc}") from exc
        return connector.model_dump(mode="json")

    @app.delete("/api/mcp/connectors/{connector_id}")
    async def delete_mcp_connector(connector_id: str) -> dict:
        await mcp_client.delete_connector(connector_id)
        return {"ok": True}

    @app.get("/api/mcp/connectors/{connector_id}/snapshot")
    async def mcp_snapshot(connector_id: str) -> dict:
        try:
            snapshot = await mcp_client.refresh_snapshot(connector_id)
        except MCPConnectionError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"MCP connector refresh failed: {exc}") from exc
        return snapshot.model_dump(mode="json")

    @app.get("/api/mcp/connectors/{connector_id}/resources/{path:path}")
    async def mcp_read_resource(connector_id: str, path: str, uri: str | None = None) -> dict:
        target_uri = uri or path
        try:
            result = await mcp_client.read_resource(connector_id, target_uri)
        except MCPConnectionError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"MCP resource read failed: {exc}") from exc
        return result

    @app.post("/api/mcp/connectors/{connector_id}/resources/import")
    async def mcp_import_resource(connector_id: str, payload: dict) -> dict:
        uri = payload.get("uri")
        if not uri:
            raise HTTPException(status_code=400, detail="Missing resource URI.")
        try:
            bundle = await mcp_client.build_input_bundle_from_resource(connector_id, uri)
        except MCPConnectionError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"Failed to import MCP resource: {exc}") from exc
        return bundle.model_dump(mode="json")

    @app.post("/api/mcp/connectors/{connector_id}/tools/{tool_name}/call")
    async def mcp_call_tool(connector_id: str, tool_name: str, payload: MCPToolCallRequest) -> dict:
        try:
            result = await mcp_client.call_tool(connector_id, tool_name, payload.arguments)
        except MCPConnectionError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"MCP tool call failed: {exc}") from exc
        return result

    @app.post("/api/mcp/connectors/{connector_id}/tools/{tool_name}/import")
    async def mcp_import_tool(connector_id: str, tool_name: str, payload: MCPToolCallRequest) -> dict:
        try:
            bundle = await mcp_client.build_input_bundle_from_tool(connector_id, tool_name, payload.arguments)
        except MCPConnectionError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"Failed to import MCP tool output: {exc}") from exc
        return bundle.model_dump(mode="json")

    @app.get("/auth/mcp/{connector_id}/start")
    async def mcp_auth_start(connector_id: str) -> RedirectResponse:
        try:
            auth_url, state = await mcp_client.build_auth_url(connector_id)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Unable to start MCP OAuth flow: {exc}") from exc
        response = RedirectResponse(url=auth_url, status_code=302)
        response.set_cookie(
            MCP_STATE_COOKIE,
            state,
            httponly=True,
            secure=settings.environment.lower() == "production",
            samesite="lax",
            max_age=600,
        )
        return response

    @app.get("/auth/mcp/callback")
    async def mcp_auth_callback(request: Request, code: str | None = None, state: str | None = None) -> RedirectResponse:
        expected_state = request.cookies.get(MCP_STATE_COOKIE)
        if not code:
            raise HTTPException(status_code=400, detail="Missing MCP authorization code.")
        if not expected_state or expected_state != state:
            raise HTTPException(status_code=400, detail="MCP OAuth state validation failed.")
        try:
            connector = await mcp_client.complete_oauth(state, code)
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"MCP OAuth token exchange failed: {exc}") from exc
        response = RedirectResponse(url=f"/?mcp_connected={connector.id}", status_code=302)
        response.delete_cookie(MCP_STATE_COOKIE)
        return response

    return app


app = create_app()
