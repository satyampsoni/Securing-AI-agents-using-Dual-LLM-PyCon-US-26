# Dual-LLM Security Demo

Small FastAPI MVP for a PyCon US poster presentation about securing agentic systems with a dual-LLM architecture.

## What it shows

- `Baseline` mode sends raw untrusted email and webpage content directly to one model.
- `Dual` mode splits the workflow into a quarantined summarizer and a privileged decision-maker.
- A policy layer separately gates simulated tools such as `create_ticket`, `mark_safe_to_ignore`, and `send_external_webhook`.
- Three curated scenarios demonstrate prompt injection, confused deputy, and the lethal trifecta.
- The UI includes a bring-your-own MCP connector rail, model-role configuration, editable payload inputs, and trace output.
- You can connect modern remote MCP servers, browse live resources or tools, and import that data into the analysis studio before running the dual-LLM pipeline.

## Run locally

1. Create a virtual environment and install dependencies:

   ```bash
   pip install -e ".[dev]"
   ```

2. Start the app:

   ```bash
   uvicorn app.main:app --reload
   ```

3. Open [http://127.0.0.1:8000](http://127.0.0.1:8000).

The default `RUN_MODE` is `replay`, which uses deterministic fixtures from [`data/replays`](/Users/satyampsoni/Desktop/Securing-AI-agents-using-Dual-LLM-PyCon-US-26/data/replays). For real MCP-backed analysis, set `RUN_MODE=live` and provide model credentials. Connector authentication depends on the MCP server you connect to.

## Configuration

- `RUN_MODE=replay|live`
- `APP_BASE_URL=http://127.0.0.1:8000`
- `ALLOW_SENSITIVE_TOOLS=false`
- `QUARANTINED_BASE_URL`, `QUARANTINED_API_KEY`, `QUARANTINED_MODEL_NAME`
- `PRIVILEGED_BASE_URL`, `PRIVILEGED_API_KEY`, `PRIVILEGED_MODEL_NAME`
- `MCP_CONNECTOR_STORE_PATH` is not currently env-configurable; connectors are stored at [`data/mcp_connectors.json`](/Users/satyampsoni/Desktop/Securing-AI-agents-using-Dual-LLM-PyCon-US-26/data/mcp_connectors.json)
- `GMAIL_CLIENT_ID`, `GMAIL_CLIENT_SECRET`
- Optional: `GMAIL_REDIRECT_URI`, `GMAIL_POLL_QUERY`, `GMAIL_POLL_MAX_RESULTS`

## MCP setup

This app now prefers current remote MCP connector patterns over bespoke one-off data integrations.

### Remote hosted MCP servers

1. Start the app with `APP_BASE_URL` set to the public or local base URL that will receive OAuth callbacks.
2. In the UI, add a connector with the remote MCP endpoint URL.
3. If the server supports OAuth, choose `OAuth` auth mode and use the `OAuth connect` button.
4. After connecting, refresh the snapshot to list resources and tools, then import a resource or tool output into the analysis studio.

Example hosted connector:

- Notion hosted MCP: `https://mcp.notion.com/mcp`

### Bring your own Gmail MCP server

If you already have a Gmail MCP server from your stack, marketplace vendor, or internal platform, add its remote MCP endpoint URL as a connector. The app will treat it like any other MCP server and can import exposed resources or tool outputs.

## Gmail direct setup

The direct Gmail OAuth flow is still in the codebase, but the current recommended UX is the MCP connector path above.

1. In Google Cloud Console, create or select a project.
2. Enable the Gmail API for that project.
3. Create OAuth client credentials for a web application.
4. Add your redirect URI, for example `http://127.0.0.1:8000/auth/gmail/callback`.
5. Set these environment variables before launching the app:

   ```bash
   export RUN_MODE=live
   export APP_BASE_URL=http://127.0.0.1:8000
   export GMAIL_CLIENT_ID=your_google_oauth_client_id
   export GMAIL_CLIENT_SECRET=your_google_oauth_client_secret
   export QUARANTINED_BASE_URL=https://your-openai-compatible-endpoint
   export QUARANTINED_API_KEY=your_quarantine_key
   export QUARANTINED_MODEL_NAME=your_quarantine_model
   export PRIVILEGED_BASE_URL=https://your-openai-compatible-endpoint
   export PRIVILEGED_API_KEY=your_privileged_key
   export PRIVILEGED_MODEL_NAME=your_privileged_model
   ```

6. Start the app and use the `Connect Gmail` button.

The app stores Gmail tokens locally in [`data/gmail_token.json`](/Users/satyampsoni/Desktop/Securing-AI-agents-using-Dual-LLM-PyCon-US-26/data/gmail_token.json). Keep that file out of source control.

## Production notes

- This app uses Gmail OAuth web-server flow with offline access so it can refresh tokens without asking the user to reconnect every time.
- Modern hosted MCP servers typically use Streamable HTTP and OAuth discovery rather than custom connector code per service.
- This app supports remote MCP discovery, dynamic client registration when the server advertises it, OAuth code flow with PKCE, and progressive browsing of tools/resources.
- The live inbox rail currently uses API polling to load recent inbox messages. Google’s Gmail push-notification docs note that poll-based sync is the recommended approach for user-owned devices and browsers, while server push requires Gmail `watch` plus Google Cloud Pub/Sub.
- For a production deployment, run behind HTTPS, store OAuth secrets in a real secret manager, and move token storage from the local filesystem into encrypted persistent storage.
- If you want automatic server-side mailbox events instead of browser-driven inbox sync, the next step is to add Gmail `users.watch` with a Pub/Sub-backed webhook worker.

## Tests

Run:

```bash
pytest
```
