# Delegated Auth Mode (In-Memory Access Tokens)

This mode is designed for environments where the MCP server does not persist refresh tokens and only keeps short‑lived `access_token` values in memory. Token refreshes are delegated to your own backend via an HTTP endpoint.

## What it does
- Stores only `access_token` and `expiry_date` in memory (per email).
- Does not read/write any token files.
- Initializes each account by calling the `set_workspace_account_token` tool with the first `access_token`.
- When a token is near expiry/expired while handling a request, calls your backend `POST /refresh_token` to obtain a new `access_token` and updates the in‑memory cache.

## Enable
- Set environment variable on the MCP child process:
  - `AUTH_TOKEN_MODE=true` (also accepts `1`, `yes`, `on`, or `delegated`)
- Configure backend refresh endpoint (or rely on default):
  - `REFRESH_TOKEN_URL` (default: `http://127.0.0.1:8000/refresh_token`)
  - Optional: `REFRESH_AUTH_HEADER=Bearer <service-credential>`
  - Optional: `REFRESH_TIMEOUT_MS=8000`, `REFRESH_RETRY_COUNT=1`, `TOKEN_EXPIRY_BUFFER_MS=300000`

## Cold start flow (recommended)
1. Start the MCP server.
2. For each account, call the tool `set_workspace_account_token`:
   - `email`: the account email
   - `token`: `{ access_token, expiry_date }` (ms since epoch; seconds are also accepted and will be converted)
3. Optionally call `list_workspace_accounts` to verify status is `VALID`.

The server will not attempt to fetch an access token automatically when none is present. It will refresh only when a cached token is nearing expiry/has expired.

## Backend /refresh_token contract
- Request: `POST REFRESH_TOKEN_URL` with JSON body `{ email: string, scopes?: string[] }`.
- Response (200): `{ access_token: string, expires_in?: number, expiry_date?: number, token_type?: 'Bearer', scope?: string|string[] }`.
  - If only `expires_in` is provided, the server computes `expiry_date = Date.now() + expires_in*1000`.
- Errors:
  - `401/403` → treated as `AUTH_REQUIRED` (not retried).
  - `5xx`/network → treated as temporary; the request will fail with a retryable error.

## Notes
- OAuth-based tools are disabled in delegated mode. Use `set_workspace_account_token` to inject tokens.
- Logs avoid printing token values. Prefer `LOG_MODE=strict` for local development.
- Accounts metadata (`accounts.json`) may still be used to store non-secret info (email/category/description).
