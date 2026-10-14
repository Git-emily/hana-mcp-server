"""
HANA MCP Server — BDC Assessment (dev)
---------------------------------------
Expose HANA schema as an MCP Server HTTP (StreamableHTTP transport).

Auth: self-hosted OAuth2 Authorization Server (RFC 6749, RFC 7591)
  - Joule connects with only the MCP URL — no Client ID/Secret needed.
  - Dynamic client registration (RFC 7591): Joule auto-registers on first use.
  - SSO via SAP IDP (XSUAA): the app proxies the auth code flow, exchanges the
    code server-side using credentials stored in VCAP_SERVICES, and issues its
    own short-lived JWT to Joule.
  - Access control via ALLOWED_USERS env var (comma-separated emails).

Deployment:
  CF BTP → cf push --vars-file vars.yml   (PORT + VCAP_SERVICES auto-injected)
  Local   → python hana_mcp_server.py     (reads .env, uses XSUAA_* vars)
"""

import os
import json
import asyncio
import logging
import secrets
import time
import hashlib
import base64
from urllib.parse import parse_qs, urlencode, urlparse

from dotenv import load_dotenv
load_dotenv(override=False)

import httpx
import jwt as pyjwt
import uvicorn
from mcp.server.fastmcp import FastMCP
import hdbcli.dbapi as hana

logger = logging.getLogger(__name__)

# ── HANA connection ────────────────────────────────────────────────────────────
HOST      = os.environ["HANA_HOST"]
HANA_PORT = int(os.getenv("HANA_PORT", "443"))
USER      = os.environ["HANA_USER"]
PASSWORD  = os.environ["HANA_PASSWORD"]
SCHEMA    = os.environ["HANA_SCHEMA"]


def connect():
    return hana.connect(
        address=HOST, port=HANA_PORT, user=USER, password=PASSWORD,
        currentSchema=SCHEMA, encrypt=True, sslValidateCertificate=False,
    )


# ── XSUAA credentials ─────────────────────────────────────────────────────────
def _load_uaa_credentials() -> dict:
    """Load XSUAA credentials from VCAP_SERVICES (CF) or env vars (local)."""
    vcap_raw = os.getenv("VCAP_SERVICES")
    if vcap_raw:
        try:
            vcap = json.loads(vcap_raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"VCAP_SERVICES is not valid JSON: {exc}") from exc
        entries = vcap.get("xsuaa", [])
        if not entries:
            raise RuntimeError("VCAP_SERVICES present but no 'xsuaa' binding found.")
        creds = entries[0]["credentials"]
        return {
            "url":          creds["url"],
            "clientid":     creds["clientid"],
            "clientsecret": creds.get("clientsecret", ""),
            "xsappname":    creds["xsappname"],
        }

    url           = os.getenv("XSUAA_URL", "")
    client_id     = os.getenv("XSUAA_CLIENT_ID", "")
    client_secret = os.getenv("XSUAA_CLIENT_SECRET", "")
    app_name      = os.getenv("XSUAA_APP_NAME", "")
    if not url or not client_id:
        raise RuntimeError(
            "XSUAA is not configured. On CF: bind 'hana-mcp-xsuaa'. "
            "Locally: set XSUAA_URL and XSUAA_CLIENT_ID."
        )
    return {
        "url":          url,
        "clientid":     client_id,
        "clientsecret": client_secret,
        "xsappname":    app_name or client_id,
    }


# ── App URL ────────────────────────────────────────────────────────────────────
def _get_app_url() -> str:
    vcap = json.loads(os.getenv("VCAP_APPLICATION", "{}"))
    uris = vcap.get("application_uris", [])
    if uris:
        return "https://" + uris[0]
    port = os.getenv("PORT", os.getenv("MCP_PORT", "8000"))
    return f"http://localhost:{port}"


# ── ASGI helpers ───────────────────────────────────────────────────────────────
async def _send_json(send, status: int, payload: dict, extra_headers=None) -> None:
    body = json.dumps(payload).encode("utf-8")
    headers = [
        (b"content-type",   b"application/json; charset=utf-8"),
        (b"content-length", str(len(body)).encode()),
    ]
    if extra_headers:
        headers += extra_headers
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body, "more_body": False})


async def _send_redirect(send, location: str) -> None:
    await send({
        "type": "http.response.start", "status": 302,
        "headers": [(b"location", location.encode("utf-8")), (b"content-length", b"0")],
    })
    await send({"type": "http.response.body", "body": b"", "more_body": False})


async def _read_body(receive) -> bytes:
    body = b""
    while True:
        msg = await receive()
        body += msg.get("body", b"")
        if not msg.get("more_body", False):
            break
    return body


# ── JWT helpers ────────────────────────────────────────────────────────────────
def _jwt_secret(creds: dict) -> str:
    override = os.getenv("JWT_SIGNING_SECRET", "")
    if override:
        return override
    # Derive from XSUAA client secret so it's stable across restarts
    raw = creds.get("clientsecret", secrets.token_hex(32))
    return hashlib.sha256(raw.encode()).hexdigest()


def _issue_token(email: str, secret: str, expires_in: int = 3600) -> str:
    now = int(time.time())
    return pyjwt.encode(
        {"sub": email, "email": email, "iat": now, "exp": now + expires_in,
         "iss": "hana-mcp-proxy"},
        secret, algorithm="HS256",
    )


def _verify_token(token: str, secret: str) -> dict | None:
    try:
        return pyjwt.decode(
            token, secret, algorithms=["HS256"],
            options={"require": ["sub", "exp", "iss"]},
        )
    except Exception:
        return None


def _pkce_verify(verifier: str, challenge: str) -> bool:
    digest   = hashlib.sha256(verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return computed == challenge


# ── OAuth2 Middleware ──────────────────────────────────────────────────────────
class OAuth2Middleware:
    """
    Combined OAuth2 Authorization Server proxy + JWT validation middleware.

    Flow (Joule Work Desktop):
      1. Joule GETs /.well-known/oauth-authorization-server → sees registration_endpoint
      2. Joule POSTs /oauth2/register → gets a dynamic client_id (no secret)
      3. Joule GETs /oauth2/authorize → we redirect user to SAP IDP (XSUAA)
      4. SAP IDP authenticates user, redirects to /oauth2/callback with a code
      5. We exchange that code for a XSUAA token using our server-side credentials
      6. We extract the user's email, check ALLOWED_USERS, issue our own JWT
      7. We redirect Joule to its localhost callback with our auth code
      8. Joule POSTs /oauth2/token with code + PKCE verifier → gets our JWT
      9. Joule presents our JWT as Bearer token on all /mcp requests

    XSUAA Client ID + Secret stay in VCAP_SERVICES — never sent to Joule.
    """

    def __init__(self, app) -> None:
        self.app = app
        self._creds: dict | None = None
        self._secret: str = secrets.token_hex(32)
        self._app_url: str | None = None
        self._init_error: str | None = None
        # In-memory stores (safe for single CF instance)
        self._clients: dict = {}   # client_id → metadata
        self._pending: dict = {}   # our_state  → Joule request params
        self._codes:   dict = {}   # our_code   → {email, challenge, ..., expires_at}
        try:
            self._creds = _load_uaa_credentials()
            self._secret = _jwt_secret(self._creds)
        except RuntimeError as exc:
            self._init_error = str(exc)
            logger.critical("OAuth2Middleware init failed: %s", exc)

    def _base_url(self) -> str:
        if not self._app_url:
            self._app_url = _get_app_url()
        return self._app_url

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        if scope["type"] == "websocket":
            await self.app(scope, receive, send)
            return

        if self._init_error:
            await _send_json(send, 500, {"error": f"Auth configuration error: {self._init_error}"})
            return

        path   = scope.get("path", "")
        method = scope.get("method", "GET").upper()

        # ── Discovery endpoints (no auth) ──────────────────────────────────────
        if path in ("/.well-known/oauth-authorization-server",
                    "/.well-known/oauth-authorization-server/mcp",
                    "/.well-known/openid-configuration"):
            await self._well_known_auth_server(send)
            return

        if path in ("/.well-known/oauth-protected-resource",
                    "/.well-known/oauth-protected-resource/mcp"):
            await self._well_known_resource(send)
            return

        # ── OAuth2 proxy endpoints (no auth) ───────────────────────────────────
        if path == "/oauth2/register" and method == "POST":
            await self._handle_register(scope, receive, send)
            return
        if path == "/oauth2/authorize" and method == "GET":
            await self._handle_authorize(scope, receive, send)
            return
        if path == "/oauth2/callback" and method == "GET":
            await self._handle_callback(scope, receive, send)
            return
        if path == "/oauth2/token" and method == "POST":
            await self._handle_token(scope, receive, send)
            return

        # ── All other requests: validate our JWT ───────────────────────────────
        headers_dict = {k: v for k, v in scope.get("headers", [])}
        auth = headers_dict.get(b"authorization", b"").decode("utf-8", errors="replace")

        if not auth.startswith("Bearer "):
            base = self._base_url()
            www_auth = f'Bearer realm="{base}/mcp", error="invalid_token"'.encode()
            body = json.dumps({"error": "Missing Authorization: Bearer <token>"}).encode()
            await send({
                "type": "http.response.start", "status": 401,
                "headers": [
                    (b"content-type",   b"application/json; charset=utf-8"),
                    (b"content-length", str(len(body)).encode()),
                    (b"www-authenticate", www_auth),
                ],
            })
            await send({"type": "http.response.body", "body": body, "more_body": False})
            return

        payload = _verify_token(auth[len("Bearer "):], self._secret)
        if not payload:
            await _send_json(send, 401, {"error": "Token invalid or expired"})
            return

        email = (payload.get("email") or payload.get("sub", "")).lower()

        # Allowlist check
        allowed_raw = os.getenv("ALLOWED_USERS", "")
        if allowed_raw.strip():
            allowed = {u.strip().lower() for u in allowed_raw.split(",") if u.strip()}
            if email not in allowed:
                logger.warning("JWT valid but %s not in ALLOWED_USERS", email)
                await _send_json(send, 403, {"error": f"Forbidden: {email} is not authorised."})
                return

        logger.info("AUTH OK principal=%s", email)

        # Rewrite Host to localhost — required by FastMCP TrustedHostMiddleware
        rewritten = [
            (k, b"localhost" if k == b"host" else v)
            for k, v in scope.get("headers", [])
        ]
        await self.app({**scope, "headers": rewritten}, receive, send)

    # ── Well-known ─────────────────────────────────────────────────────────────

    async def _well_known_auth_server(self, send) -> None:
        base = self._base_url()
        await _send_json(send, 200, {
            "issuer":                               base,
            "authorization_endpoint":               f"{base}/oauth2/authorize",
            "token_endpoint":                       f"{base}/oauth2/token",
            "registration_endpoint":                f"{base}/oauth2/register",
            "response_types_supported":             ["code"],
            "grant_types_supported":                ["authorization_code"],
            "code_challenge_methods_supported":     ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported":                     ["openid"],
        }, extra_headers=[(b"access-control-allow-origin", b"*")])

    async def _well_known_resource(self, send) -> None:
        base = self._base_url()
        await _send_json(send, 200, {
            "resource":                 f"{base}/mcp",
            "authorization_servers":    [base],
            "bearer_methods_supported": ["header"],
            "scopes_supported":         ["openid"],
        }, extra_headers=[(b"access-control-allow-origin", b"*")])

    # ── /oauth2/register ───────────────────────────────────────────────────────

    async def _handle_register(self, scope, receive, send) -> None:
        """RFC 7591 dynamic client registration — Joule calls this on first use."""
        await _read_body(receive)
        client_id = "joule-" + secrets.token_urlsafe(16)
        self._clients[client_id] = {"created_at": int(time.time())}
        await _send_json(send, 201, {
            "client_id":                  client_id,
            "client_id_issued_at":        int(time.time()),
            "token_endpoint_auth_method": "none",
            "grant_types":                ["authorization_code"],
            "response_types":             ["code"],
        })

    # ── /oauth2/authorize ──────────────────────────────────────────────────────

    async def _handle_authorize(self, scope, receive, send) -> None:
        """Receive Joule's auth request; redirect user to SAP IDP."""
        qs = parse_qs(scope.get("query_string", b"").decode())

        joule_state    = qs.get("state", [""])[0]
        joule_redirect = qs.get("redirect_uri", [""])[0]
        code_challenge = qs.get("code_challenge", [""])[0]
        ch_method      = qs.get("code_challenge_method", ["S256"])[0]

        our_state = secrets.token_urlsafe(32)
        self._pending[our_state] = {
            "joule_state":    joule_state,
            "joule_redirect": joule_redirect,
            "code_challenge": code_challenge,
            "ch_method":      ch_method,
            "expires_at":     int(time.time()) + 600,
        }

        uaa_url  = self._creds["url"].rstrip("/")
        callback = self._base_url() + "/oauth2/callback"
        params   = urlencode({
            "response_type": "code",
            "client_id":     self._creds["clientid"],
            "redirect_uri":  callback,
            "state":         our_state,
            "scope":         "openid",
        })
        await _send_redirect(send, f"{uaa_url}/oauth/authorize?{params}")

    # ── /oauth2/callback ───────────────────────────────────────────────────────

    async def _handle_callback(self, scope, receive, send) -> None:
        """SAP IDP redirects here after user login; exchange code, issue our JWT."""
        qs         = parse_qs(scope.get("query_string", b"").decode())
        xsuaa_code = qs.get("code",  [""])[0]
        our_state  = qs.get("state", [""])[0]
        error      = qs.get("error", [""])[0]

        pending = self._pending.pop(our_state, None)
        if not pending:
            await _send_json(send, 400, {"error": "Invalid or expired state"})
            return

        if error:
            desc = qs.get("error_description", [error])[0]
            redir = pending["joule_redirect"] + "?" + urlencode({
                "error": error, "error_description": desc,
                "state": pending["joule_state"],
            })
            await _send_redirect(send, redir)
            return

        if int(time.time()) > pending["expires_at"]:
            await _send_json(send, 400, {"error": "State expired"})
            return

        # Exchange XSUAA auth code for XSUAA access token (server-side)
        uaa_url  = self._creds["url"].rstrip("/")
        callback = self._base_url() + "/oauth2/callback"
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{uaa_url}/oauth/token",
                    data={
                        "grant_type":   "authorization_code",
                        "code":         xsuaa_code,
                        "redirect_uri": callback,
                    },
                    auth=(self._creds["clientid"], self._creds["clientsecret"]),
                    headers={"Accept": "application/json"},
                    timeout=10,
                )
            token_data = resp.json()
        except Exception as exc:
            logger.error("XSUAA token exchange failed: %s", exc)
            await _send_json(send, 502, {"error": "Identity provider token exchange failed"})
            return

        if "error" in token_data:
            desc = token_data.get("error_description", token_data["error"])
            redir = pending["joule_redirect"] + "?" + urlencode({
                "error": "access_denied", "error_description": desc,
                "state": pending["joule_state"],
            })
            await _send_redirect(send, redir)
            return

        # Extract user email from XSUAA access_token (it's a JWT with user_name/email)
        xsuaa_token = token_data.get("access_token", "")
        try:
            claims = pyjwt.decode(xsuaa_token, options={"verify_signature": False})
            email = (
                claims.get("email") or
                claims.get("user_name") or
                claims.get("sub", "")
            ).lower().strip()
        except Exception:
            email = ""

        if not email:
            redir = pending["joule_redirect"] + "?" + urlencode({
                "error": "server_error",
                "error_description": "Could not determine user identity from IDP token",
                "state": pending["joule_state"],
            })
            await _send_redirect(send, redir)
            return

        # Allowlist check at auth time
        allowed_raw = os.getenv("ALLOWED_USERS", "")
        if allowed_raw.strip():
            allowed = {u.strip().lower() for u in allowed_raw.split(",") if u.strip()}
            if email not in allowed:
                logger.warning("OAuth2 callback: %s not in ALLOWED_USERS", email)
                redir = pending["joule_redirect"] + "?" + urlencode({
                    "error": "access_denied",
                    "error_description": f"{email} is not authorised to use this MCP server.",
                    "state": pending["joule_state"],
                })
                await _send_redirect(send, redir)
                return

        # Issue our own auth code for Joule
        our_code = secrets.token_urlsafe(32)
        self._codes[our_code] = {
            "email":        email,
            "challenge":    pending["code_challenge"],
            "ch_method":    pending["ch_method"],
            "redirect_uri": pending["joule_redirect"],
            "expires_at":   int(time.time()) + 300,
        }
        logger.info("Issued auth code for %s", email)

        redir = pending["joule_redirect"] + "?" + urlencode({
            "code":  our_code,
            "state": pending["joule_state"],
        })
        await _send_redirect(send, redir)

    # ── /oauth2/token ─────────────────────────────────────────────────────────

    async def _handle_token(self, scope, receive, send) -> None:
        """Joule exchanges auth code + PKCE verifier for our JWT."""
        body   = await _read_body(receive)
        params = parse_qs(body.decode("utf-8", errors="replace"))

        code          = params.get("code",          [""])[0]
        code_verifier = params.get("code_verifier", [""])[0]

        entry = self._codes.pop(code, None)
        if not entry:
            await _send_json(send, 400,
                {"error": "invalid_grant", "error_description": "Code not found or already used"})
            return

        if int(time.time()) > entry["expires_at"]:
            await _send_json(send, 400,
                {"error": "invalid_grant", "error_description": "Code expired"})
            return

        if entry["challenge"] and not _pkce_verify(code_verifier, entry["challenge"]):
            await _send_json(send, 400,
                {"error": "invalid_grant", "error_description": "PKCE code_verifier mismatch"})
            return

        token = _issue_token(entry["email"], self._secret)
        logger.info("Issued access token for %s", entry["email"])
        await _send_json(send, 200, {
            "access_token": token,
            "token_type":   "Bearer",
            "expires_in":   3600,
            "scope":        "openid",
        })


# ── MCP Server ─────────────────────────────────────────────────────────────────
# host="0.0.0.0" disables FastMCP's DNS rebinding protection (only for localhost).
# Security is handled entirely by OAuth2Middleware.
mcp = FastMCP("HANA BDC Assessment", host="0.0.0.0")


@mcp.tool()
def list_tables() -> str:
    """
    Liste toutes les tables du schéma BDC assessment.
    Retourne une liste de noms de tables, une par ligne.
    """
    conn = connect()
    cur = conn.cursor()
    cur.execute(
        "SELECT TABLE_NAME FROM SYS.TABLES WHERE SCHEMA_NAME = ? ORDER BY TABLE_NAME",
        (SCHEMA,)
    )
    tables = [row[0] for row in cur.fetchall()]
    cur.close(); conn.close()
    return "\n".join(tables) if tables else "(aucune table trouvée dans ce schéma)"


@mcp.tool()
def describe_table(table_name: str) -> str:
    """
    Retourne la structure (colonnes, types, nullable) d'une table du schéma.
    Paramètre: table_name — nom exact de la table (sans schéma).
    """
    conn = connect()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT COLUMN_NAME, DATA_TYPE_NAME, LENGTH, SCALE, IS_NULLABLE, DEFAULT_VALUE
        FROM SYS.TABLE_COLUMNS
        WHERE SCHEMA_NAME = ? AND TABLE_NAME = ?
        ORDER BY POSITION
        """,
        (SCHEMA, table_name.upper())
    )
    cols = cur.fetchall()
    cur.close(); conn.close()
    if not cols:
        return f"Table '{table_name}' introuvable dans le schéma '{SCHEMA}'."
    lines = [f"Table: {SCHEMA}.{table_name}",
             f"{'COLUMN':<40} {'TYPE':<20} {'LEN':>6} {'SCALE':>6} {'NULLABLE':<10} DEFAULT"]
    lines.append("-" * 100)
    for c in cols:
        lines.append(
            f"{c[0]:<40} {c[1]:<20} {str(c[2] or ''):>6} {str(c[3] or ''):>6} {c[4]:<10} {c[5] or ''}"
        )
    return "\n".join(lines)


@mcp.tool()
def execute_query(sql: str, max_rows: int = 500) -> str:
    """
    Exécute une requête SELECT sur le schéma HANA et retourne les résultats en JSON.
    Seules les requêtes SELECT sont autorisées (sécurité read-only).
    Paramètre max_rows: limite le nombre de lignes retournées (défaut 500).
    """
    if not sql.strip().upper().startswith("SELECT"):
        return "Erreur: seules les requêtes SELECT sont autorisées."
    conn = connect()
    cur = conn.cursor()
    cur.execute(sql)
    rows = cur.fetchmany(max_rows)
    col_names = [d[0] for d in cur.description]
    cur.close(); conn.close()
    records = []
    for row in rows:
        records.append({
            col_names[i]: (v if not hasattr(v, "isoformat") else v.isoformat())
            for i, v in enumerate(row)
        })
    return json.dumps(records, ensure_ascii=False, indent=2)


@mcp.tool()
def count_rows(table_name: str, where_clause: str = "") -> str:
    """
    Retourne le nombre de lignes dans une table, avec filtre optionnel.
    Paramètre where_clause: condition SQL sans le mot-clé WHERE (ex: "STATUS = 'OPEN'").
    """
    sql = f'SELECT COUNT(*) FROM "{SCHEMA}"."{table_name}"'
    if where_clause.strip():
        sql += f" WHERE {where_clause}"
    conn = connect()
    cur = conn.cursor()
    cur.execute(sql)
    count = cur.fetchone()[0]
    cur.close(); conn.close()
    return str(count)


@mcp.tool()
def get_schema_overview() -> str:
    """
    Vue d'ensemble du schéma : liste des tables avec nombre de colonnes et nombre de lignes.
    Utile pour comprendre rapidement la structure du schéma BDC assessment.
    """
    conn = connect()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT T.TABLE_NAME, COUNT(C.COLUMN_NAME) AS COL_COUNT
        FROM SYS.TABLES T
        LEFT JOIN SYS.TABLE_COLUMNS C
          ON T.TABLE_NAME = C.TABLE_NAME AND T.SCHEMA_NAME = C.SCHEMA_NAME
        WHERE T.SCHEMA_NAME = ?
        GROUP BY T.TABLE_NAME
        ORDER BY T.TABLE_NAME
        """,
        (SCHEMA,)
    )
    tables = cur.fetchall()
    lines = [f"Schéma: {SCHEMA}",
             f"{'TABLE':<50} {'COLONNES':>10} {'LIGNES':>10}", "-" * 75]
    for (tname, ncols) in tables:
        try:
            cur.execute(f'SELECT COUNT(*) FROM "{SCHEMA}"."{tname}"')
            nrows = cur.fetchone()[0]
        except Exception:
            nrows = "?"
        lines.append(f"{tname:<50} {ncols:>10} {str(nrows):>10}")
    cur.close(); conn.close()
    return "\n".join(lines)


# ── Startup ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    server_port = int(os.getenv("PORT", os.getenv("MCP_PORT", "8000")))
    on_cf = "VCAP_APPLICATION" in os.environ

    print(f"[HANA MCP] Mode: {'BTP Cloud Foundry' if on_cf else 'local'} — port {server_port}")
    print(f"[HANA MCP] Schema: {SCHEMA} @ {HOST}:{HANA_PORT}")

    app_url = _get_app_url()
    print(f"[HANA MCP] OAuth2 server : {app_url}")
    print(f"[HANA MCP] MCP endpoint  : {app_url}/mcp")
    print(f"[HANA MCP] Auth discovery: {app_url}/.well-known/oauth-authorization-server")

    try:
        _creds_check = _load_uaa_credentials()
        print(f"[HANA MCP] XSUAA backend : {_creds_check['url']}")
    except RuntimeError as exc:
        print(f"[HANA MCP] XSUAA error   : {exc}")

    asgi_app = mcp.streamable_http_app()
    asgi_app = OAuth2Middleware(asgi_app)

    uvicorn.run(asgi_app, host="0.0.0.0", port=server_port)
