"""
HANA MCP Server — BDC Assessment
---------------------------------
Expose ton schéma HANA comme un MCP Server HTTP/SSE.

Modes de déploiement:
  Local  → http://localhost:8000/sse  (configure via .env)
  BTP CF → https://<app>.cfapps.<region>.hana.ondemand.com/sse
             (configure via `cf set-env`, PORT injecté automatiquement par CF)

Usage local:
    python hana_mcp_server.py

Sécurité:
    XSUAA OAuth2 — chaque appel doit présenter un JWT valide émis par SAP ID Service.
    Authorization: Bearer <xsuaa-jwt>
    Seuls les utilisateurs avec le rôle HanaMcpAccess (scope .access) sont autorisés.
"""

import os
import json
import asyncio
import logging
from urllib.parse import urlparse

# En local, charge le .env. Sur CF, les env vars sont déjà injectées.
from dotenv import load_dotenv
load_dotenv(override=False)   # override=False : CF env vars ont priorité sur .env

import uvicorn
from mcp.server.fastmcp import FastMCP
import hdbcli.dbapi as hana
from sap import xssec

logger = logging.getLogger(__name__)

# ── Connexion HANA ─────────────────────────────────────────────────────────────
HOST      = os.environ["HANA_HOST"]
HANA_PORT = int(os.getenv("HANA_PORT", "443"))
USER      = os.environ["HANA_USER"]
PASSWORD  = os.environ["HANA_PASSWORD"]
SCHEMA    = os.environ["HANA_SCHEMA"]

def connect():
    return hana.connect(
        address=HOST,
        port=HANA_PORT,
        user=USER,
        password=PASSWORD,
        currentSchema=SCHEMA,
        encrypt=True,
        sslValidateCertificate=False,
    )

# ── Auth middleware (XSUAA JWT validation) ─────────────────────────────────────

def _load_uaa_credentials() -> dict:
    """
    Load XSUAA credentials from VCAP_SERVICES (CF) or individual env vars (local).

    CF: credentials are injected automatically when 'hana-mcp-xsuaa' service is bound.
    Local: set XSUAA_URL, XSUAA_CLIENT_ID, XSUAA_CLIENT_SECRET, XSUAA_APP_NAME
           obtained from: cf service-key hana-mcp-xsuaa local-dev-key
    """
    vcap_raw = os.getenv("VCAP_SERVICES")
    if vcap_raw:
        try:
            vcap = json.loads(vcap_raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"VCAP_SERVICES is not valid JSON: {exc}") from exc

        entries = vcap.get("xsuaa", [])
        if not entries:
            raise RuntimeError(
                "VCAP_SERVICES present but no 'xsuaa' binding found. "
                "Add 'hana-mcp-xsuaa' to services in manifest.yml and run 'cf push'."
            )
        creds = entries[0]["credentials"]
        return {
            "url":             creds["url"],
            "clientid":        creds["clientid"],
            "clientsecret":    creds.get("clientsecret", ""),
            "xsappname":       creds["xsappname"],
            "uaadomain":       creds.get("uaadomain", urlparse(creds["url"]).netloc),
            "verificationkey": creds.get("verificationkey", ""),
            "tenantid":        creds.get("tenantid", ""),
            "identityzone":    creds.get("identityzone", ""),
        }

    # ── Local development ───────────────────────────────────────────────────────
    url           = os.getenv("XSUAA_URL", "")
    client_id     = os.getenv("XSUAA_CLIENT_ID", "")
    client_secret = os.getenv("XSUAA_CLIENT_SECRET", "")
    app_name      = os.getenv("XSUAA_APP_NAME", "")

    if not url or not client_id:
        raise RuntimeError(
            "XSUAA is not configured. On CF: bind the 'hana-mcp-xsuaa' service. "
            "Locally: set XSUAA_URL and XSUAA_CLIENT_ID (see env.example)."
        )

    creds: dict = {
        "url":          url,
        "clientid":     client_id,
        "clientsecret": client_secret,
        "xsappname":    app_name or client_id,
        "uaadomain":    os.getenv("XSUAA_DOMAIN") or urlparse(url).netloc,
    }
    vk = os.getenv("XSUAA_VERIFICATION_KEY", "")
    if vk:
        creds["verificationkey"] = vk
    return creds


async def _send_json(send, status: int, payload: dict, extra_headers: list = []) -> None:
    body = json.dumps(payload).encode("utf-8")
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [
            (b"content-type",   b"application/json; charset=utf-8"),
            (b"content-length", str(len(body)).encode()),
        ] + extra_headers,
    })
    await send({"type": "http.response.body", "body": body, "more_body": False})


async def _send_json_error(send, status: int, message: str) -> None:
    await _send_json(send, status, {"error": message})


class XSUAAMiddleware:
    """
    Pure ASGI middleware — no Starlette dependency.

    On every HTTP/WebSocket request:
      1. Extracts Bearer JWT from the Authorization header.
      2. Validates it via sap-xssec (sync call offloaded to a thread pool).
      3. Checks scope '<xsappname>.access' — only users with HanaMcpAccess role pass.
      4. Rewrites Host header to 'localhost' — required because CF routes requests
         through a reverse proxy with an external hostname, but FastMCP's internal
         TrustedHostMiddleware only allows 'localhost'.
    """

    def __init__(self, app) -> None:
        self.app = app
        self._uaa_credentials: dict | None = None
        self._init_error: str | None = None
        try:
            self._uaa_credentials = _load_uaa_credentials()
        except RuntimeError as exc:
            self._init_error = str(exc)
            logger.critical("XSUAAMiddleware init failed: %s", exc)

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        if self._init_error:
            await _send_json_error(send, 500, f"Auth configuration error: {self._init_error}")
            return

        headers = list(scope.get("headers", []))

        # Serve OAuth2 discovery without auth — Joule uses this to find XSUAA
        if scope["type"] == "http" and scope.get("path") in (
            "/.well-known/oauth-authorization-server",
            "/.well-known/oauth-authorization-server/mcp",
            "/.well-known/openid-configuration",
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource/mcp",
        ):
            uaa_url = self._uaa_credentials["url"].rstrip("/")
            xsappname = self._uaa_credentials["xsappname"]
            path = scope.get("path", "")
            if "oauth-protected-resource" in path:
                # RFC 9470 — tells Joule which auth server protects this resource
                app_url = f"https://{scope['server'][0]}" if scope.get("server") else uaa_url
                payload = {
                    "resource": "https://hana-mcp-bdc-ran.cfapps.eu12.hana.ondemand.com/mcp",
                    "authorization_servers": [uaa_url],
                    "bearer_methods_supported": ["header"],
                    "scopes_supported": [f"{xsappname}.access"],
                }
            else:
                # RFC 8414 — authorization server metadata
                payload = {
                    "issuer":                   uaa_url,
                    "authorization_endpoint":   f"{uaa_url}/oauth/authorize",
                    "token_endpoint":           f"{uaa_url}/oauth/token",
                    "jwks_uri":                 f"{uaa_url}/token_keys",
                    "response_types_supported": ["code"],
                    "grant_types_supported":    ["authorization_code", "client_credentials", "password"],
                    "code_challenge_methods_supported": ["S256"],
                    "scopes_supported":         [f"{xsappname}.access"],
                }
            await _send_json(send, 200, payload,
                             extra_headers=[(b"access-control-allow-origin", b"*")])
            return

        # 1. Extract Bearer JWT
        auth_header = next(
            (v.decode("utf-8", errors="replace") for k, v in headers if k == b"authorization"),
            "",
        )
        if not auth_header.startswith("Bearer "):
            uaa_url = self._uaa_credentials["url"].rstrip("/")
            xsappname = self._uaa_credentials["xsappname"]
            www_auth = (
                f'Bearer realm="{uaa_url}", '
                f'scope="{xsappname}.access", '
                f'error="invalid_token"'
            ).encode()
            body = json.dumps({"error": "Unauthorized: missing or malformed Authorization header. Expected: Authorization: Bearer <xsuaa-jwt>"}).encode("utf-8")
            await send({"type": "http.response.start", "status": 401, "headers": [
                (b"content-type", b"application/json; charset=utf-8"),
                (b"content-length", str(len(body)).encode()),
                (b"www-authenticate", www_auth),
            ]})
            await send({"type": "http.response.body", "body": body, "more_body": False})
            return

        token = auth_header[len("Bearer "):]

        # 2. Validate JWT (sap-xssec is synchronous — run in thread pool)
        try:
            security_ctx = await asyncio.to_thread(
                xssec.create_security_context, token, self._uaa_credentials
            )
        except Exception as exc:
            logger.warning("JWT validation rejected (client=%s): %s", scope.get("client"), exc)
            await _send_json_error(
                send, 401,
                "Unauthorized: JWT is missing, expired, or has an invalid signature.",
            )
            return

        # 3. Scope check — check_local_scope resolves "<xsappname>.access" automatically
        user = security_ctx.get_logon_name() or security_ctx.get_clientid()
        has_access = security_ctx.check_local_scope("access")
        logger.warning(
            "AUTH principal=%s has_access_scope=%s token_scopes=%s",
            user, has_access,
            getattr(security_ctx, 'get_scopes', lambda: 'n/a')(),
        )
        if not has_access:
            logger.warning("JWT valid but scope 'access' missing for principal: %s", user)
            await _send_json_error(
                send, 403,
                "Forbidden: your account lacks the 'HanaMcpAccess' role. "
                "Ask a BTP subaccount admin to assign the HanaMcpAccessCollection role collection.",
            )
            return

        # 4. Allowlist check — ALLOWED_USERS env var overrides role-collection enforcement
        #    Required because BTP shadow users receive scopes regardless of role collections.
        allowed_raw = os.getenv("ALLOWED_USERS", "")
        if allowed_raw.strip():
            allowed = {u.strip().lower() for u in allowed_raw.split(",") if u.strip()}
            if user.lower() not in allowed:
                logger.warning("User %s not in ALLOWED_USERS allowlist", user)
                await _send_json_error(
                    send, 403,
                    f"Forbidden: {user} is not authorised to use this MCP server.",
                )
                return

        # 4. Host header rewrite (CF proxy fix)
        rewritten_headers = [
            (k, b"localhost" if k == b"host" else v)
            for k, v in headers
        ]
        patched_scope = {**scope, "headers": rewritten_headers}

        await self.app(patched_scope, receive, send)

# ── MCP Server ─────────────────────────────────────────────────────────────────
# host="0.0.0.0" : évite que FastMCP auto-active la protection DNS rebinding
# (qui est déclenchée uniquement pour host=127.0.0.1/localhost et bloque les
# connexions depuis un hostname CF/remote).
# La sécurité est assurée par XSUAAMiddleware (JWT validation).
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
        lines.append(f"{c[0]:<40} {c[1]:<20} {str(c[2] or ''):>6} {str(c[3] or ''):>6} {c[4]:<10} {c[5] or ''}")
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
        records.append({col_names[i]: (v if not hasattr(v, 'isoformat') else v.isoformat())
                        for i, v in enumerate(row)})
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
    # Tables + nb colonnes
    cur.execute(
        """
        SELECT T.TABLE_NAME, COUNT(C.COLUMN_NAME) AS COL_COUNT
        FROM SYS.TABLES T
        LEFT JOIN SYS.TABLE_COLUMNS C ON T.TABLE_NAME = C.TABLE_NAME AND T.SCHEMA_NAME = C.SCHEMA_NAME
        WHERE T.SCHEMA_NAME = ?
        GROUP BY T.TABLE_NAME
        ORDER BY T.TABLE_NAME
        """,
        (SCHEMA,)
    )
    tables = cur.fetchall()
    lines = [f"Schéma: {SCHEMA}", f"{'TABLE':<50} {'COLONNES':>10} {'LIGNES':>10}", "-" * 75]
    for (tname, ncols) in tables:
        try:
            cur.execute(f'SELECT COUNT(*) FROM "{SCHEMA}"."{tname}"')
            nrows = cur.fetchone()[0]
        except Exception:
            nrows = "?"
        lines.append(f"{tname:<50} {ncols:>10} {str(nrows):>10}")
    cur.close(); conn.close()
    return "\n".join(lines)


# ── Lancement ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # CF injecte PORT automatiquement ; en local on utilise MCP_PORT (défaut 8000)
    server_port = int(os.getenv("PORT", os.getenv("MCP_PORT", "8000")))

    on_cf = "VCAP_APPLICATION" in os.environ
    if on_cf:
        print(f"[HANA MCP] Mode BTP Cloud Foundry — port {server_port}")
    else:
        print(f"[HANA MCP] Mode local — http://localhost:{server_port}/sse")

    print(f"[HANA MCP] Schéma cible : {SCHEMA} @ {HOST}:{HANA_PORT}")

    try:
        _creds_check = _load_uaa_credentials()
        print(f"[HANA MCP] XSUAA auth     : ACTIVÉ  url={_creds_check['url']}")
        print(f"[HANA MCP] XSUAA app      : {_creds_check['xsappname']}")
    except RuntimeError as _e:
        print(f"[HANA MCP] XSUAA auth     : ERREUR DE CONFIG — {_e}")

    # Récupère l'app ASGI et enveloppe avec le middleware XSUAA
    asgi_app = mcp.streamable_http_app()
    asgi_app = XSUAAMiddleware(asgi_app)

    uvicorn.run(asgi_app, host="0.0.0.0", port=server_port)
