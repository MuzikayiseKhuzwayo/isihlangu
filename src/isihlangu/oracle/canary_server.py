"""Out-of-Band (OOB) Canary Server: Deterministic verification of network callbacks."""

import asyncio
import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

from isihlangu.core.types import OOBToken
from isihlangu.storage.database import DatabaseManager


class CanaryManager:
    """Manages creation and verification of cryptographic canary tokens."""

    def __init__(self, db_manager: DatabaseManager, canary_base_url: str) -> None:
        self.db = db_manager
        self.base_url = canary_base_url.rstrip("/")

    async def generate_token(
        self, session_id: str, expected_type: str, target_component: str
    ) -> OOBToken:
        """Generates a cryptographic UUID token, registers it in the datastore, and returns an OOBToken."""
        token_uuid = str(uuid.uuid4())
        token = OOBToken(
            token_uuid=token_uuid,
            session_id=session_id,
            expected_type=expected_type,
            target_component=target_component,
        )
        await self.db.insert_canary_token(token)
        return token

    def get_canary_url(self, token: OOBToken) -> str:
        """Returns the full public callback URL for a canary token."""
        return f"{self.base_url}/c/{token.token_uuid}"

    async def verify_callback(self, token_uuid: str) -> bool:
        """Checks if a callback has been recorded for the token."""
        async with self.db.get_connection() as conn:
            cursor = await conn.execute(
                "SELECT callback_received FROM canary_tokens WHERE token_uuid = ?",
                (token_uuid,),
            )
            row = await cursor.fetchone()
            if row and row["callback_received"] == 1:
                return True
        return False

    async def poll_for_callback(
        self, token_uuid: str, timeout_seconds: float = 3.0, poll_interval: float = 0.25
    ) -> bool:
        """Polls asynchronously for a callback to arrive within a grace period."""
        deadline = asyncio.get_event_loop().time() + timeout_seconds
        while asyncio.get_event_loop().time() < deadline:
            if await self.verify_callback(token_uuid):
                return True
            await asyncio.sleep(poll_interval)
        return False


class CanaryHTTPRequestHandler(BaseHTTPRequestHandler):
    """Handles incoming HTTP callback pings, status queries, and token registrations."""

    db_manager: DatabaseManager | None = None
    loop: asyncio.AbstractEventLoop | None = None

    def do_OPTIONS(self) -> None:
        self.send_response(200)
        self._set_cors_headers()
        self.end_headers()

    def do_GET(self) -> None:
        self._handle_request("GET")

    def do_POST(self) -> None:
        content_len = int(self.headers.get("Content-Length", 0))
        body = (
            self.rfile.read(content_len).decode("utf-8", errors="replace")
            if content_len > 0
            else ""
        )
        self._handle_request("POST", body)

    def _set_cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def _send_json(self, status: int, data: dict) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self._set_cors_headers()
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def _handle_request(self, method: str, body: str = "") -> None:
        path = self.path.split("?")[0]

        # 1. Incoming Canary Callback Ping: /c/<uuid>
        if path.startswith("/c/"):
            token_uuid = path.split("/c/")[1].strip("/")
            client_ip = self.client_address[0]

            if self.db_manager and self.loop:
                asyncio.run_coroutine_threadsafe(
                    self.db_manager.mark_canary_callback(
                        token_uuid=token_uuid,
                        source_ip=client_ip,
                        payload=f"[{method}] {body}".strip(),
                    ),
                    self.loop,
                )

            self._send_json(200, {"status": "registered", "engine": "isihlangu_canary"})

        # 2. Canary Callback Check Status: /canary/check/<uuid>
        elif path.startswith("/canary/check/"):
            token_uuid = path.split("/canary/check/")[1].strip("/")
            if self.db_manager and self.loop:
                future = asyncio.run_coroutine_threadsafe(
                    self.db_manager.get_canary_token(token_uuid), self.loop
                )
                try:
                    token_data = future.result(timeout=2.0)
                    if token_data:
                        self._send_json(200, {"success": True, "token": token_data})
                    else:
                        self._send_json(404, {"success": False, "error": "Token not found"})
                except Exception as e:
                    self._send_json(500, {"success": False, "error": str(e)})
            else:
                self._send_json(500, {"success": False, "error": "Database manager not active"})

        # 3. External Token Registration: /canary/register
        elif path == "/canary/register" and method == "POST":
            try:
                payload = json.loads(body) if body else {}
                token_uuid = payload.get("token_uuid") or str(uuid.uuid4())
                session_id = payload.get("session_id") or "external_session"
                expected_type = payload.get("expected_type") or "ssrf_out_of_band"
                target_component = payload.get("target_component") or "external"

                token = OOBToken(
                    token_uuid=token_uuid,
                    session_id=session_id,
                    expected_type=expected_type,
                    target_component=target_component,
                )

                if self.db_manager and self.loop:
                    future = asyncio.run_coroutine_threadsafe(
                        self.db_manager.insert_canary_token(token), self.loop
                    )
                    future.result(timeout=2.0)
                    self._send_json(200, {"success": True, "token": token.model_dump()})
                else:
                    self._send_json(500, {"success": False, "error": "Database not active"})
            except Exception as e:
                self._send_json(400, {"success": False, "error": str(e)})

        # 4. Service Healthcheck: /health
        elif path == "/health":
            self._send_json(200, {"status": "healthy", "service": "isihlangu_canary"})

        else:
            self._send_json(404, {"error": "Not Found", "path": path})

    def log_message(self, format: str, *args: object) -> None:
        # Suppress noisy stdout logs during execution
        pass


class CanaryServer:
    """Threaded HTTP server for catching out-of-band callbacks and handling status checks."""

    def __init__(self, host: str, port: int, db_manager: DatabaseManager) -> None:
        self.host = host
        self.port = port
        self.db = db_manager
        self.server: HTTPServer | None = None
        self.thread: threading.Thread | None = None

    def start(self, loop: asyncio.AbstractEventLoop | None = None) -> None:
        handler = CanaryHTTPRequestHandler
        handler.db_manager = self.db
        handler.loop = loop or asyncio.get_running_loop()

        self.server = HTTPServer((self.host, self.port), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        if self.server:
            self.server.shutdown()
            self.server.server_close()
