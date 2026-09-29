"""Out-of-Band (OOB) Canary Server: Deterministic verification of network callbacks."""

import asyncio
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


class CanaryHTTPRequestHandler(BaseHTTPRequestHandler):
    """Handles incoming HTTP callback pings on /c/<uuid>."""

    db_manager: DatabaseManager | None = None
    loop: asyncio.AbstractEventLoop | None = None

    def do_GET(self) -> None:
        self._handle_callback("GET")

    def do_POST(self) -> None:
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len).decode("utf-8", errors="replace") if content_len > 0 else ""
        self._handle_callback("POST", body)

    def _handle_callback(self, method: str, body: str = "") -> None:
        path = self.path
        if path.startswith("/c/"):
            token_uuid = path.split("/c/")[1].split("?")[0].strip("/")
            client_ip = self.client_address[0]

            if self.db_manager and self.loop:
                asyncio.run_coroutine_threadsafe(
                    self.db_manager.mark_canary_callback(
                        token_uuid=token_uuid,
                        source_ip=client_ip,
                        payload=f"[{method}] {body}",
                    ),
                    self.loop,
                )

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"registered","engine":"isihlangu_canary"}')
        elif path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"healthy","service":"isihlangu_canary"}')
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        # Suppress noisy stdout logs during test execution
        pass


class CanaryServer:
    """Threaded HTTP server for catching out-of-band callbacks."""

    def __init__(self, host: str, port: int, db_manager: DatabaseManager) -> None:
        self.host = host
        self.port = port
        self.db = db_manager
        self.server: HTTPServer | None = None
        self.thread: threading.Thread | None = None

    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        handler = CanaryHTTPRequestHandler
        handler.db_manager = self.db
        handler.loop = loop

        self.server = HTTPServer((self.host, self.port), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        if self.server:
            self.server.shutdown()
            self.server.server_close()
