"""
Minimal Kalshi HTTP + WebSocket clients.

This module is intentionally small and matches the imports used by the user's
script:

  from clients import KalshiHttpClient, KalshiWebSocketClient, Environment

Kalshi authentication (headers + RSA signature) can vary slightly between API
versions. This implementation follows the common pattern:
  - timestamp + METHOD + path + body (UTF-8)
  - RSA-PSS + SHA256
  - base64-encoded signature

If Kalshi returns auth errors, adjust `_signing_payload()` and/or header names
to match the current Kalshi docs.
"""

from __future__ import annotations

import asyncio
import base64
import json
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Optional

import requests
import websocket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


class Environment(str, Enum):
    DEMO = "DEMO"
    PROD = "PROD"

    @property
    def http_base_url(self) -> str:
        # Common Kalshi endpoints; update if your account uses different hosts.
        if self is Environment.DEMO:
            return "https://demo-api.kalshi.com/trade-api/v2"
        return "https://api.kalshi.com/trade-api/v2"

    @property
    def ws_base_url(self) -> str:
        if self is Environment.DEMO:
            return "wss://demo-api.kalshi.com/trade-api/ws/v2"
        return "wss://api.kalshi.com/trade-api/ws/v2"


@dataclass(frozen=True)
class _AuthHeaders:
    key: str
    signature: str
    timestamp: str

    def as_requests_headers(self) -> dict[str, str]:
        return {
            "KALSHI-ACCESS-KEY": self.key,
            "KALSHI-ACCESS-SIGNATURE": self.signature,
            "KALSHI-ACCESS-TIMESTAMP": self.timestamp,
            "Content-Type": "application/json",
        }

    def as_websocket_headers(self) -> list[str]:
        # websocket-client expects list[str] "Header: value"
        return [
            f"KALSHI-ACCESS-KEY: {self.key}",
            f"KALSHI-ACCESS-SIGNATURE: {self.signature}",
            f"KALSHI-ACCESS-TIMESTAMP: {self.timestamp}",
        ]


class KalshiHttpClient:
    def __init__(self, *, key_id: str, private_key: Any, environment: Environment) -> None:
        if not key_id:
            raise ValueError("key_id is required")
        if private_key is None:
            raise ValueError("private_key is required")

        self.key_id = key_id
        self.private_key = private_key
        self.environment = environment

    def _signing_payload(self, *, timestamp: str, method: str, path: str, body: str) -> bytes:
        # Most Kalshi examples sign: timestamp + method + path + body
        return f"{timestamp}{method.upper()}{path}{body}".encode("utf-8")

    def _auth_headers(self, *, method: str, path: str, body: str = "") -> _AuthHeaders:
        # Using integer seconds is common for API signing; adjust if your docs require ms.
        timestamp = str(int(time.time()))
        payload = self._signing_payload(timestamp=timestamp, method=method, path=path, body=body)
        signature_bytes = self.private_key.sign(
            payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        signature_b64 = base64.b64encode(signature_bytes).decode("ascii")
        return _AuthHeaders(key=self.key_id, signature=signature_b64, timestamp=timestamp)

    def _request(self, method: str, path: str, *, params: Optional[dict[str, Any]] = None, json_body: Any = None) -> Any:
        # `path` should begin with "/" and be relative to trade-api/v2.
        if not path.startswith("/"):
            path = "/" + path

        body_str = ""
        if json_body is not None:
            body_str = json.dumps(json_body, separators=(",", ":"), ensure_ascii=False)

        auth = self._auth_headers(method=method, path=path, body=body_str)
        url = self.environment.http_base_url + path

        resp = requests.request(
            method=method.upper(),
            url=url,
            params=params,
            data=body_str if body_str else None,
            headers=auth.as_requests_headers(),
            timeout=30,
        )

        # Provide actionable errors (Kalshi usually returns JSON, but not always).
        if resp.status_code >= 400:
            raise RuntimeError(f"Kalshi HTTP {resp.status_code} for {method} {path}: {resp.text}")

        content_type = resp.headers.get("Content-Type", "")
        if "application/json" in content_type:
            return resp.json()
        return resp.text

    def get_balance(self) -> Any:
        # Kalshi v2 commonly exposes portfolio balance at this path.
        return self._request("GET", "/portfolio/balance")


class KalshiWebSocketClient:
    def __init__(
        self,
        *,
        key_id: str,
        private_key: Any,
        environment: Environment,
        on_message: Optional[Callable[[str], None]] = None,
    ) -> None:
        if not key_id:
            raise ValueError("key_id is required")
        if private_key is None:
            raise ValueError("private_key is required")

        self.key_id = key_id
        self.private_key = private_key
        self.environment = environment
        self._user_on_message = on_message

        self._ws_app: Optional[websocket.WebSocketApp] = None
        self._thread: Optional[threading.Thread] = None
        self._opened = threading.Event()
        self._closed = threading.Event()
        self._last_error: Optional[BaseException] = None

    def _signing_payload(self, *, timestamp: str, method: str, path: str, body: str) -> bytes:
        return f"{timestamp}{method.upper()}{path}{body}".encode("utf-8")

    def _auth_headers_for_handshake(self, *, ws_path: str) -> _AuthHeaders:
        # For the WS handshake, many APIs sign a GET for the WS path.
        timestamp = str(int(time.time()))
        payload = self._signing_payload(timestamp=timestamp, method="GET", path=ws_path, body="")
        signature_bytes = self.private_key.sign(
            payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        signature_b64 = base64.b64encode(signature_bytes).decode("ascii")
        return _AuthHeaders(key=self.key_id, signature=signature_b64, timestamp=timestamp)

    async def connect(self) -> None:
        """
        Open the WebSocket connection.

        This is an async wrapper around websocket-client (threaded) so callers
        can `asyncio.run(ws_client.connect())` as in the user's script.
        """
        if self._thread and self._thread.is_alive():
            return

        # websocket-client passes only the path portion to signing in many examples.
        # Our ws_base_url already includes `/trade-api/ws/v2`; sign that path.
        ws_path = "/trade-api/ws/v2"
        auth = self._auth_headers_for_handshake(ws_path=ws_path)
        url = self.environment.ws_base_url

        def _on_open(_: websocket.WebSocketApp) -> None:
            self._opened.set()

        def _on_message(_: websocket.WebSocketApp, message: str) -> None:
            if self._user_on_message:
                self._user_on_message(message)

        def _on_error(_: websocket.WebSocketApp, error: Any) -> None:
            if isinstance(error, BaseException):
                self._last_error = error
            else:
                self._last_error = RuntimeError(str(error))

        def _on_close(_: websocket.WebSocketApp, status_code: Any, msg: Any) -> None:
            self._closed.set()

        self._ws_app = websocket.WebSocketApp(
            url,
            header=auth.as_websocket_headers(),
            on_open=_on_open,
            on_message=_on_message,
            on_error=_on_error,
            on_close=_on_close,
        )

        def _run() -> None:
            try:
                # Keepalive settings are conservative; tweak as needed.
                self._ws_app.run_forever(ping_interval=30, ping_timeout=10)
            except BaseException as e:  # noqa: BLE001
                self._last_error = e
                self._closed.set()

        self._thread = threading.Thread(target=_run, name="kalshi-ws", daemon=True)
        self._thread.start()

        # Wait for either open, close, or error.
        await asyncio.to_thread(self._opened.wait, 15)
        if not self._opened.is_set():
            if self._last_error:
                raise RuntimeError(f"WebSocket error before open: {self._last_error}") from self._last_error
            raise TimeoutError("Timed out waiting for WebSocket to open")

    def close(self) -> None:
        if self._ws_app:
            try:
                self._ws_app.close()
            finally:
                self._closed.set()

