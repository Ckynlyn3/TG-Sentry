"""TG-Sentry Hermes plugin: fail-closed ``pre_tool_call`` review.

Contract reused verbatim from the OpenClaw adapter (adapter/openclaw/index.ts):
``POST /api/v1/instances`` then ``POST /api/v1/reviews`` (``internal/core/types.go``
ReviewInput), poll while ``pending``, accept only a matching, unexpired verdict
(``internal/core/reviews.go``). Hermes hook payload and return values:
hermes_cli/plugins.py@v0.22.2:1970-2030 (``{"action": "block", "message"}``).

Upstream reference: github.com/NousResearch/hermes-agent v0.22.2, MIT.
Standard library only; no network or credential I/O at registration time.
"""

from __future__ import annotations

import datetime
import hashlib
import http.client
import ipaddress
import json
import os
import platform
import re
import socket
import ssl
import sys
import time
import urllib.parse

ID = "tg-sentry"

# Budgets are in-repo precedents, not new numbers:
# adapter/index.ts (5 s HTTP deadline), internal/bridge/bridge.go (500 ms poll,
# 2 MiB JSON limit). The Hermes hook itself is bounded by the upstream
# plugins.hook_callback_timeout default of 30 s, so 5 s sits well below it.
BUDGET_MS = 5000
POLL_SECONDS = 0.5
MAX_BYTES = 2 << 20

GENERIC = "TG-Sentry: review denied or unavailable; tool blocked."


def _hash(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode()).hexdigest()


def _loopback(host: str) -> bool:
    """Same rule as adapter/index.ts isLoopbackHost (loopback addresses only)."""
    value = host.strip("[]").lower()
    if value == "localhost":
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def _settings() -> tuple[str, str, str | None]:
    endpoint = os.environ.get("TG_SENTRY_ENDPOINT", "")
    token = os.environ.get("TG_SENTRY_HOOK_TOKEN", "")
    node_id = os.environ.get("TG_SENTRY_NODE_ID") or None
    if not token.strip():
        raise ValueError("missing token")
    url = urllib.parse.urlsplit(endpoint)
    if (url.username or url.password or url.query or url.fragment
            or url.path not in ("", "/") or not url.hostname):
        raise ValueError("invalid endpoint")
    if url.scheme != "https" and not (url.scheme == "http" and _loopback(url.hostname)):
        raise ValueError("invalid endpoint")
    if node_id is not None and not re.fullmatch(r"[a-f0-9]{32}", node_id):
        raise ValueError("invalid node identity")
    return endpoint.rstrip("/"), token, node_id


def _platform() -> str:
    return {"darwin": "darwin", "win32": "windows"}.get(sys.platform, platform.system().lower())


class _Budget:
    """One monotonic total budget across every request, read and poll."""

    def __init__(self, ms: int = BUDGET_MS) -> None:
        self.deadline = time.monotonic() + ms / 1000

    def remaining(self) -> float:
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("decision budget exhausted")
        return left


class _DeadlineSocket:
    """Socket mixin: every recv/send timeout is the remaining total budget.

    http.client arms a socket timeout only when the connection is opened, so a
    service that drips header lines or chunk framing slower than that timeout
    never trips it and outlasts the deadline (RFC 9112 section 6.3 puts no bound
    on a peer's send rate). Re-arming before each syscall makes the absolute
    monotonic deadline hold wherever the peer stalls. ``recv_into``/``recv`` are
    the calls ``socket.SocketIO``, and therefore ``HTTPResponse.fp``, makes.
    """

    budget: _Budget

    def _arm(self) -> None:
        socket.socket.settimeout(self, self.budget.remaining())  # type: ignore[arg-type]

    def recv(self, *args: object) -> bytes:
        self._arm()
        return super().recv(*args)  # type: ignore[misc]

    def recv_into(self, *args: object) -> int:
        self._arm()
        return super().recv_into(*args)  # type: ignore[misc]

    def sendall(self, *args: object) -> None:
        self._arm()
        return super().sendall(*args)  # type: ignore[misc]


class _DeadlinePlain(_DeadlineSocket, socket.socket):
    pass


class _DeadlineTLS(_DeadlineSocket, ssl.SSLSocket):
    pass


def _connect(endpoint: urllib.parse.SplitResult, budget: _Budget) -> socket.socket:
    """Connect with the deadline armed on whichever socket type we end up with."""
    host = endpoint.hostname
    # An omitted port takes the scheme default, as http.client does (HTTP_PORT/HTTPS_PORT).
    default = http.client.HTTPS_PORT if endpoint.scheme == "https" else http.client.HTTP_PORT
    port = endpoint.port or default
    plain = socket.create_connection((host, port), budget.remaining())
    sock: socket.socket = _DeadlinePlain(fileno=plain.detach())
    sock.settimeout(budget.remaining())
    if endpoint.scheme == "https":
        context = ssl.create_default_context()
        # Documented factory hook for the per-connection TLS socket type:
        # docs.python.org/3/library/ssl.html#ssl.SSLContext.sslsocket_class
        context.sslsocket_class = _DeadlineTLS
        sock = context.wrap_socket(sock, server_hostname=host)
    sock.budget = budget  # type: ignore[attr-defined]
    return sock


def _request(endpoint: str, token: str, path: str, budget: _Budget, body: dict | None = None) -> object:
    url = urllib.parse.urlsplit(endpoint)
    conn = (http.client.HTTPSConnection if url.scheme == "https" else http.client.HTTPConnection)(
        url.hostname, url.port, timeout=budget.remaining())
    response = None
    try:
        # Own the socket rather than letting the connection open it: a
        # "Connection: close" response clears conn.sock inside getresponse()
        # (stdlib http.client, RFC 9112 section 9.6), which must not cost us
        # timeout control or the connection close.
        conn.sock = _connect(url, budget)
        headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
        payload = None if body is None else json.dumps(body)
        conn.request("GET" if body is None else "POST", "/api/v1" + path, payload, headers)
        response = conn.getresponse()
        # No redirect following: any 3xx is a failed decision.
        if response.status != 200:
            raise ValueError("decision service unavailable")
        chunks, size = [], 0
        while True:
            # read1: one underlying recv per call so a trickled body cannot
            # outlast the total budget (a plain read() loops per-recv).
            chunk = response.read1(65536)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_BYTES:
                raise ValueError("oversized decision")
            chunks.append(chunk)
        # Premature EOF: http.client leaves the unread byte count in `length`
        # when a Content-Length body ends early, and raises IncompleteRead for
        # truncated chunked framing (RFC 9112 section 6.3). An incomplete body
        # must never be parsed, however valid its prefix looks.
        if response.length not in (None, 0):
            raise ValueError("incomplete decision")
        budget.remaining()
        return json.loads(b"".join(chunks).decode("utf-8"))
    except http.client.IncompleteRead as error:
        raise ValueError("incomplete decision") from error
    finally:
        if response is not None:
            response.close()
        conn.close()




def _verdict(value: object, expected_id: str) -> dict:
    if not isinstance(value, dict) or value.get("id") != expected_id:
        raise ValueError("invalid decision")
    decision = value.get("decision")
    if decision not in ("approve", "reject", "pending"):
        raise ValueError("invalid decision")
    deadline = value.get("deadline")
    if not isinstance(deadline, str):
        raise ValueError("invalid decision")
    try:
        # Go marshals time.Time as RFC 3339 with optional fractional seconds
        # (internal/core/types.go Review.Deadline); fromisoformat handles both.
        expires = datetime.datetime.fromisoformat(deadline.replace("Z", "+00:00")).timestamp()
    except ValueError as error:
        raise ValueError("invalid decision") from error
    if time.time() > expires:
        raise ValueError("expired decision")
    if decision != "pending":
        comment, rule_id = value.get("comment"), value.get("ruleId")
        if not (isinstance(comment, str) and comment.strip() and isinstance(rule_id, str) and rule_id):
            raise ValueError("incomplete decision")
        if decision == "approve" and value.get("execution") != "awaiting_execution":
            raise ValueError("replayed decision")
    return value


def review(**kwargs: object) -> dict | None:
    """Return an explicit block, or None to permit. Never raises, never leaks."""
    try:
        endpoint, token, node_id = _settings()
        budget = _Budget()
        tool_name = kwargs.get("tool_name")
        args = kwargs.get("args")
        call_id = kwargs.get("tool_call_id")
        session = kwargs.get("session_id") or kwargs.get("task_id")
        if not (isinstance(tool_name, str) and tool_name and isinstance(args, dict)
                and isinstance(call_id, str) and call_id and isinstance(session, str) and session):
            raise ValueError("missing tool identity")
        cwd = os.path.realpath(os.getcwd())
        if not os.path.isabs(cwd):
            raise ValueError("missing workspace")
        instance_id = _hash(node_id or "", "hermes", session, cwd)
        expected_id = _hash(instance_id, call_id)
        context = json.dumps({key: kwargs.get(key) for key in
                              ("turn_id", "api_request_id", "middleware_trace") if kwargs.get(key)},
                             ensure_ascii=False, default=str)
        _request(endpoint, token, "/instances", budget, {
            "id": instance_id, "agent": "hermes", "sessionId": session, "cwd": cwd,
            "platform": _platform(), "nodeId": node_id, "hookVersion": HOOK_VERSION,
            "connectionMode": "events",
        })
        verdict = _verdict(_request(endpoint, token, "/reviews", budget, {
            "instanceId": instance_id, "callId": call_id, "toolName": tool_name,
            "argumentsObj": args, "scriptCaptureStatus": "not_applicable",
            **({"context": context} if context != "{}" else {}),
        }), expected_id)
        while verdict["decision"] == "pending":
            time.sleep(min(POLL_SECONDS, budget.remaining()))
            verdict = _verdict(_request(
                endpoint, token,
                "/reviews/%s?instanceId=%s" % (expected_id, instance_id), budget), expected_id)
        if verdict["decision"] == "reject":
            return {"action": "block", "message": "TG-Sentry: " + verdict["comment"]}
        # Only an explicit approval permits this call, and only while the total
        # budget still holds: work done after the last response (parsing the
        # verdict) counts too. Native permissions remain either way.
        budget.remaining()
        return None
    except Exception:
        # Never expose service payloads, tool arguments, URLs or bearer tokens.
        return {"action": "block", "message": GENERIC}


# Hook wire protocol version shared with every adapter (internal/core/types.go).
HOOK_VERSION = "0.1.0"


def register(ctx) -> None:
    """Hermes plugin entry point (hermes_cli/plugins.py@v0.22.2 register(ctx))."""
    ctx.register_hook("pre_tool_call", review)
