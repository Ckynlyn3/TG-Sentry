"""Local unit tests: stdlib only, local HTTP fixture, no network egress."""
import hashlib
import importlib.util
import json
import os
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

# Load the sibling plugin module by path: the directory is not a package name.
_spec = importlib.util.spec_from_file_location(
    "tg_sentry_hermes_plugin", os.path.join(os.path.dirname(os.path.abspath(__file__)), "__init__.py"))
plugin = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(plugin)

GENERIC = "TG-Sentry: review denied or unavailable; tool blocked."


def review_id(instance_id, call_id):
    return hashlib.sha256((instance_id + "\0" + call_id).encode()).hexdigest()


class Fixture:
    """Scripted decision service; records every request."""

    def __init__(self):
        self.requests = []
        self.mode = "approve"
        self.pending_polls = 0
        self.always_pending = False
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def _reply(self, code, body, headers=None):
                data = body.encode() if isinstance(body, str) else body
                self.send_response(code)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)

            def _trickle(self, first, chunks=40, delay=0.25):
                """Slow-drip a response; the client is expected to hang up first."""
                try:
                    self.wfile.write(first)
                    self.wfile.flush()
                    for _ in range(chunks):
                        self.wfile.write(b" ")
                        self.wfile.flush()
                        time.sleep(delay)
                except OSError:
                    pass
                self.close_connection = True

            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("content-length") or 0))
                body = json.loads(raw) if raw else None
                fixture.requests.append({"path": self.path, "body": body,
                                         "auth": self.headers.get("authorization")})
                fixture._respond(self, body)

            def do_GET(self):
                fixture.requests.append({"path": self.path, "body": None,
                                         "auth": self.headers.get("authorization")})
                fixture._respond(self, None)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.endpoint = "http://127.0.0.1:%d" % self.server.server_address[1]

    def _decision(self, call_id, instance_id, decision, **over):
        payload = {
            "id": review_id(instance_id, call_id),
            "decision": decision,
            "comment": "fixture decision",
            "ruleId": "fixture-rule",
            "execution": "awaiting_execution",
            # Fractional seconds + Z, exactly as Go marshals time.Time.
            "deadline": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() + 60)) + ".818593777Z",
        }
        if decision == "pending":
            del payload["comment"], payload["ruleId"], payload["execution"]
        payload.update(over)
        return {k: v for k, v in payload.items() if v is not None}

    def _respond(self, handler, body):
        mode = self.mode
        if mode == "http":
            handler._reply(503, "{}")
            return
        if mode == "malformed":
            handler._reply(200, "{")
            return
        if mode == "oversized":
            handler._reply(200, '{"pad":"' + "x" * (2 << 20) + '"}')
            return
        if mode == "slow":
            time.sleep(8)
            return
        if mode == "trickle":
            # Body framing sent at once, body bytes dripped afterwards: nothing
            # may advance past the single total budget.
            handler._trickle(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n"
                             b"content-length: 1000\r\n\r\n")
            return
        if mode == "chunk-trickle":
            # Same total budget across chunk framing: one small chunk per tick,
            # never the terminating zero-length chunk.
            try:
                handler.wfile.write(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n")
                handler.wfile.flush()
                for _ in range(40):
                    handler.wfile.write(b"1\r\n \r\n")
                    handler.wfile.flush()
                    time.sleep(0.25)
            except OSError:
                pass
            handler.close_connection = True
            return
        if mode == "header-trickle":
            # One header line around every budget tick: header parsing must be
            # deadline-bound too, not only body reads.
            handler.wfile.write(b"HTTP/1.1 200 OK\r\n")
            handler.wfile.flush()
            for _ in range(40):
                try:
                    handler.wfile.write(b"x-pad: " + b"y" * 16 + b"\r\n")
                    handler.wfile.flush()
                except OSError:
                    return
                time.sleep(0.25)
            return
        if mode == "short-body" and handler.path == "/api/v1/reviews":
            # A complete, otherwise valid approve verdict advertised with a much
            # larger Content-Length, then an early hang-up: the body is
            # incomplete, so nothing in it may be accepted.
            payload = json.dumps(self._decision(body["callId"], body["instanceId"], "approve")).encode()
            handler.send_response(200)
            handler.send_header("content-type", "application/json")
            handler.send_header("content-length", str(len(payload) + 4096))
            handler.end_headers()
            handler.wfile.write(payload)
            handler.wfile.flush()
            handler.close_connection = True
            return
        if mode == "connection-close" and handler.path == "/api/v1/reviews":
            # http.client closes conn.sock inside getresponse() for this one.
            handler._reply(200, json.dumps(self._decision(
                body["callId"], body["instanceId"], "approve")), headers={"connection": "close"})
            return
        if handler.path == "/api/v1/instances":
            handler._reply(200, "{}")
            return
        if body is None:
            # Poll echo: the review id is the URL segment (adapter/reviews.go id).
            handler._reply(200, json.dumps(self._decision("", "", "pending" if self.always_pending else "approve",
                                                          id=handler.path.split("/")[4].split("?")[0])))
            return
        instance_id = body["instanceId"]
        call_id = body["callId"]
        if mode == "pending":
            self.pending_polls -= 1
            kind = "pending" if self.always_pending or self.pending_polls > 0 else "approve"
            handler._reply(200, json.dumps(self._decision(call_id, instance_id, kind)))
            return
        # Every mutation starts from a valid approve verdict and changes exactly
        # one field, so each case reaches the check it is named for. "reject" is
        # a real verdict, not a mutation.
        decision = "reject" if mode == "reject" else "approve"
        over = {}
        if mode == "wrong-id":
            over["id"] = "other"
        elif mode == "unknown":
            over["decision"] = "allow"
        elif mode == "no-rule":
            over["ruleId"] = ""
        elif mode == "no-comment":
            over["comment"] = ""
        elif mode == "replayed":
            over["execution"] = "blocked"
        elif mode == "expired":
            over["deadline"] = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - 60)) + ".5Z"
        decision = over.pop("decision", decision)
        handler._reply(200, json.dumps(self._decision(call_id, instance_id, decision, **over)))

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def register(target, token="fixture-not-secret", **extra):
    """Register against `target`; the returned hook runs with that env applied."""
    env = {"TG_SENTRY_ENDPOINT": target, "TG_SENTRY_HOOK_TOKEN": token,
           "TG_SENTRY_NODE_ID": ""}
    env.update(extra)
    env = {k: v for k, v in env.items() if v != "" or k not in
           ("TG_SENTRY_ENDPOINT", "TG_SENTRY_HOOK_TOKEN")}
    hooks = {}

    def hook(**kwargs):
        with mock.patch.dict(os.environ, env, clear=False):
            for key in ("TG_SENTRY_NODE_ID",):
                if key not in env:
                    os.environ.pop(key, None)
            return hooks["pre_tool_call"](**kwargs)

    ctx = mock.Mock()
    ctx.register_hook = lambda name, cb: hooks.setdefault(name, cb)
    plugin.register(ctx)
    return {"pre_tool_call": hook}


class PluginTest(unittest.TestCase):
    def setUp(self):
        self.fx = Fixture()
        self.addCleanup(self.fx.close)
        self.cwd = os.path.realpath(os.getcwd())

    def hook(self, **env):
        return register(env.pop("endpoint", self.fx.endpoint), **env)["pre_tool_call"]

    def call(self, hook, **kwargs):
        payload = {"tool_name": "terminal", "args": {"command": "printf BENIGN_MARKER"},
                   "session_id": "session-fixture", "tool_call_id": "call-fixture",
                   "task_id": "task-fixture"}
        payload.update(kwargs)
        return hook(**payload)

    def test_approve_passes_and_uses_existing_http_contract(self):
        hook = self.hook()
        self.assertIsNone(self.call(hook))
        paths = [r["path"] for r in self.fx.requests]
        self.assertEqual(paths[0], "/api/v1/instances")
        self.assertEqual(paths[1], "/api/v1/reviews")
        self.assertEqual(self.fx.requests[0]["body"]["agent"], "hermes")
        self.assertEqual(self.fx.requests[1]["body"]["argumentsObj"], {"command": "printf BENIGN_MARKER"})
        self.assertEqual(self.fx.requests[1]["body"]["toolName"], "terminal")
        self.assertEqual(self.fx.requests[1]["auth"], "Bearer fixture-not-secret")
        self.assertEqual(self.fx.requests[0]["body"]["cwd"], self.cwd)

    def test_reject_blocks_with_service_comment(self):
        self.fx.mode = "reject"
        result = self.call(self.hook())
        self.assertEqual(result, {"action": "block", "message": "TG-Sentry: fixture decision"})

    def test_pending_polls_then_approves(self):
        self.fx.mode = "pending"
        self.fx.pending_polls = 2
        self.assertIsNone(self.call(self.hook()))
        polls = [r["path"] for r in self.fx.requests][2:]
        self.assertEqual(len(polls), 1)
        self.assertRegex(polls[0], r"^/api/v1/reviews/[0-9a-f]{64}\?instanceId=[0-9a-f]{64}$")
        self.assertEqual(self.fx.requests[1]["body"]["callId"], "call-fixture")

    def test_pending_blocks_at_deadline(self):
        self.fx.mode = "pending"
        self.fx.pending_polls = 10 ** 6
        self.fx.always_pending = True
        started = time.monotonic()
        self.assertEqual(self.call(self.hook()), {"action": "block", "message": GENERIC})
        self.assertLess(time.monotonic() - started, 7)

    def test_every_bad_decision_blocks_generically_and_leaks_nothing(self):
        for mode in ["malformed", "wrong-id", "unknown", "no-rule",
                     "no-comment", "replayed", "expired", "http", "oversized"]:
            with self.subTest(mode=mode):
                self.fx.mode = mode
                self.fx.requests.clear()
                result = self.call(self.hook())
                self.assertEqual(result, {"action": "block", "message": GENERIC})

    def test_oversized_and_trickled_bodies_stay_inside_one_budget(self):
        for mode in ["oversized", "trickle"]:
            with self.subTest(mode=mode):
                self.fx.mode = mode
                started = time.monotonic()
                result = self.call(self.hook())
                elapsed = time.monotonic() - started
                self.assertEqual(result, {"action": "block", "message": GENERIC})
                self.assertLess(elapsed, 7)
                message = json.dumps(result)
                for secret in ["127.0.0.1", "fixture-not-secret", "BENIGN_MARKER"]:
                    self.assertNotIn(secret, message)

    def test_header_and_chunk_trickle_stay_inside_the_same_budget(self):
        # The socket timeout must be re-armed from the remaining budget before
        # every recv, so header parsing and chunk framing cannot outlast it.
        # The fixture drips for ~10 s; only the deadline can end these calls.
        for mode in ["header-trickle", "chunk-trickle"]:
            with self.subTest(mode=mode):
                self.fx.mode = mode
                started = time.monotonic()
                result = self.call(self.hook())
                elapsed = time.monotonic() - started
                self.assertEqual(result, {"action": "block", "message": GENERIC})
                # Local test scheduling allowance of 1 s, taken from
                # internal/core/claude_install_test.go:229.
                self.assertLess(elapsed, plugin.BUDGET_MS / 1000 + 1)
                self.assertIn("TG-Sentry", result["message"])

    def test_short_body_with_overstated_content_length_blocks(self):
        # Premature EOF: the prefix is a fully valid approve verdict, but the
        # advertised Content-Length was not delivered, so it must be rejected
        # (RFC 9112 section 6.3 / http.client IncompleteRead).
        self.fx.mode = "short-body"
        self.assertEqual(self.call(self.hook()), {"action": "block", "message": GENERIC})

    def test_connection_close_response_is_accepted(self):
        # http.client clears conn.sock inside getresponse() when the service
        # answers with Connection: close, RFC 9112 section 9.6. The adapter must
        # keep its own handle on the response socket instead.
        self.fx.mode = "connection-close"
        self.assertIsNone(self.call(self.hook()))

    def test_slow_service_blocks(self):
        self.fx.mode = "slow"
        started = time.monotonic()
        self.assertEqual(self.call(self.hook()), {"action": "block", "message": GENERIC})
        self.assertLess(time.monotonic() - started, 7)

    def test_missing_identity_or_unsafe_configuration_blocks(self):
        hook = self.hook()
        self.assertEqual(self.call(hook, tool_call_id=""), {"action": "block", "message": GENERIC})
        self.assertEqual(self.call(hook, tool_name=""), {"action": "block", "message": GENERIC})
        self.assertEqual(self.call(hook, args="not-a-dict"), {"action": "block", "message": GENERIC})
        self.assertEqual(self.call(hook, session_id="", task_id=""), {"action": "block", "message": GENERIC})
        for endpoint in ["https://remote.invalid", self.fx.endpoint + "/path", "ftp://127.0.0.1"]:
            with self.subTest(endpoint=endpoint):
                self.assertEqual(self.call(self.hook(endpoint=endpoint)), {"action": "block", "message": GENERIC})
        self.assertEqual(self.call(register(self.fx.endpoint, token="")["pre_tool_call"]),
                         {"action": "block", "message": GENERIC})
        self.assertEqual(self.call(self.hook(TG_SENTRY_NODE_ID="not-hex")),
                         {"action": "block", "message": GENERIC})

    def test_omitted_port_uses_scheme_default(self):
        for url, want in (("http://svc.invalid/", 80), ("https://svc.invalid/", 443)):
            with mock.patch.object(plugin.socket, "create_connection",
                                   side_effect=OSError("stop")) as dial:
                with self.assertRaises(OSError):
                    plugin._connect(plugin.urllib.parse.urlsplit(url), plugin._Budget())
            self.assertEqual(dial.call_args.args[0], ("svc.invalid", want))

    def test_service_down_blocks(self):
        self.assertEqual(self.call(register("http://127.0.0.1:1")["pre_tool_call"]),
                         {"action": "block", "message": GENERIC})

    def test_redirect_is_not_followed(self):
        class Redirect(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                self.send_response(307)
                self.send_header("location", "http://127.0.0.1:1/")
                self.send_header("content-length", "0")
                self.end_headers()

        server = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        endpoint = "http://127.0.0.1:%d" % server.server_address[1]
        self.assertEqual(self.call(register(endpoint)["pre_tool_call"]),
                         {"action": "block", "message": GENERIC})


if __name__ == "__main__":
    unittest.main()
