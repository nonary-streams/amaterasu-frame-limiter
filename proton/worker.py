"""Private worker for bounded Proton-hook setup and stream policy ownership.

The owning module communicates using one JSON object per line. Closing stdin
retires the policy; the short expiry also fences a killed or stalled worker.
"""

import json
from collections import OrderedDict
import os
from pathlib import Path
import select
import socket
import struct
import sys
import time

import discovery
import install_hook
import amaterasu_limiter
from policy_store import PolicyStore


_MAX_MESSAGE = 65536
_REFRESH_SECONDS = 15
_MAX_COMPLETED = 256


def _serve_launch(connection, store):
    with connection:
        try:
            _, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != os.getuid():
                return
            request = amaterasu_limiter.read_message(connection, 512, 0.15)
            if (not isinstance(request, dict) or set(request) != {"version", "app_id"}
                    or request["version"] != 1):
                return
            app_id = request["app_id"]
            if app_id is not None and (not isinstance(app_id, str) or not app_id.isascii()
                                       or not app_id.isdigit() or len(app_id) > 10):
                return
            policy = store.for_application(app_id)
            connection.sendall(json.dumps({"version": 1, "policy": policy}, separators=(",", ":")).encode() + b"\n")
        except (OSError, ValueError, TypeError):
            return


def _reply(request_id, ok, **fields):
    message = {"id": request_id, "ok": ok, **fields}
    sys.stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def _handle(line, store, helper_source, completed):
    request = None
    try:
        request = json.loads(line)
        if (not isinstance(request, dict) or type(request.get("id")) is not int
                or not 1 <= request["id"] <= (1 << 53) - 1):
            raise ValueError("invalid request")
        request_id = request["id"]
        if request_id in completed:
            previous, response = completed[request_id]
            if previous != request:
                _reply(request_id, False, error="operation_id_conflict")
            else:
                _reply(request_id, **response)
            return True

        def complete(ok, **fields):
            response = {"ok": ok, **fields}
            completed[request_id] = (request, response)
            if len(completed) > _MAX_COMPLETED:
                completed.popitem(last=False)
            _reply(request_id, **response)

        operation = request.get("operation")
        if operation == "set" and set(request) == {"id", "operation", "session", "expected_revision", "revision", "policy"}:
            store.set(request["session"], request["expected_revision"], request["revision"], request["policy"])
            complete(True, state="stored")
        elif operation == "remove" and set(request) == {"id", "operation", "session", "expected_revision"}:
            store.remove(request["session"], request["expected_revision"])
            complete(True, state="removed")
        elif operation == "install" and set(request) == {"id", "operation", "tool"}:
            tool = request["tool"]
            if not isinstance(tool, str) or not Path(tool).is_absolute() or len(tool) > 4096:
                raise ValueError("invalid tool path")
            install_hook.install(tool, helper_source)
            complete(True, state="installed")
        elif operation == "discover" and set(request) == {"id", "operation", "roots"}:
            tools, diagnostics = discovery.discover(request["roots"])
            complete(True, tools=tools, diagnostics=diagnostics)
        elif operation == "close" and set(request) == {"id", "operation"}:
            complete(True, state="closed")
            return False
        else:
            raise ValueError("invalid operation")
    except (OSError, ValueError, TypeError, KeyError, SyntaxError) as error:
        request_id = request.get("id") if isinstance(request, dict) else None
        if type(request_id) is int and 1 <= request_id <= (1 << 53) - 1:
            # Mutation failures can be uncertain; do not replay them under the
            # same operation ID. The caller must resolve or retire the worker.
            response = {"ok": False, "error": type(error).__name__, "outcome": "unknown"}
            completed[request_id] = (request, response)
            if len(completed) > _MAX_COMPLETED:
                completed.popitem(last=False)
            _reply(request_id, **response)
        else:
            _reply(None, False, error=type(error).__name__)
    return True


def run(runtime_root, helper_source, owner_id="standalone", expected_policies=None):
    with PolicyStore(runtime_root, owner_id, expected_policies) as store, socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(amaterasu_limiter.policy_address(runtime_root))
        listener.listen(4)
        listener.setblocking(False)
        # An acquired lock and matching durable owner ID identify our stale file.
        # Retire it before announcing readiness; never revive old launch policy.
        store.refresh()
        _reply(None, True, state="ready")
        refresh_at = time.monotonic() + _REFRESH_SECONDS
        buffered = bytearray()
        completed = OrderedDict()
        while True:
            if time.monotonic() >= refresh_at:
                store.refresh()
                refresh_at = time.monotonic() + _REFRESH_SECONDS
            timeout = max(0, refresh_at - time.monotonic())
            readable, _, _ = select.select([sys.stdin.buffer, listener], [], [], timeout)
            if not readable:
                store.refresh()
                refresh_at = time.monotonic() + _REFRESH_SECONDS
                continue
            if sys.stdin.buffer not in readable:
                if listener in readable:
                    try:
                        connection, _ = listener.accept()
                    except BlockingIOError:
                        continue
                    _serve_launch(connection, store)
                continue
            chunk = os.read(sys.stdin.fileno(), _MAX_MESSAGE + 1)
            if not chunk:
                return
            buffered.extend(chunk)
            while b"\n" in buffered:
                end = buffered.index(b"\n")
                if end > _MAX_MESSAGE:
                    raise ValueError("input frame too large")
                line = bytes(buffered[:end])
                del buffered[:end + 1]
                if not _handle(line, store, helper_source, completed):
                    return
            if len(buffered) > _MAX_MESSAGE:
                raise ValueError("input frame too large")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("a runtime root is required")
    helper = Path(__file__).with_name("amaterasu_limiter.py").read_bytes()
    try:
        run(sys.argv[1], helper)
    except (OSError, ValueError) as error:
        _reply(None, False, error=type(error).__name__)
        raise SystemExit(1)
