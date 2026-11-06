"""Apply an owned, temporary stream policy from Proton's user_settings hook.

The file contains no persistent FPS setting. A policy is usable only while its
owner process and short-lived state are both valid. An invalid or missing state
must never prevent Proton from starting.
"""

import atexit
import json
import hashlib
import os
from pathlib import Path
import socket
import shutil
import stat
import struct
import sys
import tempfile
import time


_SHIM = "/usr/$LIB/mangohud/libMangoHud_shim.so"
_MAX_STATE = 16384


def policy_address(runtime_root):
    """A per-user, per-runtime abstract socket survives Steam's mount boundary."""
    identity = hashlib.sha256(os.fsencode(runtime_root)).hexdigest()[:24]
    return "\0amaterasu.frame-limiter.v1." + str(os.getuid()) + "." + identity


def read_message(connection, limit, timeout):
    deadline = time.monotonic() + timeout
    message = bytearray()
    while b"\n" not in message:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or len(message) > limit:
            raise ValueError("policy message exceeded its budget")
        connection.settimeout(remaining)
        chunk = connection.recv(min(4096, limit + 1 - len(message)))
        if not chunk:
            raise ValueError("incomplete policy message")
        message.extend(chunk)
    if len(message) > limit or message.count(b"\n") != 1 or message[-1] != 10:
        raise ValueError("invalid policy message")
    return json.loads(message)


def _request_policy(runtime_root, app_id):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(0.2)
        connection.connect(policy_address(runtime_root))
        _, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != os.getuid():
            raise ValueError("policy peer belongs to another user")
        connection.sendall(json.dumps({"version": 1, "app_id": app_id}).encode() + b"\n")
        reply = read_message(connection, _MAX_STATE, 0.2)
    if not isinstance(reply, dict) or reply.get("version") != 1:
        raise ValueError("invalid policy reply")
    policy = reply.get("policy")
    if policy is not None and not isinstance(policy, dict):
        raise ValueError("invalid policy")
    return policy


def _process_start(pid):
    # The comm field in /proc/<pid>/stat may itself contain spaces and ')'.
    with open(f"/proc/{pid}/stat", "r", encoding="ascii") as handle:
        fields = handle.read(8192).rsplit(")", 1)[1].split()
    return int(fields[19])


def _load_policy(path, now_ms):
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_mode & 0o022):
            raise ValueError("invalid state file ownership or mode")
        payload = source.read(_MAX_STATE + 1)
    if len(payload) > _MAX_STATE:
        raise ValueError("state file too large")
    state = json.loads(payload)
    if not isinstance(state, dict) or state.get("version") != 1:
        raise ValueError("unsupported state")
    owner = state.get("owner")
    if not isinstance(owner, dict):
        raise ValueError("missing owner")
    pid = owner.get("pid")
    started = owner.get("start_ticks")
    expires = owner.get("expires_unix_ms")
    if (type(pid) is not int or pid < 1 or type(started) is not int
            or type(expires) is not int or expires <= now_ms
            or expires > now_ms + 120_000 or _process_start(pid) != started
            or os.stat(f"/proc/{pid}").st_uid != os.getuid()):
        raise ValueError("state owner is not current")
    return state.get("policies")


def _select_policy(policies, app_id):
    if not isinstance(policies, list) or len(policies) > 32:
        raise ValueError("invalid policy list")
    selected = []
    for policy in policies:
        if not isinstance(policy, dict):
            raise ValueError("invalid policy")
        target = policy.get("app_id")
        if target is not None and (not isinstance(target, str) or not target.isascii()
                                   or not target.isdigit() or len(target) > 10):
            raise ValueError("invalid app identity")
        if target == app_id and target is not None:
            selected.append(policy)
    if not selected:
        selected = [policy for policy in policies if policy.get("app_id") is None]
    # Equivalent sessions may share a policy; differing policies are ambiguous.
    if not selected or any(candidate != selected[0] for candidate in selected[1:]):
        return None
    return selected[0]


def _edits(policy, inherited):
    provider = policy.get("provider")
    rate = policy.get("limit_millihz")
    preset = policy.get("preset")
    method = policy.get("method")
    graph = policy.get("graph")
    if (provider not in ("proton", "mangohud-proton", "mangohud")
            or type(rate) is not int or not 1 <= rate <= 1_000_000
            or preset not in ("custom", "1", "2", "3", "4")
            or method not in ("early", "late") or type(graph) is not bool):
        raise ValueError("invalid limiter policy")
    rate_text = f"{rate // 1000}.{rate % 1000:03d}".rstrip("0").rstrip(".")
    overlay = provider != "proton"
    changes = {}
    if provider != "mangohud":
        dxvk_rate = str((rate + 500) // 1000)
        current = inherited.get("DXVK_CONFIG", "")
        clauses = [f"{key} = {dxvk_rate}" for key in
                   ("dxvk.maxFrameRate", "dxgi.maxFrameRate", "d3d9.maxFrameRate")]
        changes["DXVK_CONFIG"] = "; ".join(([current] if current else []) + clauses)
        changes["DXVK_FRAME_RATE"] = dxvk_rate
        changes["VKD3D_FRAME_RATE"] = rate_text
    if overlay:
        config = ["read_cfg"]
        if inherited.get("MANGOHUD_CONFIG"):
            config.append(inherited["MANGOHUD_CONFIG"])
        if preset != "custom":
            config.append(f"preset={preset}")
        if provider == "mangohud-proton" or preset != "custom" or graph:
            config.append("no_display=0")
        if graph:
            config.append("frame_timing=1")
        config.extend((f"fps_limit_method={method}",
                       f"fps_limit={rate_text if provider == 'mangohud' else '0'}"))
        changes["MANGOHUD"] = "1"
        changes["MANGOHUD_CONFIG"] = ",".join(config)
    else:
        changes["MANGOHUD"] = None
        changes["MANGOHUD_CONFIG"] = None
    changes["MANGOHUD_FPS_LIMIT"] = (
        rate_text if provider == "mangohud" and rate % 1000 == 0 else None
    )
    preload = [item for item in inherited.get("LD_PRELOAD", "").split(":")
               if item and item != _SHIM]
    if overlay:
        preload.append(_SHIM)
    changes["LD_PRELOAD"] = ":".join(preload) or None
    return changes


def _container_overlay(changes, inherited, host_root=Path("/run/host"), temporary_parent=None):
    """Expose installed host overlay libraries inside pressure-vessel only.

    Keep other Vulkan layers and preloads intact. The private manifests and
    symlinks live for the Proton process, which waits for its game to exit.
    """
    source_directory = host_root / "usr/share/vulkan/implicit_layer.d"
    if changes.get("MANGOHUD") != "1" or not source_directory.is_dir():
        return changes
    manifests = []
    for source in sorted(source_directory.glob("MangoHud*.json"))[:8]:
        data = source.read_bytes()
        if len(data) > 65536:
            raise ValueError("overlay manifest too large")
        document = json.loads(data)
        layer = document.get("layer", {})
        library = layer.get("library_path")
        if not isinstance(library, str) or not Path(library).is_absolute():
            continue
        mapped = host_root / library.lstrip("/")
        if not mapped.is_file():
            continue
        layer["library_path"] = str(mapped)
        manifests.append((source.name, document))
    if not manifests:
        return changes
    directory = Path(tempfile.mkdtemp(prefix="amaterasu-mangohud-", dir=temporary_parent))
    try:
        layers = directory / "implicit_layer.d"
        layers.mkdir(mode=0o700)
        for name, document in manifests:
            (layers / name).write_text(json.dumps(document), encoding="utf-8")
        # $LIB names are distribution-specific (and can be identical for both
        # ELF classes). $PLATFORM lets each game's loader select its own class.
        for bits, candidates, layouts in [
            (2, ("usr/lib/mangohud", "usr/lib64/mangohud", "usr/lib/x86_64-linux-gnu/mangohud"),
             ("x86_64", "haswell", "xeon_phi")),
            (1, ("usr/lib32/mangohud", "usr/lib/i386-linux-gnu/mangohud"),
             ("i686", "i586", "i486", "i386")),
        ]:
            for relative in candidates:
                source = host_root / relative
                shim = source / "libMangoHud_shim.so"
                if not shim.is_file():
                    continue
                with shim.open("rb") as handle:
                    if handle.read(5) != b"\x7fELF" + bytes([bits]):
                        continue
                for layout in layouts:
                    target = directory / "platform" / layout
                    target.mkdir(mode=0o700, parents=True, exist_ok=True)
                    for library in ("libMangoHud_shim.so", "libMangoHud_opengl.so"):
                        if (source / library).is_file():
                            (target / library).symlink_to(source / library)
                break
        preloads = [item for item in changes.get("LD_PRELOAD", "").split(":") if item and item != _SHIM]
        preloads.append(str(directory / "platform/$PLATFORM/libMangoHud_shim.so"))
        changes["LD_PRELOAD"] = ":".join(preloads)
        key = "VK_IMPLICIT_LAYER_PATH" if inherited.get("VK_IMPLICIT_LAYER_PATH") else "VK_ADD_IMPLICIT_LAYER_PATH"
        changes[key] = str(layers) + (":" + inherited[key] if inherited.get(key) else "")
        atexit.register(shutil.rmtree, directory, ignore_errors=True)
        return changes
    except BaseException:
        shutil.rmtree(directory, ignore_errors=True)
        raise


def apply(namespace, state_path=None):
    """Update Proton's current session environment, if an owned policy exists."""
    try:
        settings = namespace.setdefault("user_settings", {})
        if not isinstance(settings, dict):
            return False
        session = namespace.get("g_session") or getattr(sys.modules.get("__main__"), "g_session", None)
        environment = getattr(session, "env", None)
        if not isinstance(environment, dict):
            return False
        if state_path is None:
            runtime = environment.get("XDG_RUNTIME_DIR") or os.environ.get("XDG_RUNTIME_DIR")
            if not runtime or not Path(runtime).is_absolute():
                return False
            state_path = Path(runtime) / "amaterasu" / "frame-limiter" / "active.json"
        app_id = environment.get("SteamAppId") or environment.get("SteamGameId")
        try:
            policies = _load_policy(state_path, time.time_ns() // 1_000_000)
            policy = _select_policy(policies, app_id)
        except FileNotFoundError:
            # pressure-vessel hides the host runtime directory. A live local
            # worker can supply the same policy without exposing that directory.
            policy = _request_policy(Path(state_path).parents[2], app_id)
        if policy is None:
            return False
        inherited = dict(settings)
        inherited.update(environment)
        changes = _edits(policy, inherited)
        changes = _container_overlay(changes, inherited)
        for key, value in changes.items():
            for mapping in (settings, environment):
                if value is None:
                    mapping.pop(key, None)
                else:
                    mapping[key] = value
        return True
    except (OSError, ValueError, TypeError, KeyError, IndexError, RecursionError):
        return False
