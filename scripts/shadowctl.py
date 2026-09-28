"""Truthful ON/OFF controller for the bounded DAXXER shadow observer."""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import secrets
import signal
import subprocess
import sys
import time
from pathlib import Path

from shadow_runtime import COMPONENT_ROOT, RuntimeErrorSafe, canonical, run_once, strict_json, utc_now, validate_all_queues
from storage import StorageError, file_lock, safe_path


SCRIPT = Path(__file__).resolve().with_name("shadow_runtime.py")
_LOCAL_LAUNCHERS = {}
if os.name == "nt":
    ctypes.windll.kernel32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    ctypes.windll.kernel32.OpenProcess.restype = ctypes.c_void_p
    ctypes.windll.kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    ctypes.windll.kernel32.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
    ctypes.windll.kernel32.LocalFree.argtypes = [ctypes.c_void_p]


def _atomic_json(path: Path, value: dict) -> None:
    safe_path(path.parent.parent, path.relative_to(path.parent.parent))
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    temporary.write_bytes(canonical(value) + b"\n")
    os.replace(temporary, path)


def _read_state(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        safe_path(path.parent.parent, path.relative_to(path.parent.parent))
        state = strict_json(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeErrorSafe("control state is malformed; refusing process action") from exc
    required = {"schema_version", "pid", "token", "root", "config", "script", "python", "status", "created_at"}
    if type(state) is not dict or not required <= set(state) or state.get("schema_version") != "0.2":
        raise RuntimeErrorSafe("control state is invalid; refusing process action")
    if type(state["pid"]) is not int or state["pid"] <= 0 or any(type(state[key]) is not str or not state[key] for key in ("token", "root", "config", "script", "python", "status", "created_at")):
        raise RuntimeErrorSafe("control state has invalid process identity")
    return state


def _process_alive(pid: int) -> bool:
    for launcher in list(_LOCAL_LAUNCHERS.values()):
        launcher.poll()
    if pid <= 0:
        return False
    if os.name == "nt":
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return False
        exit_code = ctypes.c_ulong()
        try:
            if not ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return False
            return exit_code.value == 259  # STILL_ACTIVE
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _split_windows(command: str) -> list[str]:
    argc = ctypes.c_int()
    ctypes.windll.shell32.CommandLineToArgvW.restype = ctypes.POINTER(ctypes.c_wchar_p)
    pointer = ctypes.windll.shell32.CommandLineToArgvW(command, ctypes.byref(argc))
    if not pointer:
        return []
    try:
        return [pointer[index] for index in range(argc.value)]
    finally:
        ctypes.windll.kernel32.LocalFree(pointer)


def _process_command(pid: int) -> dict | None:
    """Read exact OS process identity. Missing data means no authority to stop."""
    if os.name == "nt":
        ps = (
            f"$p=Get-CimInstance Win32_Process -Filter 'ProcessId = {pid}'; "
            "if ($null -ne $p) { $p | Select-Object CommandLine,ExecutablePath,CreationDate | ConvertTo-Json -Compress }"
        )
        try:
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps],
                capture_output=True, text=True, timeout=8, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if result.returncode != 0 or not result.stdout.strip():
            return None
        try:
            value = json.loads(result.stdout)
            return {"argv": _split_windows(value["CommandLine"]), "executable": value["ExecutablePath"], "created": value["CreationDate"]}
        except (KeyError, TypeError, json.JSONDecodeError):
            return None
    path = Path("/proc") / str(pid) / "cmdline"
    try:
        argv = [item.decode("utf-8", errors="replace") for item in path.read_bytes().split(b"\0") if item]
        executable = str((Path("/proc") / str(pid) / "exe").resolve())
        created = (Path("/proc") / str(pid) / "stat").read_text(encoding="utf-8").split()[21]
        return {"argv": argv, "executable": executable, "created": created}
    except OSError:
        return None


def _norm_arg(value: str) -> str:
    return value.casefold().replace("/", "\\") if os.name == "nt" else value


def _identity_matches(state: dict, process_info: dict | None, root: Path) -> bool:
    if type(process_info) is not dict:
        return False
    if Path(state["root"]).resolve() != Path(root).resolve():
        return False
    if Path(state["script"]).resolve() != SCRIPT.resolve():
        return False
    expected = ["-B", state["script"], "watch", "--config", state["config"], "--root", state["root"],
                "--state", str(Path(state["root"]) / "runtime" / "shadow-process.json"), "--token", state["token"]]
    argv = process_info.get("argv")
    if type(argv) is not list or [_norm_arg(v) for v in argv[1:]] != [_norm_arg(v) for v in expected]:
        return False
    runtime_python = state.get("runtime_python")
    if not runtime_python or _norm_arg(process_info.get("executable", "")) != _norm_arg(runtime_python):
        return False
    recorded = state.get("process_identity")
    if recorded is not None and (recorded.get("created") != process_info.get("created") or
                                 _norm_arg(recorded.get("executable", "")) != _norm_arg(process_info.get("executable", ""))):
        return False
    return True


def inspect_status(root: Path = COMPONENT_ROOT, *, command_reader=_process_command) -> dict:
    root = Path(root).resolve()
    state_path = safe_path(root, "runtime/shadow-process.json")
    state = _read_state(state_path)
    if state is None:
        return {"state": "off", "running": False, "verified": True, "reason": "no recorded observer"}
    if state["status"] == "stopped" and not _process_alive(state["pid"]):
        return {"state": "off", "running": False, "verified": True, "pid": state["pid"], "reason": "recorded observer stopped"}
    if not _process_alive(state["pid"]):
        return {"state": "stale", "running": False, "verified": False, "pid": state["pid"], "reason": "recorded process is not running"}
    command = command_reader(state["pid"])
    verified = _identity_matches(state, command, root)
    if not verified:
        return {"state": "unverified", "running": True, "verified": False, "pid": state["pid"], "reason": "PID is live but command/root identity did not verify"}
    state_name = "on" if state["status"] in {"starting", "running"} else "error"
    result = {"state": state_name, "running": True, "verified": True, "pid": state["pid"], "reason": "observer identity verified"}
    for field in ("heartbeat_at", "ready_at", "last_scan", "last_error"):
        if field in state:
            result[field] = state[field]
    if "heartbeat_at" in state:
        try:
            heartbeat = __import__("datetime").datetime.fromisoformat(state["heartbeat_at"])
            age = (__import__("datetime").datetime.now(__import__("datetime").timezone.utc) - heartbeat).total_seconds()
            poll = __import__("shadow_runtime").load_config(Path(state["config"]), root)["poll_seconds"]
            from reviewer import settings
            timeout = settings(root).get("timeout_seconds", 0)
            if age > max(10, poll * 2 + 5, timeout + 5):
                result.update(state="error", reason="observer identity verified but heartbeat is stale")
        except Exception:
            result.update(state="error", reason="observer identity verified but heartbeat could not be assessed")
    return result


def start(root: Path = COMPONENT_ROOT, config_path: Path | None = None, *, wait_seconds: float = 15.0) -> dict:
    try:
        with file_lock(safe_path(root, "runtime/.control.lock")):
            return _start(root, config_path, wait_seconds=wait_seconds)
    except StorageError as exc:
        raise RuntimeErrorSafe(str(exc)) from exc


def _start(root: Path, config_path: Path | None, *, wait_seconds: float) -> dict:
    root = Path(root).resolve()
    config_path = Path(config_path or root / "config" / "shadow-config.json").resolve()
    state_path = safe_path(root, "runtime/shadow-process.json")
    existing = inspect_status(root)
    if existing["running"]:
        if existing["verified"]:
            return {**existing, "changed": False}
        raise RuntimeErrorSafe("a live unverified PID is recorded; refusing to start another observer")
    if existing["state"] == "stale":
        stale = _read_state(state_path)
        stale.update(status="stopped", stopped_at=utc_now(), stop_reason="reconciled_dead_pid")
        _atomic_json(state_path, stale)
    # Validate before creating a process.
    from shadow_runtime import load_config
    load_config(config_path, root)
    root.joinpath("runtime").mkdir(parents=True, exist_ok=True)
    stop_request = safe_path(root, "runtime/stop-request.json")
    if stop_request.exists():
        stop_request.unlink()
    log_path = safe_path(root, "runtime/shadow.log")
    token = secrets.token_hex(16)
    staged = {
        "schema_version": "0.2", "pid": 0, "token": token,
        "root": str(root), "config": str(config_path), "script": str(SCRIPT),
        "python": str(Path(sys.executable).resolve()), "status": "launching", "created_at": utc_now(),
    }
    _atomic_json(state_path, staged)
    # A Windows venv launcher can create another PID; use the base interpreter
    # because the observer needs only the standard library.
    executable = getattr(sys, "_base_executable", sys.executable)
    command = [executable, "-B", str(SCRIPT), "watch", "--config", str(config_path),
               "--root", str(root), "--state", str(state_path), "--token", token]
    creationflags = 0
    popen_kwargs = {}
    if os.name == "nt":
        creationflags = 0x00000008 | 0x00000200  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    else:
        popen_kwargs["start_new_session"] = True
    child_env = os.environ.copy()
    if root != COMPONENT_ROOT.resolve():
        child_env["DAXXER_SHADOW_TEST_ROOT"] = str(root)
    with log_path.open("ab", buffering=0) as log:
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
            cwd=str(root), creationflags=creationflags, close_fds=True, env=child_env, **popen_kwargs,
        )
    state = {
        "schema_version": "0.2", "pid": process.pid, "token": token,
        "root": str(root), "config": str(config_path), "script": str(SCRIPT),
        "python": str(Path(sys.executable).resolve()), "status": "starting", "created_at": utc_now(),
    }
    _atomic_json(state_path, state)
    _LOCAL_LAUNCHERS[str(root)] = process
    deadline = time.time() + wait_seconds
    latest = None
    while time.time() < deadline:
        time.sleep(0.05)
        latest = inspect_status(root)
        if (latest["state"] in {"on", "error", "unverified"} and "ready_at" in latest):
            break
    latest = inspect_status(root)
    if latest["state"] != "on" or not latest.get("ready_at") or not latest["verified"]:
        try:
            log_tail = log_path.read_text(encoding="utf-8", errors="replace")[-500:].strip()
        except OSError:
            log_tail = "log unavailable"
        raise RuntimeErrorSafe(f"observer did not reach a verified running state: {latest['state']} ({latest['reason']}); {log_tail}")
    process.poll()
    state = _read_state(state_path)
    info = _process_command(state["pid"])
    if not _identity_matches(state, info, root):
        raise RuntimeErrorSafe("observer process identity could not be established")
    return {**latest, "changed": True}


def stop(root: Path = COMPONENT_ROOT, *, command_reader=_process_command, wait_seconds: float = 8.0) -> dict:
    try:
        with file_lock(safe_path(root, "runtime/.control.lock")):
            return _stop(root, command_reader=command_reader, wait_seconds=wait_seconds)
    except StorageError as exc:
        raise RuntimeErrorSafe(str(exc)) from exc


def _stop(root: Path, *, command_reader, wait_seconds: float) -> dict:
    root = Path(root).resolve()
    state_path = safe_path(root, "runtime/shadow-process.json")
    state = _read_state(state_path)
    if state is None:
        return {"state": "off", "running": False, "verified": True, "changed": False, "reason": "observer already off"}
    if not _process_alive(state["pid"]):
        state.update(status="stopped", stopped_at=utc_now(), stop_reason="reconciled_dead_pid")
        _atomic_json(state_path, state)
        return {"state": "off", "running": False, "verified": True, "changed": True, "reason": "reconciled dead observer"}
    command = command_reader(state["pid"])
    if not _identity_matches(state, command, root):
        raise RuntimeErrorSafe("recorded PID command/root did not verify; refusing to terminate it")
    request_path = safe_path(root, "runtime/stop-request.json")
    _atomic_json(request_path, {"schema_version": "0.2", "action": "stop", "token": state["token"], "requested_at": utc_now()})
    deadline = time.time() + wait_seconds
    while _process_alive(state["pid"]) and time.time() < deadline:
        time.sleep(0.05)
    forced = False
    if _process_alive(state["pid"]):
        raise RuntimeErrorSafe("stop requested; observer still exiting. Run status/off again; force termination is disabled")
    launcher = _LOCAL_LAUNCHERS.pop(str(root), None)
    if launcher is not None:
        try:
            launcher.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
    validate_all_queues(root)
    try:
        latest = _read_state(state_path) or state
    except RuntimeErrorSafe:
        latest = state
    latest.update(status="stopped", stopped_at=utc_now())
    _atomic_json(state_path, latest)
    return {"state": "off", "running": False, "verified": True, "pid": state["pid"], "changed": True, "forced": forced, "reason": "verified observer stopped"}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Control the bounded DAXXER shadow observer")
    parser.add_argument("command", choices=("on", "off", "status", "run-once"))
    parser.add_argument("--root", type=Path, default=COMPONENT_ROOT)
    parser.add_argument("--config", type=Path)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    config = (args.config or root / "config" / "shadow-config.json").resolve()
    try:
        if root != COMPONENT_ROOT.resolve():
            raise RuntimeErrorSafe("controller root is outside the bounded component")
        if config != root / "config" / "shadow-config.json":
            raise RuntimeErrorSafe("controller config must be the component configuration")
        if args.command == "on":
            result = start(root, config)
        elif args.command == "off":
            result = stop(root)
        elif args.command == "status":
            result = inspect_status(root)
        else:
            result = run_once(config, root)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    except (OSError, RuntimeErrorSafe, ValueError) as exc:
        print(json.dumps({"state": "error", "error": type(exc).__name__, "message": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
