"""Bounded, read-only source observer for DAXXER shadow intake v0.2."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from vil import VILError, assess
from storage import StorageError, file_lock, safe_path
from ledger import Invalid, check, schema


COMPONENT_ROOT = Path(__file__).resolve().parents[1]
ROUTES = ("pending", "retained", "rejected")
CONTENT_SECRET_PATTERNS = (
    re.compile(r"""(?i)["']?(?:[a-z0-9]+[_-])*(?:password|passwd|api[_-]?key|access[_-]?token|client[_-]?secret|token|secret)["']?\s*[:=]\s*["']?[^\s"',}]{4,}"""),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.I),
    re.compile(r"(?im)^\s*['\"]?(?:[A-Z0-9]+_)*(?:password|passwd|api[_-]?key|access[_-]?token|client[_-]?secret)['\"]?\s*[:=]\s*['\"]?[^\s'\"]{8,}"),
    re.compile(r"(?i)\bauthorization\s*:\s*bearer\s+[A-Za-z0-9._~+/-]{8,}"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,})\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
)


class RuntimeErrorSafe(StorageError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def strict_json(text: str):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise RuntimeErrorSafe("duplicate JSON key")
            result[key] = value
        return result
    def bad_constant(_value):
        raise RuntimeErrorSafe("non-finite JSON number")
    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=bad_constant)
    except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
        raise RuntimeErrorSafe("invalid JSON") from exc


def digest(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def event_hash(event: dict) -> str:
    return digest({key: value for key, value in event.items() if key != "content_hash"})


def _read_json(path: Path) -> dict:
    try:
        value = strict_json(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, RuntimeErrorSafe) as exc:
        raise RuntimeErrorSafe(f"invalid JSON configuration or state: {path}") from exc
    if type(value) is not dict:
        raise RuntimeErrorSafe("configuration root must be an object")
    return value


def _bounded_score(value, name: str) -> float:
    if type(value) not in (int, float) or not 0 <= value <= 1:
        raise RuntimeErrorSafe(f"{name} must be a number from 0 to 1")
    return float(value)


def load_config(path: Path, root: Path = COMPONENT_ROOT) -> dict:
    config = _read_json(Path(path))
    required = {"schema_version", "first_run_mode", "poll_seconds", "limits", "safe_content_extensions",
                "excluded_directory_names", "secret_name_patterns", "vil", "sources"}
    if set(config) != required or config.get("schema_version") != "0.2":
        raise RuntimeErrorSafe("configuration fields or schema version are invalid")
    if config["first_run_mode"] not in {"baseline", "backfill"}:
        raise RuntimeErrorSafe("first_run_mode must be baseline or backfill")
    if type(config["poll_seconds"]) not in (int, float) or not 0.1 <= config["poll_seconds"] <= 86400:
        raise RuntimeErrorSafe("poll_seconds must be from 0.1 to 86400")
    limits = config["limits"]
    if type(limits) is not dict or set(limits) != {"max_events_per_scan", "max_content_bytes", "max_state_entries"}:
        raise RuntimeErrorSafe("invalid limits")
    for name, low, high in (("max_events_per_scan", 1, 10000), ("max_content_bytes", 1, 1048576),
                            ("max_state_entries", 1, 100000)):
        if type(limits.get(name)) is not int or not low <= limits[name] <= high:
            raise RuntimeErrorSafe(f"invalid limit: {name}")
    extensions = config["safe_content_extensions"]
    if type(extensions) is not list or not extensions or any(type(x) is not str or not re.fullmatch(r"\.[a-z0-9]{1,10}", x) for x in extensions):
        raise RuntimeErrorSafe("safe_content_extensions must be lowercase extensions")
    if len(set(extensions)) != len(extensions):
        raise RuntimeErrorSafe("duplicate safe content extension")
    for field in ("excluded_directory_names", "secret_name_patterns"):
        if type(config[field]) is not list or not config[field] or any(type(x) is not str or not x for x in config[field]):
            raise RuntimeErrorSafe(f"invalid {field}")
    try:
        for pattern in config["secret_name_patterns"]:
            re.compile(pattern, re.I)
    except re.error as exc:
        raise RuntimeErrorSafe("invalid secret-name pattern") from exc
    if type(config["vil"]) is not dict or set(config["vil"]) != {"thresholds"}:
        raise RuntimeErrorSafe("invalid VIL configuration")
    try:
        assess(
            {"relevance": 0, "source_quality": 0, "freshness": 0, "actionability": 0},
            {"traceability": 0, "completeness": 0, "corroboration": 0},
            thresholds=config["vil"]["thresholds"],
        )
    except (VILError, TypeError) as exc:
        raise RuntimeErrorSafe("invalid VIL thresholds") from exc
    sources = config["sources"]
    if type(sources) is not list or not sources:
        raise RuntimeErrorSafe("at least one source is required")
    normalized = []
    ids = set()
    source_fields = {"id", "path", "recursive", "max_depth", "max_files", "metadata_only",
                     "relevance", "source_quality", "corroboration"}
    for source in sources:
        if type(source) is not dict or set(source) != source_fields:
            raise RuntimeErrorSafe("invalid source fields")
        source_id = source.get("id")
        if type(source_id) is not str or not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,63}", source_id) or source_id in ids:
            raise RuntimeErrorSafe("source IDs must be unique lowercase slugs")
        ids.add(source_id)
        raw_path = source.get("path")
        if type(raw_path) is not str or not raw_path:
            raise RuntimeErrorSafe("source path must be a string")
        raw_path = raw_path.replace("${COMPONENT_ROOT}", str(Path(root).resolve()))
        if not Path(raw_path).expanduser().is_absolute():
            raise RuntimeErrorSafe("source paths must be absolute or use COMPONENT_ROOT")
        resolved = Path(raw_path).expanduser().resolve()
        if not resolved.is_absolute():
            raise RuntimeErrorSafe("source paths must resolve absolutely")
        if type(source.get("recursive")) is not bool or type(source.get("metadata_only")) is not bool:
            raise RuntimeErrorSafe("source flags must be booleans")
        for name, low, high in (("max_depth", 0, 12), ("max_files", 1, 10000)):
            if type(source.get(name)) is not int or not low <= source[name] <= high:
                raise RuntimeErrorSafe(f"invalid source {name}")
        item = dict(source)
        item["path"] = str(resolved)
        for name in ("relevance", "source_quality", "corroboration"):
            item[name] = _bounded_score(source.get(name), name)
        normalized.append(item)
    result = dict(config)
    result["sources"] = normalized
    return result


def safety_exclusion(path: Path, source_root: Path, config: dict) -> str | None:
    """Return an exclusion reason without reading file bytes."""
    try:
        relative = path.relative_to(source_root)
    except ValueError:
        return "outside_source_root"
    parts = relative.parts
    blocked_dirs = {name.casefold() for name in config["excluded_directory_names"]}
    if any(part.startswith(".") for part in parts):
        return "hidden_path"
    if any(part.casefold() in blocked_dirs for part in parts[:-1]):
        return "excluded_directory"
    joined = "/".join(parts)
    if any(re.search(pattern, joined, re.I) for pattern in config["secret_name_patterns"]):
        return "secret_like_name"
    try:
        # Reject junctions and links in every ancestor, including the source root.
        for parent in [source_root, *path.parents]:
            if parent == source_root.parent:
                break
            if parent.is_symlink() or getattr(parent.lstat(), "st_file_attributes", 0) & 0x400:
                return "linked_source_directory"
        if path.is_symlink():
            return "symlink"
        attributes = getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0)
        if attributes & 0x400:
            return "reparse_point"
        if not path.resolve().is_relative_to(source_root.resolve()):
            return "resolved_outside_source_root"
    except OSError:
        return "unreadable_metadata"
    return None


def _iter_files(source: dict, config: dict, after: str | None = None):
    root = Path(source["path"])
    if not root.is_dir() or root.is_symlink() or getattr(root.lstat(), "st_file_attributes", 0) & 0x400:
        return
    blocked = {name.casefold() for name in config["excluded_directory_names"]}
    def walk(directory, depth):
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda e: (e.name + ("/" if e.is_dir(follow_symlinks=False) else "")).casefold())
        except OSError:
            raise RuntimeErrorSafe("source directory could not be scanned")
        for entry in entries:
            candidate = Path(entry.path)
            if entry.name.startswith(".") or entry.name.casefold() in blocked or safety_exclusion(candidate, root, config):
                continue
            if entry.is_dir(follow_symlinks=False):
                if source["recursive"] and depth < source["max_depth"]:
                    yield from walk(candidate, depth + 1)
            elif entry.is_file(follow_symlinks=False):
                if after is None or candidate.relative_to(root).as_posix().casefold() > after.casefold():
                    yield candidate
    for index, path in enumerate(walk(root, 0)):
        if index >= source["max_files"]:
            break
        yield path

def _freshness(age_seconds: float) -> float:
    if age_seconds < -300:
        return 0.0
    if age_seconds <= 86400:
        return 1.0
    if age_seconds <= 7 * 86400:
        return 0.8
    if age_seconds <= 30 * 86400:
        return 0.6
    if age_seconds <= 180 * 86400:
        return 0.4
    return 0.2


def _actionability(extension: str) -> float:
    return 0.9 if extension in {".md", ".json", ".jsonl", ".yaml", ".yml"} else 0.75 if extension in {".txt", ".csv"} else 0.4


def observe_file(path: Path, source: dict, config: dict, *, observed_epoch: float | None = None) -> dict | None:
    """Create a sanitized observation. Returns None when safety requires silence."""
    source_root = Path(source["path"])
    if safety_exclusion(path, source_root, config):
        return None
    try:
        before = path.stat(follow_symlinks=False)
    except OSError:
        return None
    relative = path.relative_to(source_root).as_posix()
    extension = path.suffix.casefold()
    now_epoch = time.time() if observed_epoch is None else observed_epoch
    signal_values = {
        "relevance": source["relevance"],
        "source_quality": source["source_quality"],
        "freshness": _freshness(now_epoch - before.st_mtime),
        "actionability": _actionability(extension),
    }
    pre_vil = assess(
        signal_values,
        {"traceability": 0.65, "completeness": 0.75 if source["metadata_only"] else 0.6, "corroboration": 0.0},
        thresholds=config["vil"]["thresholds"],
    )
    content = None
    content_sha256 = None
    capture_reason = "metadata_only_source" if source["metadata_only"] else "extension_or_size_not_allowed"
    if pre_vil["route"] == "rejected":
        capture_reason = "vil_rejected_metadata_only"
    elif not source["metadata_only"] and extension in config["safe_content_extensions"] and before.st_size <= config["limits"]["max_content_bytes"]:
        try:
            with path.open("rb") as stream:
                raw = stream.read(config["limits"]["max_content_bytes"] + 1)
            after = path.stat(follow_symlinks=False)
            if (len(raw) != before.st_size or
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or
                safety_exclusion(path, source_root, config)):
                return None
            content = raw.decode("utf-8")
        except (OSError, UnicodeError):
            capture_reason = "not_stable_utf8_text"
        else:
            if any(pattern.search(content) for pattern in CONTENT_SECRET_PATTERNS):
                return None
            content_sha256 = hashlib.sha256(raw).hexdigest()
            capture_reason = "safe_text_captured"
    fingerprint_input = {
        "source_id": source["id"], "source_root": str(source_root), "relative_path": relative,
        "size": before.st_size, "mtime_ns": before.st_mtime_ns,
    }
    fingerprint = digest(fingerprint_input)
    verification_values = {
        "traceability": 1.0 if content_sha256 else 0.65,
        "completeness": 1.0 if content_sha256 else 0.75 if capture_reason == "metadata_only_source" else 0.6,
        "corroboration": 0.0,
    }
    vil = pre_vil if pre_vil["route"] == "rejected" else assess(signal_values, verification_values, thresholds=config["vil"]["thresholds"])
    if vil["route"] == "rejected":
        content = None
        content_sha256 = None
        capture_reason = "vil_rejected_metadata_only"
    observation = {
        "source_id": source["id"],
        "source_root": str(source_root),
        "relative_path": relative,
        "size": before.st_size,
        "mtime_ns": before.st_mtime_ns,
        "extension": extension,
        "metadata_only": content is None,
        "capture_reason": capture_reason,
        "content_sha256": content_sha256,
        "content": content,
        "fingerprint": fingerprint,
        "trust": "untrusted_candidate_evidence",
    }
    return {
        "event_id": "DXI-" + fingerprint[:24].upper(),
        "observation": observation,
        "safety": {"decision": "ALLOW", "filter": "shadow-intake-safety-v0.2",
                   "secret_scan": "not_scanned_metadata" if content is None else "heuristic_no_match"},
        "vil": vil,
        "authority": {
            "operation": "read_only",
            "gate": "ALLOW",
            "may_execute_actions": False,
            "note": "Component intake only; reviewer required before a ledger episode.",
        },
        "route": vil["route"],
        "ledger_status": "candidate_only",
    }


class AppendQueue:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.root = self.path.parents[2]
        self.lock_path = self.root / "queue" / ".intake.lock"

    def _load_route(self) -> list[dict]:
        safe_path(self.root, self.path.relative_to(self.root))
        if not self.path.exists():
            return []
        raw = self.path.read_bytes()
        if raw and not raw.endswith(b"\n"):
            raise RuntimeErrorSafe(f"torn queue write: {self.path}")
        records = []
        ids = set()
        for number, line in enumerate(raw.decode("utf-8").splitlines(), 1):
            try:
                record = strict_json(line)
                check(record, schema("intake-event.schema.json"))
            except Invalid as exc:
                raise RuntimeErrorSafe(f"invalid queue schema at line {number}") from exc
            except RuntimeErrorSafe as exc:
                raise RuntimeErrorSafe(f"malformed queue JSON at line {number}") from exc
            self.validate_record(record, number)
            if record["event_id"] in ids:
                raise RuntimeErrorSafe("duplicate route event ID")
            ids.add(record["event_id"])
            records.append(record)
        return records

    def validate_record(self, record, number=1):
        check(record, schema("intake-event.schema.json"))
        check(record["vil"], schema("vil-assessment.schema.json"))
        required = {"schema_version", "event_id", "sequence", "recorded_at", "previous_hash",
                    "observation", "safety", "vil", "authority", "route", "ledger_status", "content_hash"}
        if type(record) is not dict or set(record) != required:
            raise RuntimeErrorSafe(f"invalid queue record fields at line {number}")
        if record["schema_version"] != "0.2" or type(record["sequence"]) is not int or record["sequence"] < 1:
            raise RuntimeErrorSafe(f"invalid queue version or sequence at line {number}")
        if record["route"] != self.path.parent.name or record["ledger_status"] != "candidate_only":
            raise RuntimeErrorSafe(f"wrong route or ledger status at line {number}")
        observation_fields = {"source_id", "source_root", "relative_path", "size", "mtime_ns", "extension", "metadata_only",
                              "capture_reason", "content_sha256", "content", "fingerprint", "trust"}
        observation = record["observation"]
        if type(observation) is not dict or set(observation) != observation_fields or observation["trust"] != "untrusted_candidate_evidence":
            raise RuntimeErrorSafe(f"invalid observation at line {number}")
        if type(observation["size"]) is not int or observation["size"] < 0 or type(observation["mtime_ns"]) is not int:
            raise RuntimeErrorSafe(f"invalid observation metadata at line {number}")
        if observation["content"] is None:
            if observation["content_sha256"] is not None or observation["metadata_only"] is not True:
                raise RuntimeErrorSafe(f"inconsistent metadata-only observation at line {number}")
        elif (type(observation["content"]) is not str or observation["metadata_only"] is not False or
              hashlib.sha256(observation["content"].encode("utf-8")).hexdigest() != observation["content_sha256"]):
            raise RuntimeErrorSafe(f"invalid captured content at line {number}")
        expected_safety = {"decision": "ALLOW", "filter": "shadow-intake-safety-v0.2",
                           "secret_scan": "not_scanned_metadata" if observation["content"] is None else "heuristic_no_match"}
        expected_authority = {"operation": "read_only", "gate": "ALLOW", "may_execute_actions": False,
                              "note": "Component intake only; reviewer required before a ledger episode."}
        if record["safety"] != expected_safety or record["authority"] != expected_authority:
            raise RuntimeErrorSafe(f"invalid safety or authority boundary at line {number}")
        vil = record["vil"]
        if type(vil) is not dict:
            raise RuntimeErrorSafe(f"invalid VIL at line {number}")
        try:
            expected_vil = assess(vil["signal"], vil["verifiability"], signal_weights=vil["signal_weights"],
                                  verifiability_weights=vil["verifiability_weights"], thresholds=vil["thresholds"])
        except (KeyError, VILError, TypeError) as exc:
            raise RuntimeErrorSafe(f"invalid VIL at line {number}") from exc
        if vil != expected_vil or record["route"] != vil["route"]:
            raise RuntimeErrorSafe(f"forged VIL or route at line {number}")
        fingerprint = digest({key: observation[key] for key in ("source_id", "source_root", "relative_path", "size", "mtime_ns")})
        relative = Path(observation["relative_path"])
        if relative.is_absolute() or relative.drive or ".." in relative.parts:
            raise RuntimeErrorSafe("invalid source relative path")
        if observation["fingerprint"] != fingerprint or record["event_id"] != "DXI-" + fingerprint[:24].upper():
            raise RuntimeErrorSafe("forged observation identity")
        if observation["content"] is not None and (record["route"] == "rejected" or any(p.search(observation["content"]) for p in CONTENT_SECRET_PATTERNS)):
            raise RuntimeErrorSafe("unsafe captured content")
        if vil["verifiability"]["corroboration"] != 0:
            raise RuntimeErrorSafe("observer cannot attest independent corroboration")
        if type(record["previous_hash"]) not in (str, type(None)) or (record["previous_hash"] is not None and not re.fullmatch(r"[0-9a-f]{64}", record["previous_hash"])):
            raise RuntimeErrorSafe(f"invalid previous hash at line {number}")
        if event_hash(record) != record["content_hash"]:
            raise RuntimeErrorSafe(f"duplicate ID or content hash mismatch at line {number}")

    def load(self) -> list[dict]:
        validate_all_queues(self.root)
        return self._load_route()

    def append(self, candidate: dict) -> dict:
        self.path.parent.mkdir(parents=True, exist_ok=True)

        safe_path(self.root, self.path.relative_to(self.root))
        try:
            with file_lock(safe_path(self.root, "queue/.intake.lock")):
                all_records = _load_all_routes(self.root)
                validate_all_queues(self.root)
                if candidate["event_id"] in {r["event_id"] for r in all_records}:
                    raise RuntimeErrorSafe("duplicate intake event")
                record = {"schema_version": "0.2", "sequence": len(all_records) + 1,
                          "recorded_at": utc_now(),
                          "previous_hash": all_records[-1]["content_hash"] if all_records else None,
                          **candidate}
                record["content_hash"] = event_hash(record)
                check(record, schema("intake-event.schema.json"))
                self.validate_record(record)
                encoded = canonical(record) + b"\n"
                with self.path.open("ab", buffering=0) as handle:
                    if handle.write(encoded) != len(encoded):
                        raise RuntimeErrorSafe("short queue append")
                    os.fsync(handle.fileno())
                return record
        except (StorageError, Invalid) as exc:
            raise RuntimeErrorSafe(str(exc)) from exc


def _atomic_json(path: Path, value: dict) -> None:
    safe_path(path.parent.parent, path.relative_to(path.parent.parent))
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    temporary.write_bytes(canonical(value) + b"\n")
    os.replace(temporary, path)


def _load_scan_state(path: Path) -> dict:
    if not path.exists():
        return {"schema_version": "0.2", "fingerprints": {}, "cursors": {}, "baseline_complete_sources": [], "baselined": False, "config_hash": None, "source_offset": 0}
    value = _read_json(path)
    if set(value) != {"schema_version", "fingerprints", "cursors", "baseline_complete_sources", "baselined", "config_hash", "source_offset"} or value["schema_version"] != "0.2" or type(value["fingerprints"]) is not dict or type(value["cursors"]) is not dict or type(value["baseline_complete_sources"]) is not list or type(value["baselined"]) is not bool:
        raise RuntimeErrorSafe("invalid scan state")
    if any(type(k) is not str or type(v) is not str for k, v in value["fingerprints"].items()):
        raise RuntimeErrorSafe("invalid scan fingerprints")
    if type(value["source_offset"]) is not int or value["source_offset"] < 0 or any(type(v) is not str for v in value["cursors"].values()):
        raise RuntimeErrorSafe("invalid scan cursor")
    return value


def _load_all_routes(root: Path) -> list[dict]:
    records = []
    for route in ROUTES:
        records.extend(AppendQueue(root / "queue" / route / "intake-events.jsonl")._load_route())
    records.sort(key=lambda record: record["sequence"])
    return records


def validate_all_queues(root: Path) -> set[str]:
    ids = set()
    previous = None
    records = _load_all_routes(root)
    for sequence, record in enumerate(records, 1):
        if record["sequence"] != sequence or record["previous_hash"] != previous:
            raise RuntimeErrorSafe("broken global intake sequence or hash chain")
        if record["event_id"] in ids:
            raise RuntimeErrorSafe("event ID appears in multiple queues")
        ids.add(record["event_id"])
        previous = record["content_hash"]
    return ids


def run_once(config_path: Path, root: Path = COMPONENT_ROOT, *, stop_check=None, heartbeat=None) -> dict:
    root = Path(root).resolve()
    try:
        with file_lock(safe_path(root, "runtime/.scan.lock")):
            result = _scan_once(config_path, root, stop_check=stop_check)
            from reviewer import review_queue
            if not result["stopped"]:
                result["review"] = review_queue(root, stop_check=stop_check, source_config=config_path, heartbeat=heartbeat)
                if result["review"]["captured"]:
                    from summarize_experience import generate
                    generate(root)
            return result
    except (StorageError, Invalid) as exc:
        raise RuntimeErrorSafe(str(exc)) from exc


def _scan_once(config_path: Path, root: Path = COMPONENT_ROOT, *, stop_check=None) -> dict:
    root = Path(root).resolve()
    config = load_config(config_path, root)
    state_path = safe_path(root, "runtime/scan-state.json")
    state = _load_scan_state(state_path)
    config_hash = digest(config)
    if state["config_hash"] != config_hash:
        state.update(cursors={}, baseline_complete_sources=[], baselined=False, config_hash=config_hash)
    known_ids = validate_all_queues(root)
    counts = {"observed": 0, "baselined": 0, "new": 0, "duplicate": 0, "retained": 0, "pending": 0, "rejected": 0, "source_errors": 0, "stopped": False}
    fingerprints = state["fingerprints"]
    baseline_only = not state["baselined"] and config["first_run_mode"] == "baseline"
    completed_sources = set(state["baseline_complete_sources"])
    event_limit = config["limits"]["max_events_per_scan"]
    stop = False
    offset = state["source_offset"] % len(config["sources"])
    sources = config["sources"][offset:] + config["sources"][:offset]
    for source in sources:
        if baseline_only and source["id"] in completed_sources:
            continue
        source_path = Path(source["path"])
        if not source_path.is_dir() or source_path.is_symlink() or getattr(source_path.lstat(), "st_file_attributes", 0) & 0x400:
            counts["source_errors"] += 1
            continue
        source_observed = 0
        prior_cursor = state["cursors"].get(source["id"])
        for path in _iter_files(source, config, prior_cursor):
            source_observed += 1
            if stop_check and stop_check():
                counts["stopped"] = True
                stop = True
                break
            state["cursors"][source["id"]] = path.relative_to(Path(source["path"])).as_posix()
            counts["observed"] += 1
            candidate = observe_file(path, {**source, "metadata_only": True} if baseline_only else source, config)
            if candidate is None:
                continue
            key = source["id"] + ":" + candidate["observation"]["relative_path"]
            fingerprint = candidate["observation"]["fingerprint"]
            if baseline_only:
                fingerprints[key] = fingerprint
                counts["baselined"] += 1
                continue
            if fingerprints.get(key) == fingerprint or candidate["event_id"] in known_ids:
                counts["duplicate"] += 1
                fingerprints[key] = fingerprint
                continue
            route = candidate["route"]
            if stop_check and stop_check():
                counts["stopped"] = True
                stop = True
                break
            AppendQueue(root / "queue" / route / "intake-events.jsonl").append(candidate)
            fingerprints[key] = fingerprint
            known_ids.add(candidate["event_id"])
            counts["new"] += 1
            counts[route] += 1
            if counts["new"] >= event_limit:
                stop = True
                break
        if stop:
            break
        if source_observed == 0 and prior_cursor is not None:
            state["cursors"].pop(source["id"], None)
            if baseline_only:
                completed_sources.add(source["id"])
        elif baseline_only and source_observed < source["max_files"] and not counts["stopped"]:
            state["cursors"].pop(source["id"], None)
            completed_sources.add(source["id"])
        elif source_observed < source["max_files"]:
            state["cursors"].pop(source["id"], None)
    maximum = config["limits"]["max_state_entries"]
    if len(fingerprints) > maximum:
        if baseline_only:
            raise RuntimeErrorSafe("baseline exceeds state capacity; raise max_state_entries or reduce source scope")
        fingerprints = dict(list(fingerprints.items())[-maximum:])
    source_ids = {source["id"] for source in config["sources"]}
    baselined = state["baselined"] or (baseline_only and completed_sources == source_ids and not counts["stopped"])
    _atomic_json(state_path, {"schema_version": "0.2", "fingerprints": fingerprints, "cursors": state["cursors"],
                              "baseline_complete_sources": sorted(completed_sources), "baselined": baselined,
                              "config_hash": config_hash, "source_offset": (offset + 1) % len(sources)})
    validate_all_queues(root)
    return counts


def _update_control_state(state_path: Path, token: str, **updates) -> None:
    state = _read_json(state_path)
    if state.get("token") != token:
        raise RuntimeErrorSafe("control state does not belong to this observer")
    if state.get("pid") != os.getpid():
        if state.get("status") != "starting" or "ready_at" in state:
            raise RuntimeErrorSafe("control state does not belong to this observer")
        state["launcher_pid"] = state["pid"]
        state["pid"] = os.getpid()
    state.update(updates)
    _atomic_json(state_path, state)


def stop_requested(root: Path, token: str) -> bool:
    request = Path(root) / "runtime" / "stop-request.json"
    if not request.exists():
        return False
    try:
        value = _read_json(request)
    except RuntimeErrorSafe:
        return False
    return value.get("schema_version") == "0.2" and value.get("token") == token and value.get("action") == "stop"


def watch(config_path: Path, root: Path, state_path: Path, token: str) -> int:
    config = load_config(config_path, root)
    deadline = time.time() + 5
    while time.time() < deadline:
        if state_path.exists():
            try:
                staged = _read_json(state_path)
                if staged.get("token") == token and staged.get("pid", 0) > 0:
                    break
            except RuntimeErrorSafe:
                pass
        time.sleep(0.05)
    else:
        raise RuntimeErrorSafe("controller handshake timed out")
    from shadowctl import _process_command
    info = _process_command(os.getpid())
    if not info:
        raise RuntimeErrorSafe("OS process identity unavailable")
    _update_control_state(state_path, token, status="running", ready_at=utc_now(), heartbeat_at=utc_now(),
                          runtime_python=info["executable"],
                          process_identity={"created": info["created"], "executable": info["executable"]})
    stopping = False

    def request_stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, request_stop)
    while not stopping:
        try:
            counts = run_once(config_path, root, stop_check=lambda: stop_requested(root, token),
                              heartbeat=lambda: _update_control_state(state_path, token, heartbeat_at=utc_now()))
            degraded = bool(counts["source_errors"] or counts.get("review", {}).get("errors"))
            _update_control_state(state_path, token, status="error" if degraded else "running", heartbeat_at=utc_now(), last_scan=counts, last_error="SourceOrReviewError" if degraded else None)
        except Exception as exc:  # watcher must report failure without leaking content
            _update_control_state(state_path, token, status="error", heartbeat_at=utc_now(), last_error=type(exc).__name__)
        if stop_requested(root, token):
            stopping = True
            continue
        deadline = time.monotonic() + config["poll_seconds"]
        while not stopping and time.monotonic() < deadline:
            if stop_requested(root, token):
                stopping = True
                break
            time.sleep(min(0.25, max(0, deadline - time.monotonic())))
    _update_control_state(state_path, token, status="stopped", stopped_at=utc_now())
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="DAXXER bounded shadow observer")
    subparsers = parser.add_subparsers(dest="command", required=True)
    once = subparsers.add_parser("run-once")
    once.add_argument("--config", type=Path, required=True)
    once.add_argument("--root", type=Path, default=COMPONENT_ROOT)
    watcher = subparsers.add_parser("watch")
    watcher.add_argument("--config", type=Path, required=True)
    watcher.add_argument("--root", type=Path, required=True)
    watcher.add_argument("--state", type=Path, required=True)
    watcher.add_argument("--token", required=True)
    args = parser.parse_args(argv)
    try:
        requested_root = args.root.resolve()
        testing_root = os.environ.get("DAXXER_SHADOW_TEST_ROOT")
        if requested_root != COMPONENT_ROOT.resolve() and (not testing_root or requested_root != Path(testing_root).resolve()):
            raise RuntimeErrorSafe("runtime root is outside the bounded component")
        if args.config.resolve() != requested_root / "config" / "shadow-config.json" and not testing_root:
            raise RuntimeErrorSafe("runtime config must be the component configuration")
        if args.command == "run-once":
            print(json.dumps(run_once(args.config, args.root), sort_keys=True))
            return 0
        if args.state.resolve() != requested_root / "runtime" / "shadow-process.json":
            raise RuntimeErrorSafe("state must remain within the component runtime directory")
        return watch(args.config.resolve(), args.root.resolve(), args.state.resolve(), args.token)
    except (OSError, RuntimeErrorSafe, VILError) as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
