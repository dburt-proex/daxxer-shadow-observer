"""Standard-library tests for the bounded v0.2 observer."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from shadow_runtime import (AppendQueue, RuntimeErrorSafe, load_config, observe_file,
                            run_once, safety_exclusion)
from shadowctl import _process_alive, inspect_status, start, stop
from vil import VILError, assess


def config_value(root: Path, *, metadata_only=False, max_content_bytes=64, poll_seconds=0.2, first_run_mode="backfill") -> dict:
    return {
        "schema_version": "0.2",
        "first_run_mode": first_run_mode,
        "poll_seconds": poll_seconds,
        "limits": {"max_events_per_scan": 20, "max_content_bytes": max_content_bytes, "max_state_entries": 100},
        "safe_content_extensions": [".json", ".md", ".txt"],
        "excluded_directory_names": [".git", "node_modules", "venv", ".venv", "__pycache__"],
        "secret_name_patterns": [
            r"(^|[._-])\.env($|[._-])",
            r"(^|[._-])(secret|credential|password|api[-_]?key|private[-_]?key|id_rsa)($|[._-])",
            r"\.(pem|p12|pfx|key)$",
        ],
        "vil": {"thresholds": {"retain": 0.75, "queue": 0.45}},
        "sources": [{
            "id": "test-inbox", "path": str(root / "inbox"), "recursive": True,
            "max_depth": 3, "max_files": 20, "metadata_only": metadata_only,
            "relevance": 0.95, "source_quality": 0.9, "corroboration": 0.8,
        }],
    }


class ShadowRuntimeTests(unittest.TestCase):
    def setUp(self):
        (ROOT / "work").mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / "work")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "inbox").mkdir(parents=True)
        self.config_path = self.root / "shadow-config.json"
        self.write_config(config_value(self.root))

    def write_config(self, value):
        self.config_path.write_text(json.dumps(value), encoding="utf-8")

    def loaded(self):
        return load_config(self.config_path, self.root)

    def test_vil_uses_limiting_score_and_explicit_thresholds(self):
        high_signal = {"relevance": 1, "source_quality": 1, "freshness": 1, "actionability": 1}
        for verification, expected in [
            ({"traceability": 1, "completeness": 1, "corroboration": 1}, "retained"),
            ({"traceability": 0.5, "completeness": 0.5, "corroboration": 0.5}, "pending"),
            ({"traceability": 0.1, "completeness": 0.1, "corroboration": 0.1}, "rejected"),
        ]:
            result = assess(high_signal, verification)
            self.assertEqual(result["final"], min(result["weighted_signal"], result["weighted_verifiability"]))
            self.assertEqual(result["route"], expected)
            self.assertIn("shadow-intake-profile", result["model"])

    def test_vil_rejects_bad_dimensions_weights_and_thresholds(self):
        signal = {"relevance": 1, "source_quality": 1, "freshness": 1, "actionability": 1}
        verification = {"traceability": 1, "completeness": 1, "corroboration": 1}
        with self.assertRaises(VILError):
            assess({**signal, "invented": 1}, verification)
        with self.assertRaises(VILError):
            assess(signal, verification, thresholds={"retain": 0.4, "queue": 0.8})

    def test_malformed_config_fails_closed(self):
        for mutation in ("missing", "bad_regex", "bad_source_flag", "bad_limit"):
            value = config_value(self.root)
            if mutation == "missing":
                del value["sources"]
            elif mutation == "bad_regex":
                value["secret_name_patterns"] = ["["]
            elif mutation == "bad_source_flag":
                value["sources"][0]["metadata_only"] = "false"
            else:
                value["limits"]["max_content_bytes"] = 0
            self.write_config(value)
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeErrorSafe):
                self.loaded()

    def test_hidden_secret_symlink_and_blocked_directories_are_excluded(self):
        config = self.loaded()
        inbox = self.root / "inbox"
        paths = [inbox / ".hidden.md", inbox / "api-key.txt", inbox / "node_modules" / "note.md"]
        paths[2].parent.mkdir()
        for path in paths:
            path.write_text("safe", encoding="utf-8")
            self.assertIsNotNone(safety_exclusion(path, inbox, config))
        link = inbox / "linked.md"
        try:
            link.symlink_to(paths[0])
        except OSError:
            pass
        else:
            self.assertEqual(safety_exclusion(link, inbox, config), "symlink")

    def test_content_capture_requires_safe_extension_size_and_text(self):
        config = self.loaded()
        source = config["sources"][0]
        safe = self.root / "inbox" / "note.md"
        unsafe_extension = self.root / "inbox" / "program.py"
        too_large = self.root / "inbox" / "large.txt"
        safe.write_text("small note", encoding="utf-8")
        unsafe_extension.write_text("print('x')", encoding="utf-8")
        too_large.write_text("x" * 65, encoding="utf-8")
        self.assertEqual(observe_file(safe, source, config)["observation"]["content"], "small note")
        self.assertIsNone(observe_file(unsafe_extension, source, config)["observation"]["content"])
        self.assertIsNone(observe_file(too_large, source, config)["observation"]["content"])

    def test_secret_bearing_content_is_silently_excluded(self):
        config = self.loaded()
        for index, secret in enumerate((
            '"api_key": "sk-abcdefghijklmnopqrstuvwxyz123456"',
            "OPENAI_API_KEY=abcdefghijklmnopqrstuvwxyz123456",
            "Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
            "token=ghp_abcdefghijklmnopqrstuvwxyz123456",
        )):
            path = self.root / "inbox" / f"ordinary-{index}.md"
            path.write_text(secret, encoding="utf-8")
            with self.subTest(secret=index):
                self.assertIsNone(observe_file(path, config["sources"][0], config))

    def test_rejected_candidate_never_stores_raw_content(self):
        value = config_value(self.root)
        value["sources"][0].update(relevance=0.1, source_quality=0.1, corroboration=0)
        self.write_config(value)
        config = self.loaded()
        path = self.root / "inbox" / "low-value.md"
        path.write_text("harmless but low value", encoding="utf-8")
        candidate = observe_file(path, config["sources"][0], config)
        self.assertEqual(candidate["route"], "rejected")
        self.assertIsNone(candidate["observation"]["content"])
        self.assertEqual(candidate["observation"]["capture_reason"], "vil_rejected_metadata_only")

    def test_metadata_source_never_reads_or_hashes_content(self):
        value = config_value(self.root, metadata_only=True)
        self.write_config(value)
        config = self.loaded()
        path = self.root / "inbox" / "note.md"
        path.write_text("ordinary", encoding="utf-8")
        observation = observe_file(path, config["sources"][0], config)["observation"]
        self.assertTrue(observation["metadata_only"])
        self.assertIsNone(observation["content"])
        self.assertIsNone(observation["content_sha256"])

    def test_run_once_deduplicates_and_only_creates_candidate_queue(self):
        (self.root / "inbox" / "decision.md").write_text("Review this bounded candidate.", encoding="utf-8")
        first = run_once(self.config_path, self.root)
        second = run_once(self.config_path, self.root)
        self.assertEqual(first["new"], 1)
        self.assertEqual(second["new"], 0)
        self.assertEqual(second["duplicate"], 1)
        records = AppendQueue(self.root / "queue" / "retained" / "intake-events.jsonl").load()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["ledger_status"], "candidate_only")
        self.assertFalse((self.root / "data" / "episodes.jsonl").exists())

    def test_changed_file_produces_new_event_without_touching_source(self):
        path = self.root / "inbox" / "decision.md"
        path.write_text("first", encoding="utf-8")
        run_once(self.config_path, self.root)
        original_exists = path.exists()
        time.sleep(0.01)
        path.write_text("second", encoding="utf-8")
        result = run_once(self.config_path, self.root)
        self.assertEqual(result["new"], 1)
        self.assertTrue(original_exists and path.exists())
        self.assertEqual(path.read_text(encoding="utf-8"), "second")

    def test_append_chain_detects_tampering_and_torn_write(self):
        path = self.root / "inbox" / "decision.md"
        path.write_text("candidate", encoding="utf-8")
        run_once(self.config_path, self.root)
        queue_path = self.root / "queue" / "retained" / "intake-events.jsonl"
        queue = AppendQueue(queue_path)
        records = queue.load()
        records[0]["observation"]["size"] += 1
        queue_path.write_text(json.dumps(records[0], separators=(",", ":")) + "\n", encoding="utf-8")
        with self.assertRaises(RuntimeErrorSafe):
            queue.load()
        queue_path.write_text("{}", encoding="utf-8")
        with self.assertRaises(RuntimeErrorSafe):
            queue.load()

    def test_strict_queue_rejects_duplicate_keys_nonfinite_and_forged_route(self):
        path = self.root / "inbox" / "decision.md"
        path.write_text("candidate", encoding="utf-8")
        run_once(self.config_path, self.root)
        queue_path = self.root / "queue" / "retained" / "intake-events.jsonl"
        original = queue_path.read_text(encoding="utf-8")
        record = json.loads(original)
        record["route"] = "pending"
        record["content_hash"] = __import__("shadow_runtime").event_hash(record)
        queue_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
        with self.assertRaises(RuntimeErrorSafe):
            AppendQueue(queue_path).load()
        queue_path.write_text('{"x":1,"x":2}\n', encoding="utf-8")
        with self.assertRaises(RuntimeErrorSafe):
            AppendQueue(queue_path).load()
        queue_path.write_text('{"x":NaN}\n', encoding="utf-8")
        with self.assertRaises(RuntimeErrorSafe):
            AppendQueue(queue_path).load()

    def test_baseline_mode_emits_no_history_then_observes_change(self):
        self.write_config(config_value(self.root, first_run_mode="baseline"))
        path = self.root / "inbox" / "existing.md"
        path.write_text("existing", encoding="utf-8")
        first = run_once(self.config_path, self.root)
        self.assertEqual(first["new"], 0)
        self.assertEqual(first["baselined"], 1)
        path.write_text("changed", encoding="utf-8")
        second = run_once(self.config_path, self.root)
        self.assertEqual(second["new"], 1)

    def test_stop_check_prevents_append_and_partial_baseline_completion(self):
        self.write_config(config_value(self.root, first_run_mode="baseline"))
        (self.root / "inbox" / "existing.md").write_text("existing", encoding="utf-8")
        result = run_once(self.config_path, self.root, stop_check=lambda: True)
        self.assertTrue(result["stopped"])
        state = json.loads((self.root / "runtime" / "scan-state.json").read_text(encoding="utf-8"))
        self.assertFalse(state["baselined"])

    def test_future_timestamp_is_penalized(self):
        config = self.loaded()
        path = self.root / "inbox" / "future.md"
        path.write_text("candidate", encoding="utf-8")
        future = time.time() + 86400
        os.utime(path, (future, future))
        candidate = observe_file(path, config["sources"][0], config, observed_epoch=time.time())
        self.assertEqual(candidate["vil"]["signal"]["freshness"], 0.0)

    def test_stop_refuses_live_pid_when_identity_does_not_match(self):
        runtime = self.root / "runtime"
        runtime.mkdir()
        state = {
            "schema_version": "0.2", "pid": os.getpid(), "token": "test-token",
            "root": str(self.root.resolve()), "config": str(self.config_path.resolve()),
            "script": str((ROOT / "scripts" / "shadow_runtime.py").resolve()),
            "python": str(Path(sys.executable).resolve()), "status": "running", "created_at": "2026-09-18T00:00:00+00:00",
        }
        (runtime / "shadow-process.json").write_text(json.dumps(state), encoding="utf-8")
        with self.assertRaises(RuntimeErrorSafe):
            stop(self.root, command_reader=lambda _pid: "some unrelated process")
        self.assertTrue(_process_alive(os.getpid()))

    def test_on_status_off_controls_only_verified_observer(self):
        started = None
        try:
            started = start(self.root, self.config_path)
            self.assertTrue(started["running"] and started["verified"])
            status = inspect_status(self.root)
            self.assertEqual(status["state"], "on")
            stopped = stop(self.root)
            self.assertTrue(stopped["changed"])
            self.assertFalse(stopped["running"])
            self.assertFalse(_process_alive(started["pid"]))
            self.assertEqual(inspect_status(self.root)["state"], "off")
        finally:
            if started and _process_alive(started["pid"]):
                # Only the PID launched by this test can reach this cleanup path.
                try:
                    stop(self.root)
                except Exception:
                    if os.name == "nt":
                        handle = __import__("ctypes").windll.kernel32.OpenProcess(1, False, started["pid"])
                        if handle:
                            __import__("ctypes").windll.kernel32.TerminateProcess(handle, 1)
                            __import__("ctypes").windll.kernel32.CloseHandle(handle)
                    else:
                        os.kill(started["pid"], 15)


if __name__ == "__main__":
    unittest.main()
