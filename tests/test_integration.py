"""Safety and end-to-end checks using disposable local data and model mocks."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from ledger import Ledger, canonical, record_hash
from reviewer import initialize, model_advice, review_queue, settings
from shadow import validation
from shadow_runtime import AppendQueue, RuntimeErrorSafe, _iter_files, digest, event_hash, load_config, observe_file, run_once
from storage import StorageError, file_lock, safe_path
from summarize_experience import generate
import shadowctl
from test_shadow_runtime import config_value


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        # Windows TEMP can use an 8.3 alias; source configuration resolves it.
        self.root = Path(self.temp.name).resolve()
        initialize(self.root)
        (self.root / "config").mkdir()
        self.config = self.root / "config/shadow-config.json"
        self.value = config_value(self.root, max_content_bytes=4096)
        self.config.write_text(json.dumps(self.value), encoding="utf-8")
        self.review = {"enabled": True, "mode": "rules", "model": None, "max_per_scan": 10, "timeout_seconds": 1}
        self.write_review()

    def write_review(self):
        (self.root / "config/reviewer.json").write_text(json.dumps(self.review), encoding="utf-8")

    def note(self, text="Review the current DAXXER build.", name="note.md"):
        path = self.root / "inbox" / name
        path.parent.mkdir(exist_ok=True, parents=True)
        path.write_text(text, encoding="utf-8")
        return path

    def capture(self):
        self.note()
        return run_once(self.config, self.root)

    def event(self):
        self.capture()
        return AppendQueue(self.root / "queue/retained/intake-events.jsonl").load()[0]

    def test_automatic_flow_records_incomplete_and_deduplicates(self):
        first = self.capture()
        self.assertEqual(first["review"]["captured"], 1)
        record = Ledger(self.root).load()[0]
        self.assertEqual(record["payload"]["status"], "incomplete")
        self.assertIsNone(record["payload"]["actual"]["decision"])
        self.assertIsNone(record["payload"]["outcome"]["success"])
        self.assertFalse(record["training_eligibility"]["eligible"])
        self.assertEqual(record["payload"]["shadow"]["gate"], "REVIEW")
        before = (self.root / "data/episodes.jsonl").read_bytes()
        run_once(self.config, self.root)
        self.assertEqual(before, (self.root / "data/episodes.jsonl").read_bytes())
        result = validation(self.root)
        self.assertEqual(result["episodes_captured"], 1)
        self.assertEqual(result["intake_events"], 1)
        self.assertIn("incomplete", generate(self.root).read_text())

    def test_source_stays_unchanged_and_evidence_survives_source_changes(self):
        path = self.note()
        before = path.read_bytes()
        run_once(self.config, self.root)
        self.assertEqual(path.read_bytes(), before)
        path.write_text("A later change.", encoding="utf-8")
        self.assertEqual(Ledger(self.root).summary()["records"], 1)
        run_once(self.config, self.root)
        self.assertEqual(Ledger(self.root).summary()["records"], 2)

    def test_rejected_candidates_do_not_become_episodes(self):
        self.value["sources"][0].update(relevance=0, source_quality=0)
        self.config.write_text(json.dumps(self.value))
        self.capture()
        self.assertEqual(Ledger(self.root).summary()["records"], 0)
        events = AppendQueue(self.root / "queue/rejected/intake-events.jsonl").load()
        self.assertIsNone(events[0]["observation"]["content"])

    def test_secret_patterns_cover_inline_json_yaml_and_prefixed_variables(self):
        samples = ['{"ordinary": 1, "client_secret": "syntheticabcd"}',
                   "SERVICE_ACCESS_TOKEN=syntheticabcd", "password: abcdefg",
                   "-----BEGIN PRIVATE KEY-----"]
        for index, text in enumerate(samples):
            self.note(text, str(index) + ".md")
        self.assertEqual(run_once(self.config, self.root)["new"], 0)
        self.assertEqual(list((self.root / "evidence").glob("*.json")), [])

    def test_baseline_never_reads_content_or_ingests_unchanged_history(self):
        self.value["first_run_mode"] = "baseline"
        self.config.write_text(json.dumps(self.value))
        source = self.note()
        original_open = Path.open
        def guarded_open(path, *args, **kwargs):
            if path == source:
                raise AssertionError("baseline must not open source content")
            return original_open(path, *args, **kwargs)
        with patch.object(Path, "open", new=guarded_open):
            run_once(self.config, self.root)
        self.assertEqual(run_once(self.config, self.root)["new"], 0)
        self.assertEqual(Ledger(self.root).summary()["records"], 0)

    def test_scan_lock_refuses_overlapping_scans(self):
        self.note()
        with file_lock(safe_path(self.root, "runtime/.scan.lock")):
            with self.assertRaises(RuntimeErrorSafe):
                run_once(self.config, self.root)
        self.assertEqual(run_once(self.config, self.root)["new"], 1)

    def test_lock_released_after_crashed_writer(self):
        target = self.root / "runtime/test.lock"
        code = "from storage import file_lock; import os,sys;\nwith file_lock(sys.argv[1]): os._exit(9)"
        result = subprocess.run([sys.executable, "-B", "-c", code, str(target)], cwd=Path(__file__).resolve().parents[1] / "scripts")
        self.assertEqual(result.returncode, 9)
        with file_lock(target):
            pass

    def test_storage_links_refused_without_touching_target(self):
        outside = self.root / "outside"
        outside.mkdir()
        link = self.root / "linked"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest("OS does not allow symlink creation")
        with self.assertRaises(StorageError):
            safe_path(self.root, "linked/new.json")
        self.assertFalse((outside / "new.json").exists())

    def test_containment_rejects_parent_absolute_and_drive(self):
        for relative in ("../escape", str(self.root.absolute())):
            with self.subTest(relative=relative), self.assertRaises(StorageError):
                safe_path(self.root, relative)

    def test_queue_refuses_forged_candidate_before_any_write(self):
        event = self.event()
        event["event_id"] = "DXI-" + "A" * 24
        candidate = {k:v for k,v in event.items() if k not in {"schema_version", "sequence", "recorded_at", "previous_hash", "content_hash"}}
        path = self.root / "queue/retained/intake-events.jsonl"
        before = path.read_bytes()
        with self.assertRaises(RuntimeErrorSafe):
            AppendQueue(path).append(candidate)
        self.assertEqual(before, path.read_bytes())
        self.assertEqual(list(path.parent.glob("*.tmp")), [])

    def test_queue_rejects_rehashed_forged_provenance(self):
        event = self.event()
        event["observation"]["source_root"] += "/fake"
        event["content_hash"] = event_hash(event)
        path = self.root / "queue/retained/intake-events.jsonl"
        path.write_bytes(canonical(event) + b"\n")
        with self.assertRaises(RuntimeErrorSafe):
            AppendQueue(path).load()

    def test_revoked_sources_are_not_reviewed(self):
        self.review["enabled"] = False
        self.write_review()
        self.capture()
        self.review["enabled"] = True
        self.write_review()
        self.value["sources"][0]["metadata_only"] = True
        self.config.write_text(json.dumps(self.value))
        self.assertEqual(review_queue(self.root)["errors"], 1)
        self.assertEqual(Ledger(self.root).summary()["records"], 0)

    def test_deleted_cursor_does_not_starve_later_files(self):
        config = load_config(self.config, self.root)
        self.note(name="a.md")
        self.note(name="b.md")
        self.note(name="c.md")
        (self.root / "inbox/b.md").unlink()
        paths = list(_iter_files(config["sources"][0], config, "b.md"))
        self.assertEqual([p.name for p in paths], ["c.md"])

    def test_directory_order_is_consistent_with_cursor_order(self):
        self.note(name="a/child.md")
        self.note(name="a.md")
        config = load_config(self.config, self.root)
        names = [p.relative_to(self.root / "inbox").as_posix() for p in _iter_files(config["sources"][0], config)]
        self.assertEqual(names, sorted(names))

    def test_rotation_prevents_busy_source_starvation(self):
        other = self.root / "other"
        other.mkdir()
        self.value["limits"]["max_events_per_scan"] = 1
        self.value["sources"].append({**self.value["sources"][0], "id":"another-source", "path":str(other)})
        self.config.write_text(json.dumps(self.value))
        self.note(name="a.md")
        self.note(name="b.md")
        (other / "c.md").write_text("Other source")
        run_once(self.config, self.root)
        run_once(self.config, self.root)
        self.assertEqual(Ledger(self.root).summary()["records"], 2)
        sources = {r["payload"]["context"]["evidence"][0]["source"] for r in Ledger(self.root).load()}
        self.assertTrue(any("other" in s for s in sources))

    def test_relative_source_paths_fail_closed(self):
        self.value["sources"][0]["path"] = "arbitrary-directory"
        self.config.write_text(json.dumps(self.value))
        with self.assertRaises(RuntimeErrorSafe):
            load_config(self.config, self.root)

    def test_model_configuration_forbids_cloud_names(self):
        self.review.update(mode="ollama", model="some:cloud")
        self.write_review()
        with self.assertRaises(StorageError):
            settings(self.root)

    def model_config(self):
        return {"mode":"ollama", "model":"test-local:1b", "timeout_seconds":1}

    def good_transport(self, endpoint, payload, timeout):
        if endpoint == "show":
            return {"model_info":{"general.architecture":"test"}}
        self.assertNotIn("tools", payload)
        self.assertEqual(payload["format"]["additionalProperties"], False)
        return {"done":True, "message":{"content":json.dumps({"interpretation":"Unverified source note.", "recommendation":"Seek human review.", "lesson":"Verify outcomes first."})}}

    def test_model_advice_has_no_authority_fields(self):
        advice = model_advice(self.event(), self.model_config(), self.good_transport)
        self.assertEqual(set(advice), {"interpretation","recommendation","lesson"})

    def test_remote_model_is_rejected_before_sending_evidence(self):
        endpoints = []
        def transport(endpoint, payload, timeout):
            endpoints.append(endpoint)
            return {"remote_host":"https://example.invalid", "model_info":{"general.architecture":"test"}}
        with self.assertRaises(StorageError):
            model_advice(self.event(), self.model_config(), transport)
        self.assertEqual(endpoints, ["show"])

    def test_model_failure_keeps_unknown_and_no_fallback_episode(self):
        self.review.update(mode="ollama", model="test-local:1b")
        self.write_review()
        self.note()
        with patch("reviewer.model_advice", side_effect=TimeoutError()):
            result = run_once(self.config, self.root)
        self.assertEqual(result["review"]["errors"], 1)
        self.assertEqual(Ledger(self.root).summary()["records"], 0)
        result = review_queue(self.root, transport=self.good_transport)
        self.assertEqual(result["captured"], 1)
        record = Ledger(self.root).load()[0]
        self.assertFalse(record["payload"]["outcome"]["verified"])
        self.assertFalse(record["training_eligibility"]["eligible"])
        self.assertEqual(record["payload"]["context"]["claims"][1]["classification"], "INTERPRETATION")

    def test_model_tool_calls_and_missing_output_fail(self):
        for result in ({"done":False}, {"done":True,"message":{"content":"{}", "tool_calls":[{}]}},
                       {"done":True,"message":{"content":"not json"}}):
            def transport(endpoint, payload, timeout):
                return self.good_transport(endpoint,payload,timeout) if endpoint == "show" else result
            with self.subTest(result=result), self.assertRaises((StorageError, KeyError)):
                model_advice(self.event(), self.model_config(), transport)

    def test_queue_content_hash_is_checked(self):
        event = self.event()
        event["observation"]["content"] += "changed"
        event["content_hash"] = event_hash(event)
        path = self.root / "queue/retained/intake-events.jsonl"
        path.write_bytes(canonical(event) + b"\n")
        with self.assertRaises(RuntimeErrorSafe):
            AppendQueue(path).load()

    def test_init_preserves_existing_records(self):
        self.capture()
        before = (self.root / "data/episodes.jsonl").read_bytes()
        initialize(self.root)
        self.assertEqual(before, (self.root / "data/episodes.jsonl").read_bytes())

    def test_off_timeout_never_claims_stopped_or_forces_a_kill(self):
        state = {"schema_version": "0.2", "pid": os.getpid(), "token": "synthetic-stop",
                 "root":str(self.root), "config":str(self.config),
                 "script":str(shadowctl.SCRIPT), "python":sys.executable,
                 "status":"running", "created_at":"2026-09-28T00:00:00+00:00"}
        path = self.root / "runtime/shadow-process.json"
        path.write_text(json.dumps(state))
        with patch("shadowctl._process_alive", return_value=True), patch("shadowctl._identity_matches", return_value=True):
            with self.assertRaises(RuntimeErrorSafe):
                shadowctl.stop(self.root, command_reader=lambda pid:{}, wait_seconds=0)
        self.assertEqual(json.loads(path.read_text())["status"], "running")
        self.assertTrue((self.root / "runtime/stop-request.json").exists())
        self.assertFalse(hasattr(shadowctl, "_terminate"))

    def test_controller_cli_refuses_output_root_escape(self):
        result = subprocess.run([sys.executable, "-B", str(shadowctl.SCRIPT.with_name("shadowctl.py")),
                                 "run-once", "--root", str(self.root)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(Ledger(self.root).summary()["records"], 0)


if __name__ == "__main__":
    unittest.main()
