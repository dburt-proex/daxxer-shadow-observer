"""Single entry point for the bounded local observer."""
import argparse
import json
from pathlib import Path
import sys

from ledger import Ledger, ROOT, parse
from reviewer import configure_model, initialize, review_queue, settings
from shadow_runtime import _load_all_routes, load_config, run_once, validate_all_queues
from shadowctl import inspect_status, start, stop
from storage import file_lock, safe_path
from summarize_experience import generate


def validation(root=ROOT):
    with file_lock(safe_path(root, "runtime/.scan.lock")):
        validate_all_queues(root)
        queue = _load_all_routes(root)
        with Ledger(root).lock():
            result = Ledger(root).summary()
        result["intake_events"] = len(queue)
        result["routes"] = {route: sum(e["route"] == route for e in queue) for route in ("pending", "retained", "rejected")}
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("init", "on", "off", "status", "scan", "review", "validate", "summary", "record", "model", "rules"))
    parser.add_argument("--name", help="already installed local Ollama model")
    parser.add_argument("--input", type=Path)
    parser.add_argument("--record-id")
    parser.add_argument("--kind", choices=("episode", "outcome", "correction"), default="episode")
    parser.add_argument("--supersedes")
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            initialize()
            load_config(ROOT / "config/shadow-config.json")
            settings(ROOT)
            result = {"initialized": True, "status": inspect_status()}
        elif args.command == "on":
            initialize()
            settings(ROOT)
            result = start()
        elif args.command == "off":
            result = stop()
        elif args.command == "status":
            result = inspect_status()
            result["reviewer"] = settings(ROOT)
        elif args.command in ("model", "rules"):
            if args.command == "model" and not args.name:
                parser.error("model requires --name")
            result = configure_model(args.name if args.command == "model" else None)
        elif args.command == "scan":
            initialize()
            result = run_once(ROOT / "config/shadow-config.json")
        elif args.command == "review":
            with file_lock(safe_path(ROOT, "runtime/.scan.lock")):
                result = review_queue()
        elif args.command == "validate":
            result = validation()
        elif args.command == "summary":
            result = validation()
            result["report"] = str(generate())
        else:
            if not args.input or not args.record_id:
                parser.error("record requires --input and --record-id")
            record = Ledger().append(args.kind, args.record_id, parse(args.input.read_text(encoding="utf-8")), args.supersedes)
            result = {"record_id": record["record_id"], "content_hash": record["content_hash"],
                      "training_eligibility": record["training_eligibility"]}
        print(json.dumps(result, sort_keys=True, ensure_ascii=False))
        return 1 if result.get("errors") or result.get("source_errors") or result.get("review", {}).get("errors") or result.get("state") in ("error", "unverified", "stale") else 0
    except (OSError, ValueError, UnicodeError, KeyError, TypeError) as exc:
        # Exception text from network/model parsers may include secret input.
        print(json.dumps({"state": "error", "error": type(exc).__name__, "message": "Operation failed; preserve records and inspect configuration or validation."}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
