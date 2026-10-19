#!/usr/bin/env python3
"""Command-line entry point for the attacker-verifier engine.

Subcommands, in the order a run uses them:

    select-targets   Rank attack targets in a scope and write targets.json.
    check            Screen probes for faithfulness, run the admitted ones in a
                     sandbox, apply the crash oracle, and write run.json plus a
                     traces file for any trace the deterministic stage leaves
                     undecided.
    show-traces      Print those traces compactly for the trace judge.
    finalize         Merge the trace-judge verdicts into run.json, aggregate the
                     signal, and with --out write the Markdown report.
    session          Read or write the per-session execution-mode marker.
    config           Print the effective configuration.
    version          Print the engine version.

The coding agent runs these around its own two jobs -- proposing probes and
judging the undecided traces -- as described in the skill instructions. Each
run command prints a summary whose first line names the FALCON stage it ran
(see ``display.py``).
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import __version__, config as config_mod  # noqa: E402
from engine import display, faithfulness, models as models_mod, report, runner, targets as targets_mod, verifier  # noqa: E402

STDOUT_EXCERPT = 1500


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _say(text: str) -> None:
    sys.stdout.write(text if text.endswith("\n") else text + "\n")
    sys.stdout.flush()


def _load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _write_json(path: str, data: Any) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)


def _repo_name(repo_root: str) -> str:
    return os.path.basename(os.path.abspath(repo_root)) or "repo"


def _trace_excerpt(trace: Dict[str, Any]) -> Dict[str, Any]:
    stdout = trace.get("stdout", "") or ""
    return {
        "target": trace.get("target", {}),
        "target_seen": trace.get("target_seen", False),
        "target_active_at_exit": trace.get("target_active", False),
        "frames": trace.get("frames", []),
        "observations": [o.get("parsed", o.get("raw")) for o in trace.get("observations", [])],
        "stdout": stdout[:STDOUT_EXCERPT],
        "stderr": (trace.get("stderr", "") or "")[:600],
        "top_level_exception": trace.get("top_level_exception"),
        "returncode": trace.get("returncode"),
        "killed_by_signal": trace.get("killed_by_signal", False),
        "signal": trace.get("signal"),
        "timed_out": trace.get("timed_out", False),
        "duration_s": trace.get("duration_s"),
    }


# --------------------------------------------------------------------------- #
# select-targets
# --------------------------------------------------------------------------- #
def cmd_select_targets(args: argparse.Namespace) -> int:
    cfg = config_mod.load_config(args.repo, args.config_json)
    # Run files usually live under .attacker-verifier/runs/; make sure git ignores them
    # before the agent writes its probes there.
    runner.ensure_state_dir(os.path.abspath(args.repo))
    found = targets_mod.select_targets(
        args.repo, scope=args.scope, path=args.path, max_targets=cfg["max_targets"]
    )
    for target in found:
        target.pop("source", None)  # keep targets.json small; skill re-reads files
    skipped = targets_mod.not_attacked(args.repo, scope=args.scope, path=args.path)
    payload = {
        "schema": "attacker-verifier/targets@1",
        "repo_root": os.path.abspath(args.repo),
        "scope": args.scope,
        "path": args.path,
        "max_targets": cfg["max_targets"],
        "probes_min": cfg["probes_min"],
        "probes_max": cfg["probes_max"],
        "targets": found,
        "not_attacked": skipped,
    }
    _write_json(args.out, payload)
    _say(display.targets_block(payload, args.turn))
    return 0


# --------------------------------------------------------------------------- #
# check
# --------------------------------------------------------------------------- #
def _resolve_target(repo_root: str, target_str: str, lookup: Dict[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    target_str = target_str.strip()
    if target_str in lookup:
        return lookup[target_str]
    if "::" in target_str:
        file_part, qual = target_str.split("::", 1)
    elif ":" in target_str and target_str.count(":") == 1:
        file_part, qual = target_str.split(":", 1)
    else:
        # Match by qualname alone if unambiguous.
        matches = [t for t in lookup.values() if t["qualname"] == target_str]
        return matches[0] if len(matches) == 1 else None
    file_part = file_part.strip()
    qual = qual.strip()
    key = "%s::%s" % (file_part, qual)
    if key in lookup:
        return lookup[key]
    abspath = os.path.join(repo_root, file_part)
    if os.path.isfile(abspath):
        return {"file": file_part, "qualname": qual, "kind": "function", "lineno": None, "score": 0}
    return None


def _module_path(rel_file: str) -> str:
    """Dotted import path of a repository file, e.g. ``app/files.py`` -> ``app.files``."""
    parts = os.path.splitext(rel_file.replace(os.sep, "/"))[0].split("/")
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(p for p in parts if p)


def cmd_check(args: argparse.Namespace) -> int:
    cfg = config_mod.load_config(args.repo, args.config_json)
    repo_root = os.path.abspath(args.repo)
    targets_doc = _load_json(args.targets)
    probes_doc = _load_json(args.probes)

    lookup: Dict[str, Dict[str, Any]] = {}
    for target in targets_doc.get("targets", []):
        lookup["%s::%s" % (target["file"], target["qualname"])] = target

    probe_list = probes_doc.get("probes", [])
    probed_targets = {str(p.get("target", "")).strip() for p in probe_list}
    _say(display.check_header(len(probe_list), len(probed_targets), args.turn))

    traces_dir = args.traces_dir or os.path.join(os.path.dirname(os.path.abspath(args.out)), "traces")
    os.makedirs(traces_dir, exist_ok=True)

    results: List[Dict[str, Any]] = []
    uncertain: List[Dict[str, Any]] = []

    for order, probe in enumerate(probe_list):
        probe_id = str(probe.get("id") or "probe_%d" % order)
        target_str = str(probe.get("target", ""))
        target = _resolve_target(repo_root, target_str, lookup)
        record: Dict[str, Any] = {
            "id": probe_id,
            "target": {"file": (target or {}).get("file"), "qualname": (target or {}).get("qualname"),
                       "lineno": (target or {}).get("lineno")},
            "cwe": probe.get("cwe"),
            "rationale": probe.get("rationale"),
        }

        if target is None:
            record.update(status="inconclusive",
                          faithfulness={"stage": "runtime", "rule": "target_not_inferred",
                                        "detail": "probe names no resolvable target: %r" % target_str})
            results.append(record)
            _say(display.probe_line(record))
            continue

        script = probe.get("script", "")
        # Stage the probe inside the repo so its imports resolve from the root.
        probe_path = os.path.join(runner.ensure_state_dir(repo_root), "probes", "%s.py" % _safe_name(probe_id))
        os.makedirs(os.path.dirname(probe_path), exist_ok=True)
        with open(probe_path, "w", encoding="utf-8") as handle:
            handle.write(script)
        record["probe_path"] = os.path.relpath(probe_path, repo_root)

        fstat = faithfulness.static_check(script, target["qualname"], _module_path(target["file"]))
        if not fstat["admitted"]:
            record.update(status="rejected_static",
                          faithfulness={"stage": "static", "rule": fstat["rule"], "detail": fstat["detail"]})
            results.append(record)
            _say(display.probe_line(record))
            continue

        target_file_abs = os.path.join(repo_root, target["file"])
        trace = runner.run_probe(repo_root, probe_path, target_file_abs, target["qualname"], cfg,
                                 target_kind=target.get("kind", "function"))

        fatt = faithfulness.runtime_check(trace, target["qualname"])
        if not fatt["admitted"]:
            record.update(status="inconclusive",
                          faithfulness={"stage": "runtime", "rule": fatt["rule"], "detail": fatt["detail"]})
            results.append(record)
            _say(display.probe_line(record))
            continue

        core = verifier.core_verdict(trace)
        excerpt = _trace_excerpt(trace)
        record.update(status="admitted", faithfulness={"stage": None, "rule": None, "detail": ""},
                      core=core, trace_excerpt=excerpt)
        results.append(record)

        if core["verdict"] != verifier.INSECURE:
            trace_path = os.path.join(traces_dir, "%s.json" % _safe_name(probe_id))
            _write_json(trace_path, excerpt)
            uncertain.append({"id": probe_id, "target": record["target"],
                              "cwe": probe.get("cwe"), "rationale": probe.get("rationale"),
                              "trace": excerpt})
        _say(display.probe_line(record))

    run = {
        "schema": "attacker-verifier/run@1",
        "tool_version": __version__,
        "repo_name": _repo_name(repo_root),
        "repo_root": repo_root,
        "scope": targets_doc.get("scope"),
        "path": targets_doc.get("path"),
        "execution": {k: cfg["execution"].get(k) for k in ("mode", "image", "container")},
        "config": _safe_config(cfg),
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "targets": targets_doc.get("targets", []),
        "not_attacked": targets_doc.get("not_attacked", []),
        "results": results,
    }
    _write_json(args.out, run)

    judge_doc = {
        "schema": "attacker-verifier/traces@1",
        "instructions": "Judge each trace with the stage-3 trace-judge prompt. "
                        "Write verdicts to a JSON object mapping probe id -> "
                        "{verdict: secure|insecure, reason, evidence, confidence}.",
        "traces": uncertain,
    }
    _write_json(args.traces_out, judge_doc)

    _say("\n".join(display.check_summary(results, len(uncertain))))
    return 0


def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name)[:80] or "probe"


def _safe_config(cfg: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(cfg)
    return out


# --------------------------------------------------------------------------- #
# finalize
# --------------------------------------------------------------------------- #
def cmd_finalize(args: argparse.Namespace) -> int:
    run = _load_json(args.run)
    verdicts = _load_json(args.verdicts) if args.verdicts and os.path.isfile(args.verdicts) else {}

    results = run.get("results", [])
    by_target: Dict[str, List[Dict[str, Any]]] = {}
    # Every selected target is reported; one the attacker wrote no probe for
    # has no evidence.
    for target in run.get("targets", []):
        by_target.setdefault("%s::%s" % (target.get("file"), target.get("qualname")), [])
    for record in results:
        key = "%s::%s" % (record["target"].get("file"), record["target"].get("qualname"))
        by_target.setdefault(key, []).append(record)

    per_target: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    rule_counts: Dict[str, int] = {}
    total_admitted = total_rejected = total_inconclusive = total_undecided = 0

    overall = verifier.NO_EVIDENCE
    for key, records in by_target.items():
        agg = verifier.aggregate(records, verdicts)
        admitted = sum(1 for r in records if r["status"] == "admitted")
        rejected = sum(1 for r in records if r["status"] == "rejected_static")
        inconclusive = sum(1 for r in records if r["status"] == "inconclusive")
        total_admitted += admitted
        total_rejected += rejected
        total_inconclusive += inconclusive
        total_undecided += sum(1 for r in agg["resolved"] if r["verdict"] == verifier.UNCERTAIN)
        for record in records:
            rule = record.get("faithfulness", {}).get("rule")
            if rule:
                rule_counts[rule] = rule_counts.get(rule, 0) + 1

        file_part, _, qual = key.partition("::")
        per_target.append({
            "file": file_part, "qualname": qual, "signal": agg["signal"],
            "admitted": admitted, "rejected_static": rejected, "inconclusive": inconclusive,
        })

        if agg["signal"] == verifier.INSECURE:
            overall = verifier.INSECURE
        elif overall != verifier.INSECURE and agg["signal"] == verifier.SECURE:
            overall = verifier.SECURE

        for counter in agg["counterexamples"]:
            record = next((r for r in records if r["id"] == counter["id"]), {})
            findings.append({
                "id": counter["id"],
                "stage": counter["stage"],
                "reason": counter["reason"],
                "evidence": counter.get("evidence", ""),
                "cwe": record.get("cwe"),
                "target": record.get("target", {}),
                "trace_excerpt": json.dumps(record.get("trace_excerpt", {}), indent=2)
                if record.get("trace_excerpt") else "",
            })

    rank = {verifier.INSECURE: 0, verifier.SECURE: 1}
    per_target.sort(key=lambda r: (rank.get(r["signal"], 2), r["file"], r["qualname"]))
    findings.sort(key=lambda f: (f.get("stage") or 9, f["target"].get("file", "")))

    stats = {
        "targets": len(by_target),
        "probes_total": len(results),
        "admitted": total_admitted,
        "rejected_static": total_rejected,
        "inconclusive": total_inconclusive,
        "undecided": total_undecided,
        "findings": len(findings),
        "targets_insecure": sum(1 for r in per_target if r["signal"] == "insecure"),
        "rule_counts": rule_counts,
    }

    execution = run.get("execution", {})
    execution_label = execution.get("mode", "host")
    if execution.get("mode") == "docker":
        execution_label = "docker (%s)" % (execution.get("image") or execution.get("container") or "?")

    scope_label = run.get("scope", "whole")
    if run.get("path"):
        scope_label = "%s · %s" % (scope_label, run["path"])

    final = {
        "signal": overall,
        "meta": {
            "repo_name": run.get("repo_name", "repo"),
            "generated_at": run.get("generated_at", datetime.datetime.now().isoformat(timespec="seconds")),
            "scope_label": scope_label,
            "execution_label": execution_label,
            "tool_version": run.get("tool_version", __version__),
            "skipped_languages": args.skipped.split(",") if args.skipped else [
                "%s (not Python)" % rel for rel in run.get("not_attacked", [])],
        },
        "stats": stats,
        "findings": findings,
        "per_target": per_target,
        "config_json": json.dumps(run.get("config", {}), indent=2),
    }

    # The Markdown report is written only when asked for (--out): the repair loop
    # of /secure-code-generation finalizes every turn and reads final.json.
    out_path = args.out
    if args.report_dir:
        out_path = os.path.join(args.report_dir, "%s_%s.md" % (
            _safe_name(final["meta"]["repo_name"]), datetime.datetime.now().strftime("%Y%m%d-%H%M%S")))
    if out_path:
        with open(out_path, "w", encoding="utf-8") as handle:
            handle.write(report.render_markdown(final))
    if args.final_out:
        _write_json(args.final_out, final)

    _say(display.final_block(final, args.turn, out_path))
    return 0


# --------------------------------------------------------------------------- #
# session / config / version
# --------------------------------------------------------------------------- #
def cmd_session(args: argparse.Namespace) -> int:
    marker = os.path.join(args.data_dir, "sessions", "%s.json" % _safe_name(args.session_id))
    if args.set_json is not None:
        execution = json.loads(args.set_json)
        _write_json(marker, execution)
        _say("FALCON sandbox: probes run %s for the rest of this session" % _where(execution))
        return 0
    if os.path.isfile(marker):
        execution = _load_json(marker)
        _say("FALCON sandbox: probes run %s (chosen earlier in this session)" % _where(execution))
        _say(json.dumps(execution))
        return 0
    _say("FALCON sandbox: not chosen yet for this session")
    return 0


def _where(execution: Dict[str, Any]) -> str:
    if execution.get("mode") == "docker":
        return "in docker (%s)" % (execution.get("image") or execution.get("container") or "?")
    return "on the host"


def cmd_show_traces(args: argparse.Namespace) -> int:
    _say(display.traces_block(_load_json(args.traces).get("traces", []), args.turn))
    return 0


def cmd_config(args: argparse.Namespace) -> int:
    cfg = config_mod.load_config(args.repo, args.config_json)
    print(json.dumps(cfg, indent=2))
    return 0


def cmd_resolve_model(args: argparse.Namespace) -> int:
    resolved = models_mod.resolve(args.model)
    if resolved is None:
        sys.stderr.write("attacker-verifier: unknown or unsupported model: %r\n" % args.model)
        return 1
    print(resolved)
    return 0


def cmd_list_models(args: argparse.Namespace) -> int:
    found = models_mod.list_models()
    for model in found:
        print(model["name"])
    return 0


def cmd_version(_args: argparse.Namespace) -> int:
    print(__version__)
    return 0


# --------------------------------------------------------------------------- #
# argument parsing
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="attacker-verifier", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    common_repo = {"default": ".", "help": "repository root (default: current dir)"}
    common_cfg = {"default": None, "help": "inline JSON config override"}
    common_turn = {"default": None, "metavar": "T/N",
                   "help": "repair turn shown in the output, e.g. 1/2 (display only)"}

    p = sub.add_parser("select-targets", help="rank attack targets in a scope")
    p.add_argument("--repo", **common_repo)
    p.add_argument("--scope", choices=["whole", "changed", "path"], default="whole")
    p.add_argument("--path", default=None, help="file or directory for --scope path")
    p.add_argument("--out", required=True, help="where to write targets.json")
    p.add_argument("--config-json", **common_cfg)
    p.add_argument("--turn", **common_turn)
    p.set_defaults(func=cmd_select_targets)

    p = sub.add_parser("check", help="screen, run, and crash-check probes")
    p.add_argument("--repo", **common_repo)
    p.add_argument("--targets", required=True, help="targets.json from select-targets")
    p.add_argument("--probes", required=True, help="probes.json from the attacker")
    p.add_argument("--out", required=True, help="where to write run.json")
    p.add_argument("--traces-out", required=True, help="where to write the trace-judge input")
    p.add_argument("--traces-dir", default=None, help="directory for individual trace files")
    p.add_argument("--config-json", **common_cfg)
    p.add_argument("--turn", **common_turn)
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("finalize", help="merge judge verdicts and write the report")
    p.add_argument("--repo", **common_repo)
    p.add_argument("--run", required=True, help="run.json from check")
    p.add_argument("--verdicts", default=None, help="trace-judge verdicts JSON (optional)")
    p.add_argument("--out", default=None, help="write the Markdown report here (none if omitted)")
    p.add_argument("--report-dir", default=None, help="write the report as <dir>/<repo>_<timestamp>.md")
    p.add_argument("--final-out", default=None, help="also write the finalised run JSON here")
    p.add_argument("--skipped", default=None, help="comma-separated 'not attacked' notes")
    p.add_argument("--turn", **common_turn)
    p.set_defaults(func=cmd_finalize)

    p = sub.add_parser("show-traces", help="print the undecided traces for the trace judge")
    p.add_argument("--traces", required=True, help="traces.json from check")
    p.add_argument("--turn", **common_turn)
    p.set_defaults(func=cmd_show_traces)

    p = sub.add_parser("session", help="read or write the per-session execution marker")
    p.add_argument("--data-dir", required=True)
    p.add_argument("--session-id", required=True)
    p.add_argument("--set-json", default=None, help="record this execution config")
    p.set_defaults(func=cmd_session)

    p = sub.add_parser("config", help="print the effective configuration")
    p.add_argument("--repo", **common_repo)
    p.add_argument("--config-json", **common_cfg)
    p.set_defaults(func=cmd_config)

    p = sub.add_parser("resolve-model", help="map a model label to an Agent-tool model id")
    p.add_argument("model", help="e.g. 'Opus 5.5', 'opus', 'main coding agent'")
    p.set_defaults(func=cmd_resolve_model)

    p = sub.add_parser("list-models", help="print Claude Code's live model names (fable excluded)")
    p.set_defaults(func=cmd_list_models)

    p = sub.add_parser("version", help="print the engine version")
    p.set_defaults(func=cmd_version)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except config_mod.ConfigError as exc:
        sys.stderr.write("attacker-verifier: configuration error: %s\n" % exc)
        return 2
    except FileNotFoundError as exc:
        sys.stderr.write("attacker-verifier: %s\n" % exc)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
