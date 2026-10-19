"""Terminal summaries printed by the engine commands.

Each command prints a short block whose first line names the FALCON stage it
ran and its counts, for example::

    FALCON ① Targets · 3 targets in core/ · turn 1/2

The rest of the block lists what the stage decided, one item per line, and a
last line saying what comes next. Claude Code shows the first lines of a
command's output in the transcript, so the headline carries the result.

The plugin's hooks module (``hooks/falcon.tsx``) reads the same headlines to
draw the stage band and the transcript rows, so keep their wording stable.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

STAGES = {
    "targets": "① Targets",
    "attack": "② Attack",
    "faithfulness": "③ Faithfulness",
    "sandbox": "④ Sandbox",
    "verify": "⑤ Verify",
    "feedback": "⑥ Feedback",
}

_VERDICT = {"insecure": "INSECURE", "secure": "SECURE", "no-evidence": "NO EVIDENCE"}
_REASON_WIDTH = 110


def _plural(count: int, word: str) -> str:
    return "%d %s%s" % (count, word, "" if count == 1 else "s")


def _headline(stages: List[str], parts: List[str], turn: Optional[str]) -> str:
    text = "FALCON " + " · ".join(STAGES[s] for s in stages)
    if parts:
        text += " · " + " · ".join(parts)
    if turn:
        text += " · turn " + turn
    return text


def _short(text: Any, width: int = _REASON_WIDTH) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= width else text[: width - 1] + "…"


def _table(rows: List[List[str]], indent: str = "  ") -> List[str]:
    if not rows:
        return []
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]) - 1)]
    lines = []
    for row in rows:
        cells = [cell.ljust(widths[i]) for i, cell in enumerate(row[:-1])] + [row[-1]]
        lines.append((indent + "  ".join(cells)).rstrip())
    return lines


def targets_block(payload: Dict[str, Any], turn: Optional[str]) -> str:
    found = payload["targets"]
    where = payload.get("path") or "the repository"
    if payload.get("scope") == "changed":
        where = "the changed code"
    if not found:
        return "\n".join([
            _headline(["targets"], ["nothing to attack in %s" % where], turn),
            "Next: stop and tell the user that no Python function, method, or class is in scope.",
        ]) + "\n"
    lines = [_headline(["targets"], ["%s in %s" % (_plural(len(found), "target"), where)], turn)]
    lines += _table([
        [t["qualname"], "%s:%s" % (t["file"], t.get("lineno") or "?"), t.get("kind", "function")]
        for t in found
    ])
    skipped = payload.get("not_attacked") or []
    if skipped:
        shown = ", ".join(skipped[:4]) + (", …" if len(skipped) > 4 else "")
        lines.append("Not attacked (not Python): %s" % shown)
    lines.append("Next: %s · write %d–%d probes per target." % (
        STAGES["attack"], payload["probes_min"], payload["probes_max"]))
    return "\n".join(lines) + "\n"


def check_header(probe_count: int, target_count: int, turn: Optional[str]) -> str:
    return _headline(["faithfulness", "sandbox"], [
        "%s for %s" % (_plural(probe_count, "probe"), _plural(target_count, "target")),
    ], turn)


def probe_line(record: Dict[str, Any]) -> str:
    target = record["target"].get("qualname") or "?"
    status = record["status"]
    rule = (record.get("faithfulness") or {}).get("rule") or ""
    if status == "rejected_static":
        mark, label, note = "−", "rejected", rule
    elif status == "inconclusive":
        mark, label, note = "?", "inconclusive", rule
    elif (record.get("core") or {}).get("verdict") == "insecure":
        mark, label, note = "✗", "crashed", "crash oracle: " + _short(record["core"].get("reason"), 70)
    else:
        mark, label, note = "✓", "admitted", "trace goes to the judge"
    return "  %s %-12s %-22s %-18s %s" % (mark, label, _short(record["id"], 22), _short(target, 18), note)


def check_summary(results: List[Dict[str, Any]], to_judge: int) -> List[str]:
    admitted = sum(1 for r in results if r["status"] == "admitted")
    rejected = sum(1 for r in results if r["status"] == "rejected_static")
    inconclusive = sum(1 for r in results if r["status"] == "inconclusive")
    crashed = sum(1 for r in results if (r.get("core") or {}).get("verdict") == "insecure")
    lines = ["Result: %d admitted · %d rejected · %d inconclusive · %d crashed · %d to judge" % (
        admitted, rejected, inconclusive, crashed, to_judge)]
    if to_judge:
        lines.append("Next: %s · run show-traces and judge the %s from the traces alone." % (
            STAGES["verify"], _plural(to_judge, "trace")))
    else:
        lines.append("Next: %s · no trace needs the judge; run finalize." % STAGES["feedback"])
    return lines


def final_block(final: Dict[str, Any], turn: Optional[str], report_path: Optional[str]) -> str:
    stats = final["stats"]
    signal = final["signal"]
    verdict = _VERDICT.get(signal, signal.upper())
    if signal == "insecure":
        parts = [verdict, "%s in %d of %s" % (
            _plural(stats["findings"], "finding"), stats["targets_insecure"], _plural(stats["targets"], "target"))]
    elif signal == "secure":
        secure = sum(1 for row in final["per_target"] if row["signal"] == "secure")
        if secure == stats["targets"]:
            parts = [verdict, "no violation in %s" % _plural(stats["targets"], "target")]
        else:
            parts = [verdict, "no violation in %d of %s · %d without evidence" % (
                secure, _plural(stats["targets"], "target"), stats["targets"] - secure)]
    else:
        parts = [verdict, "no probe was admitted"]
    parts.append("%d of %s admitted" % (stats["admitted"], _plural(stats["probes_total"], "probe")))
    lines = [_headline(["feedback"], parts, turn)]

    rows = []
    for row in final["per_target"]:
        mark = {"insecure": "✗", "secure": "✓"}.get(row["signal"], "?")
        probes = row["admitted"] + row["rejected_static"] + row["inconclusive"]
        counts = ("%d admitted, %d rejected, %d inconclusive" % (
            row["admitted"], row["rejected_static"], row["inconclusive"])) if probes else "no probes"
        rows.append(["%s %s" % (mark, _VERDICT.get(row["signal"], row["signal"])),
                     "%s::%s" % (row["file"], row["qualname"]), counts])
    lines += _table(rows)

    for index, finding in enumerate(final["findings"], start=1):
        target = finding["target"]
        lines.append("Finding %d · %s::%s · %s · probe %s · stage %s" % (
            index, target.get("file", "?"), target.get("qualname", "?"), finding.get("cwe") or "weakness",
            finding["id"], finding.get("stage", "?")))
        lines.append("  " + _short(finding.get("reason"), 160))
    if report_path:
        lines.append("Report: %s" % report_path)
    return "\n".join(lines) + "\n"


def traces_block(traces: List[Dict[str, Any]], turn: Optional[str]) -> str:
    """The undecided traces in a compact form for the trace judge."""
    if not traces:
        return _headline(["verify"], ["no trace to judge"], turn) + "\n"
    lines = [_headline(["verify"], ["%s to judge" % _plural(len(traces), "trace")], turn)]
    for index, item in enumerate(traces, start=1):
        trace = item.get("trace") or {}
        target = item.get("target") or {}
        lines.append("")
        lines.append("[%d/%d] %s · %s::%s · %s" % (
            index, len(traces), item.get("id"), target.get("file"), target.get("qualname"),
            item.get("cwe") or "no weakness named"))
        if item.get("rationale"):
            lines.append("  rationale: " + _short(item["rationale"], 300))
        frames = trace.get("frames") or []
        for frame in frames[:4]:
            args = ", ".join("%s=%s" % (name, value) for name, value in (frame.get("args") or {}).items())
            exception = frame.get("exception")
            if exception:
                outcome = "raised %s: %s" % (exception.get("type"), _short(exception.get("message"), 300))
            else:
                outcome = "returned " + _short(frame.get("return"), 300)
            lines.append("  call: %s(%s) %s" % (frame.get("func"), _short(args, 300), outcome))
        if len(frames) > 4:
            lines.append("  … %d more calls of the target" % (len(frames) - 4))
        for observation in trace.get("observations") or []:
            lines.append("  observation: " + _short(json.dumps(observation, default=str), 700))
        if trace.get("stderr"):
            lines.append("  stderr: " + _short(trace["stderr"], 400))
        if trace.get("top_level_exception"):
            lines.append("  uncaught: " + _short(json.dumps(trace["top_level_exception"], default=str), 300))
        ending = "exit code %s" % trace.get("returncode")
        if trace.get("killed_by_signal"):
            ending += ", killed by signal %s" % trace.get("signal")
        if trace.get("timed_out"):
            ending += ", timed out"
        lines.append("  %s, %ss" % (ending, trace.get("duration_s")))
    return "\n".join(lines) + "\n"
