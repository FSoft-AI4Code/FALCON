# The attack → verify loop

This document describes one **pass** of the loop both skills run over a scope.
`/check-code-security` runs a single pass and reports; `/secure-code-generation`
runs a pass, repairs, and loops. The skills carry the exact commands with the
paths filled in; this is the longer explanation of each step.

## Showing progress

The pass has six stages:

| Stage | Who runs it |
|---|---|
| ① Targets | engine `select-targets` |
| ② Attack | the attacker (you, or the attacker subagent) |
| ③ Faithfulness | engine `check` |
| ④ Sandbox | engine `check` |
| ⑤ Verify | engine `check` (crash oracle), then the trace judge (you, or the verifier subagent) |
| ⑥ Feedback | engine `finalize` |

Each engine command prints its own stage line first, for example
`FALCON ③ Faithfulness · ④ Sandbox · 14 probes for 3 targets`, so do not repeat
what it printed. Before a stage you run yourself (② Attack, ⑤ Verify, and the
Code step of `/secure-code-generation`), write one line in this form and
nothing else about it:

```
**FALCON ② Attack** · turn 1/2 · attacker: main coding agent · 3 targets, 5–10 probes each
```

Leave out `turn t/N` in `/check-code-security`. In `/secure-code-generation`,
pass `--turn t/N` to `select-targets`, `check`, and `finalize`, so their lines,
and the stage band the plugin draws above the prompt, name the turn.

## Configuration for the run

Resolve settings in this order, each overriding the previous: engine defaults →
`.attacker-verifier/config.json` at the repo root (if present) → the arguments
the user passed to the skill. Build a single JSON string, `CONFIG_JSON`, holding
the non-default settings plus the `execution` block from the session marker.
Recognised settings:

| Setting | Meaning | Default |
|---|---|---|
| `probes_min`, `probes_max` | probe budget per target (`--probes 5-10`) | 5, 10 |
| `attacker_max_turns` | attacker turn budget per target (`--attacker-max-turns 20`) | 20 |
| `attacker` | `main coding agent` (inline) or a model name, from `/config`; `--attacker` overrides | `main coding agent` |
| `attacker_effort` | reasoning effort for a delegated attacker (`--attacker-effort high`) | `inherit` |
| `verifier` | `main coding agent` (inline) or a model name, from `/config`; `--verifier` overrides | `main coding agent` |
| `verifier_effort` | reasoning effort for a delegated verifier (`--verifier-effort high`) | `inherit` |
| `num_turns` | repair cycles, generation only (`--turns 2`) | 2 |
| `max_targets` | cap on targets attacked (`--max-targets 20`) | 20 |
| `execution` | sandbox block from the session marker | `{"mode":"host"}` |

`main coding agent` means the session's own agent plays the role. Any model
name, including the model the session runs on, means the role runs as its own
subagent (`attacker-verifier:attacker` or `attacker-verifier:verifier`) in a
separate context, as in the paper, where the attacker and the judge are separate
calls. Map the name to the Agent tool's `model` with `engine resolve-model
"<value>"`: it prints `main` for `main coding agent`, a family alias (`opus`,
`sonnet`, `haiku`) for the newest model of a family, and a model id otherwise.
When delegating, set the subagent's effort to the configured value unless it is
`inherit`.

Keep a per-run directory for intermediate files inside the repository's
git-ignored state directory:
`RUN_DIR="${CLAUDE_PROJECT_DIR}/.attacker-verifier/runs/${CLAUDE_SESSION_ID}/pass-<k>"`,
where k counts the passes in the session.

## Steps

### 1. Select targets — deterministic

```
python3 "${CLAUDE_PLUGIN_ROOT}/engine/cli.py" select-targets \
  --repo "<repo>" --scope <whole|changed|path> [--path <P>] \
  --out "$RUN_DIR/targets.json" --config-json "$CONFIG_JSON" [--turn t/N]
```

It prints the targets (functions, methods, and classes, ranked by security
relevance), the probe budget, and any source files in other languages, which
are listed as not attacked; `targets.json` holds the same with line ranges. If
nothing is in scope, tell the user and stop.

### 2. Attack — the attacker agent

The attacker proposes probes. It is an **agent**, not a single reply: it may
read the code and the repository and iterate, up to its turn budget
(`attacker_max_turns`, default 20), before writing its probes. Read the attacker
prompt at `${CLAUDE_PLUGIN_ROOT}/engine/prompts/attacker.md` and follow it
exactly.

- If `attacker` is `main coding agent` (default): **you** play the attacker,
  inline. For each target, work through the attacker prompt and produce between
  `probes_min` and `probes_max` deterministic probes. Treat `attacker_max_turns`
  as your budget of attacker steps: explore within it, then commit probes.
- Otherwise (a model name): resolve it with `engine resolve-model "<value>"` and
  delegate to the `attacker-verifier:attacker` subagent via the Agent tool with
  `model` set to the printed value. Its prompt names the targets, the probe and
  turn budgets, the attacker prompt file, and the path to write its probes to.

**Turn budget and return/stop rule.** The attacker must return its probes within
`attacker_max_turns`:

- When the budget is reached, it returns the probes it has (even if fewer than
  `probes_min`).
- If the attacker finishes or hits the budget without having written a probes
  file, make **one** final request: "output the probes JSON you have now to
  `<path>`, even if incomplete; if you have none, return `{"probes": []}`." This
  compels a return.
- If it still produces no probes for a target, **stop** on that target: it
  contributes no probes and is reported with no evidence. Do not loop further.

Collect all probes into one file `"$RUN_DIR/probes.json"` (the file must be
named `probes.json`):

```json
{ "probes": [
  { "id": "unique_id", "target": "path.py::Qualified.symbol",
    "cwe": "weakness name or id", "rationale": "what it exercises, no verdict",
    "script": "complete deterministic Python script" }
] }
```

Never put an expected output or a verdict in a probe. Never read repository
tests. Write only inside `AV_SCRATCH`. Print at least one
`AV_OBSERVATION:<json>` line per probe, after the target call, and mark
payloads with `AV_CANARY_<id>`.

### 3. Screen, run, and crash-check — deterministic (sandbox)

```
python3 "${CLAUDE_PLUGIN_ROOT}/engine/cli.py" check \
  --repo "<repo>" --targets "$RUN_DIR/targets.json" \
  --probes "$RUN_DIR/probes.json" --out "$RUN_DIR/run.json" \
  --traces-out "$RUN_DIR/traces.json" --config-json "$CONFIG_JSON" [--turn t/N]
```

This removes probes that would report their own behaviour (faithfulness check),
runs the admitted probes in the sandbox, applies the crash oracle, and writes
any trace it could not decide to `traces.json`. It prints one line per probe
and a `Result:` line with the counts.

### 4. Judge undecided traces — the verifier (stage 3)

If the check printed `0 to judge`, skip to step 5. Otherwise print the traces
in a compact form with

```
python3 "${CLAUDE_PLUGIN_ROOT}/engine/cli.py" show-traces \
  --traces "$RUN_DIR/traces.json" [--turn t/N]
```

and judge each one with the stage-3 prompt at
`${CLAUDE_PLUGIN_ROOT}/engine/prompts/verifier_stage3.md`, reading **only** the
trace — not the source, the patch, or any test. `traces.json` has every field.

- If `verifier` is `main coding agent` (default): you judge each trace inline.
- Otherwise (a model name): resolve it with `engine resolve-model "<value>"` and
  delegate to the `attacker-verifier:verifier` subagent via the Agent tool with
  `model` set to the printed value, naming the judge prompt, the traces file,
  and the path to write verdicts to.

Write the verdicts to `"$RUN_DIR/verdicts.json"` (the file must be named
`verdicts.json`):

```json
{ "<probe_id>": { "verdict": "secure" | "insecure",
  "reason": "name the weakness and the behaviour that shows it",
  "evidence": "probe id and the trace field the verdict rests on",
  "confidence": "high" | "low" } }
```


### 5. Aggregate

```
python3 "${CLAUDE_PLUGIN_ROOT}/engine/cli.py" finalize \
  --run "$RUN_DIR/run.json" --verdicts "$RUN_DIR/verdicts.json" \
  --final-out "$RUN_DIR/final.json" [--report-dir "<repo>"] [--turn t/N]
```

It prints the verdict, one line per target, and each finding with its reason.
`final.json` carries the per-target signal and the counterexamples (the unsafe
findings). The signal for a target is **insecure** if any admitted probe is
insecure, **secure** if the admitted set is non-empty and none is insecure, and
**no-evidence** if no probe was admitted.

A Markdown report is written only when asked for: `--report-dir <dir>` writes
`<dir>/<repo>_<timestamp>.md`, and `--out <path>` names the file. For
`/check-code-security`, pass `--report-dir` with the repository root. For
`/secure-code-generation`, leave both out during the loop and use `final.json`
to drive repair; write a report only if the user asks. Files listed as not
attacked by `select-targets` go into the report; `--skipped` replaces that
list.
