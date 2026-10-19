---
name: check-code-security
description: >-
  Audit code in this repository for security vulnerabilities by generating
  adversarial proof-of-concept probes, running them in a sandbox, and judging
  the resulting execution traces. Reports which parts of the repository are
  unsafe and writes a Markdown report named with the repo and a timestamp. Use
  when the user wants to check, audit, or find security issues in existing code.
argument-hint: "[path] [--probes 5-10] [--attacker opus|sonnet|haiku] [--verifier opus|sonnet|haiku] [--scope whole|changed|path]"
disable-model-invocation: false
---

# Check code security

Audit code by attacking it and judging what it does at runtime, not by reading
it. One FALCON pass over the chosen scope has six stages: ① select targets,
② attack them with proof-of-concept probes, ③ drop unfaithful probes, ④ run the
rest in a sandbox, ⑤ judge the execution traces, ⑥ report.

Repo root: `${CLAUDE_PROJECT_DIR}`. The user's arguments are: `$ARGUMENTS`.

## Run values

Run each command below as its own Bash call, on its own, with every path
written out: shell variables do not carry over between calls. Use the Read and
Write tools for the files named here, not `cat` or scripts.

- Engine: `python3 "${CLAUDE_PLUGIN_ROOT}/engine/cli.py"`
- Run directory, written `<RUN>` below:
  `${CLAUDE_PROJECT_DIR}/.attacker-verifier/runs/${CLAUDE_SESSION_ID}/pass-<k>`, where k counts
  the attack passes run in this session, starting at 1. The engine creates it.
- Settings in effect (`/config`, or `/plugin` → attacker-verifier →
  Configure): attacker `${user_config.attacker}` (effort
  `${user_config.attacker_effort}`), verifier `${user_config.verifier}`
  (effort `${user_config.verifier_effort}`), attacker turns per target
  `${user_config.attacker_max_turns}`, probes per target
  `${user_config.probes_min}`–`${user_config.probes_max}`, max targets
  `${user_config.max_targets}`.

The attacker and verifier settings decide who plays each role. `main coding
agent` means you play it here. Any model name, even the model you are running
on, means the role runs as its own subagent (`attacker-verifier:attacker`,
`attacker-verifier:verifier`) in a separate context: never play a role yourself
when it is set to a model.

An argument overrides a setting for this run: `--probes MIN-MAX`,
`--attacker <model>`, `--verifier <model>`, `--attacker-effort <level>`,
`--verifier-effort <level>`, `--attacker-max-turns N`, `--max-targets N`.
`<CONFIG>` below is a JSON object with `probes_min`, `probes_max`,
`max_targets`, and the `execution` block from step 1, for example
`{"execution":{"mode":"host"},"probes_min":5,"probes_max":10,"max_targets":20}`.

The engine commands print their own stage lines (`FALCON ① Targets · …`).
Before ② and ⑤, which you run, write one line such as
`**FALCON ② Attack** · attacker: main coding agent · 3 targets, 5–10 probes each`
and nothing more about the stage.

## 1. Sandbox

```
python3 "${CLAUDE_PLUGIN_ROOT}/engine/cli.py" session --data-dir "${CLAUDE_PLUGIN_DATA}" --session-id "${CLAUDE_SESSION_ID}"
```

If it says the sandbox was chosen earlier, its last line is the `execution`
block; go on. If it says `not chosen yet`, ask once with `AskUserQuestion`, header
`Sandbox`, question `Probes run real code with adversarial inputs. Where
should they run?`, and these two options in this order:

1. `Run here (host)`: child processes on this machine with CPU, memory, and
   time limits, under this session's permissions.
2. `Use Docker`: a fresh container per probe from an image, or `docker exec`
   into a running container that has the repository mounted.

For Docker, also ask for the image (for example `python:3.12-slim`) or the
container name. Record the choice with the same command plus `--set-json`
and one of `'{"mode":"host"}'`,
`'{"mode":"docker","image":"python:3.12-slim","workdir":"/work"}'`, or
`'{"mode":"docker","container":"NAME","workdir":"/work"}'`.
`${CLAUDE_PLUGIN_ROOT}/docs/sandbox.md` describes the modes.

## 2. Scope

- A path, a file, or functions named in the arguments or earlier in the
  conversation: `--scope path --path <it>`. Only uncommitted work:
  `--scope changed`.
- Nothing named: ask with `AskUserQuestion`, two options:
  1. `Tell me what to check`: the user names a file, directory, or functions;
     use `--scope path`.
  2. `Scan the whole repository`: all non-test Python, ranked by security
     relevance, up to max targets; use `--scope whole`.

This version attacks Python; `select-targets` lists other source files in
scope as not attacked, and the report carries them.

## 3. ① Targets

```
python3 "${CLAUDE_PLUGIN_ROOT}/engine/cli.py" select-targets --repo "${CLAUDE_PROJECT_DIR}" --scope <scope> [--path <P>] --out "<RUN>/targets.json" --config-json '<CONFIG>'
```

It prints the targets and the probe budget. If nothing is in scope, say so and
stop.

## 4. ② Attack

With the attacker on `main coding agent`, you are the attacker. Read
`${CLAUDE_PLUGIN_ROOT}/engine/prompts/attacker.md` and follow it: read each
target's code (never the repository's tests), then write between the minimum
and maximum number of probes per target. The attacker turn budget is per
target; when it runs out, keep the probes you have.

With a model name, run
`python3 "${CLAUDE_PLUGIN_ROOT}/engine/cli.py" resolve-model "<name>"` and
delegate to the `attacker-verifier:attacker` subagent instead: one Agent call
for the targets (split them over a few calls when there are many, each writing
its own file that you then merge), with `model` set to the printed value and
the effort unless it is `inherit`. Its prompt names the targets, the probe
budget, the turn budget, the attacker prompt
`${CLAUDE_PLUGIN_ROOT}/engine/prompts/attacker.md`, and the file to write. If
it returns without writing probes, ask it once to write what it has; a target
that still has none is reported with no evidence.

Write all probes with the Write tool to `<RUN>/probes.json`:

```json
{ "probes": [
  { "id": "abs_path", "target": "core/storage.py::load_report", "cwe": "CWE-22",
    "rationale": "what the input exercises, stated without a verdict",
    "script": "complete deterministic Python script" }
] }
```

## 5. ③ Faithfulness and ④ Sandbox

```
python3 "${CLAUDE_PLUGIN_ROOT}/engine/cli.py" check --repo "${CLAUDE_PROJECT_DIR}" --targets "<RUN>/targets.json" --probes "<RUN>/probes.json" --out "<RUN>/run.json" --traces-out "<RUN>/traces.json" --config-json '<CONFIG>'
```

It drops probes that would report their own behaviour instead of the target's,
runs the rest one at a time in the sandbox under a tracer, applies the crash
oracle, and prints one line per probe and a `Result:` line.

## 6. ⑤ Verify

If the result says `0 to judge`, write `{}` to `<RUN>/verdicts.json` and go on.
Otherwise, with the verifier on `main coding agent`, read
`${CLAUDE_PLUGIN_ROOT}/engine/prompts/verifier_stage3.md`, print the traces with

```
python3 "${CLAUDE_PLUGIN_ROOT}/engine/cli.py" show-traces --traces "<RUN>/traces.json"
```

and judge each trace from the trace alone, never from the source
(`<RUN>/traces.json` has every field if you need more). With a model name,
resolve it as above and delegate to the `attacker-verifier:verifier` subagent
instead, naming in its prompt the judge prompt
`${CLAUDE_PLUGIN_ROOT}/engine/prompts/verifier_stage3.md`, the traces file,
and the file to write. Either way the verdicts go, through the Write tool, to
`<RUN>/verdicts.json`:

```json
{ "abs_path": { "verdict": "insecure", "reason": "names the weakness and the behaviour that shows it",
                "evidence": "probe id and the trace field quoted", "confidence": "high" } }
```

## 7. ⑥ Feedback

```
python3 "${CLAUDE_PLUGIN_ROOT}/engine/cli.py" finalize --run "<RUN>/run.json" --verdicts "<RUN>/verdicts.json" --final-out "<RUN>/final.json" --report-dir "${CLAUDE_PROJECT_DIR}"
```

It writes the report as `<repo>_<timestamp>.md` in the repository root and
prints the verdict, a line per target, each finding with its reason, and the
report path.

## 8. Summary

Reply in this form, one table row per finding and one per target with none,
then the report path:

**FALCON verdict: INSECURE** · 1 finding in 1 of 3 targets · 11 of 14 probes admitted

| Target | Verdict | Evidence |
|---|---|---|
| `core/storage.py::load_report` | INSECURE · CWE-22 | `abs_path`: an absolute name returned a canary planted outside `REPORTS_DIR` |
| `core/storage.py::save_report` | SECURE | 4 probes admitted, none showed a violation |

Report: `webapp_20261018-213000.md`

Add at most two sentences: which finding matters most and why. A secure verdict
means no admitted probe exposed a violation under this budget, not that the
code is proven safe. If there are findings, offer to fix them with
`/secure-code-generation`; do not change code in this skill unless the user
asks.
