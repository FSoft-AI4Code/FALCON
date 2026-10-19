---
name: secure-code-generation
description: >-
  Generate or edit code to satisfy a request, then harden it against security
  vulnerabilities by repeatedly attacking it with adversarial proof-of-concept
  probes, judging the execution traces, and repairing any violation found. Runs
  a configurable number of attack-verify-repair turns and returns code that is
  both functional and secure. Use when the user asks to write, implement, or
  change code and wants it to be secure.
argument-hint: "<what to build> [--turns 2] [--probes 5-10] [--attacker opus|sonnet|haiku] [--verifier opus|sonnet|haiku]"
disable-model-invocation: false
---

# Secure code generation

Write the code the user asked for, then make it withstand attack. After the
first implementation, run up to N FALCON turns. Each turn attacks the changed
code (① targets, ② attack, ③ faithfulness, ④ sandbox, ⑤ verify, ⑥ feedback)
and repairs what a concrete counterexample shows to be unsafe.

Repo root: `${CLAUDE_PROJECT_DIR}`. The user's arguments are: `$ARGUMENTS`.

## Run values

Run each command below as its own Bash call, on its own, with every path
written out: shell variables do not carry over between calls. Use the Read and
Write tools for the files named here, not `cat` or scripts.

- Engine: `python3 "${CLAUDE_PLUGIN_ROOT}/engine/cli.py"`
- Run directory of turn t, written `<RUN>` below:
  `${CLAUDE_PROJECT_DIR}/.attacker-verifier/runs/${CLAUDE_SESSION_ID}/pass-<k>`, where k counts
  the attack passes run in this session (each turn is one), starting at 1.
  The engine creates it.
- Settings in effect (`/config`, or `/plugin` → attacker-verifier →
  Configure): repair turns N = `${user_config.num_turns}`, attacker
  `${user_config.attacker}` (effort `${user_config.attacker_effort}`), verifier
  `${user_config.verifier}` (effort `${user_config.verifier_effort}`),
  attacker turns per target `${user_config.attacker_max_turns}`, probes per
  target `${user_config.probes_min}`–`${user_config.probes_max}`, max targets
  `${user_config.max_targets}`.

The attacker and verifier settings decide who plays each role. `main coding
agent` means you play it here. Any model name, even the model you are running
on, means the role runs as its own subagent (`attacker-verifier:attacker`,
`attacker-verifier:verifier`) in a separate context: never play a role yourself
when it is set to a model.

An argument overrides a setting for this run: `--turns N`, `--probes MIN-MAX`,
`--attacker <model>`, `--verifier <model>`, `--attacker-effort <level>`,
`--verifier-effort <level>`, `--attacker-max-turns N`, `--max-targets N`.
`<CONFIG>` below is a JSON object with `probes_min`, `probes_max`,
`max_targets`, and the `execution` block from step 1, for example
`{"execution":{"mode":"host"},"probes_min":5,"probes_max":10,"max_targets":20}`.

The engine commands print their own stage lines (`FALCON ① Targets · …`).
Before the steps you run (Code, ② Attack, ⑤ Verify), write one line such as
`**FALCON ② Attack** · turn 1/2 · attacker: main coding agent · 2 targets, 5–10 probes each`
and nothing more about the step.

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

## 2. Code

Write `**FALCON Code** · turn 0/N · main coding agent · <the request in a few words>`,
then build or edit the code as the main coding agent. Keep it working: run the
project's tests or exercise the feature. The attacker targets what you change.

## 3. Turns

For each turn t from 1 to N:

1. **① Targets.**

   ```
   python3 "${CLAUDE_PLUGIN_ROOT}/engine/cli.py" select-targets --repo "${CLAUDE_PROJECT_DIR}" --scope changed --out "<RUN>/targets.json" --config-json '<CONFIG>' --turn t/N
   ```

   Outside a git repository, use `--scope path --path <a file you changed>`
   instead. If nothing is in scope, say so and stop.

2. **② Attack.** With the attacker on `main coding agent`, you are the
   attacker: read `${CLAUDE_PLUGIN_ROOT}/engine/prompts/attacker.md` and
   follow it, then write between the minimum and maximum number of probes per
   target. Never read the repository's tests. Write all probes with the Write
   tool to `<RUN>/probes.json`, as
   `{"probes": [{"id", "target": "path.py::Qualified.symbol", "cwe", "rationale", "script"}]}`.
   With a model name, run
   `python3 "${CLAUDE_PLUGIN_ROOT}/engine/cli.py" resolve-model "<name>"` and
   delegate to the `attacker-verifier:attacker` subagent instead: one Agent
   call for the turn's targets (split them over a few calls when there are
   many, each writing its own file that you then merge), with `model` set to
   the printed value and the effort unless `inherit`. Its prompt names the
   targets, the probe budget, the turn budget, the attacker prompt
   `${CLAUDE_PLUGIN_ROOT}/engine/prompts/attacker.md`, and the file to write.
   If it returns without writing probes, ask it once to write what it has.

3. **③ Faithfulness and ④ Sandbox.**

   ```
   python3 "${CLAUDE_PLUGIN_ROOT}/engine/cli.py" check --repo "${CLAUDE_PROJECT_DIR}" --targets "<RUN>/targets.json" --probes "<RUN>/probes.json" --out "<RUN>/run.json" --traces-out "<RUN>/traces.json" --config-json '<CONFIG>' --turn t/N
   ```

4. **⑤ Verify.** If the result says `0 to judge`, write `{}` to
   `<RUN>/verdicts.json`. Otherwise, with the verifier on `main coding agent`,
   read `${CLAUDE_PLUGIN_ROOT}/engine/prompts/verifier_stage3.md`, print the
   traces with
   `python3 "${CLAUDE_PLUGIN_ROOT}/engine/cli.py" show-traces --traces "<RUN>/traces.json" --turn t/N`,
   and judge each trace from the trace alone, never from the source. With a
   model name, delegate to the `attacker-verifier:verifier` subagent instead,
   naming in its prompt the judge prompt
   `${CLAUDE_PLUGIN_ROOT}/engine/prompts/verifier_stage3.md`, the traces file,
   and the file to write. Either way the verdicts go, through the Write tool,
   to `<RUN>/verdicts.json`, as
   `{"<probe id>": {"verdict": "secure"|"insecure", "reason", "evidence", "confidence"}}`.

5. **⑥ Feedback.**

   ```
   python3 "${CLAUDE_PLUGIN_ROOT}/engine/cli.py" finalize --run "<RUN>/run.json" --verdicts "<RUN>/verdicts.json" --final-out "<RUN>/final.json" --turn t/N
   ```

   It prints the verdict and each finding with its probe and reason;
   `<RUN>/final.json` has them in full. No report file is written in the loop.

6. **Repair or stop.** If the verdict is SECURE or NO EVIDENCE, stop: the code
   withstood this turn's attack. Otherwise write
   `**FALCON Code** · turn t/N · main coding agent · repairing F finding(s)`
   and, for each finding, fix the root cause in the code under test (validate
   or normalise the input, enforce the boundary, use the safe API). Do not
   weaken a probe, special-case a canary, or silence the symptom. Run the
   functional checks again so the feature keeps working.

Stop after N turns or at the first turn that finds nothing, and keep the last
working version of the code.

## 4. Summary

Start with a verdict line such as
`**FALCON verdict: SECURE** after 2 turns · turn 1: 1 finding, repaired · turn 2: no violation in 1 target`,
then:

- what you built or changed,
- each finding: target, weakness, probe, and how you fixed it,
- the final state: secure under the budget used, or the findings that remain
  when the turns ran out.

A clean result means no admitted probe exposed a violation under this budget,
not a proof of safety. Offer `--turns` or `--probes` for a deeper pass. If the
user asks for a written report, run `finalize` once more with
`--report-dir "${CLAUDE_PROJECT_DIR}"`.
