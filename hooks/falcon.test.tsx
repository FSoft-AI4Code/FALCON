import { describe, expect, test } from 'claude-code/testing'

const PLUGIN = 'attacker-verifier'
const CLI = 'python3 "/plugins/attacker-verifier/engine/cli.py"'

const TARGETS = `FALCON ① Targets · 3 targets in core/ · turn 1/2
  load_report  core/storage.py:11  function
  save_report  core/storage.py:20  function
  report_view  core/reports.py:6   function
Next: ② Attack · write 5–10 probes per target.
`

const CHECK = `FALCON ③ Faithfulness · ④ Sandbox · 5 probes for 2 targets · turn 1/2
  ✓ admitted     abs_path               load_report        trace goes to the judge
  ✓ admitted     dotdot                 load_report        trace goes to the judge
  − rejected     shadow                 load_report        target_redefined
  − rejected     fake_canary            load_report        probe_prints_fabricated_canary
  ? inconclusive import_only            report_view        target_frame_missing
Result: 2 admitted · 2 rejected · 1 inconclusive · 0 crashed · 2 to judge
Next: ⑤ Verify · judge 2 traces in traces.json from the traces alone.
`

const INSECURE = `FALCON ⑥ Feedback · INSECURE · 1 finding in 1 of 3 targets · 2 of 5 probes admitted · turn 1/2
  ✗ INSECURE     core/storage.py::load_report  2 admitted, 2 rejected, 0 inconclusive
  ? NO EVIDENCE  core/reports.py::report_view  0 admitted, 0 rejected, 1 inconclusive
  ? NO EVIDENCE  core/storage.py::save_report  no probes
Finding 1 · core/storage.py::load_report · CWE-22 · probe abs_path · stage 3
  Path traversal (CWE-22): an absolute name was accepted and load_report returned a file planted outside the reports directory.
Report: /work/webapp/webapp_20261018-213000.md
`

const SECURE = `FALCON ⑥ Feedback · SECURE · no violation in 1 of 3 targets · 2 without evidence · 2 of 5 probes admitted · turn 2/2
  ✓ SECURE       core/storage.py::load_report  2 admitted, 2 rejected, 0 inconclusive
  ? NO EVIDENCE  core/reports.py::report_view  0 admitted, 0 rejected, 1 inconclusive
  ? NO EVIDENCE  core/storage.py::save_report  no probes
`

const PROBES = JSON.stringify({
  probes: [
    { id: 'abs_path', target: 'core/storage.py::load_report', cwe: 'CWE-22', rationale: 'absolute name', script: 'x' },
    { id: 'dotdot', target: 'core/storage.py::load_report', cwe: 'CWE-22', rationale: 'dot-dot name', script: 'x' },
    { id: 'import_only', target: 'core/reports.py::report_view', cwe: 'CWE-22', rationale: 'view', script: 'x' },
  ],
})

const VERDICTS = JSON.stringify({
  abs_path: { verdict: 'insecure', reason: 'canary planted outside the reports directory was returned', evidence: 'x' },
  dotdot: { verdict: 'secure', reason: 'rejected with ValueError', evidence: 'x' },
})

const CHECK_SKILL = "# Check code security\nall settings come from attacker-verifier.\nThe user's arguments are: `core/`."
const GENERATE_SKILL =
  "# Secure code generation\n- Settings in effect: repair turns N = `3`, attacker `main coding agent`\n(/plugin → attacker-verifier → Configure)\nThe user's arguments are: `fix the path traversal`."

const BAND = {
  component: 'AbovePrompt',
  props: { hasSurvey: false, isWorking: true, maxRows: 20, bodyColumns: 120, scroll: { offset: 0, bodyRows: 19 }, view: {} },
  viewport: { columns: 125, rows: 40 },
} as const

// Stands in for the engine beneath the plugin: the skill text as given, the
// prompt as typed, and each engine command's output from the fixtures above.
function answerTools(on: any, outputs: Record<string, string>) {
  on('skill.prompt', ($: unknown, e: any) => ({ text: e.text }))
  on('prompt.submit', ($: unknown, e: any) => ({ text: e.text }))
  on('turn.complete', ($: unknown, e: any) => ({ text: e.answer }))
  on('ui.render', ($: any, e: any) => {
    const { Box } = $.ui.resolve(e)
    return <Box />
  })
  on('tool.call', ($: unknown, e: any) => {
    if (e.tool === 'Bash') {
      const second = /--turn 2\//.test(e.command) ? ':2' : ''
      const stdout = [...e.command.matchAll(/cli\.py"\s+(\S+)/g)]
        .map(match => outputs[match[1] + second] ?? outputs[match[1]] ?? '')
        .join('')
      return { result: { stdout, stderr: '', interrupted: false } }
    }
    if (e.tool === 'Write') {
      return { result: { type: 'create', filePath: e.file_path, content: e.content, structuredPatch: [], originalFile: null } }
    }
    return { result: {} }
  })
}

async function bandText(ui: any): Promise<string> {
  const found = await ui.findAll({ type: 'Text' })
  return found.map((element: any) => element.text).join('\n')
}

describe('the FALCON band', () => {
  for (const surface of ['terminal', 'desktop'] as const) {
    test(`follows a check run to its verdict on ${surface}`, async ($: any, on: any) => {
      answerTools(on, { 'select-targets': TARGETS, check: CHECK, finalize: INSECURE })
      await $.skill.prompt({ skill: 'attacker-verifier:check-code-security', text: CHECK_SKILL })
      const ui = await $.ui.mount({ plugin: PLUGIN, surface, ...BAND })
      expect(await bandText(ui)).toMatch(/check-code-security core\//)
      expect(await bandText(ui)).toMatch(/● Targets/)

      await $.tool.call({ tool: 'Bash', command: `${CLI} select-targets --repo . --scope path --path core/ --out /r/targets.json` })
      let text = await bandText(ui)
      expect(text).toMatch(/✓ Targets\s+─\s+● Attack\s+─\s+○ Faithfulness/)
      expect(text).toMatch(/② Attack\s+attacker · 5–10 probes each\s+3 targets/)

      await $.tool.call({ tool: 'Write', file_path: '/r/probes.json', content: PROBES })
      expect(await bandText(ui)).toMatch(/3 probes/)

      await $.tool.call({ tool: 'Bash', command: `${CLI} check --repo . --targets /r/targets.json --probes /r/probes.json --out /r/run.json --traces-out /r/traces.json` })
      text = await bandText(ui)
      expect(text).toMatch(/✓ Faithfulness/)
      expect(text).toMatch(/3 rejected/)
      expect(text).toMatch(/● Verify/)
      expect(text).toMatch(/judging 2/)

      await $.tool.call({ tool: 'Write', file_path: '/r/verdicts.json', content: VERDICTS })
      await $.tool.call({ tool: 'Bash', command: `${CLI} finalize --run /r/run.json --verdicts /r/verdicts.json --out /work/webapp/webapp_20261018-213000.md` })
      text = await bandText(ui)
      expect(text).toMatch(/✗ INSECURE/)
      expect(text).toMatch(/core\/storage\.py::load_report/)
      expect(text).toMatch(/load_report\s+CWE-22 · abs_path/)
      expect(text).toMatch(/webapp_20261018-213000\.md/)

      await ui.press({ key: 'falcon-hide' })
      expect(await ui.find({ type: 'Text', text: /FALCON/ })).toBeUndefined()
      await ui.unmount()
    })
  }

  test('shows the repair loop of secure-code-generation', async ($: any, on: any) => {
    answerTools(on, { 'select-targets': TARGETS, check: CHECK, finalize: INSECURE, 'finalize:2': SECURE })
    await $.skill.prompt({ skill: 'attacker-verifier:secure-code-generation', text: GENERATE_SKILL })
    const ui = await $.ui.mount({ plugin: PLUGIN, surface: 'terminal', ...BAND })
    expect(await bandText(ui)).toMatch(/● Code/)
    expect(await bandText(ui)).toMatch(/turn 0\/3/)

    await $.tool.call({ tool: 'Bash', command: `${CLI} select-targets --repo . --scope changed --out /r/t.json --turn 1/2` })
    expect(await bandText(ui)).toMatch(/✓ Code/)
    expect(await bandText(ui)).toMatch(/turn 1\/2/)
    await $.tool.call({ tool: 'Bash', command: `${CLI} check --repo . --targets /r/t.json --probes /r/p.json --out /r/run.json --traces-out /r/tr.json --turn 1/2` })
    await $.tool.call({ tool: 'Bash', command: `${CLI} finalize --run /r/run.json --verdicts /r/v.json --final-out /r/f.json --turn 1/2` })
    let text = await bandText(ui)
    expect(text).toMatch(/● Code/)
    expect(text).toMatch(/repairing 1/)
    expect(text).toMatch(/judged 2/)

    await $.tool.call({ tool: 'Bash', command: `${CLI} select-targets --repo . --scope changed --out /r/t.json --turn 2/2` })
    expect(await bandText(ui)).toMatch(/turn 2\/2/)
    await $.tool.call({ tool: 'Bash', command: `${CLI} check --repo . --targets /r/t.json --probes /r/p.json --out /r/run.json --traces-out /r/tr.json --turn 2/2` })
    await $.tool.call({ tool: 'Bash', command: `${CLI} finalize --run /r/run.json --verdicts /r/v.json --final-out /r/f.json --turn 2/2` })
    text = await bandText(ui)
    expect(text).toMatch(/✓ SECURE/)
    expect(text).toMatch(/turn 1 ✗ 1 finding\s+→\s+turn 2 ✓ secure/)
    await ui.unmount()
  })

  test('says when the turn ended before a verdict, and clears on the next prompt', async ($: any, on: any) => {
    answerTools(on, { 'select-targets': TARGETS })
    await $.prompt.submit({ text: '/check-code-security core/', wait: false, origin: { kind: 'composer' } })
    const ui = await $.ui.mount({ plugin: PLUGIN, surface: 'terminal', ...BAND })
    await $.tool.call({ tool: 'Bash', command: `${CLI} select-targets --repo . --scope path --path core/ --out /r/t.json` })
    await $.turn.complete({ answer: '', durationMs: 1, isAborted: true, turnId: 't1', reason: 'aborted' })
    expect(await bandText(ui)).toMatch(/■ STOPPED/)
    expect(await bandText(ui)).toMatch(/during Attack/)
    await $.prompt.submit({ text: 'never mind', wait: false, origin: { kind: 'composer' } })
    expect(await ui.find({ type: 'Text', text: /FALCON/ })).toBeUndefined()
    await ui.unmount()
  })

  test('reads every engine call in a chained command', async ($: any, on: any) => {
    answerTools(on, { session: 'FALCON sandbox: probes run on the host for the rest of this session\n', 'select-targets': TARGETS })
    await $.skill.prompt({ skill: 'attacker-verifier:check-code-security', text: CHECK_SKILL })
    const ui = await $.ui.mount({ plugin: PLUGIN, surface: 'terminal', ...BAND })
    await $.tool.call({
      tool: 'Bash',
      command: `${CLI} session --data-dir /d --session-id s --set-json '{"mode":"host"}'\n${CLI} select-targets --repo . --scope path --path core/ --out /r/t.json`,
    })
    const text = await bandText(ui)
    expect(text).toMatch(/sandbox: host/)
    expect(text).toMatch(/✓ Targets/)
    expect(text).toMatch(/● Attack/)
    await ui.unmount()
  })

  test('keeps the run going while a subagent works after the turn ends', async ($: any, on: any) => {
    answerTools(on, { 'select-targets': TARGETS, check: CHECK })
    await $.skill.prompt({ skill: 'attacker-verifier:check-code-security', text: CHECK_SKILL })
    const ui = await $.ui.mount({ plugin: PLUGIN, surface: 'terminal', ...BAND })
    await $.tool.call({ tool: 'Bash', command: `${CLI} select-targets --repo . --scope path --path core/ --out /r/t.json` })
    await $.tool.call({ tool: 'Agent', subagent_type: 'attacker-verifier:attacker', model: 'sonnet', description: 'Attack', prompt: 'x' })
    expect(await bandText(ui)).toMatch(/attacker · sonnet subagent/)
    await $.turn.complete({ answer: 'waiting', durationMs: 1, isAborted: false, turnId: 't1', reason: 'answer' })
    await $.prompt.submit({ text: '<task-notification>done</task-notification>', wait: false, origin: { kind: 'task-notification' } })
    expect(await bandText(ui)).not.toMatch(/STOPPED/)
    await $.tool.call({ tool: 'Bash', command: `${CLI} check --repo . --targets /r/t.json --probes /r/p.json --out /r/run.json --traces-out /r/tr.json` })
    expect(await bandText(ui)).toMatch(/● Verify/)
    await ui.unmount()
  })

  test('narrow terminals get one line for the stage in progress', async ($: any, on: any) => {
    answerTools(on, { 'select-targets': TARGETS })
    await $.skill.prompt({ skill: 'attacker-verifier:check-code-security', text: CHECK_SKILL })
    await $.tool.call({ tool: 'Bash', command: `${CLI} select-targets --repo . --scope path --path core/ --out /r/t.json` })
    const ui = await $.ui.mount({ plugin: PLUGIN, surface: 'terminal', ...BAND, props: { ...BAND.props, bodyColumns: 70 } })
    const text = await bandText(ui)
    expect(text).toMatch(/1 of 6 stages done/)
    expect(text).toMatch(/② Attack\s+attacker · 5–10 probes each/)
    await ui.unmount()
  })
})

describe('transcript rows', () => {
  for (const surface of ['terminal', 'desktop', 'vscode'] as const) {
    test(`draw engine calls as FALCON stages on ${surface}`, async ($: any) => {
      const row = await $.ui.mount({
        plugin: PLUGIN,
        surface,
        component: 'ToolUse',
        props: {
          tool_use_id: 'toolu_1',
          tool: 'Bash',
          input: { command: `${CLI} check --repo . --targets t.json --probes p.json --out r.json --traces-out tr.json` },
          isRunning: false,
          isErrored: false,
          isInterrupted: false,
          output: { stdout: CHECK, stderr: '', interrupted: false },
        },
      })
      const text = (await row.findAll({ type: 'Text' })).map((element: any) => element.text).join('')
      expect(text).toMatch(/FALCON ③ Faithfulness · ④ Sandbox/)
      expect(text).toMatch(/2 admitted · 3 rejected · 0 crashed · 2 to judge/)
      await row.unmount()

      const result = await $.ui.mount({
        plugin: PLUGIN,
        surface,
        component: 'ToolResult',
        props: { tool_use_id: 'toolu_1', tool: 'Bash', isErrored: false, output: { stdout: CHECK, stderr: '', interrupted: false } },
      })
      const lines = (await result.findAll({ type: 'Text' })).map((element: any) => element.text)
      expect(lines[0]).toMatch(/⎿ {2}✓ admitted/)
      expect(lines.join('\n')).toMatch(/− rejected\s+shadow/)
      await result.unmount()
    })
  }

  test("draw Claude's stage notes like the engine's rows", async ($: any) => {
    const row = await $.ui.mount({
      plugin: PLUGIN,
      surface: 'terminal',
      component: 'AssistantMessage',
      props: { text: '**FALCON ② Attack** · attacker: main coding agent · 3 targets, 5–10 probes each', isFirstOfReply: true },
    })
    const text = (await row.findAll({ type: 'Text' })).map((element: any) => element.text).join('')
    expect(text).toMatch(/FALCON ② Attack\s+attacker: main coding agent · 3 targets/)
    await row.unmount()
  })

  test('draw the probe file as the attack stage', async ($: any) => {
    const row = await $.ui.mount({
      plugin: PLUGIN,
      surface: 'terminal',
      component: 'ToolUse',
      props: {
        tool_use_id: 'toolu_2',
        tool: 'Write',
        input: { file_path: '/data/runs/x/probes.json', content: PROBES },
        isRunning: false,
        isErrored: false,
        isInterrupted: false,
      },
    })
    const text = (await row.findAll({ type: 'Text' })).map((element: any) => element.text).join('')
    expect(text).toMatch(/② Attack {2}probes\.json/)
    expect(text).toMatch(/3 probes for 2 targets/)
    await row.unmount()
  })
})
