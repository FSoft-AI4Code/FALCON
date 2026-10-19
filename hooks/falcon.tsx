// FALCON's live view in Claude Code.
//
// While /check-code-security or /secure-code-generation runs, a band above the
// prompt shows the stages of the attack -> verify loop and marks the one in
// progress. The transcript rows of the engine commands, the probe file, and
// the verdict file are drawn as the stage they belong to. When the run ends,
// the band shows the verdict and the findings until the next prompt.
//
// Every hook here only observes: tool calls pass through unchanged. Progress
// comes from the headline each engine command prints (engine/display.py) and
// from the probe and verdict files the agent writes.

import { atom, read, update } from 'claude-code'
import type { Register } from 'claude-code'

import type {
  FalconCommand,
  FalconFinding,
  FalconRun,
  FalconStage,
  FalconStageStatus,
  FalconVerdict,
} from './falcon-state'

const runAtom = atom({ plugin: 'attacker-verifier', key: 'run' } as const, null)

type Dollar = Parameters<typeof read>[0]
type Ui = { Box: any; Text: any; Button: any }

// `who` is the role that does the stage's work, shown on the band's detail line.
const STAGES: ReadonlyArray<{ key: FalconStage; label: string; number: string; who: string }> = [
  { key: 'code', label: 'Code', number: '', who: 'Claude' },
  { key: 'targets', label: 'Targets', number: '①', who: 'engine' },
  { key: 'attack', label: 'Attack', number: '②', who: 'attacker' },
  { key: 'faithfulness', label: 'Faithfulness', number: '③', who: 'engine' },
  { key: 'sandbox', label: 'Sandbox', number: '④', who: 'engine' },
  { key: 'verify', label: 'Verify', number: '⑤', who: 'verifier' },
  { key: 'feedback', label: 'Feedback', number: '⑥', who: 'engine' },
]

const SKILLS: Record<string, FalconCommand> = {
  'attacker-verifier:check-code-security': 'check-code-security',
  'attacker-verifier:secure-code-generation': 'secure-code-generation',
  'check-code-security': 'check-code-security',
  'secure-code-generation': 'secure-code-generation',
}

// ---------------------------------------------------------------- parsing --

type EngineCall = { sub: string; turn: number | null; turns: number | null; scope: string }

const ENGINE = /engine\/cli\.py["']?\s+(select-targets|check|show-traces|finalize|session|resolve-model)\b/g

// Every engine command in a shell command, in order. Each one's flags are read
// from the text up to the next engine command.
function engineCalls(command: string): EngineCall[] {
  const found = [...command.matchAll(ENGINE)]
  return found.map((match, index) => {
    const end = index + 1 < found.length ? found[index + 1]!.index : command.length
    const text = command.slice(match.index, end)
    const turn = /--turn[=\s]+["']?(\d+)\/(\d+)/.exec(text)
    const path = /--path[=\s]+(?:"([^"]*)"|'([^']*)'|(\S+))/.exec(text)
    const scope = /--scope[=\s]+["']?(\w+)/.exec(text)
    let where = path ? (path[1] ?? path[2] ?? path[3] ?? '') : scope ? (scope[1] ?? '') : ''
    if (where === 'changed') where = 'changed code'
    return {
      sub: match[1] ?? '',
      turn: turn ? Number(turn[1]) : null,
      turns: turn ? Number(turn[2]) : null,
      scope: where,
    }
  })
}

function textOf(output: unknown): string {
  if (typeof output === 'string') return output
  if (output && typeof output === 'object') {
    const record = output as { stdout?: unknown; text?: unknown }
    if (typeof record.stdout === 'string') return record.stdout
    if (typeof record.text === 'string') return record.text
  }
  return ''
}

function parseJson(text: string): any {
  try {
    return JSON.parse(text)
  } catch {
    return null
  }
}

type Probe = { id: string; target: string; cwe: string; rationale: string }

function parseProbes(content: string): Probe[] | null {
  const doc = parseJson(content)
  if (!doc || !Array.isArray(doc.probes)) return null
  return doc.probes.map((probe: any) => ({
    id: String(probe?.id ?? '?'),
    target: String(probe?.target ?? '?'),
    cwe: String(probe?.cwe ?? ''),
    rationale: String(probe?.rationale ?? ''),
  }))
}

type Verdict = { id: string; verdict: string; reason: string }

function parseVerdicts(content: string): Verdict[] | null {
  const doc = parseJson(content)
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return null
  return Object.entries(doc).map(([id, value]: [string, any]) => ({
    id,
    verdict: String(value?.verdict ?? '?'),
    reason: String(value?.reason ?? ''),
  }))
}

type CheckCounts = { admitted: number; rejected: number; inconclusive: number; crashed: number; toJudge: number }

function parseCheck(text: string): CheckCounts | null {
  const m = /Result: (\d+) admitted · (\d+) rejected · (\d+) inconclusive · (\d+) crashed · (\d+) to judge/.exec(text)
  if (!m) return null
  return {
    admitted: Number(m[1]),
    rejected: Number(m[2]),
    inconclusive: Number(m[3]),
    crashed: Number(m[4]),
    toJudge: Number(m[5]),
  }
}

type Final = { verdict: FalconVerdict; summary: string; findings: FalconFinding[]; report: string }

function parseFinal(text: string): Final | null {
  const head = /FALCON ⑥ Feedback · (INSECURE|SECURE|NO EVIDENCE) · ([^\n]*)/.exec(text)
  if (!head) return null
  const verdict: FalconVerdict = head[1] === 'INSECURE' ? 'insecure' : head[1] === 'SECURE' ? 'secure' : 'no-evidence'
  const findings: FalconFinding[] = []
  const pattern = /^Finding \d+ · ([^\n]+?) · ([^\n]+?) · probe (\S+) · stage \S+\n {2}([^\n]*)/gm
  for (let m = pattern.exec(text); m !== null; m = pattern.exec(text)) {
    findings.push({ target: m[1] ?? '', weakness: m[2] ?? '', probe: m[3] ?? '', reason: m[4] ?? '' })
  }
  const report = /^Report: (.+)$/m.exec(text)
  return {
    verdict,
    summary: (head[2] ?? '').replace(/ · turn \d+\/\d+$/, ''),
    findings,
    report: report ? (report[1] ?? '') : '',
  }
}

function plural(count: number, word: string): string {
  return `${count} ${word}${count === 1 ? '' : 's'}`
}

function clip(text: string, width: number): string {
  const flat = text.replace(/\s+/g, ' ').trim()
  return flat.length <= width ? flat : flat.slice(0, Math.max(1, width - 1)) + '…'
}

// Cuts a line to width without touching its spacing, so columns stay aligned.
function cut(text: string, width: number): string {
  return text.length <= width ? text : text.slice(0, Math.max(1, width - 1)) + '…'
}

function basename(path: string): string {
  return path.split('/').pop() ?? path
}

function symbol(target: string): string {
  const qual = target.includes('::') ? target.split('::').pop() ?? target : target
  return qual
}

// ------------------------------------------------------------------ state --

function freshRun(command: FalconCommand, scope: string, turns: number): FalconRun {
  const status = {} as FalconRun['status']
  const notes = {} as FalconRun['notes']
  for (const stage of STAGES) {
    status[stage.key] = 'pending'
    notes[stage.key] = ''
  }
  const generating = command === 'secure-code-generation'
  status[generating ? 'code' : 'targets'] = 'running'
  notes[generating ? 'code' : 'targets'] = generating ? 'implementing' : 'choosing scope'
  return {
    command,
    scope,
    turn: generating ? 0 : 1,
    turns: generating ? turns : 1,
    sandbox: '',
    status,
    notes,
    verdict: null,
    summary: '',
    findings: [],
    report: '',
    history: [],
    isFinished: false,
    isStopped: false,
    isHidden: false,
  }
}

function mark(run: FalconRun, stage: FalconStage, status: FalconStageStatus, note?: string): FalconRun {
  return {
    ...run,
    status: { ...run.status, [stage]: status },
    notes: note === undefined ? run.notes : { ...run.notes, [stage]: note },
  }
}

function startTurn(run: FalconRun, turn: number): FalconRun {
  const status = { ...run.status }
  const notes = { ...run.notes }
  for (const stage of STAGES) {
    if (stage.key === 'code') continue
    status[stage.key] = 'pending'
    notes[stage.key] = ''
  }
  status.code = 'done'
  notes.code = turn <= 1 ? 'implemented' : 'repaired'
  return { ...run, turn, status, notes, verdict: null, summary: '', findings: [], report: '' }
}

function skillCommand(skill: string, text: string): FalconCommand | null {
  const command = SKILLS[skill]
  if (!command) return null
  // A bare name could be another plugin's skill; ours names the plugin.
  return skill.includes(':') || text.includes('attacker-verifier') ? command : null
}

function shortArgs(args: string): string {
  const value = args.trim()
  return value.startsWith('$') ? '' : clip(value.replace(/(^|\s)--\S+(\s+[^-\s]\S*)?/g, ' '), 48)
}

function scopeOf(text: string): string {
  const args = /The user's arguments are: `([^`\n]*)`/.exec(text)
  return shortArgs(args?.[1] ?? '')
}

function turnsOf(text: string): number {
  const flag = /--turns[=\s]+(\d+)/.exec(text)
  const setting = /[Rr]epair turns(?: N =|:) `(\d+)`/.exec(text)
  return Number(flag?.[1] ?? setting?.[1] ?? 2)
}

// The two commands as typed, or as the model calls them with the Skill tool.
// skill.prompt says the same with the settings filled in, but it does not run
// where an organization manages the plugins, so these start the run as well.
const SLASH = /^\/(?:attacker-verifier:)?(check-code-security|secure-code-generation)(?:\s+([\s\S]*))?$/

function runFromCommand(command: FalconCommand, args: string): FalconRun {
  return freshRun(command, shortArgs(args), turnsOf(args))
}

type Step =
  | { kind: 'skill'; command: FalconCommand; args: string }
  | { kind: 'engine'; calls: EngineCall[] }
  | { kind: 'probes'; content: string }
  | { kind: 'verdicts'; content: string }
  | { kind: 'agent'; role: 'attacker' | 'verifier'; model: string }

function classify(e: { tool: string } & Record<string, unknown>): Step | null {
  if (e.tool === 'Bash' && typeof e.command === 'string') {
    const calls = engineCalls(e.command)
    return calls.length ? { kind: 'engine', calls } : null
  }
  if (e.tool === 'Write' && typeof e.file_path === 'string' && typeof e.content === 'string') {
    if (e.file_path.endsWith('probes.json')) return { kind: 'probes', content: e.content }
    if (e.file_path.endsWith('verdicts.json')) return { kind: 'verdicts', content: e.content }
    return null
  }
  if (e.tool === 'Skill' && typeof e.skill === 'string') {
    const command = SKILLS[e.skill]
    return command && e.skill.includes(':')
      ? { kind: 'skill', command, args: typeof e.args === 'string' ? e.args : '' }
      : null
  }
  if (e.tool === 'Agent' && typeof e.subagent_type === 'string') {
    const model = typeof e.model === 'string' ? e.model : ''
    if (e.subagent_type === 'attacker-verifier:attacker') return { kind: 'agent', role: 'attacker', model }
    if (e.subagent_type === 'attacker-verifier:verifier') return { kind: 'agent', role: 'verifier', model }
  }
  return null
}

function before(step: Step, current: FalconRun | null): FalconRun | null {
  if (step.kind === 'skill') return runFromCommand(step.command, step.args)
  if (step.kind === 'agent') {
    if (!current) return current
    const note = step.model ? `${step.model} subagent` : 'subagent'
    return step.role === 'attacker' ? mark(current, 'attack', 'running', note) : mark(current, 'verify', 'running', note)
  }
  if (step.kind !== 'engine') return current
  return step.calls.reduce<FalconRun | null>((run, call) => beforeEngine(call, run), current)
}

function beforeEngine(call: EngineCall, current: FalconRun | null): FalconRun | null {
  const { sub, turn, turns, scope } = call
  // A turn can end while a subagent works or the user is asked something; the
  // next engine call picks the run up again.
  if (current && current.isStopped && !current.verdict && sub !== 'select-targets') {
    current = { ...current, isStopped: false, isFinished: false }
  }
  if (sub === 'select-targets') {
    // Continue the run in progress, or one the turn ended before its verdict;
    // anything else is a new pass outside the skills, shown as a check.
    const isActive = current !== null && (!current.isFinished || (current.isStopped && !current.verdict))
    let run = isActive ? { ...current, isFinished: false, isStopped: false } : freshRun('check-code-security', scope, 1)
    if (run.command === 'secure-code-generation') {
      if (turns !== null) run = { ...run, turns }
      const next = turn ?? (run.turn === 0 || run.status.feedback === 'done' ? run.turn + 1 : run.turn)
      if (next !== run.turn) run = startTurn(run, next)
    }
    if (scope && !run.scope) run = { ...run, scope }
    return mark(run, 'targets', 'running', 'selecting')
  }
  if (!current) return current
  if (sub === 'check') {
    let run = mark(current, 'attack', 'done')
    run = mark(run, 'faithfulness', 'running', 'screening')
    return mark(run, 'sandbox', 'running', 'running probes')
  }
  if (sub === 'finalize') {
    const judged = current.notes.verify.replace(/^judging /, 'judged ')
    const run = mark(current, 'verify', 'done', judged || 'judged')
    return mark(run, 'feedback', 'running', 'aggregating')
  }
  return current
}

function after(step: Step, current: FalconRun | null, output: string): FalconRun | null {
  if (!current) return current
  if (step.kind === 'probes') {
    const probes = parseProbes(step.content)
    if (!probes) return current
    return mark(current, 'attack', current.status.attack === 'done' ? 'done' : 'running', plural(probes.length, 'probe'))
  }
  if (step.kind === 'verdicts') {
    const verdicts = parseVerdicts(step.content)
    if (!verdicts) return current
    const insecure = verdicts.filter(v => v.verdict === 'insecure').length
    return mark(current, 'verify', current.status.verify, `${insecure} insecure of ${verdicts.length}`)
  }
  if (step.kind !== 'engine') return current
  return step.calls.reduce<FalconRun | null>((run, call) => afterEngine(call, run, output), current)
}

function afterEngine(call: EngineCall, current: FalconRun | null, output: string): FalconRun | null {
  if (!current) return current
  const { sub } = call
  if (sub === 'session') {
    const where = /FALCON sandbox: probes run (?:on the |in )(.+?)(?: for the rest| \(chosen)/.exec(output)
    return where ? { ...current, sandbox: where[1] ?? '' } : current
  }
  if (sub === 'select-targets') {
    const found = /FALCON ① Targets · (\d+) targets? in /.exec(output)
    if (/FALCON ① Targets · nothing to attack/.test(output)) {
      const run = mark(current, 'targets', 'done', 'none in scope')
      return { ...run, isFinished: true, summary: 'nothing to attack in scope' }
    }
    if (!found) return current
    const budget = /write (\d+)–(\d+) probes per target/.exec(output)
    const run = mark(current, 'targets', 'done', plural(Number(found[1]), 'target'))
    return mark(run, 'attack', 'running', budget ? `${budget[1]}–${budget[2]} probes each` : 'writing probes')
  }
  if (sub === 'check') {
    const counts = parseCheck(output)
    if (!counts) return current
    const removed = counts.rejected + counts.inconclusive
    const probes = /FALCON ③ Faithfulness · ④ Sandbox · (\d+) probes? for/.exec(output)
    let run = probes ? mark(current, 'attack', 'done', plural(Number(probes[1]), 'probe')) : current
    run = mark(run, 'faithfulness', 'done', removed ? `${removed} rejected` : 'all admitted')
    run = mark(run, 'sandbox', 'done', `${counts.admitted + counts.inconclusive} ran`)
    const crashes = counts.crashed ? `${plural(counts.crashed, 'crash')}` : ''
    if (counts.toJudge > 0) {
      return mark(run, 'verify', 'running', [crashes, `judging ${counts.toJudge}`].filter(Boolean).join(' · '))
    }
    return mark(run, 'verify', 'done', crashes || 'nothing to judge')
  }
  if (sub === 'finalize') {
    const final = parseFinal(output)
    if (!final) return current
    let run = mark(current, 'feedback', 'done',
      final.findings.length ? plural(final.findings.length, 'counterexample') : final.report ? 'report' : 'no violation')
    run = { ...run, verdict: final.verdict, summary: final.summary, findings: final.findings, report: final.report }
    if (run.command === 'secure-code-generation') {
      run = { ...run, history: [...run.history, { turn: run.turn, verdict: final.verdict, findings: final.findings.length }] }
      if (final.verdict === 'insecure' && run.turn < run.turns) {
        return mark(run, 'code', 'running', `repairing ${final.findings.length}`)
      }
    }
    return { ...run, isFinished: true }
  }
  return current
}

// ------------------------------------------------------------------- band --

function stageStyle(status: FalconStageStatus): { glyph: string; props: Record<string, unknown> } {
  if (status === 'running') return { glyph: '●', props: { color: 'claude', bold: true } }
  if (status === 'done') return { glyph: '✓', props: { color: 'success' } }
  return { glyph: '○', props: { dimColor: true } }
}

function headerText(run: FalconRun): string {
  // A generation run's scope is the request; keep it short so the turn shows.
  const scope = run.command === 'secure-code-generation' && run.scope ? `"${clip(run.scope, 34)}"` : run.scope
  const parts = [run.command + (scope ? ` ${scope}` : '')]
  if (run.command === 'secure-code-generation') {
    parts.push(run.turn === 0 ? `turn 0/${run.turns}` : `turn ${run.turn}/${run.turns}`)
  }
  if (run.sandbox) parts.push(`sandbox: ${run.sandbox}`)
  return parts.join(' · ')
}

const ROLE_COLOR: Record<string, string> = { Claude: 'claude', attacker: 'error', verifier: 'suggestion' }

// Two lines under the header: the stages as chips joined by connectors, then
// the stage in progress with who runs it and what it is doing, followed by the
// counts the finished stages left.
function drawStages(ui: Ui, run: FalconRun, columns: number) {
  const { Box, Text } = ui
  const stages = STAGES.filter(stage => stage.key !== 'code' || run.command === 'secure-code-generation')
  const active = stages.find(stage => run.status[stage.key] === 'running')
  const header = (
    <Text>
      <Text bold color="claude">FALCON</Text>
      <Text dimColor>{'  ' + clip(headerText(run), Math.max(10, columns - 10))}</Text>
    </Text>
  )
  const chipsWidth = stages.reduce((sum, stage) => sum + stage.label.length + 2, 0) + 3 * (stages.length - 1)
  const counts = stages
    .filter(stage => run.status[stage.key] === 'done' && run.notes[stage.key])
    .map(stage => run.notes[stage.key])
    .join(' · ')
  const lines = [header]
  if (chipsWidth <= columns) {
    const chips: unknown[] = []
    stages.forEach((stage, index) => {
      const { glyph, props } = stageStyle(run.status[stage.key])
      if (index > 0) chips.push(<Text dimColor>{' ─ '}</Text>)
      chips.push(<Text {...props}>{`${glyph} ${stage.label}`}</Text>)
    })
    lines.push(<Text>{chips}</Text>)
  } else {
    const done = stages.filter(stage => run.status[stage.key] === 'done').length
    lines.push(<Text dimColor>{`${done} of ${stages.length} stages done`}</Text>)
  }
  if (active) {
    const name = `${active.number ? active.number + ' ' : ''}${active.label}`
    const who = active.key === 'code' && run.turn > 0 ? 'Claude repairs' : active.who
    const doing = run.notes[active.key]
    const head = `${name}  ${who}${doing ? ' · ' + doing : ''}`
    const room = columns - head.length - 4
    lines.push(
      <Text>
        <Text bold color="claude">{name}</Text>
        <Text>{'  '}</Text>
        <Text color={ROLE_COLOR[active.who] ?? 'inactive'}>{who}</Text>
        <Text dimColor>{(doing ? ' · ' + doing : '') + (counts && room > 12 ? '    ' + clip(counts, room) : '')}</Text>
      </Text>,
    )
  }
  return <Box flexDirection="column">{lines}</Box>
}

function drawVerdict($: Dollar, ui: Ui, run: FalconRun, columns: number) {
  const { Box, Text, Button } = ui
  const look = run.verdict === 'insecure'
    ? { label: '✗ INSECURE', color: 'error' }
    : run.verdict === 'secure'
      ? { label: '✓ SECURE', color: 'success' }
      : run.verdict === 'no-evidence'
        ? { label: '? NO EVIDENCE', color: 'warning' }
        : { label: '■ STOPPED', color: 'warning' }
  const active = STAGES.find(stage => run.status[stage.key] === 'running')
  const summary = run.verdict
    ? run.summary
    : run.summary || (active ? `the turn ended during ${active.label}` : 'the turn ended before a verdict')
  const lines = []
  if (run.command === 'secure-code-generation' && run.history.length) {
    const steps = run.history.map(turn =>
      turn.verdict === 'insecure' ? `turn ${turn.turn} ✗ ${plural(turn.findings, 'finding')}` : `turn ${turn.turn} ✓ ${turn.verdict}`)
    lines.push(<Text dimColor>{'  ' + clip(steps.join('  →  '), columns - 4)}</Text>)
  }
  // One row per unsafe target: its weaknesses, the probes that showed them, and
  // the first reason.
  const byTarget = new Map<string, FalconFinding[]>()
  for (const finding of run.findings) byTarget.set(finding.target, [...(byTarget.get(finding.target) ?? []), finding])
  const targets = [...byTarget.entries()]
  for (const [target, found] of targets.slice(0, 3)) {
    const weaknesses = [...new Set(found.map(finding => finding.weakness))].join(', ')
    const probes = found.map(finding => finding.probe)
    lines.push(
      <Text>
        <Text color="error">{'  ✗ '}</Text>
        <Text bold>{target}</Text>
        <Text dimColor>{'  ' + clip(`${weaknesses} · ${probes.length > 2 ? `${probes.slice(0, 2).join(', ')} +${probes.length - 2}` : probes.join(', ')}`, Math.max(10, columns - target.length - 8))}</Text>
      </Text>,
    )
    lines.push(<Text dimColor>{'    ' + clip(found[0]!.reason, columns - 6)}</Text>)
  }
  if (targets.length > 3) lines.push(<Text dimColor>{`  … ${targets.length - 3} more targets in the report`}</Text>)
  if (run.report) lines.push(<Text dimColor>{'  report  ' + basename(run.report)}</Text>)
  return (
    <Box flexDirection="column">
      <Box flexDirection="row" justifyContent="space-between">
        <Text>
          <Text bold color="claude">FALCON</Text>
          <Text>{'  '}</Text>
          <Text bold color={look.color}>{look.label}</Text>
          <Text dimColor>{'  ' + clip(summary, Math.max(10, columns - 34))}</Text>
        </Text>
        <Button
          key="falcon-hide"
          label="Hide"
          onPress={() => update($, runAtom, current => (current ? { ...current, isHidden: true } : current))}
        />
      </Box>
      {lines}
    </Box>
  )
}

// ------------------------------------------------------- transcript rows --

type Row = { stage: string; title: string; detail: string; titleColor?: string }
type Part = { text: string; color?: string; dim?: boolean; bold?: boolean }
type Line = Part[]

// Element props are plain data, so leave a prop out rather than set it to undefined.
function partProps(part: Part): Record<string, unknown> {
  const props: Record<string, unknown> = {}
  if (part.color) props.color = part.color
  if (part.dim) props.dimColor = true
  if (part.bold) props.bold = true
  return props
}

const MARK_COLOR: Record<string, string> = { '✓': 'success', '✗': 'error', '−': 'warning', '?': 'warning' }

// One line of an engine command's output: the status in its color, the name
// plain, the rest dim, spacing kept.
function engineLine(raw: string): Line {
  const line = raw.replace(/\s+$/, '').replace(/^ {2}/, '')
  const status = /^([✓✗−?] \S+(?: EVIDENCE)?)(\s+)(\S+)(.*)$/.exec(line)
  if (status) {
    const color = MARK_COLOR[status[1]!.charAt(0)] ?? 'warning'
    return [{ text: status[1]!, color }, { text: status[2]! }, { text: status[3]! }, { text: status[4]!, dim: true }]
  }
  if (line.startsWith('Finding ')) {
    const [head, ...rest] = line.split(' · ')
    return [{ text: head ?? '', color: 'error', bold: true }, { text: rest.length ? ' · ' + rest.join(' · ') : '' }]
  }
  if (/^(Next|Report|Result):/.test(line)) return [{ text: line, dim: true }]
  const name = /^(\S+)(.*)$/.exec(line)
  return name && !line.startsWith(' ') ? [{ text: name[1]! }, { text: name[2]!, dim: true }] : [{ text: line, dim: true }]
}

function rowFor(tool: string, input: unknown, output: unknown): Row | null {
  const args = (input ?? {}) as Record<string, unknown>
  if (tool === 'Bash' && typeof args.command === 'string') {
    const calls = engineCalls(args.command)
    // A command that chains several engine calls is drawn as its last stage.
    const call = [...calls].reverse().find(one => one.sub !== 'resolve-model') ?? calls[0]
    if (!call) return null
    const text = textOf(output)
    const head = /^FALCON ([^\n]*)$/m.exec(text)
    if (call.sub === 'select-targets') {
      const counts = head ? head[1]!.replace(/^① Targets · /, '') : `select targets${call.scope ? ' in ' + call.scope : ''}`
      return { stage: '① Targets', title: '', detail: counts }
    }
    if (call.sub === 'check') {
      const counts = parseCheck(text)
      const detail = counts
        ? `${counts.admitted} admitted · ${counts.rejected + counts.inconclusive} rejected · ${counts.crashed} crashed · ${counts.toJudge} to judge`
        : head ? head[1]!.replace(/^③ Faithfulness · ④ Sandbox · /, '') : 'screen and run the probes'
      return { stage: '③ Faithfulness · ④ Sandbox', title: '', detail }
    }
    if (call.sub === 'finalize') {
      const final = parseFinal(text)
      const detail = final ? `${final.verdict.toUpperCase()} · ${final.summary}` : 'aggregate the verdicts'
      return { stage: '⑥ Feedback', title: '', detail }
    }
    if (call.sub === 'session') {
      const line = /FALCON sandbox: ([^\n]+)/.exec(text)
      const detail = line ? (line[1] ?? '').replace(' for the rest of this session', '') : 'check this session\'s sandbox choice'
      return { stage: 'Sandbox', title: '', detail }
    }
    if (call.sub === 'show-traces') {
      const counts = /FALCON ⑤ Verify · ([^\n]+?)(?: · turn \d+\/\d+)?$/m.exec(text)
      return { stage: '⑤ Verify', title: '', detail: counts ? counts[1] ?? '' : 'show the traces to judge' }
    }
    if (call.sub === 'resolve-model') {
      const model = text.trim().split('\n').pop() ?? ''
      return { stage: 'Model', title: '', detail: model === 'main' ? 'main coding agent' : model || 'resolve the model' }
    }
    return null
  }
  if (tool === 'Write' && typeof args.file_path === 'string' && typeof args.content === 'string') {
    if (args.file_path.endsWith('probes.json')) {
      const probes = parseProbes(args.content)
      const targets = probes ? new Set(probes.map(probe => probe.target)).size : 0
      return { stage: '② Attack', title: 'probes.json', detail: probes ? `${plural(probes.length, 'probe')} for ${plural(targets, 'target')}` : '' }
    }
    if (args.file_path.endsWith('verdicts.json')) {
      const verdicts = parseVerdicts(args.content)
      const insecure = verdicts ? verdicts.filter(v => v.verdict === 'insecure').length : 0
      return { stage: '⑤ Verify', title: 'verdicts.json', detail: verdicts ? `${plural(verdicts.length, 'trace')} judged · ${insecure} insecure` : '' }
    }
    return null
  }
  if (tool === 'Agent' && typeof args.subagent_type === 'string') {
    const model = typeof args.model === 'string' ? ` · ${args.model}` : ''
    const description = typeof args.description === 'string' ? args.description : ''
    if (args.subagent_type === 'attacker-verifier:attacker') {
      return { stage: '② Attack', title: 'attacker', titleColor: 'error', detail: description + model }
    }
    if (args.subagent_type === 'attacker-verifier:verifier') {
      return { stage: '⑤ Verify', title: 'verifier', titleColor: 'suggestion', detail: description + model }
    }
    return null
  }
  if (tool === 'Read' && typeof args.file_path === 'string') {
    const path = args.file_path
    if (path.endsWith('engine/prompts/attacker.md')) return { stage: '② Attack', title: '', detail: 'read the attacker prompt' }
    if (path.endsWith('engine/prompts/verifier_stage3.md')) return { stage: '⑤ Verify', title: '', detail: 'read the trace-judge prompt' }
    if (path.endsWith('/traces.json')) return { stage: '⑤ Verify', title: '', detail: 'read the undecided traces' }
    if (path.endsWith('/targets.json')) return { stage: '① Targets', title: '', detail: 'read the targets' }
    if (path.endsWith('/final.json')) return { stage: '⑥ Feedback', title: '', detail: 'read the findings' }
    if (path.endsWith('docs/sandbox.md')) return { stage: 'Sandbox', title: '', detail: 'read the sandbox modes' }
    if (path.endsWith('docs/attack-verify-loop.md')) return { stage: 'Loop', title: '', detail: 'read the attack → verify procedure' }
  }
  return null
}

function resultLines(tool: string, output: unknown): Line[] | null {
  if (tool === 'Bash') {
    const text = textOf(output)
    if (!text.startsWith('FALCON ')) return null
    const lines = text.split('\n').slice(1).filter(raw => raw.trim())
    if (text.startsWith('FALCON ⑤ Verify')) {
      // The trace listing: one line per trace; the judge reads the rest.
      return lines.filter(line => line.startsWith('[')).map(line => [{ text: line }])
    }
    if (text.startsWith('FALCON sandbox:')) return []
    return lines.map(engineLine)
  }
  if (tool === 'Write' && output && typeof output === 'object') {
    const record = output as { filePath?: unknown; content?: unknown }
    if (typeof record.filePath !== 'string' || typeof record.content !== 'string') return null
    if (record.filePath.endsWith('probes.json')) {
      const probes = parseProbes(record.content)
      if (!probes) return null
      const idWidth = Math.min(22, Math.max(...probes.map(probe => probe.id.length)))
      const targetWidth = Math.min(20, Math.max(...probes.map(probe => symbol(probe.target).length)))
      return probes.map(probe => [
        { text: cut(probe.id, idWidth).padEnd(idWidth) + '  ' },
        { text: cut(symbol(probe.target), targetWidth).padEnd(targetWidth) + '  ', dim: true },
        { text: cut(probe.cwe, 10).padEnd(10) + '  ', color: 'warning' },
        { text: probe.rationale, dim: true },
      ])
    }
    if (record.filePath.endsWith('verdicts.json')) {
      const verdicts = parseVerdicts(record.content)
      if (!verdicts) return null
      const sorted = [...verdicts].sort((a, b) => Number(b.verdict === 'insecure') - Number(a.verdict === 'insecure'))
      const idWidth = Math.min(22, Math.max(...sorted.map(v => v.id.length)))
      return sorted.map(v => [
        { text: v.verdict === 'insecure' ? '✗ insecure  ' : '✓ secure    ', color: v.verdict === 'insecure' ? 'error' : 'success' },
        { text: cut(v.id, idWidth).padEnd(idWidth) + '  ' },
        { text: v.reason, dim: true },
      ])
    }
  }
  return null
}

// ---------------------------------------------------------------- register --

export const register: Register = on => {
  on('skill.prompt', async ($, e, next) => {
    const command = skillCommand(e.skill, e.text)
    if (command) {
      const run = freshRun(command, scopeOf(e.text), command === 'secure-code-generation' ? turnsOf(e.text) : 1)
      await update($, runAtom, () => run).catch(() => undefined)
    }
    return next(e)
  })

  on('tool.call', async ($, e, next) => {
    const step = classify(e as unknown as { tool: string } & Record<string, unknown>)
    if (step === null) return next(e)
    await update($, runAtom, current => before(step, current ?? null)).catch(() => undefined)
    const ran = await next(e)
    if (!('deny' in ran && ran.deny !== undefined)) {
      const output = typeof ran.text === 'string' ? ran.text : textOf(ran.result)
      await update($, runAtom, current => after(step, current ?? null, output)).catch(() => undefined)
    }
    return ran
  })

  on('turn.complete', async ($, e, next) => {
    if (e.agentId === undefined) {
      await update($, runAtom, current => {
        if (!current || current.isFinished) return current
        // The main turn may end while the attacker or verifier subagent runs in
        // the background; its result starts the next turn.
        const waiting = (['attack', 'verify'] as const).some(
          stage => current.status[stage] === 'running' && current.notes[stage].endsWith('subagent'))
        return waiting && e.reason === 'answer' ? current : { ...current, isFinished: true, isStopped: true }
      }).catch(() => undefined)
    }
    return next(e)
  })

  on('prompt.submit', async ($, e, next) => {
    // Only a person's prompt starts or clears a run; a background task's
    // notification belongs to the run in progress.
    const isPerson = e.origin.kind === 'composer' || e.origin.kind === 'bridge' || e.origin.kind === 'sdk'
    if (isPerson) {
      const slash = SLASH.exec(e.text.trim())
      await update($, runAtom, current => {
        if (slash) return runFromCommand(slash[1] as FalconCommand, slash[2] ?? '')
        return current && current.isFinished ? null : current
      }).catch(() => undefined)
    }
    return next(e)
  })

  on('ui.render', { component: 'AbovePrompt' }, async ($, e, next) => {
    const run = await read($, runAtom)
    if (!run || run.isHidden || e.props.hasSurvey) return next(e)
    const ui = $.ui.resolve(e) as unknown as Ui
    const columns = e.props.bodyColumns
    return run.isFinished ? drawVerdict($, ui, run, columns) : drawStages(ui, run, columns)
  })

  on('ui.render', { component: 'ToolUse' }, async ($, e, next) => {
    const row = rowFor(e.props.tool, e.props.input, e.props.output)
    if (!row) return next(e)
    const { Text } = $.ui.resolve(e) as unknown as Ui
    const dot = e.props.isErrored ? 'error' : e.props.isRunning ? 'claude' : 'success'
    return (
      <Text>
        <Text color={dot}>{'⏺ '}</Text>
        <Text bold color="claude">FALCON</Text>
        <Text bold>{' ' + row.stage}</Text>
        <Text bold {...(row.titleColor ? { color: row.titleColor } : {})}>{row.title ? '  ' + row.title : ''}</Text>
        <Text dimColor>{(row.detail ? '  ' + row.detail : '') + (e.props.isRunning ? ' …' : '')}</Text>
      </Text>
    )
  })

  // Claude's one-line stage notes (`**FALCON ② Attack** · …`) drawn like the
  // engine's stage rows.
  on('ui.render', { component: 'AssistantMessage' }, async ($, e, next) => {
    const line = /^\*\*FALCON ([^*\n]+)\*\*([^\n]*)$/.exec(e.props.text.trim())
    if (!line || e.props.isSummary) return next(e)
    const { Text } = $.ui.resolve(e) as unknown as Ui
    return (
      <Text>
        <Text>{e.props.isFirstOfReply ? '⏺ ' : '  '}</Text>
        <Text bold color="claude">FALCON</Text>
        <Text bold>{' ' + (line[1] ?? '').trim()}</Text>
        <Text dimColor>{'  ' + (line[2] ?? '').replace(/^\s*·\s*/, '').trim()}</Text>
      </Text>
    )
  })

  on('ui.render', { component: 'ToolResult' }, async ($, e, next) => {
    if (e.props.isErrored) return next(e)
    const lines = resultLines(e.props.tool, e.props.output)
    if (!lines) return next(e)
    const { Box, Text } = $.ui.resolve(e) as unknown as Ui
    // The sandbox line says all there is in the row above it.
    if (lines.length === 0) return <Box />
    const columns = Math.max(40, (e.viewport?.columns ?? 100) - 8)
    const shown = lines.slice(0, 8)
    return (
      <Box flexDirection="column">
        {shown.map((line, index) => {
          let room = columns
          const parts = line.map(part => {
            const text = room > 0 ? cut(part.text, room) : ''
            room -= part.text.length
            return <Text {...partProps(part)}>{text}</Text>
          })
          return <Text><Text dimColor>{index === 0 ? '  ⎿  ' : '     '}</Text>{parts}</Text>
        })}
        {lines.length > shown.length ? [<Text dimColor>{`     … ${lines.length - shown.length} more`}</Text>] : []}
      </Box>
    )
  })
}
