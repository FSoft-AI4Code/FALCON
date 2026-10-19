export type FalconCommand = 'check-code-security' | 'secure-code-generation'

export type FalconStage = 'code' | 'targets' | 'attack' | 'faithfulness' | 'sandbox' | 'verify' | 'feedback'

export type FalconStageStatus = 'pending' | 'running' | 'done'

export type FalconVerdict = 'insecure' | 'secure' | 'no-evidence'

export type FalconFinding = { target: string; weakness: string; probe: string; reason: string }

export type FalconTurn = { turn: number; verdict: FalconVerdict; findings: number }

export type FalconRun = {
  command: FalconCommand
  scope: string
  turn: number
  turns: number
  sandbox: string
  status: { [stage in FalconStage]: FalconStageStatus }
  notes: { [stage in FalconStage]: string }
  verdict: FalconVerdict | null
  summary: string
  findings: FalconFinding[]
  report: string
  history: FalconTurn[]
  isFinished: boolean
  isStopped: boolean
  isHidden: boolean
}

declare module 'claude-code' {
  interface PluginState {
    'attacker-verifier': { run: FalconRun | null }
  }
}
