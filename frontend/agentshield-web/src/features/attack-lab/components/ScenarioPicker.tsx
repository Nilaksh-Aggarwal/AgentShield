import type { ComponentType } from 'react'
import { LockIcon, ShieldIcon, type IconProps } from '@/shared/components/ui'
import type { AttackScenario } from '../model/scenarios'

export type ScenarioGroup = 'input' | 'agent'

interface GroupOption {
  group: ScenarioGroup
  label: string
  flow: string
  Icon: ComponentType<IconProps>
}

const groups: readonly GroupOption[] = [
  { group: 'input', label: 'Input security', flow: 'Detect → Score → Policy', Icon: ShieldIcon },
  { group: 'agent', label: 'Agent security', flow: 'Authorize → Gateway → Execute', Icon: LockIcon },
]

/** The two kinds of scenario. Buttons with `aria-pressed`, not ARIA tabs: each one selects a list below. */
export function GroupSwitch({ group, onChange }: { group: ScenarioGroup; onChange: (group: ScenarioGroup) => void }) {
  return (
    <div role="group" aria-label="Scenario type" className="grid gap-2 sm:grid-cols-2">
      {groups.map(({ group: value, label, flow, Icon }) => (
        <button
          key={value}
          type="button"
          aria-pressed={group === value}
          onClick={() => onChange(value)}
          className="flex min-h-11 cursor-pointer items-center gap-3 rounded-lg border border-border bg-surface px-4 py-3 text-left shadow-xs transition-colors hover:border-primary/60 aria-pressed:border-primary aria-pressed:bg-primary/10"
        >
          <Icon className="size-5 shrink-0 text-primary" />
          <span className="flex flex-col">
            <span className="font-semibold text-foreground">{label}</span>
            <span className="sr-only">: </span>
            <span className="text-xs text-muted">{flow}</span>
          </span>
        </button>
      ))}
    </div>
  )
}

interface ScenarioListProps {
  label: string
  scenarios: readonly AttackScenario[]
  selectedId: string
  onSelect: (scenario: AttackScenario) => void
}

/** The scenarios of one group. Selecting one never sends anything: only Run does. */
export function ScenarioList({ label, scenarios, selectedId, onSelect }: ScenarioListProps) {
  return (
    <ul aria-label={label} className="grid gap-2">
      {scenarios.map((scenario) => (
        <li key={scenario.id}>
          <button
            type="button"
            aria-pressed={scenario.id === selectedId}
            onClick={() => onSelect(scenario)}
            className="flex min-h-11 w-full cursor-pointer items-start gap-3 rounded-md border border-border bg-surface px-3 py-2 text-left transition-colors hover:border-primary/60 aria-pressed:border-primary aria-pressed:bg-primary/10"
          >
            {/* Spoken separators: the visual layout alone would run the name together ("I-01Ignore your rules"). */}
            <span className="mt-0.5 font-mono text-xs font-semibold text-muted">{scenario.id}</span>{' '}
            <span className="flex min-w-0 flex-col">
              <span className="text-sm font-semibold text-foreground">{scenario.title}</span>
              <span className="sr-only">, </span>
              <span className="text-xs text-muted">{scenario.category}</span>
            </span>
          </button>
        </li>
      ))}
    </ul>
  )
}
