import type { DecisionFilter } from '../api/listActivity'
import { decisionFilters } from '../model'

interface ActivityFiltersProps {
  value: DecisionFilter
  onChange: (value: DecisionFilter) => void
}

/** Which decisions to list. A toggle group: exactly one option is pressed. */
export function ActivityFilters({ value, onChange }: ActivityFiltersProps) {
  return (
    <div role="group" aria-label="Show decisions" className="flex flex-wrap gap-2">
      {decisionFilters.map((option) => (
        <button
          key={option.value}
          type="button"
          aria-pressed={option.value === value}
          onClick={() => onChange(option.value)}
          className="inline-flex h-11 cursor-pointer items-center rounded-md border border-border bg-surface px-4 text-sm font-semibold text-foreground transition-colors hover:border-primary/60 aria-pressed:border-primary aria-pressed:bg-primary/10"
        >
          {option.label}
        </button>
      ))}
    </div>
  )
}
