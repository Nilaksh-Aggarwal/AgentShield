import { exampleInputs, type ExampleInput } from '../model'

interface ExampleInputsProps {
  selectedId: string | undefined
  onSelect: (example: ExampleInput) => void
  disabled: boolean
}

/** Demonstration inputs that fill the text box. Loading one never starts an analysis by itself. */
export function ExampleInputs({ selectedId, onSelect, disabled }: ExampleInputsProps) {
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <h2 id="examples-heading" className="text-sm font-semibold text-foreground">
          Try an example
        </h2>
        <p className="text-xs text-muted">Demonstration inputs, not a benchmark.</p>
      </div>
      <ul className="grid gap-2 sm:grid-cols-2" aria-labelledby="examples-heading">
        {exampleInputs.map((example) => (
          <li key={example.id}>
            <button
              type="button"
              onClick={() => onSelect(example)}
              aria-pressed={selectedId === example.id}
              disabled={disabled}
              className="flex h-full min-h-11 w-full cursor-pointer flex-col items-start gap-0.5 rounded-md border border-border bg-background px-3 py-2 text-left transition-colors not-disabled:hover:border-primary/60 disabled:cursor-not-allowed disabled:opacity-50 aria-pressed:border-primary aria-pressed:bg-primary/10"
            >
              <span className="text-sm font-semibold text-foreground">{example.label}</span>
              <span className="text-xs text-muted">{example.description}</span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  )
}
