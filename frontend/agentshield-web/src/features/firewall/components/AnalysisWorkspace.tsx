import type { FormEvent, KeyboardEvent, Ref } from 'react'
import { Button, Card, ErrorIcon, InfoIcon, SpinnerIcon, XIcon } from '@/shared/components/ui'
import { MAX_INPUT_LENGTH } from '../api/analyzeInput'
import type { ExampleInput } from '../model'
import { ExampleInputs } from './ExampleInputs'

interface AnalysisWorkspaceProps {
  input: string
  onInputChange: (value: string) => void
  onSubmit: () => void
  onClear: () => void
  onExample: (example: ExampleInput) => void
  selectedExample: ExampleInput | undefined
  pending: boolean
  /** Field-level messages from a 422, shown next to the text box. */
  inputErrors: readonly string[]
  canClear: boolean
  textareaRef?: Ref<HTMLTextAreaElement>
}

export function AnalysisWorkspace({
  input,
  onInputChange,
  onSubmit,
  onClear,
  onExample,
  selectedExample,
  pending,
  inputErrors,
  canClear,
  textareaRef,
}: AnalysisWorkspaceProps) {
  const tooLong = input.length > MAX_INPUT_LENGTH
  const canSubmit = input.trim().length > 0 && !tooLong && !pending
  const describedBy = ['firewall-input-help', selectedExample?.note && 'firewall-input-note', inputErrors.length > 0 && 'firewall-input-errors']
    .filter(Boolean)
    .join(' ')

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (canSubmit) {
      onSubmit()
    }
  }

  // Ctrl+Enter (Cmd+Enter on macOS) submits from the text box, where Enter alone adds a new line.
  function handleKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) {
      event.preventDefault()
      event.currentTarget.form?.requestSubmit()
    }
  }

  return (
    <Card as="section" aria-labelledby="workspace-heading" className="space-y-6">
      <h2 id="workspace-heading" className="sr-only">
        Input
      </h2>
      <form onSubmit={handleSubmit} aria-busy={pending} className="space-y-3">
        <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
          <label htmlFor="firewall-input" className="text-sm font-semibold text-foreground">
            Input to analyze
          </label>
          <span
            id="firewall-input-help"
            className={`text-xs tabular-nums ${tooLong ? 'font-semibold text-danger' : 'text-muted'}`}
          >
            {input.length.toLocaleString()} / {MAX_INPUT_LENGTH.toLocaleString()} characters
            {tooLong && ' — over the limit'}
          </span>
        </div>
        <textarea
          id="firewall-input"
          ref={textareaRef}
          value={input}
          onChange={(event) => onInputChange(event.target.value)}
          onKeyDown={handleKeyDown}
          rows={7}
          placeholder="Paste untrusted text here, for example a user message or a web page an agent is about to read."
          aria-invalid={tooLong || inputErrors.length > 0}
          aria-describedby={describedBy}
          // Untrusted and possibly sensitive content: keep it out of browser spell-check, autofill and autocorrect.
          spellCheck={false}
          autoComplete="off"
          autoCapitalize="off"
          autoCorrect="off"
          className="block min-h-40 w-full resize-y rounded-md border border-border bg-background px-3 py-2 font-mono text-sm text-foreground placeholder:font-sans placeholder:text-muted aria-[invalid=true]:border-danger"
        />
        {selectedExample?.note && (
          <p id="firewall-input-note" className="flex gap-2 text-xs text-muted">
            <InfoIcon className="mt-px size-3.5" />
            {selectedExample.note}
          </p>
        )}
        {inputErrors.length > 0 && (
          <div id="firewall-input-errors" role="alert" className="space-y-1 text-sm text-danger">
            {inputErrors.map((message) => (
              <p key={message} className="flex gap-1.5">
                <ErrorIcon className="mt-0.5 size-4" />
                {message}
              </p>
            ))}
          </div>
        )}
        <div className="flex flex-wrap items-center gap-3 pt-1">
          <Button type="submit" disabled={!canSubmit} className="min-w-36 px-6 max-sm:flex-1">
            {pending && <SpinnerIcon />}
            {pending ? 'Analyzing…' : 'Analyze'}
          </Button>
          <Button variant="ghost" onClick={onClear} disabled={!canClear || pending}>
            <XIcon />
            Clear
          </Button>
          <p className="ml-auto hidden text-xs text-muted sm:block">
            <kbd className="rounded border border-border bg-background px-1.5 py-0.5 font-sans">Ctrl</kbd> +{' '}
            <kbd className="rounded border border-border bg-background px-1.5 py-0.5 font-sans">Enter</kbd> to analyze
          </p>
        </div>
      </form>

      <div className="border-t border-border pt-5">
        <ExampleInputs selectedId={selectedExample?.id} onSelect={onExample} disabled={pending} />
      </div>
    </Card>
  )
}
