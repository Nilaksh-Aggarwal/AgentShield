import { useRef, useState } from 'react'
import { isApiError } from '@/services/api'
import { DocumentTitle, PageHeader } from '@/shared/components/layout'
import { Card, EmptyState, ShieldIcon, SpinnerIcon } from '@/shared/components/ui'
import { useFirewallAnalysis } from '../hooks/useFirewallAnalysis'
import {
  pipelineOutcomes,
  presentAiParticipation,
  presentDecision,
  presentFinding,
  presentRiskLevel,
  type ExampleInput,
} from '../model'
import { AnalysisErrorCard } from './AnalysisErrorCard'
import { AnalysisPipeline, type PipelineState } from './AnalysisPipeline'
import { AnalysisResult } from './AnalysisResult'
import { AnalysisWorkspace } from './AnalysisWorkspace'
import { HowAgentShieldProtects } from './HowAgentShieldProtects'

export function AnalyzePage() {
  const [input, setInput] = useState('')
  const [selectedExample, setSelectedExample] = useState<ExampleInput>()
  const [notice, setNotice] = useState('')
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  const analysis = useFirewallAnalysis()

  const result = analysis.data
  const error = analysis.error
  const inputErrors = isApiError(error) ? (error.fieldErrors.input ?? []) : []

  // Presentation only: every value below is read from the API response, none is computed from the input.
  const findings = result ? result.analysis.findings.map(presentFinding) : []
  const ai = presentAiParticipation(findings, result?.analysis.decision ?? '')
  const decision = result ? presentDecision(result.analysis.decision) : undefined
  const risk = result ? presentRiskLevel(result.analysis.risk.level) : undefined

  const pipelineState: PipelineState = analysis.isPending ? 'running' : error ? 'failed' : result ? 'done' : 'idle'
  const outcomes =
    result && decision && risk
      ? pipelineOutcomes({ findings, decision, risk, score: result.analysis.risk.score, ai, inputLength: analysis.variables?.length })
      : undefined

  function handleInputChange(value: string) {
    setInput(value)
    setNotice('')
    if (selectedExample && value !== selectedExample.text) {
      setSelectedExample(undefined)
    }
  }

  function handleExample(example: ExampleInput) {
    analysis.reset()
    setInput(example.text)
    setSelectedExample(example)
    setNotice(`Example loaded: ${example.label}. Press Analyze to check it.`)
  }

  function handleClear() {
    analysis.reset()
    setInput('')
    setSelectedExample(undefined)
    setNotice('Input cleared.')
    textareaRef.current?.focus()
  }

  function handleSubmit() {
    setNotice('')
    analysis.mutate(input)
  }

  // Announced by screen readers; the visible UI carries the same information.
  let statusMessage = notice
  if (analysis.isPending) {
    statusMessage = 'Analyzing input…'
  } else if (result && decision && risk) {
    statusMessage = `Analysis complete. ${decision.label}: ${decision.action}. ${risk.label}, ${result.analysis.risk.score} out of 100. ${findings.length} ${findings.length === 1 ? 'finding' : 'findings'}.`
  }

  return (
    <div className="space-y-10">
      <DocumentTitle title="Analyze input" />
      <PageHeader
        eyebrow="Firewall"
        title="Analyze input"
        description={
          <>
            <p>
              AgentShield checks untrusted input through several security layers, explains what it found and returns a
              decision: Allow, Review or Block. The deterministic policy always decides; AI-assisted analysis, when
              enabled, only adds findings.
            </p>
            <p className="text-sm">
              AgentShield does not store the text. When AI-assisted analysis is enabled on the server, a normalised copy
              with secrets masked is sent to the configured AI provider.
            </p>
          </>
        }
      />

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_20rem] lg:items-start">
        <div className="min-w-0 space-y-6">
          <AnalysisWorkspace
            input={input}
            onInputChange={handleInputChange}
            onSubmit={handleSubmit}
            onClear={handleClear}
            onExample={handleExample}
            selectedExample={selectedExample}
            pending={analysis.isPending}
            inputErrors={inputErrors}
            canClear={input.length > 0 || result !== undefined || error !== null}
            textareaRef={textareaRef}
          />

          {analysis.isPending ? (
            // Honest progress: the API answers only after the whole pipeline has run, so no stage is shown as done.
            <Card className="space-y-4" aria-hidden="true">
              <p className="flex items-center gap-3 font-medium text-foreground">
                <SpinnerIcon className="size-5 text-primary" />
                Analyzing through AgentShield’s security pipeline…
              </p>
              <div className="space-y-2 motion-safe:animate-pulse">
                <div className="h-3 w-2/3 rounded bg-border" />
                <div className="h-3 w-1/2 rounded bg-border" />
                <div className="h-3 w-3/5 rounded bg-border" />
              </div>
            </Card>
          ) : error ? (
            <AnalysisErrorCard error={error} announce={inputErrors.length === 0} />
          ) : result ? (
            <AnalysisResult result={result} findings={findings} ai={ai} stale={analysis.variables !== input} />
          ) : (
            <EmptyState
              icon={<ShieldIcon className="size-5" />}
              title="Analyze an input"
              description={
                <p>
                  Paste text above or try one of the examples to see how AgentShield evaluates potentially malicious
                  instructions.
                </p>
              }
            />
          )}
        </div>

        <AnalysisPipeline state={pipelineState} outcomes={outcomes} />
      </div>

      <HowAgentShieldProtects />

      <p role="status" className="sr-only">
        {statusMessage}
      </p>
    </div>
  )
}
