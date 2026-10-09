import type { ComponentType } from 'react'
import {
  Card,
  CardHeader,
  CheckCircleIcon,
  ChipIcon,
  CircleIcon,
  EyeOffIcon,
  FlagIcon,
  GaugeIcon,
  InboxIcon,
  LayersIcon,
  RulesIcon,
  ScaleIcon,
  TextIcon,
  WarningIcon,
  type IconProps,
} from '@/shared/components/ui'
import { pipelineStages, type PipelineStageId, type StageOutcome, type StageStatus } from '../model'

export type PipelineState = 'idle' | 'running' | 'done' | 'failed'

const stageIcon: Record<PipelineStageId, ComponentType<IconProps>> = {
  input: InboxIcon,
  normalize: TextIcon,
  rules: RulesIcon,
  obfuscation: EyeOffIcon,
  ai: ChipIcon,
  aggregation: LayersIcon,
  risk: GaugeIcon,
  policy: ScaleIcon,
  decision: FlagIcon,
}

// Class strings are written out in full so Tailwind can find them when scanning the source.
const statusStyle: Record<StageStatus, { Icon: ComponentType<IconProps>; className: string }> = {
  done: { Icon: CheckCircleIcon, className: 'text-success' },
  clear: { Icon: CheckCircleIcon, className: 'text-success' },
  flagged: { Icon: WarningIcon, className: 'text-warning' },
  held: { Icon: WarningIcon, className: 'text-warning' },
  unknown: { Icon: CircleIcon, className: 'text-muted' },
}

const subtitle: Record<PipelineState, string> = {
  idle: 'Every input passes through these stages, in this order.',
  running: 'Analyzing… The stages run on the server; results appear once all of them have finished.',
  done: 'What the last analysis reported at each stage.',
  failed: 'The last analysis did not complete, so there are no stage results.',
}

// Class strings are written out in full so Tailwind can find them when scanning the source.
const layoutClass = {
  // A side column on desktop: vertical timeline on phones and from `lg`, numbered 3-column grid on tablets.
  rail: {
    list: 'md:grid-cols-3 md:gap-y-5 lg:grid-cols-1 lg:gap-y-0',
    item: 'md:pb-0 lg:pb-5 lg:last:pb-0',
    connector: 'md:hidden lg:block',
  },
  // A full-width section: vertical timeline on phones, numbered 3-column grid from `md`.
  wide: {
    list: 'md:grid-cols-3 md:gap-y-6',
    item: 'md:pb-0',
    connector: 'md:hidden',
  },
} as const

interface AnalysisPipelineProps {
  state: PipelineState
  outcomes?: Record<PipelineStageId, StageOutcome>
  layout?: keyof typeof layoutClass
  /** Level of the card title in the page outline (`h3` inside a section that has its own `h2`). */
  headingLevel?: 'h2' | 'h3'
}

/**
 * The analysis pipeline, the one visualisation of it in the app (Analyze page and Overview). Stage results come only
 * from a completed response; while an analysis runs, no stage is shown as finished.
 */
export function AnalysisPipeline({ state, outcomes, layout = 'rail', headingLevel = 'h2' }: AnalysisPipelineProps) {
  const classes = layoutClass[layout]

  return (
    <Card as="section" padding="none" aria-labelledby="pipeline-heading" aria-busy={state === 'running'}>
      <CardHeader as={headingLevel} id="pipeline-heading" title="Security pipeline" description={subtitle[state]} />
      <ol className={`grid gap-x-6 px-4 py-4 sm:px-6 ${classes.list}`}>
        {pipelineStages.map((stage, index) => {
          const Icon = stageIcon[stage.id]
          const outcome = state === 'done' ? outcomes?.[stage.id] : undefined
          const status = outcome ? statusStyle[outcome.status] : undefined
          const last = index === pipelineStages.length - 1

          return (
            <li key={stage.id} className={`relative flex gap-3 pb-5 last:pb-0 ${classes.item}`}>
              {/* Timeline connector (single-column layouts only). */}
              {!last && (
                <span className={`absolute top-9 bottom-0 left-4 w-px bg-border ${classes.connector}`} aria-hidden="true" />
              )}
              <span
                className={`relative flex size-8 shrink-0 items-center justify-center rounded-full border border-border bg-background text-muted ${state === 'running' ? 'motion-safe:animate-pulse' : ''}`}
                aria-hidden="true"
              >
                <Icon className="size-4" />
              </span>
              <div className="min-w-0 pt-1">
                <p className="text-sm font-semibold text-foreground">
                  <span className="sr-only">Stage {index + 1}: </span>
                  {stage.name}
                </p>
                <p className="text-xs text-muted">{stage.description}</p>
                {outcome && status && (
                  <p className={`mt-1 flex items-center gap-1.5 text-xs font-medium ${status.className}`}>
                    <status.Icon className="size-3.5" />
                    <span className="text-foreground">{outcome.summary}</span>
                  </p>
                )}
              </div>
            </li>
          )
        })}
      </ol>
    </Card>
  )
}
