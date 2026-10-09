import type { ComponentType } from 'react'
import { ChipIcon, LockIcon, RulesIcon, type IconProps, type Tone } from '@/shared/components/ui'
import type { FindingSource } from '../model'

/** How each finding source is marked. AI-assisted findings are highlighted as a signal, never styled as a verdict. */
export const sourceStyle: Record<FindingSource, { tone: Tone; Icon: ComponentType<IconProps> }> = {
  rules: { tone: 'neutral', Icon: RulesIcon },
  ai: { tone: 'info', Icon: ChipIcon },
  system: { tone: 'neutral', Icon: LockIcon },
}
