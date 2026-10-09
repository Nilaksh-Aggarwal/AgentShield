import { AnalysisPipeline } from '@/features/firewall'
import { DocumentTitle, PageHeader } from '@/shared/components/layout'
import { ArrowDownIcon, ArrowRightIcon, ButtonLink, FlagIcon, SectionHeader, buttonClassName } from '@/shared/components/ui'
import { AiSafetySection } from './components/AiSafetySection'
import { CapabilityGrid } from './components/CapabilityGrid'
import { KeywordComparison } from './components/KeywordComparison'
import { Limitations } from './components/Limitations'
import { SecurityByDesign } from './components/SecurityByDesign'
import { SecurityOperations } from './components/SecurityOperations'
import { TryItCallout } from './components/TryItCallout'

/**
 * The product introduction: what AgentShield is, what it checks for, how it decides and what it does not claim. Every
 * statement describes implemented behaviour. The only numbers are the security operations counts, read live from the API's
 * in-memory activity history and labelled as exactly that.
 */
export function OverviewPage() {
  return (
    <div className="space-y-14">
      <DocumentTitle title="Overview" />
      <PageHeader
        eyebrow="AI agent firewall"
        title="Protect AI applications from malicious instructions"
        description={
          <>
            <p className="text-foreground">
              AgentShield analyzes untrusted input before it reaches an AI agent, combining deterministic security rules,
              obfuscation detection and optional AI-assisted analysis. Every input gets a decision, Allow, Review or
              Block, from a deterministic security policy.
            </p>
            <p>
              AI agents act on the text they read. Anyone who can put text in front of an agent, in a message, a web page
              or a document, can try to override its instructions, take over its role or extract its secrets: prompt
              injection.
            </p>
          </>
        }
        actions={
          <>
            <ButtonLink to="/attack-lab">
              <FlagIcon />
              Open the Attack Lab
            </ButtonLink>
            <ButtonLink to="/analyze" variant="secondary">
              Analyze an input
              <ArrowRightIcon />
            </ButtonLink>
            <a href="#how-it-works" className={buttonClassName({ variant: 'secondary' })}>
              How it works
              <ArrowDownIcon />
            </a>
          </>
        }
      />

      <SecurityOperations />
      <CapabilityGrid />
      <KeywordComparison />

      {/* Target of "How it works": focusable so keyboard and screen-reader users land here, not just scroll here. */}
      <section id="how-it-works" tabIndex={-1} aria-labelledby="how-heading" className="scroll-mt-6 space-y-6 focus:outline-none">
        <SectionHeader
          id="how-heading"
          eyebrow="How it works"
          title="One pipeline for every input"
          description="The same stages run for every input, in the same order. On the Analyze page, each stage also shows what it reported for your input."
        />
        <AnalysisPipeline state="idle" layout="wide" headingLevel="h3" />
      </section>

      <AiSafetySection />
      <SecurityByDesign />
      <Limitations />
      <TryItCallout />
    </div>
  )
}
