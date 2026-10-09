export function AppFooter() {
  return (
    <footer className="border-t border-border bg-surface">
      <div className="mx-auto flex w-full max-w-6xl flex-col gap-1 px-4 py-4 text-xs text-muted sm:flex-row sm:justify-between sm:px-6">
        <p>AgentShield — security firewall prototype for AI agents.</p>
        <p>Decisions come from a deterministic policy. AI analysis, when enabled, is one additional signal.</p>
      </div>
    </footer>
  )
}
