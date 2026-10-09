const ProductName = 'AgentShield'

/**
 * Sets the browser tab title for the current page. React 19 hoists `<title>` into the document head; render exactly
 * one per page.
 */
export function DocumentTitle({ title }: { title?: string }) {
  // A single string child: React requires <title> to contain text only.
  return <title>{title ? `${title} · ${ProductName}` : `${ProductName} — AI agent firewall`}</title>
}
