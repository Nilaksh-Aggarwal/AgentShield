import type { ComponentType } from 'react'
import { Link, NavLink } from 'react-router'
import { ApiHealthIndicator } from '@/features/system-status'
import { ActivityIcon, AnalyzeIcon, FlagIcon, LockIcon, OverviewIcon, ShieldIcon, type IconProps } from '@/shared/components/ui'

interface NavItem {
  to: string
  label: string
  Icon: ComponentType<IconProps>
  /** Match the path exactly (the root route would otherwise match every page). */
  end?: boolean
}

const navItems: NavItem[] = [
  { to: '/', label: 'Overview', Icon: OverviewIcon, end: true },
  { to: '/analyze', label: 'Analyze', Icon: AnalyzeIcon },
  { to: '/activity', label: 'Activity', Icon: ActivityIcon },
  { to: '/agents', label: 'Agents', Icon: LockIcon },
  { to: '/attack-lab', label: 'Attack Lab', Icon: FlagIcon },
]

/**
 * Brand, primary navigation and live API status. One navigation landmark at every width: on small screens it wraps
 * onto its own full-width row of tabs, from `lg` it sits inline between brand and status.
 */
export function AppHeader() {
  return (
    <header className="border-b border-border bg-surface">
      <div className="mx-auto grid w-full max-w-6xl grid-cols-[1fr_auto] items-center gap-x-6 px-4 sm:px-6 lg:grid-cols-[auto_1fr_auto]">
        <Link to="/" className="col-start-1 row-start-1 flex h-14 items-center gap-2.5 rounded-md text-foreground no-underline">
          <span className="flex size-8 items-center justify-center rounded-md bg-primary text-primary-foreground">
            <ShieldIcon className="size-5" />
          </span>
          <span className="flex flex-col leading-tight">
            <span className="font-semibold tracking-tight">AgentShield</span>
            <span className="hidden text-xs text-muted sm:block">AI agent firewall</span>
          </span>
        </Link>

        <nav
          aria-label="Primary"
          className="col-span-2 row-start-2 -mx-4 border-t border-border px-4 sm:-mx-6 sm:px-6 lg:col-span-1 lg:col-start-2 lg:row-start-1 lg:mx-0 lg:border-t-0 lg:px-0"
        >
          <ul className="grid grid-cols-5 lg:flex lg:gap-1">
            {navItems.map(({ to, label, Icon, end }) => (
              <li key={to}>
                <NavLink
                  to={to}
                  end={end}
                  // Focus ring drawn inside the tab: the header's top edge is the viewport's top edge.
                  // Below `sm` five tabs share the width, so the icon sits above a smaller label.
                  className="flex h-11 flex-col items-center justify-center gap-0.5 border-b-2 border-transparent px-0.5 text-[0.6875rem] font-medium whitespace-nowrap text-muted no-underline transition-colors hover:text-foreground focus-visible:-outline-offset-2 aria-[current=page]:border-primary aria-[current=page]:text-foreground sm:flex-row sm:gap-2 sm:px-2 sm:text-sm md:px-3 lg:h-14 lg:px-2 xl:px-3"
                >
                  <Icon className="size-4" />
                  {label}
                </NavLink>
              </li>
            ))}
          </ul>
        </nav>

        <div className="col-start-2 row-start-1 flex justify-end lg:col-start-3">
          <ApiHealthIndicator />
        </div>
      </div>
    </header>
  )
}
