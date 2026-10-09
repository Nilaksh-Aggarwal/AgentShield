import { createBrowserRouter } from 'react-router'
import { RootLayout } from '@/app/layouts/RootLayout'
import { ActivityPage } from '@/features/activity'
import { AgentSecurityPage } from '@/features/agents'
import { AnalyzePage } from '@/features/firewall'
import { OverviewPage } from '@/features/overview'
import { NotFound } from '@/shared/components/NotFound'
import { AttackLabRoute } from './AttackLabRoute'
import { RouteErrorView } from './RouteErrorView'

/** Primary navigation (`AppHeader`) links to the first five routes. */
export const router = createBrowserRouter([
  {
    path: '/',
    element: <RootLayout />,
    errorElement: <RouteErrorView />,
    children: [
      { index: true, element: <OverviewPage /> },
      { path: 'analyze', element: <AnalyzePage /> },
      { path: 'activity', element: <ActivityPage /> },
      { path: 'agents', element: <AgentSecurityPage /> },
      { path: 'attack-lab', element: <AttackLabRoute /> },
      { path: '*', element: <NotFound /> },
    ],
  },
])
