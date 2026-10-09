import { Outlet } from 'react-router'
import { AppShell } from './AppShell'

export function RootLayout() {
  return (
    <AppShell>
      <Outlet />
    </AppShell>
  )
}
