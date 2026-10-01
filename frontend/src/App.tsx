import { RouterProvider, createBrowserRouter } from 'react-router-dom'
import { AppLayout } from '@/components/layout/AppLayout'
import { OverviewPage } from '@/pages/OverviewPage'
import { InspectorPage } from '@/pages/InspectorPage'
import { InferencesPage } from '@/pages/InferencesPage'
import { AuditPage } from '@/pages/AuditPage'
import { CompliancePage } from '@/pages/CompliancePage'
import { SettingsPage } from '@/pages/SettingsPage'
import { NotFoundPage } from '@/pages/NotFoundPage'

/**
 * `createBrowserRouter` routing (decision recorded in DECISIONS.md): a layout
 * route renders Header, Sidebar, Outlet, Footer, ReportDrawer and HelpDialog.
 */
export const router = createBrowserRouter([
  {
    path: '/',
    element: <AppLayout />,
    children: [
      { index: true, element: <OverviewPage /> },
      { path: 'inspector', element: <InspectorPage /> },
      { path: 'inferences', element: <InferencesPage /> },
      { path: 'audit', element: <AuditPage /> },
      { path: 'compliance', element: <CompliancePage /> },
      { path: 'settings', element: <SettingsPage /> },
      { path: '*', element: <NotFoundPage /> },
    ],
  },
])

export default function App() {
  return <RouterProvider router={router} />
}
