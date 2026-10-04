import { NavLink } from 'react-router-dom'
import { BrainCircuit, LayoutDashboard, ScanSearch, ShieldAlert, ShieldCheck, Scale, Settings } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { Tooltip } from '@/components/ui/Tooltip'
import { cn } from '@/components/ui/cn'
import { useSentinel } from '@/store/useSentinel'
import { fmtInt } from '@/lib/format'
import { APP_VERSION } from '@/lib/version'

export interface NavItem {
  to: string
  label: string
  shortLabel: string
  icon: LucideIcon
}

/** Sidebar navigation model (spec 4.1 table). */
export const NAV_ITEMS: NavItem[] = [
  { to: '/', label: 'Dashboard Overview', shortLabel: 'Overview', icon: LayoutDashboard },
  { to: '/inspector', label: 'Traffic Inspector & PCAP Parser', shortLabel: 'Inspector', icon: ScanSearch },
  { to: '/inferences', label: 'AI Inferences & Classification', shortLabel: 'Inferences', icon: BrainCircuit },
  { to: '/audit', label: 'Security Audit & Threat Matrix', shortLabel: 'Audit', icon: ShieldAlert },
  { to: '/compliance', label: 'Config Compliance & DH Key Lab', shortLabel: 'Compliance', icon: Scale },
  { to: '/settings', label: 'Settings & AI Model Logs', shortLabel: 'Settings', icon: Settings },
]

/** Left navigation with active state, capture summary card and version. */
export function Sidebar() {
  const collapsed = useSentinel((s) => s.sidebarCollapsed)
  const live = useSentinel((s) => s.live)
  const upload = useSentinel((s) => s.upload)

  const capturing = live.status === 'capturing'
  const busy = upload.status === 'uploading' || upload.status === 'parsing' || upload.status === 'inferring'

  return (
    <nav
      aria-label="Primary"
      data-testid="sidebar"
      className={cn(
        'sticky top-header z-30 hidden h-[calc(100vh-var(--header-height,56px))] shrink-0 flex-col border-r border-border bg-bg-card md:flex',
        collapsed ? 'w-sidebar-rail' : 'w-sidebar',
      )}
      style={{ width: collapsed ? 64 : 248 }}
    >
      <ul className="flex-1 space-y-1 p-2">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon
          const link = (
            <NavLink
              to={item.to}
              end={item.to === '/'}
              aria-label={collapsed ? item.label : undefined}
              className={({ isActive }) =>
                cn(
                  'relative flex items-center gap-2.5 rounded-control px-2.5 py-2 text-[13px] transition-colors',
                  collapsed ? 'justify-center' : '',
                  isActive ? 'bg-bg-card text-text-primary' : 'text-text-secondary hover:bg-bg-card/60 hover:text-text-primary',
                )
              }
            >
              {({ isActive }) => (
                <>
                  {isActive ? (
                    <span className="absolute left-0 top-1/2 h-5 w-[3px] -translate-y-1/2 rounded-r bg-blue" aria-hidden="true" />
                  ) : null}
                  <Icon size={16} aria-hidden="true" />
                  {!collapsed ? <span className="truncate">{item.shortLabel}</span> : null}
                  {!collapsed ? <span className="sr-only">{item.label}</span> : null}
                </>
              )}
            </NavLink>
          )
          return (
            <li key={item.to}>
              {collapsed ? (
                <Tooltip content={item.label} side="bottom">
                  {link}
                </Tooltip>
              ) : (
                link
              )}
            </li>
          )
        })}
      </ul>

      <div className="border-t border-border p-3">
        {collapsed ? (
          <p className="text-center text-2xs text-text-secondary" title={capturing ? 'Capture running' : 'Capture idle'}>
            <ShieldCheck size={14} className={cn('mx-auto', capturing ? 'text-blue' : 'text-text-secondary')} aria-hidden="true" />
            <span className="sr-only">{capturing ? 'Capture running' : 'Capture idle'}</span>
          </p>
        ) : (
          <div className="rounded-card border border-border bg-bg-card p-2.5" data-testid="capture-summary">
            <p className="flex items-center justify-between gap-2 text-2xs font-semibold uppercase tracking-wide text-text-secondary">
              <span>Capture status</span>
              <span
                className="inline-flex items-center rounded-full border border-dashed border-amber/70 bg-amber/10 px-1.5 py-px text-2xs text-amber"
                title="The live capture stream is simulated; upload a pcap for real analysis."
              >
                SIMULATED
              </span>
            </p>
            {capturing ? (
              <dl className="mt-1.5 grid grid-cols-2 gap-x-2 gap-y-1 text-[11px]">
                <dt className="text-text-secondary">Packets</dt>
                <dd className="tnum text-right text-text-primary">{fmtInt(live.counters.packets)}</dd>
                <dt className="text-text-secondary">IKE</dt>
                <dd className="tnum text-right text-text-primary">{fmtInt(live.counters.ike)}</dd>
                <dt className="text-text-secondary">ESP</dt>
                <dd className="tnum text-right text-text-primary">{fmtInt(live.counters.esp)}</dd>
                <dt className="text-text-secondary">AH</dt>
                <dd className="tnum text-right text-text-primary">{fmtInt(live.counters.ah)}</dd>
              </dl>
            ) : (
              <p className="mt-1 text-[11px] text-text-secondary">
                {busy ? `Processing ${upload.fileName ?? 'trace'}…` : 'Idle — no capture running.'}
              </p>
            )}
          </div>
        )}
        <p className={cn('mt-2 text-center text-2xs text-text-secondary', collapsed ? 'sr-only' : '')}>v{APP_VERSION}</p>
      </div>
    </nav>
  )
}
