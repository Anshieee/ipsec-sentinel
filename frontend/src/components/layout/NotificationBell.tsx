import { useState } from 'react'
import { Bell, CheckCheck, CircleAlert, CircleCheck, Info, TriangleAlert } from 'lucide-react'
import { Popover } from '@/components/ui/Popover'
import { Button } from '@/components/ui/Button'
import { cn } from '@/components/ui/cn'
import { useSentinel } from '@/store/useSentinel'
import { relTime } from '@/lib/format'
import type { Notification } from '@/types/misc'

const SEVERITY_ICON: Record<Notification['severity'], typeof Info> = {
  info: Info,
  success: CircleCheck,
  warn: TriangleAlert,
  critical: CircleAlert,
}

const SEVERITY_CLASS: Record<Notification['severity'], string> = {
  info: 'text-blue',
  success: 'text-green',
  warn: 'text-amber',
  critical: 'text-red',
}

/** Notification bell with unread badge and the five most recent entries. */
export function NotificationBell() {
  const notifications = useSentinel((s) => s.notifications)
  const markAllRead = useSentinel((s) => s.markAllRead)
  const [open, setOpen] = useState(false)

  const unread = notifications.filter((n) => !n.read).length
  const badge = unread > 9 ? '9+' : `${unread}`
  const latest = notifications.slice(0, 5)

  return (
    <Popover
      open={open}
      onOpenChange={setOpen}
      label="Notifications"
      align="end"
      trigger={
        <button
          type="button"
          className="relative inline-flex h-8 w-8 items-center justify-center rounded-control text-text-secondary hover:bg-bg-card hover:text-text-primary"
          aria-label={`Notifications, ${unread} unread`}
          data-testid="notification-bell"
        >
          <Bell size={16} aria-hidden="true" />
          {unread > 0 ? (
            <span
              className="absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-red px-1 text-2xs font-semibold text-white"
              aria-hidden="true"
            >
              {badge}
            </span>
          ) : null}
        </button>
      }
    >
      <div className="w-72" data-testid="notification-list">
        <div className="mb-1 flex items-center justify-between">
          <p className="text-[11px] font-semibold uppercase tracking-wide text-text-secondary">Notifications</p>
          <Button variant="ghost" size="sm" onClick={markAllRead} disabled={unread === 0}>
            <CheckCheck size={12} aria-hidden="true" />
            Mark all read
          </Button>
        </div>
        <ul className="max-h-72 space-y-1 overflow-y-auto" aria-live="polite">
          {latest.length === 0 ? (
            <li className="px-1 py-3 text-xs text-text-secondary">No notifications yet.</li>
          ) : (
            latest.map((notification) => {
              const Icon = SEVERITY_ICON[notification.severity]
              return (
                <li
                  key={notification.id}
                  className={cn(
                    'flex items-start gap-2 rounded-control px-1.5 py-1.5',
                    notification.read ? 'opacity-60' : '',
                  )}
                >
                  <Icon size={14} className={cn('mt-0.5 shrink-0', SEVERITY_CLASS[notification.severity])} aria-hidden="true" />
                  <span className="min-w-0 flex-1">
                    <span className="block text-xs leading-4 text-text-primary">{notification.message}</span>
                    <span className="text-2xs text-text-secondary">{relTime(notification.at)}</span>
                  </span>
                </li>
              )
            })
          )}
        </ul>
      </div>
    </Popover>
  )
}
