import { Link } from 'react-router-dom'
import { EmptyState } from '@/components/ui/States'

/** 404 route (spec 4.1): `EmptyState` with a link back to the dashboard. */
export function NotFoundPage() {
  return (
    <div data-testid="page-not-found" className="pt-8">
      <EmptyState
        title="Page not found"
        body="The requested workbench page does not exist."
        actions={
          <Link
            to="/"
            className="inline-flex h-9 items-center justify-center rounded-control bg-accent-solid px-3 text-[13px] font-medium text-white transition-colors hover:bg-accent hover:text-ink-inverse active:bg-accent-solid/80 active:text-white"
          >
            Back to the dashboard
          </Link>
        }
      />
    </div>
  )
}
