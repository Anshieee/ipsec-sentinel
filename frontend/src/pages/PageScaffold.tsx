import type { ReactNode } from 'react'
import { PageHeader } from '@/components/PageHeader'
import { EmptyAnalysis } from '@/components/EmptyAnalysis'
import { useAnalysis } from '@/store/useSentinel'

export interface PageScaffoldProps {
  title: string
  description: string
  testId: string
  /** Rendered when an analysis is loaded. */
  children?: ReactNode
  actions?: ReactNode
}

/**
 * Shared page frame: header, the common empty state (spec 13) and the
 * page-specific populated content.
 */
export function PageScaffold({ title, description, testId, children, actions }: PageScaffoldProps) {
  const analysis = useAnalysis()

  return (
    <div data-testid={testId}>
      <PageHeader title={title} description={description} actions={actions} />
      {analysis ? children : <EmptyAnalysis />}
    </div>
  )
}
