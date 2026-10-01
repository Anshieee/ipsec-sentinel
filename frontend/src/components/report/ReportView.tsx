import { useMemo } from 'react'
import { Check, Copy } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { ReactMarkdown, markdownComponents, remarkGfm } from './markdown'

export interface ReportViewProps {
  markdown: string
  copied: boolean
  onCopied: () => void
  /** Called when the clipboard is unavailable, so the caller can notify. */
  onError?: () => void
}

/**
 * Renders report markdown with anchorable headings plus a "Copy markdown" action.
 */
export function ReportView({ markdown, copied, onCopied, onError }: ReportViewProps) {
  const content = useMemo(() => markdown, [markdown])

  const copy = async (): Promise<void> => {
    try {
      await navigator.clipboard.writeText(markdown)
      onCopied()
    } catch {
      onError?.()
    }
  }

  return (
    <div className="space-y-2">
      <div className="flex justify-end">
        <Button variant="secondary" size="sm" onClick={() => void copy()} aria-label="Copy markdown">
          {copied ? <Check size={14} aria-hidden="true" /> : <Copy size={14} aria-hidden="true" />}
          {copied ? 'Copied' : 'Copy markdown'}
        </Button>
      </div>
      <article className="report-markdown text-sm" data-testid="report-markdown">
        <ReactMarkdown remarkPlugins={[remarkGfm]} components={markdownComponents}>
          {content}
        </ReactMarkdown>
      </article>
    </div>
  )
}
