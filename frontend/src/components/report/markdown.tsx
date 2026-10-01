import type { ComponentProps, ReactNode } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { cn } from '@/components/ui/cn'

type MarkdownComponents = ComponentProps<typeof ReactMarkdown>['components']

function headingId(children: ReactNode): string {
  const text =
    typeof children === 'string'
      ? children
      : Array.isArray(children)
        ? String(children[0] ?? '')
        : typeof children === 'object' && children !== null && 'props' in children
          ? String((children as { props?: { children?: unknown } }).props?.children ?? '')
          : ''
  return text
    .toLowerCase()
    .trim()
    .replace(/[^\w\s-]/g, '')
    .replace(/\s+/g, '-')
}

/** Shared renderer styles for report markdown (drawer and print view). */
export const markdownComponents: MarkdownComponents = {
  h1: ({ children }) => (
    <h1 id={headingId(children)} className="scroll-mt-24 mt-6 mb-3 text-xl font-semibold text-ink first:mt-0">
      {children}
    </h1>
  ),
  h2: ({ children }) => (
    <h2
      id={headingId(children)}
      className="scroll-mt-24 mt-6 mb-3 border-b border-line pb-2 text-base font-semibold text-ink first:mt-0"
    >
      {children}
    </h2>
  ),
  h3: ({ children }) => (
    <h3 id={headingId(children)} className="scroll-mt-24 mt-4 mb-2 text-sm font-semibold text-ink">
      {children}
    </h3>
  ),
  p: ({ children }) => <p className="my-2 text-[13px] leading-5 text-muted">{children}</p>,
  ul: ({ children }) => <ul className="my-2 list-disc space-y-1 pl-5 text-[13px] text-muted">{children}</ul>,
  ol: ({ children }) => <ol className="my-2 list-decimal space-y-1 pl-5 text-[13px] text-muted">{children}</ol>,
  li: ({ children }) => <li className="leading-5">{children}</li>,
  table: ({ children }) => (
    <div className="my-3 overflow-x-auto rounded-control border border-line">
      <table className="w-full border-collapse text-left text-xs">{children}</table>
    </div>
  ),
  thead: ({ children }) => <thead className="bg-raised text-ink">{children}</thead>,
  th: ({ children }) => <th className="border-b border-line px-3 py-2 font-semibold">{children}</th>,
  td: ({ children }) => <td className="border-b border-line px-3 py-2 align-top text-muted last:border-b-0">{children}</td>,
  tr: ({ children }) => <tr className="odd:bg-surface even:bg-raised/40">{children}</tr>,
  code: ({ children, className: codeClass }) => (
    <code className={cn('rounded bg-raised px-1 py-0.5 font-mono text-[11px] text-ink', codeClass)}>{children}</code>
  ),
  pre: ({ children }) => (
    <pre className="my-3 overflow-x-auto rounded-control border border-line bg-raised p-3 font-mono text-xs text-ink">
      {children}
    </pre>
  ),
  a: ({ children, href }) => (
    <a href={href} className="text-accent underline underline-offset-2 hover:text-highlight">
      {children}
    </a>
  ),
  blockquote: ({ children }) => (
    <blockquote className="my-3 border-l-2 border-accent pl-3 text-[13px] italic text-muted">{children}</blockquote>
  ),
  hr: () => <hr className="my-4 border-line" />,
  strong: ({ children }) => <strong className="font-semibold text-ink">{children}</strong>,
}

export { ReactMarkdown, remarkGfm }
