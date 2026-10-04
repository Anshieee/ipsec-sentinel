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
    <h1 id={headingId(children)} className="scroll-mt-24 mt-6 mb-3 text-xl font-semibold text-text-primary first:mt-0">
      {children}
    </h1>
  ),
  h2: ({ children }) => (
    <h2
      id={headingId(children)}
      className="scroll-mt-24 mt-6 mb-3 border-b border-border pb-2 text-base font-semibold text-text-primary first:mt-0"
    >
      {children}
    </h2>
  ),
  h3: ({ children }) => (
    <h3 id={headingId(children)} className="scroll-mt-24 mt-4 mb-2 text-sm font-semibold text-text-primary">
      {children}
    </h3>
  ),
  p: ({ children }) => <p className="my-2 text-[13px] leading-5 text-text-secondary">{children}</p>,
  ul: ({ children }) => <ul className="my-2 list-disc space-y-1 pl-5 text-[13px] text-text-secondary">{children}</ul>,
  ol: ({ children }) => <ol className="my-2 list-decimal space-y-1 pl-5 text-[13px] text-text-secondary">{children}</ol>,
  li: ({ children }) => <li className="leading-5">{children}</li>,
  table: ({ children }) => (
    <div className="my-3 overflow-x-auto rounded-control border border-border">
      <table className="w-full border-collapse text-left text-xs">{children}</table>
    </div>
  ),
  thead: ({ children }) => <thead className="bg-bg-card text-text-primary">{children}</thead>,
  th: ({ children }) => <th className="border-b border-border px-3 py-2 font-semibold">{children}</th>,
  td: ({ children }) => <td className="border-b border-border px-3 py-2 align-top text-text-secondary last:border-b-0">{children}</td>,
  tr: ({ children }) => <tr className="odd:bg-bg-elevated even:bg-bg-card/40">{children}</tr>,
  code: ({ children, className: codeClass }) => (
    <code className={cn('rounded bg-bg-card px-1 py-0.5 font-mono text-[11px] text-text-primary', codeClass)}>{children}</code>
  ),
  pre: ({ children }) => (
    <pre className="my-3 overflow-x-auto rounded-control border border-border bg-bg-card p-3 font-mono text-xs text-text-primary">
      {children}
    </pre>
  ),
  a: ({ children, href }) => (
    <a href={href} className="text-blue underline underline-offset-2 hover:text-blue">
      {children}
    </a>
  ),
  blockquote: ({ children }) => (
    <blockquote className="my-3 border-l-2 border-blue pl-3 text-[13px] italic text-text-secondary">{children}</blockquote>
  ),
  hr: () => <hr className="my-4 border-border" />,
  strong: ({ children }) => <strong className="font-semibold text-text-primary">{children}</strong>,
}

export { ReactMarkdown, remarkGfm }
