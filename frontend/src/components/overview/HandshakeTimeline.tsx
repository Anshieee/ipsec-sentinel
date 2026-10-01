import { useRef, useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import { ArrowRight, Lock, Repeat, ShieldCheck, KeyRound } from 'lucide-react'
import { Card, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { cn } from '@/components/ui/cn'
import { fmtInt } from '@/lib/format'
import type { HandshakeStep } from '@/types/analysis'

function isRekey(step: HandshakeStep): boolean {
  return step.step.toLowerCase().includes('rekey') || step.id.startsWith('hs-rekey')
}

function StepIcon({ step }: { step: HandshakeStep }) {
  if (isRekey(step)) return <Repeat size={14} className="text-highlight" aria-hidden="true" />
  if (step.encrypted) return <Lock size={14} className="text-safe" aria-hidden="true" />
  if (step.step.includes('SA_INIT') || step.step.includes('Identity'))
    return <KeyRound size={14} className="text-accent" aria-hidden="true" />
  return <ShieldCheck size={14} className="text-muted" aria-hidden="true" />
}

/** Handshake timeline stepper (spec 10.1 C.2). */
export function HandshakeTimeline({ steps }: { steps: HandshakeStep[] }) {
  const [expanded, setExpanded] = useState<string | null>(null)
  const buttonsRef = useRef<Map<string, HTMLButtonElement | null>>(new Map())
  const reduceMotion = useReducedMotion()

  const focusStep = (index: number): void => {
    if (steps.length === 0) return
    const bounded = (index + steps.length) % steps.length
    const step = steps[bounded]
    if (step) buttonsRef.current.get(step.id)?.focus()
  }

  const currentIndex = steps.findIndex((step) => step.id === expanded)

  return (
    <Card data-testid="handshake-timeline">
      <CardHeader title="Handshake timeline" description={`${steps.length} observed steps`} />
      <ol className="relative space-y-1">
        <span className="absolute bottom-2 left-[15px] top-2 w-px bg-line" aria-hidden="true" />
        {steps.map((step, index) => {
          const open = expanded === step.id
          const rekey = isRekey(step)
          return (
            <motion.li
              key={step.id}
              initial={reduceMotion ? false : { opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: reduceMotion ? 0 : 0.18, delay: reduceMotion ? 0 : index * 0.03 }}
              className="relative"
            >
              <button
                type="button"
                ref={(el) => {
                  buttonsRef.current.set(step.id, el)
                }}
                aria-expanded={open}
                data-row-id={step.id}
                onKeyDown={(event) => {
                  if (event.key === 'ArrowDown') {
                    event.preventDefault()
                    focusStep(index + 1)
                  } else if (event.key === 'ArrowUp') {
                    event.preventDefault()
                    focusStep(index - 1)
                  }
                }}
                onClick={() => setExpanded(open ? null : step.id)}
                className={cn(
                  'flex w-full items-start gap-3 rounded-control px-2 py-2 text-left hover:bg-raised/60',
                  open ? 'bg-raised' : '',
                )}
              >
                <span
                  className={cn(
                    'relative z-10 flex size-[30px] shrink-0 items-center justify-center rounded-full border bg-surface',
                    rekey ? 'border-highlight/50' : 'border-line',
                  )}
                >
                  <StepIcon step={step} />
                </span>
                <span className="min-w-0 flex-1">
                  <span className="flex flex-wrap items-center gap-2">
                    <span className="text-[13px] font-medium text-ink">{step.step}</span>
                    {rekey ? <Badge tone="cyan">Rekey</Badge> : null}
                    {step.encrypted ? <Badge tone="safe">Encrypted</Badge> : null}
                  </span>
                  <span className="mt-0.5 flex flex-wrap items-center gap-2 text-[11px] text-muted">
                    <span className="tnum">+{step.timeSec.toFixed(3)} s</span>
                    <span className="tnum">{fmtInt(step.sizeBytes)} B</span>
                    <span className="inline-flex items-center gap-1">
                      <ArrowRight size={11} aria-hidden="true" />
                      {step.direction === 'n/a' ? 'n/a' : step.direction.replace('->', ' → ')}
                    </span>
                  </span>
                </span>
              </button>

              {open ? (
                <dl className="mb-2 ml-10 grid grid-cols-[minmax(0,auto)_1fr] gap-x-3 gap-y-1 rounded-control border border-line bg-raised/50 p-2 text-xs">
                  {Object.entries(step.details).map(([key, value]) => (
                    <div key={key} className="contents">
                      <dt className="text-muted">{key}</dt>
                      <dd className="break-all text-ink">{value}</dd>
                    </div>
                  ))}
                </dl>
              ) : null}
            </motion.li>
          )
        })}
      </ol>
      <p className="sr-only">
        Use the up and down arrow keys to move between steps and Enter or Space to expand a step. Current step index:{' '}
        {currentIndex + 1}
      </p>
    </Card>
  )
}
