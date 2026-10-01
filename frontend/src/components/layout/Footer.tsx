import { useSentinel } from '@/store/useSentinel'

/** One-line footer with the demonstration notice and build version (spec 4.4). */
export function Footer() {
  const dataSource = useSentinel((s) => s.settings.dataSource)
  const live = dataSource === 'live'
  return (
    <footer className="flex h-8 shrink-0 items-center justify-between border-t border-line bg-raised px-4 text-[11px] text-muted">
      <span>
        {live
          ? 'Live backend. Simulated surfaces (capture stream, model registry) are badged SIMULATED.'
          : 'Demonstration data. Analysis results are simulated.'}
      </span>
      <span className="tnum">IPsec-AI Sentinel v0.1.0</span>
    </footer>
  )
}
