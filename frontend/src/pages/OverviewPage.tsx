import { PageScaffold } from './PageScaffold'
import { KpiBar } from '@/components/overview/KpiBar'
import { UploadZone } from '@/components/overview/UploadZone'
import { CryptoCard } from '@/components/overview/CryptoCard'
import { StatusChipsRow } from '@/components/overview/StatusChipsRow'
import { ClassChart } from '@/components/overview/ClassChart'
import { HandshakeTimeline } from '@/components/overview/HandshakeTimeline'
import { LiveTicker } from '@/components/overview/LiveTicker'
import { OverviewBottom } from '@/components/overview/OverviewBottom'
import { useAnalysis } from '@/store/useSentinel'
import { isNoIpsec } from '@/components/ui/NoIpsecBanner'

/** Dashboard Overview (`/`), spec 10.1. */
export function OverviewPage() {
  const analysis = useAnalysis()
  const noIpsec = isNoIpsec(analysis)

  return (
    <PageScaffold
      title="Dashboard Overview"
      description="Risk posture, handshake timeline, threat matrix and traffic summary for the current capture."
      testId="page-overview"
    >
      {analysis ? (
        <div className="grid grid-cols-12 gap-4">
          <div className="col-span-12">
            <KpiBar analysis={analysis} />
          </div>

          <div className="col-span-12 grid grid-cols-12 gap-4 lg:grid-cols-12">
            <div className="col-span-12 space-y-4 xl:col-span-5">
              <UploadZone />
              {noIpsec ? null : <CryptoCard analysis={analysis} />}
              {noIpsec ? null : <StatusChipsRow analysis={analysis} />}
            </div>

            <div className="col-span-12 space-y-4 xl:col-span-7">
              {noIpsec ? null : <ClassChart classes={analysis.trafficClasses} />}
              <HandshakeTimeline steps={analysis.handshake} />
              <LiveTicker />
            </div>
          </div>

          <div className="col-span-12">
            <OverviewBottom />
          </div>
        </div>
      ) : null}
    </PageScaffold>
  )
}
