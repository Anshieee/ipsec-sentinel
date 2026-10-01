import { PageScaffold } from './PageScaffold'
import { InferenceTable } from '@/components/inferences/InferenceTable'
import { ClassificationDetail } from '@/components/inferences/ClassificationDetail'
import { FlowFeaturesCard } from '@/components/inferences/FlowFeaturesCard'
import { ModelEvaluation } from '@/components/inferences/ModelEvaluation'
import { ConfidenceBreakdown } from '@/components/inferences/ConfidenceBreakdown'
import { useAnalysis } from '@/store/useSentinel'

/** AI Inferences & Classification (`/inferences`), spec 10.3. */
export function InferencesPage() {
  const analysis = useAnalysis()

  return (
    <PageScaffold
      title="AI Inferences"
      description="Detected protocol parameters, traffic classification, flow features and model evaluation."
      testId="page-inferences"
    >
      {analysis ? (
        <div className="grid grid-cols-12 gap-4">
          <div className="col-span-12">
            <InferenceTable analysis={analysis} />
          </div>
          <div className="col-span-12 grid grid-cols-1 gap-4 xl:grid-cols-2">
            <ClassificationDetail classes={analysis.trafficClasses} />
            <FlowFeaturesCard analysis={analysis} />
          </div>
          <div className="col-span-12">
            <ModelEvaluation />
          </div>
          <div className="col-span-12">
            <ConfidenceBreakdown analysis={analysis} />
          </div>
        </div>
      ) : null}
    </PageScaffold>
  )
}
