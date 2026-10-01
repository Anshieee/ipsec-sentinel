import type { AnalysisResult } from '@/types/analysis'
import { hashString } from '@/lib/prng'
import { FIXTURE_SPECS, fixtureIdForFileName } from './spec'
import { buildFixture } from './fixtureBuilder'
import type { FixtureId } from './spec'

const cache = new Map<FixtureId, AnalysisResult>()

/** Builds once, then returns the same deterministic instance. */
export function getFixture(id: FixtureId): AnalysisResult {
  const cached = cache.get(id)
  if (cached) return cached
  const spec = FIXTURE_SPECS[id]
  const built = buildFixture(spec)
  cache.set(id, built)
  return built
}

/** Fixture selection from an uploaded file name (spec 8.3). */
export function getFixtureForFileName(fileName: string): AnalysisResult {
  return getFixture(fixtureIdForFileName(fileName, hashString))
}

/** Returns a detached copy so callers can stamp their own metadata. */
export function cloneFixture(id: FixtureId): AnalysisResult {
  return structuredClone(getFixture(id))
}

export { FIXTURE_SPECS, fixtureIdForFileName, fixtureSpec } from './spec'
export { buildFixture } from './fixtureBuilder'
export { buildHandshake } from './handshake'
export { buildPackets, buildSecurityAssociations, MAX_SAMPLE } from './capture'
export type { FixtureId, FixtureSpec } from './spec'
