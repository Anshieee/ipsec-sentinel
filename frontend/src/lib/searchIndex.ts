import type { AnalysisResult } from '@/types/analysis'

export type SearchGroup = 'findings' | 'handshake' | 'recommendations' | 'packets'

export interface SearchHit {
  /** Matches `highlightId` in the store so the target row can be outlined. */
  id: string
  group: SearchGroup
  title: string
  subtitle?: string
  route: string
  /** Lowercased haystack. */
  haystack: string
}

export const SEARCH_GROUP_LABEL: Record<SearchGroup, string> = {
  findings: 'Findings',
  handshake: 'Handshake steps',
  recommendations: 'Recommendations',
  packets: 'Packets',
}

export const SEARCH_GROUP_ORDER: SearchGroup[] = ['findings', 'handshake', 'recommendations', 'packets']

/** Client-side index built from the current analysis (spec 4.5). */
export function buildSearchIndex(analysis: AnalysisResult): SearchHit[] {
  const hits: SearchHit[] = []

  for (const finding of analysis.findings) {
    hits.push({
      id: finding.id,
      group: 'findings',
      title: finding.title,
      subtitle: `${finding.ruleId} · ${finding.severity}`,
      route: '/audit',
      haystack: `${finding.title} ${finding.evidence} ${finding.recommendation} ${finding.ruleId}`.toLowerCase(),
    })
  }

  for (const step of analysis.handshake) {
    hits.push({
      id: step.id,
      group: 'handshake',
      title: step.step,
      subtitle: `+${step.timeSec.toFixed(3)} s · ${step.sizeBytes} B`,
      route: '/',
      haystack: `${step.step} ${Object.values(step.details).join(' ')}`.toLowerCase(),
    })
  }

  const seenRecommendations = new Set<string>()
  for (const finding of analysis.findings) {
    if (seenRecommendations.has(finding.recommendation)) continue
    seenRecommendations.add(finding.recommendation)
    hits.push({
      id: `rec-${finding.ruleId}`,
      group: 'recommendations',
      title: finding.recommendation,
      subtitle: finding.ruleId,
      route: '/audit',
      haystack: `${finding.recommendation} ${finding.ruleId} ${finding.category}`.toLowerCase(),
    })
  }

  for (const packet of analysis.packets) {
    const spi = packet.spi ?? ''
    hits.push({
      id: `packet-${packet.no}`,
      group: 'packets',
      title: packet.info,
      subtitle: `#${packet.no} · ${packet.src} → ${packet.dst}`,
      route: '/inspector',
      haystack: `${packet.info} ${spi} ${packet.src} ${packet.dst} ${packet.proto}`.toLowerCase(),
    })
  }

  return hits
}

export interface SearchResults {
  groups: { group: SearchGroup; hits: SearchHit[] }[]
  total: number
}

const MAX_PER_GROUP = 3
const MAX_TOTAL = 9

/** Case-insensitive substring match, grouped, 3 per group and 9 overall. */
export function searchIndex(index: SearchHit[], query: string): SearchResults {
  const needle = query.trim().toLowerCase()
  if (needle.length === 0) return { groups: [], total: 0 }

  const byGroup = new Map<SearchGroup, SearchHit[]>()
  for (const group of SEARCH_GROUP_ORDER) byGroup.set(group, [])

  for (const hit of index) {
    if (!hit.haystack.includes(needle)) continue
    const bucket = byGroup.get(hit.group)
    if (!bucket || bucket.length >= MAX_PER_GROUP) continue
    bucket.push(hit)
  }

  const groups = SEARCH_GROUP_ORDER.map((group) => ({ group, hits: byGroup.get(group) ?? [] })).filter(
    (entry) => entry.hits.length > 0,
  )

  // Flatten in group order, keeping the overall cap.
  const flat: SearchHit[] = []
  for (const entry of groups) {
    for (const hit of entry.hits) {
      if (flat.length >= MAX_TOTAL) break
      flat.push(hit)
    }
  }
  const allowed = new Set(flat.map((hit) => hit.id))
  const trimmedGroups = groups
    .map((entry) => ({ group: entry.group, hits: entry.hits.filter((hit) => allowed.has(hit.id)) }))
    .filter((entry) => entry.hits.length > 0)

  return { groups: trimmedGroups, total: flat.length }
}
