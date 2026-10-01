import type { Param, ProtocolInfo, TrafficLabel } from '@/types/analysis'
import { fmtPct } from './format'
import { dhGroup } from './dh'

export type RuleResult = 'fail' | 'pass' | 'unknown'

export type RuleParamKey =
  | 'ikeVersion'
  | 'exchangeMode'
  | 'mode'
  | 'ipVersion'
  | 'natTraversal'
  | 'ike.encryption'
  | 'ike.integrity'
  | 'ike.prf'
  | 'ike.dhGroup'
  | 'ike.lifetimeSec'
  | 'child.encryption'
  | 'child.integrity'
  | 'child.pfs'
  | 'child.pfsGroup'
  | 'child.lifetimeSec'
  | 'child.replayProtection'
  | 'child.esn'
  | 'traffic.top'

export interface RuleContext {
  protocol: ProtocolInfo
  trafficClasses: { label: TrafficLabel; probability: number }[]
  /** Maximum accepted CHILD SA lifetime in seconds (policy override). */
  childLifetimeMaxSec: number
  minRuleConfidence: number
}

export interface RuleCheck {
  result: RuleResult
  evidence: string
}

export interface Rule {
  id: string
  severity: import('@/types/analysis').Severity
  category: import('@/types/analysis').ThreatCategory
  stride: import('@/types/analysis').StrideTag
  title: string
  reference: string
  recommendation: string
  /** Parameters the rule reads; an inferred value below `minRuleConfidence` makes the rule unknown. */
  dependsOn: RuleParamKey[]
  check(ctx: RuleContext): RuleCheck
}

export const UNKNOWN_EVIDENCE = 'Not evaluated: insufficient confidence in the underlying inference.'

export function getParam(ctx: RuleContext, key: RuleParamKey): Param<unknown> | null {
  const p = ctx.protocol
  switch (key) {
    case 'ikeVersion':
      return p.ikeVersion
    case 'exchangeMode':
      return p.exchangeMode
    case 'mode':
      return p.mode
    case 'ipVersion':
      return p.ipVersion
    case 'natTraversal':
      return p.natTraversal
    case 'ike.encryption':
      return p.ike.encryption
    case 'ike.integrity':
      return p.ike.integrity
    case 'ike.prf':
      return p.ike.prf
    case 'ike.dhGroup':
      return p.ike.dhGroup
    case 'ike.lifetimeSec':
      return p.ike.lifetimeSec
    case 'child.encryption':
      return p.child.encryption
    case 'child.integrity':
      return p.child.integrity
    case 'child.pfs':
      return p.child.pfs
    case 'child.pfsGroup':
      return p.child.pfsGroup
    case 'child.lifetimeSec':
      return p.child.lifetimeSec
    case 'child.replayProtection':
      return p.child.replayProtection
    case 'child.esn':
      return p.child.esn
    case 'traffic.top': {
      const top = topClass(ctx.trafficClasses)
      return { value: top.label, provenance: 'inferred', confidence: top.probability }
    }
    default:
      return null
  }
}

export function topClass(trafficClasses: { label: TrafficLabel; probability: number }[]): {
  label: TrafficLabel
  probability: number
} {
  if (trafficClasses.length === 0) return { label: 'Other', probability: 0 }
  return trafficClasses.reduce((best, cur) => (cur.probability > best.probability ? cur : best), trafficClasses[0])
}

const isDesFamily = (name: string): boolean => {
  const upper = name.trim().toUpperCase()
  return upper.startsWith('3DES') || upper.startsWith('DES')
}

const confidenceLabel = (param: Param<unknown>): string =>
  param.provenance === 'observed' ? 'observed' : `inferred, ${fmtPct(param.confidence)} confidence`

/** Baseline rule table: NIST SP 800-77 Rev. 1 profile (spec 7.1). */
export const BASELINE_RULES: Rule[] = [
  {
    id: 'R01',
    severity: 'critical',
    category: 'Key Exchange',
    stride: 'Information Disclosure',
    title: 'Weak Diffie-Hellman group in the IKE SA',
    reference: 'NIST SP 800-131A Rev. 2; Logjam (CVE-2015-4000)',
    recommendation:
      'Replace DH group 1/2 with group 14 or higher, preferably ECP group 19, 20, or 21.',
    dependsOn: ['ike.dhGroup'],
    check(ctx) {
      const group = ctx.protocol.ike.dhGroup.value
      const entry = dhGroup(group)
      const desc = entry ? `${entry.bits}-bit ${entry.kind}` : 'unknown modulus'
      if (group === 1 || group === 2) {
        return {
          result: 'fail',
          evidence: `IKE SA uses DH group ${group} (${desc}); observed in IKE_SA_INIT.`,
        }
      }
      return { result: 'pass', evidence: `IKE SA uses DH group ${group} (${desc}); modulus is at least 1536 bits.` }
    },
  },
  {
    id: 'R02',
    severity: 'critical',
    category: 'Weak Cipher',
    stride: 'Information Disclosure',
    title: 'DES or 3DES cipher in use',
    reference: 'Sweet32 (CVE-2016-2183); NIST SP 800-131A Rev. 2',
    recommendation: 'Replace 3DES/DES with AES-256-GCM (or AES-128-GCM).',
    dependsOn: ['ike.encryption', 'child.encryption'],
    check(ctx) {
      const ike = ctx.protocol.ike.encryption
      const child = ctx.protocol.child.encryption
      const weak = isDesFamily(String(ike.value)) || isDesFamily(String(child.value))
      const evidence = `IKE SA encryption is ${String(ike.value)} (${confidenceLabel(ike)}); CHILD SA encryption is ${String(child.value)} (${confidenceLabel(child)}).`
      return weak ? { result: 'fail', evidence } : { result: 'pass', evidence }
    },
  },
  {
    id: 'R03',
    severity: 'critical',
    category: 'Protocol',
    stride: 'Spoofing',
    title: 'IKEv1 Aggressive Mode negotiation',
    reference: 'RFC 2409; NIST SP 800-77 Rev. 1',
    recommendation:
      'Disable IKEv1 Aggressive Mode; migrate to IKEv2 with certificate or strong PSK authentication.',
    dependsOn: ['exchangeMode'],
    check(ctx) {
      const mode = ctx.protocol.exchangeMode
      const fail = mode.value === 'Aggressive Mode'
      const evidence = `Exchange mode is ${String(mode.value)} (${confidenceLabel(mode)}).`
      return { result: fail ? 'fail' : 'pass', evidence }
    },
  },
  {
    id: 'R04',
    severity: 'high',
    category: 'PFS',
    stride: 'Information Disclosure',
    title: 'Perfect Forward Secrecy disabled',
    reference: 'NIST SP 800-77 Rev. 1; RFC 7296',
    recommendation: 'Enable Perfect Forward Secrecy on the CHILD SA using an ECP group or MODP 2048 or larger.',
    dependsOn: ['child.pfs'],
    check(ctx) {
      const pfs = ctx.protocol.child.pfs
      const evidence = `CHILD SA perfect forward secrecy is ${pfs.value ? 'enabled' : 'disabled'} (${confidenceLabel(pfs)}).`
      return { result: pfs.value ? 'pass' : 'fail', evidence }
    },
  },
  {
    id: 'R05',
    severity: 'high',
    category: 'Replay',
    stride: 'Tampering',
    title: 'ESP anti-replay protection disabled',
    reference: 'RFC 4303 (ESP anti-replay)',
    recommendation: 'Enable ESP anti-replay with a window of at least 64 packets; consider ESN on high-throughput links.',
    dependsOn: ['child.replayProtection'],
    check(ctx) {
      const replay = ctx.protocol.child.replayProtection
      const evidence = `ESP anti-replay is ${replay.value ? 'enabled' : 'disabled'} (${confidenceLabel(replay)}).`
      return { result: replay.value ? 'pass' : 'fail', evidence }
    },
  },
  {
    id: 'R06',
    severity: 'high',
    category: 'Lifetime',
    stride: 'Information Disclosure',
    title: 'CHILD SA lifetime exceeds the policy maximum',
    reference: 'NIST SP 800-77 Rev. 1',
    recommendation: 'Reduce CHILD SA lifetime to 3,600 s or 8 hours at most, and enforce volume-based rekeying.',
    dependsOn: ['child.lifetimeSec'],
    check(ctx) {
      const lifetime = ctx.protocol.child.lifetimeSec
      const value = lifetime.value
      const evidence =
        value === null
          ? 'CHILD SA lifetime was not observed in the capture.'
          : `CHILD SA lifetime is ${value.toLocaleString('en-US')} s (${confidenceLabel(lifetime)}); policy maximum is ${ctx.childLifetimeMaxSec.toLocaleString('en-US')} s.`
      if (value === null) return { result: 'unknown', evidence }
      return { result: value > ctx.childLifetimeMaxSec ? 'fail' : 'pass', evidence }
    },
  },
  {
    id: 'R07',
    severity: 'medium',
    category: 'Weak Cipher',
    stride: 'Tampering',
    title: 'Legacy HMAC-SHA1-96 or HMAC-MD5-96 integrity',
    reference: 'RFC 8247; NIST SP 800-131A Rev. 2',
    recommendation: 'Use HMAC-SHA2-256 or higher, or an AEAD cipher such as AES-GCM.',
    dependsOn: ['ike.integrity', 'child.integrity'],
    check(ctx) {
      const ike = ctx.protocol.ike.integrity
      const child = ctx.protocol.child.integrity
      const weak = ['HMAC-SHA1-96', 'HMAC-MD5-96'].includes(String(ike.value)) || ['HMAC-SHA1-96', 'HMAC-MD5-96'].includes(String(child.value))
      const evidence = `IKE integrity is ${String(ike.value)} (${confidenceLabel(ike)}); CHILD integrity is ${String(child.value)} (${confidenceLabel(child)}).`
      return { result: weak ? 'fail' : 'pass', evidence }
    },
  },
  {
    id: 'R08',
    severity: 'medium',
    category: 'Weak Cipher',
    stride: 'Information Disclosure',
    title: 'AES-CBC encryption without AEAD',
    reference: 'RFC 8247',
    recommendation: 'Prefer AES-GCM (AEAD). CBC with separate HMAC is acceptable only where GCM is unavailable.',
    dependsOn: ['ike.encryption', 'child.encryption'],
    check(ctx) {
      const ike = String(ctx.protocol.ike.encryption.value)
      const child = String(ctx.protocol.child.encryption.value)
      const isCbc = (name: string) => name.startsWith('AES-') && name.includes('CBC')
      const fail = isCbc(ike) || isCbc(child)
      const evidence = `IKE SA encryption is ${ike}; CHILD SA encryption is ${child}; ${fail ? 'CBC mode requires a separate HMAC' : 'no AES-CBC cipher is in use'}.`
      return { result: fail ? 'fail' : 'pass', evidence }
    },
  },
  {
    id: 'R09',
    severity: 'medium',
    category: 'Metadata',
    stride: 'Information Disclosure',
    title: 'Traffic type is inferable from the encrypted flow',
    reference: 'NIST SP 800-77 Rev. 1 (traffic-flow confidentiality)',
    recommendation: 'Enable traffic-flow confidentiality (ESP padding, dummy traffic) or use a fixed-size cell tunnel.',
    dependsOn: ['traffic.top'],
    check(ctx) {
      const top = topClass(ctx.trafficClasses)
      const evidence = `Top traffic class is ${top.label} with probability ${fmtPct(top.probability)}.`
      if (top.probability >= 0.6) return { result: 'fail', evidence }
      return { result: 'pass', evidence }
    },
  },
  {
    id: 'R10',
    severity: 'low',
    category: 'Replay',
    stride: 'Tampering',
    title: 'Extended Sequence Numbers disabled',
    reference: 'RFC 4304',
    recommendation: 'Enable Extended Sequence Numbers to remove 32-bit sequence exhaustion risk.',
    dependsOn: ['child.esn'],
    check(ctx) {
      const esn = ctx.protocol.child.esn
      const evidence = `Extended Sequence Numbers are ${esn.value ? 'enabled' : 'disabled'} (${confidenceLabel(esn)}).`
      return { result: esn.value ? 'pass' : 'fail', evidence }
    },
  },
  {
    id: 'R11',
    severity: 'low',
    category: 'Key Exchange',
    stride: 'Information Disclosure',
    title: 'MODP group used where elliptic-curve groups are preferred',
    reference: 'RFC 8247',
    recommendation: 'Prefer elliptic-curve groups (19, 20, 21) for stronger security per byte.',
    dependsOn: ['ike.dhGroup'],
    check(ctx) {
      const group = ctx.protocol.ike.dhGroup.value
      const entry = dhGroup(group)
      const desc = entry ? `${entry.name}` : 'unknown group'
      const fail = group === 14 || group === 15
      const evidence = `IKE SA uses DH group ${group} (${desc}); ECP groups 19, 20 and 21 give equal or better security per byte.`
      return { result: fail ? 'fail' : 'pass', evidence }
    },
  },
]
