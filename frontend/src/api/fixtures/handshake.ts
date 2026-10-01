import type { HandshakeStep } from '@/types/analysis'
import { dhKeBytes, dhLabel } from '@/lib/dh'
import { hexFromRng, mulberry32 } from '@/lib/prng'
import type { FixtureSpec } from './spec'

const ENCRYPTED_DETAILS: Record<string, string> = { Payload: 'Encrypted (size and timing only)' }

function ikev2Steps(spec: FixtureSpec): HandshakeStep[] {
  const rng = mulberry32(spec.seed)
  const initiatorSpi = hexFromRng(rng, 16)
  const responderSpi = hexFromRng(rng, 16)
  const dhBytes = dhKeBytes(spec.ike.dhGroup)
  const pfsDhBytes = spec.child.pfsGroup.value === null ? 0 : dhKeBytes(spec.child.pfsGroup.value)
  const [tInit, tInitResp, tAuth, tAuthResp, tEsp] = spec.handshakeTimes
  const natd = spec.natTraversal ? 'present' : 'absent'

  const initDetails: Record<string, string> = {
    'Initiator SPI': initiatorSpi,
    'Responder SPI': responderSpi,
    'Proposal: encryption': spec.ike.encryption,
    'Proposal: integrity': spec.ike.integrity,
    'Proposal: PRF': spec.ike.prf,
    'Proposal: DH group': dhLabel(spec.ike.dhGroup),
    'Proposal: Nonce length': '32',
    'NAT-D': natd,
  }

  const steps: HandshakeStep[] = [
    {
      id: 'hs-ikev2-sa-init-req',
      step: 'IKE_SA_INIT request',
      index: 1,
      timeSec: tInit ?? 0,
      direction: 'initiator->responder',
      sizeBytes: 184 + dhBytes,
      encrypted: false,
      details: initDetails,
    },
    {
      id: 'hs-ikev2-sa-init-res',
      step: 'IKE_SA_INIT response',
      index: 2,
      timeSec: tInitResp ?? 0.012,
      direction: 'responder->initiator',
      sizeBytes: 184 + dhBytes,
      encrypted: false,
      details: initDetails,
    },
    {
      id: 'hs-ikev2-auth-req',
      step: 'IKE_AUTH request',
      index: 3,
      timeSec: tAuth ?? 0.031,
      direction: 'initiator->responder',
      sizeBytes: 288,
      encrypted: true,
      details: ENCRYPTED_DETAILS,
    },
    {
      id: 'hs-ikev2-auth-res',
      step: 'IKE_AUTH response',
      index: 4,
      timeSec: tAuthResp ?? 0.058,
      direction: 'responder->initiator',
      sizeBytes: 272,
      encrypted: true,
      details: ENCRYPTED_DETAILS,
    },
    {
      id: 'hs-esp-established',
      step: 'ESP stream established',
      index: 5,
      timeSec: tEsp ?? 0.071,
      direction: 'n/a',
      sizeBytes: 0,
      encrypted: false,
      details: { Note: `First ESP packet observed at +${(tEsp ?? 0.071).toFixed(3)} s` },
    },
  ]

  spec.rekeyTimes.forEach((rekeyTime, i) => {
    const size = 160 + pfsDhBytes
    steps.push({
      id: `hs-rekey-req-${i + 1}`,
      step: 'CREATE_CHILD_SA (rekey)',
      index: 6 + i * 2,
      timeSec: rekeyTime,
      direction: 'initiator->responder',
      sizeBytes: size,
      encrypted: true,
      details: ENCRYPTED_DETAILS,
    })
    steps.push({
      id: `hs-rekey-res-${i + 1}`,
      step: 'CREATE_CHILD_SA (rekey)',
      index: 7 + i * 2,
      timeSec: rekeyTime + 0.02,
      direction: 'responder->initiator',
      sizeBytes: size,
      encrypted: true,
      details: ENCRYPTED_DETAILS,
    })
  })

  return steps
}

function ikev1Steps(spec: FixtureSpec): HandshakeStep[] {
  const rng = mulberry32(spec.seed)
  const initiatorSpi = hexFromRng(rng, 16)
  const responderSpi = hexFromRng(rng, 16)
  const [t1, t2, t3, t4, t5, t6, tEsp] = spec.handshakeTimes
  const sizes = [216, 184, 96, 152, 152, 72]
  const names = [
    'Phase 1 Aggressive Mode msg 1',
    'Phase 1 Aggressive Mode msg 2',
    'Phase 1 Aggressive Mode msg 3',
    'Phase 2 Quick Mode msg 1',
    'Phase 2 Quick Mode msg 2',
    'Phase 2 Quick Mode msg 3',
  ]
  const times = [t1 ?? 0, t2 ?? 0.041, t3 ?? 0.083, t4 ?? 0.12, t5 ?? 0.16, t6 ?? 0.201]
  const directions: HandshakeStep['direction'][] = [
    'initiator->responder',
    'responder->initiator',
    'initiator->responder',
    'initiator->responder',
    'responder->initiator',
    'initiator->responder',
  ]

  const phase1Details: Record<string, string> = {
    'Initiator SPI': initiatorSpi,
    'Responder SPI': responderSpi,
    'Proposal: encryption': spec.ike.encryption,
    'Proposal: integrity': spec.ike.integrity,
    'Proposal: PRF': spec.ike.prf,
    'Proposal: DH group': dhLabel(spec.ike.dhGroup),
    'Proposal: Nonce length': '32',
    'NAT-D': spec.natTraversal ? 'present' : 'absent',
  }

  const steps: HandshakeStep[] = names.map((name, i) => {
    const encrypted = i >= 3 // Quick Mode payloads are encrypted
    return {
      id: `hs-ikev1-${i + 1}`,
      step: name,
      index: i + 1,
      timeSec: times[i],
      direction: directions[i],
      sizeBytes: sizes[i],
      encrypted,
      details: encrypted
        ? { ...ENCRYPTED_DETAILS }
        : i === 0
          ? { ...phase1Details }
          : {
              'Initiator SPI': i === 2 ? initiatorSpi : responderSpi,
              Payload: i === 1 ? 'Nonce, KE, identification, hash' : 'Hash and identity (aggressive mode reveals identities)',
            },
    }
  })

  steps.push({
    id: 'hs-esp-established',
    step: 'ESP stream established',
    index: 7,
    timeSec: tEsp ?? 0.24,
    direction: 'n/a',
    sizeBytes: 0,
    encrypted: false,
    details: { Note: `First ESP packet observed at +${(tEsp ?? 0.24).toFixed(3)} s` },
  })

  return steps
}

/** IKEv2 or IKEv1 handshake timeline for the fixture (spec 8.7). */
export function buildHandshake(spec: FixtureSpec): HandshakeStep[] {
  return spec.ikeVersion === 'IKEv2' ? ikev2Steps(spec) : ikev1Steps(spec)
}
