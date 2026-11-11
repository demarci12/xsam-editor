import type { ThreatScenario, ToeeRef, XsamModel } from '../xsam/types'

/** STRIDE category → violated cybersecurity property (as named in XSAM). */
export const STRIDE_PROPERTY: [string, string][] = [
  ['Spoofing', 'Authe'],
  ['Tampering', 'Integ'],
  ['Repudiation', 'NonRe'],
  ['Information Disclosure', 'Confi'],
  ['Denial of Service', 'Avail'],
  ['Elevation of Privilege', 'Autho'],
]

/**
 * XSAM threat scenarios don't store the violated property as a field; it is in the STRIDE
 * title ("Tampering (Integrity) on …") or the description ("Compromised asset: … / Integ").
 */
export function threatProperty(ts: ThreatScenario): string | null {
  const m = /Compromised asset:.*?\/\s*([A-Za-z]{5})\b/.exec(ts.description)
  if (m) return m[1]
  for (const [k, p] of STRIDE_PROPERTY) if (ts.title.startsWith(k) || ts.description.includes(`STRIDE category: ${k}`)) return p
  return null
}

const key = (r: ToeeRef) => `${r.kind}:${r.id}`

export interface LinkIssue {
  ts: ThreatScenario
  dsId: string
  asset: ToeeRef
  property: string
}

/**
 * A threat scenario compromises asset × property and leads to damage scenarios; each linked
 * damage scenario should list that asset × property among its concerned assets.
 */
export function threatDamageIssues(m: XsamModel): { mismatches: LinkIssue[]; uncovered: { dsId: string; asset: ToeeRef; property: string }[] } {
  const mismatches: LinkIssue[] = []
  const covered = new Set<string>()
  for (const ts of Object.values(m.threatScenarios)) {
    const p = threatProperty(ts)
    if (!p) continue
    for (const dsId of ts.damageScenarioIds) {
      const d = m.damageScenarios[dsId]
      if (!d) continue
      for (const a of ts.actedOn) {
        covered.add(`${dsId}|${key(a)}|${p}`)
        if (!d.assets.some((x) => key(x.target) === key(a) && x.property === p)) mismatches.push({ ts, dsId, asset: a, property: p })
      }
    }
  }
  const uncovered: { dsId: string; asset: ToeeRef; property: string }[] = []
  for (const d of Object.values(m.damageScenarios))
    for (const a of d.assets) if (!covered.has(`${d.id}|${key(a.target)}|${a.property}`)) uncovered.push({ dsId: d.id, asset: a.target, property: a.property })
  return { mismatches, uncovered }
}
