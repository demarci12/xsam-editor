import { IMPACT_CATEGORIES, IMPACT_LEVELS, type DamageScenario, type ImpactCategory, type ImpactLevel, type XsamModel } from './types'

/**
 * Impact option codes look like `AB.S3` or `XY.F1.0`: scale prefix, category letter, then the
 * level index (0 = negligible … 3 = severe), optionally followed by a sub-variant.
 */
export function impactIndex(option: string | null | undefined): number | null {
  if (!option) return null
  const m = /\.[A-Z]+(\d+)(?:\.\d+)?$/.exec(option)
  return m ? Math.min(3, Number(m[1])) : null
}

export function impactLevelOf(d: DamageScenario): ImpactLevel | null {
  let max = -1
  for (const c of IMPACT_CATEGORIES) {
    const i = impactIndex(d.impacts[c]?.option)
    if (i !== null) max = Math.max(max, i)
  }
  return max < 0 ? null : IMPACT_LEVELS[max]
}

export const impactRank = (l: string | null | undefined) => (l ? IMPACT_LEVELS.indexOf(l as ImpactLevel) : -1)

export interface ScaleInfo {
  id: string
  label: string
  /** Option code per category and level index, as used in this model. */
  options: Partial<Record<ImpactCategory, (string | null)[]>>
  count: number
}

/**
 * Impact scales live in an external AssessmentModel; learn their option codes from the
 * damage scenarios that use them so new ratings are written in the same vocabulary.
 */
export function learnScales(model: XsamModel): ScaleInfo[] {
  const scales = new Map<string, ScaleInfo>()
  for (const d of Object.values(model.damageScenarios)) {
    const id = d.scale ?? ''
    const s = scales.get(id) ?? { id, label: '', options: {}, count: 0 }
    s.count++
    for (const c of IMPACT_CATEGORIES) {
      const opt = d.impacts[c]?.option
      const i = impactIndex(opt)
      if (opt && i !== null) {
        const arr = (s.options[c] ??= [null, null, null, null])
        arr[i] ??= opt
      }
    }
    scales.set(id, s)
  }
  for (const s of scales.values()) {
    // Fill gaps by pattern, e.g. AB.S0 seen → AB.S1..3; XY.F1.0 → XY.F3.0.
    const any = Object.values(s.options).flat().find(Boolean) ?? null
    const prefix = any ? any.split('.')[0] : 'RU'
    for (const c of IMPACT_CATEGORIES) {
      const arr = (s.options[c] ??= [null, null, null, null])
      const sample = arr.find(Boolean)
      for (let i = 0; i < 4; i++) {
        if (arr[i]) continue
        arr[i] = sample ? sample.replace(/([A-Z]+)\d+/, `$1${i}`) : `${prefix}.${c}${i}`
      }
    }
    s.label = `${prefix} scale${s.id ? ` (${s.id.slice(-5)})` : ''}`
  }
  return [...scales.values()].sort((a, b) => b.count - a.count)
}
