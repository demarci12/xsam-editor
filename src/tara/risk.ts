import { FeasibilityEngine, levelOf, type Evaluation } from '../xsam/feasibility'
import { impactLevelOf, impactRank } from '../xsam/impact'
import { CATEGORIES, FEASIBILITY_LEVELS, type AttackStep, type FeasibilityLevel, type ImpactLevel, type ThreatScenario, type XsamModel } from '../xsam/types'
import type { TaraExtras } from './types'

export interface RiskRow {
  ts: ThreatScenario
  feasibility: FeasibilityLevel | null
  feasibilitySource: 'tree' | 'explicit' | 'none'
  evaluation: Evaluation | null
  /** Worst linked damage scenario. */
  impact: ImpactLevel | null
  worstDs: string | null
  risk: number | null
  residualFeasibility: FeasibilityLevel | null
  residualRisk: number | null
  /** Root attack step stored level differs from what its tree computes. */
  staleRoot: { stored: string; computed: string } | null
}

export const riskValue = (extras: TaraExtras, impact: ImpactLevel | null, feas: FeasibilityLevel | null) =>
  impact && feas ? extras.settings.riskMatrix[impact][feas] : null

/** Steps with the controls' feasibility floors applied (for residual risk). */
export function residualSteps(model: XsamModel, extras: TaraExtras): AttackStep[] {
  const byName = new Map<string, Partial<Record<(typeof CATEGORIES)[number], number>>>()
  for (const c of Object.values(extras.controls)) {
    for (const n of c.stepNames) {
      const f = byName.get(n) ?? {}
      for (const cat of CATEGORIES) if (c.floors[cat] !== undefined) f[cat] = Math.max(f[cat] ?? 0, c.floors[cat]!)
      byName.set(n, f)
    }
  }
  return Object.values(model.steps).map((s) => {
    const floors = byName.get(s.name)
    if (!floors) return s
    const ratings = { ...s.ratings }
    for (const cat of CATEGORIES) {
      if (floors[cat] === undefined) continue
      // A control on a refined step acts as an extra AND condition with these floors.
      ratings[cat] = { ...(ratings[cat] ?? { value: 0 }), value: Math.max(ratings[cat]?.value ?? 0, floors[cat]!) }
    }
    return { ...s, ratings }
  })
}

export function computeRisks(model: XsamModel, extras: TaraExtras, engine: FeasibilityEngine): RiskRow[] {
  const residualEngine = new FeasibilityEngine(residualSteps(model, extras))
  const byName = new Map(Object.values(model.steps).map((s) => [s.name, s]))
  return Object.values(model.threatScenarios).map((ts) => {
    const evaluation = ts.threatenedBy ? engine.evaluateExpr(ts.threatenedBy) : null
    let feasibility: FeasibilityLevel | null = evaluation?.level ?? null
    let source: RiskRow['feasibilitySource'] = feasibility ? 'tree' : 'none'
    if (ts.explicitFeasibility) {
      feasibility = ts.explicitFeasibility as FeasibilityLevel
      source = 'explicit'
    }
    let impact: ImpactLevel | null = null
    let worstDs: string | null = null
    for (const id of ts.damageScenarioIds) {
      const d = model.damageScenarios[id]
      const l = d ? impactLevelOf(d) : null
      if (l && impactRank(l) > impactRank(impact)) {
        impact = l
        worstDs = id
      }
    }
    if (ts.explicitImpact) impact = ts.explicitImpact as ImpactLevel
    const residual = ts.threatenedBy ? residualEngine.evaluateExpr(ts.threatenedBy) : null
    const residualFeasibility = source === 'explicit' ? feasibility : (residual?.level ?? null)

    let staleRoot: RiskRow['staleRoot'] = null
    if (ts.threatenedBy?.kind === 'ref') {
      const root = byName.get(ts.threatenedBy.name)
      if (root?.storedLevel && evaluation?.level && root.storedLevel !== evaluation.level)
        staleRoot = { stored: root.storedLevel, computed: evaluation.level }
    }
    return {
      ts,
      feasibility,
      feasibilitySource: source,
      evaluation,
      impact,
      worstDs,
      risk: riskValue(extras, impact, feasibility),
      residualFeasibility,
      residualRisk: riskValue(extras, impact, residualFeasibility),
      staleRoot,
    }
  })
}

export const RISK_COLORS = ['', 'var(--r1)', 'var(--r2)', 'var(--r3)', 'var(--r4)', 'var(--r5)']
export { FEASIBILITY_LEVELS, levelOf }
