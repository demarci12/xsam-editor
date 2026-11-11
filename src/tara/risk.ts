import { FeasibilityEngine, levelOf, type Evaluation } from '../xsam/feasibility'
import { impactLevelOf, impactRank } from '../xsam/impact'
import { refsOf } from '../xsam/expr'
import { CATEGORIES, FEASIBILITY_LEVELS, type AttackStep, type Expr, type FeasibilityLevel, type ImpactLevel, type SecurityControl, type ThreatScenario, type XsamModel } from '../xsam/types'
import { DEFAULT_CONTROL_META, type TaraExtras } from './types'

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
  /** Every attack path is cut by applied controls. */
  residualBlocked: boolean
  residualRisk: number | null
  /** Root attack step stored level differs from what its tree computes. */
  staleRoot: { stored: string; computed: string } | null
}

export const riskValue = (extras: TaraExtras, impact: ImpactLevel | null, feas: FeasibilityLevel | null) =>
  impact && feas ? extras.settings.riskMatrix[impact][feas] : null

/** Is a control applied for residual risk? Planned controls don't count yet. */
export const controlActive = (extras: TaraExtras, id: string) => (extras.controlMeta?.[id]?.status ?? DEFAULT_CONTROL_META.status) !== 'Planned'

function exprTrue(e: Expr, active: (name: string) => boolean): boolean {
  if (e.kind === 'ref') return active(e.name)
  return e.kind === 'and' ? e.children.every((c) => exprTrue(c, active)) : e.children.some((c) => exprTrue(c, active))
}

export interface ResidualModel {
  steps: AttackStep[]
  /** Steps whose path is removed by a control without bypass rating (XSAM RemoveAllDamage). */
  blocked: Set<string>
  /** Step name → controls that apply to it. */
  mitigations: Map<string, SecurityControl[]>
}

/**
 * Residual analysis: a step whose `mitigatedBy` is satisfied by applied controls is either
 * cut off (control has no rating: it removes the damage) or needs at least the attack
 * potential rated on the controls to bypass them.
 */
export function residualModel(model: XsamModel, extras: TaraExtras): ResidualModel {
  const byName = new Map(Object.values(model.controls).map((c) => [c.name, c]))
  const active = (n: string) => {
    const c = byName.get(n)
    return !!c && controlActive(extras, c.id)
  }
  const blocked = new Set<string>()
  const mitigations = new Map<string, SecurityControl[]>()
  const steps = Object.values(model.steps).map((s) => {
    if (!s.mitigatedBy || !exprTrue(s.mitigatedBy, active)) return s
    const ctrls = refsOf(s.mitigatedBy).filter(active).map((n) => byName.get(n)!)
    mitigations.set(s.name, ctrls)
    const rated = ctrls.filter((c) => CATEGORIES.some((k) => c.ratings[k]))
    if (!rated.length) {
      blocked.add(s.name)
      return s
    }
    const ratings = { ...s.ratings }
    for (const c of rated)
      for (const k of CATEGORIES) if (c.ratings[k]) ratings[k] = { ...(ratings[k] ?? { value: 0 }), value: Math.max(ratings[k]?.value ?? 0, c.ratings[k]!.value) }
    return { ...s, ratings }
  })
  return { steps, blocked, mitigations }
}

export function computeRisks(model: XsamModel, extras: TaraExtras, engine: FeasibilityEngine): RiskRow[] {
  const rm = residualModel(model, extras)
  const residualEngine = new FeasibilityEngine(rm.steps, rm.blocked)
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
    const residualBlocked = source !== 'explicit' && !!residual?.blocked
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
      residualBlocked,
      // All attack paths removed by controls: lowest risk value.
      residualRisk: residualBlocked ? (impact ? 1 : null) : riskValue(extras, impact, residualFeasibility),
      staleRoot,
    }
  })
}

export const RISK_COLORS = ['', 'var(--r1)', 'var(--r2)', 'var(--r3)', 'var(--r4)', 'var(--r5)']
export { FEASIBILITY_LEVELS, levelOf }
