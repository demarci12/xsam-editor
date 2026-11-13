import { allSteps, FeasibilityEngine, LEVEL_MIN_TOTAL, levelOf, type Evaluation } from '../xsam/feasibility'
import { impactLevelOf, impactRank } from '../xsam/impact'
import { refsOf } from '../xsam/expr'
import { CATEGORIES, FEASIBILITY_LEVELS, type AttackStep, type Expr, type FeasibilityLevel, type ImpactLevel, type SecurityControl, type ThreatScenario, type XsamModel } from '../xsam/types'
import { DEFAULT_CONTROL_META, type TaraExtras } from './types'

export interface RiskRow {
  ts: ThreatScenario
  feasibility: FeasibilityLevel | null
  /** tree = computed from the attack tree; stored = MPS value (no tree); none = unknown. */
  feasibilitySource: 'tree' | 'stored' | 'none'
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
  /** Assumptions that capped this scenario (dampedBy). */
  damping: { name: string; maxFeasibility?: string; maxImpact?: string; maxRisk?: string }[]
  /** Step names in the tree that neither the model nor its catalog defines (e.g. `null` in the export). */
  unresolved: string[]
  /** Values stored by MPS that differ from what this tool computes. */
  storedMismatch: { feasibility?: string; impact?: string; risk?: string } | null
}

export const riskValue = (extras: TaraExtras, impact: ImpactLevel | null, feas: FeasibilityLevel | null) =>
  impact && feas ? extras.settings.riskMatrix[impact][feas] : null

/** Is a control applied for residual risk? Planned controls don't count yet. */
export const controlActive = (extras: TaraExtras, id: string) => (extras.controlMeta?.[id]?.status ?? DEFAULT_CONTROL_META.status) !== 'Planned'

function exprTrue(e: Expr, active: (name: string) => boolean): boolean {
  if (e.kind === 'ref') return active(e.name)
  return e.kind === 'and' ? e.children.every((c) => exprTrue(c, active)) : e.children.some((c) => exprTrue(c, active))
}

const FEAS_ORDER: FeasibilityLevel[] = ['Very low', 'Low', 'Medium', 'High']
/** The harder (less feasible) of two levels. */
const harder = (a: FeasibilityLevel | null, b: string | undefined): FeasibilityLevel | null =>
  !b || !FEAS_ORDER.includes(b as FeasibilityLevel) ? a : !a ? null : FEAS_ORDER[Math.min(FEAS_ORDER.indexOf(a), FEAS_ORDER.indexOf(b as FeasibilityLevel))]
const lowerImpact = (a: ImpactLevel | null, b: string | undefined): ImpactLevel | null =>
  !b || impactRank(b) < 0 ? a : !a ? null : impactRank(b) < impactRank(a) ? (b as ImpactLevel) : a

/** How a control affects a mitigated step in residual analysis. */
export type ControlEffect = { kind: 'block' } | { kind: 'rating'; ratings: SecurityControl['ratings'] } | { kind: 'level'; level: FeasibilityLevel; from: string } | { kind: 'none' }

export function controlEffect(c: SecurityControl, tsLevel: (tsName: string) => FeasibilityLevel | null): ControlEffect {
  if (c.isImpossible) return { kind: 'block' }
  if (CATEGORIES.some((k) => c.ratings[k])) return { kind: 'rating', ratings: c.ratings }
  if (c.dependsOn) {
    const l = tsLevel(c.dependsOn)
    if (l) return { kind: 'level', level: l, from: c.dependsOn }
  }
  if (c.storedLevel && FEAS_ORDER.includes(c.storedLevel as FeasibilityLevel)) return { kind: 'level', level: c.storedLevel as FeasibilityLevel, from: 'stored bypass feasibility' }
  // No bypass information: RemoveAllDamage removes the path; detective controls have no effect.
  return c.effects.includes('RemoveAllDamage') ? { kind: 'block' } : { kind: 'none' }
}

export interface ResidualModel {
  steps: AttackStep[]
  /** Steps whose path is removed by an applied control. */
  blocked: Set<string>
  /** Least attack potential a step needs because a control must be bypassed. */
  minTotal: Map<string, number>
  /** Step name → controls that apply to it. */
  mitigations: Map<string, SecurityControl[]>
}

/**
 * Residual analysis. A step whose `mitigatedBy` holds for the applied controls needs the attacker
 * to bypass them: impossible controls (and RemoveAllDamage controls without bypass data) remove
 * the step; controls with a rating raise each factor; controls with a bypass feasibility level
 * (stored by MPS, or the level of the threat scenario they depend on) set a minimum potential.
 */
export function residualModel(model: XsamModel, extras: TaraExtras, tsLevel: (tsName: string) => FeasibilityLevel | null = () => null): ResidualModel {
  const byName = new Map(Object.values(model.controls).map((c) => [c.name, c]))
  const active = (n: string) => {
    const c = byName.get(n)
    return !!c && controlActive(extras, c.id)
  }
  const blocked = new Set<string>()
  const minTotal = new Map<string, number>()
  const mitigations = new Map<string, SecurityControl[]>()
  const steps = allSteps(model).map((s) => {
    if (!s.mitigatedBy || !exprTrue(s.mitigatedBy, active)) return s
    const ctrls = refsOf(s.mitigatedBy).filter(active).map((n) => byName.get(n)!)
    const effects = ctrls.map((c) => controlEffect(c, tsLevel))
    if (effects.every((e) => e.kind === 'none')) return s
    mitigations.set(s.name, ctrls)
    if (effects.some((e) => e.kind === 'block')) {
      blocked.add(s.name)
      return s
    }
    // The attacker must bypass every applied control: take the hardest.
    for (const e of effects) if (e.kind === 'level') minTotal.set(s.name, Math.max(minTotal.get(s.name) ?? 0, LEVEL_MIN_TOTAL[e.level]))
    const ratings = { ...s.ratings }
    for (const e of effects)
      if (e.kind === 'rating')
        for (const k of CATEGORIES) if (e.ratings[k]) ratings[k] = { ...(ratings[k] ?? { value: 0 }), value: Math.max(ratings[k]?.value ?? 0, e.ratings[k]!.value) }
    return { ...s, ratings }
  })
  return { steps, blocked, minTotal, mitigations }
}

export function computeRisks(model: XsamModel, extras: TaraExtras, engine: FeasibilityEngine): RiskRow[] {
  const byName = new Map(allSteps(model).map((s) => [s.name, s]))
  const assumptions = new Map(Object.values(model.assumptions ?? {}).map((a) => [a.name, a]))
  const tsByName = new Map(Object.values(model.threatScenarios).map((t) => [t.name, t]))

  const inherent = (ts: ThreatScenario) => {
    const evaluation = ts.threatenedBy ? engine.evaluateExpr(ts.threatenedBy) : null
    let feasibility: FeasibilityLevel | null = evaluation?.level ?? null
    let source: RiskRow['feasibilitySource'] = feasibility ? 'tree' : 'none'
    // Without a tree, or with a tree that references steps the file doesn't contain, MPS's stored value is the best we have.
    if ((!ts.threatenedBy || evaluation?.unresolved.length) && ts.storedFeasibility) {
      feasibility = ts.storedFeasibility as FeasibilityLevel
      source = 'stored'
    }
    const damping = (ts.dampedBy ?? []).map((n) => assumptions.get(n)).filter((a): a is NonNullable<typeof a> => !!a)
    for (const a of damping) feasibility = harder(feasibility, a.maxFeasibility)
    return { evaluation, feasibility, source, damping }
  }
  const tsLevel = (name: string) => {
    const t = tsByName.get(name)
    return t ? inherent(t).feasibility : null
  }
  const rm = residualModel(model, extras, tsLevel)
  const residualEngine = new FeasibilityEngine(rm.steps, rm.blocked, rm.minTotal)

  return Object.values(model.threatScenarios).map((ts) => {
    const { evaluation, feasibility, source, damping } = inherent(ts)
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
    if (!impact && ts.storedImpact) impact = ts.storedImpact as ImpactLevel
    for (const a of damping) impact = lowerImpact(impact, a.maxImpact)
    const capRisk = (r: number | null) => {
      for (const a of damping) if (r !== null && a.maxRisk && Number(a.maxRisk) < r) r = Number(a.maxRisk)
      return r
    }

    const residual = ts.threatenedBy ? residualEngine.evaluateExpr(ts.threatenedBy) : null
    const residualBlocked = source === 'tree' && !!residual?.blocked
    let residualFeasibility = source === 'tree' ? (residual?.level ?? null) : feasibility
    for (const a of damping) residualFeasibility = harder(residualFeasibility, a.maxFeasibility)

    let staleRoot: RiskRow['staleRoot'] = null
    if (ts.threatenedBy?.kind === 'ref') {
      const root = byName.get(ts.threatenedBy.name)
      if (root?.storedLevel && evaluation?.level && root.storedLevel !== evaluation.level) staleRoot = { stored: root.storedLevel, computed: evaluation.level }
    }
    const risk = capRisk(riskValue(extras, impact, feasibility))
    const mismatch: NonNullable<RiskRow['storedMismatch']> = {}
    if (source === 'tree' && ts.storedFeasibility && ts.storedFeasibility !== feasibility) mismatch.feasibility = ts.storedFeasibility
    if (ts.storedImpact && impact && ts.storedImpact !== impact) mismatch.impact = ts.storedImpact
    if (ts.storedRisk && risk !== null && ts.storedRisk !== String(risk)) mismatch.risk = ts.storedRisk
    return {
      ts,
      feasibility,
      feasibilitySource: source,
      evaluation,
      impact,
      worstDs,
      risk,
      residualFeasibility,
      residualBlocked,
      // All attack paths removed by controls: lowest risk value.
      residualRisk: residualBlocked ? (impact ? 1 : null) : capRisk(riskValue(extras, impact, residualFeasibility)),
      staleRoot,
      damping: damping.map((a) => ({ name: a.name, maxFeasibility: a.maxFeasibility, maxImpact: a.maxImpact, maxRisk: a.maxRisk })),
      unresolved: evaluation?.unresolved ?? [],
      storedMismatch: Object.keys(mismatch).length ? mismatch : null,
    }
  })
}

export const RISK_COLORS = ['', 'var(--r1)', 'var(--r2)', 'var(--r3)', 'var(--r4)', 'var(--r5)']
export { FEASIBILITY_LEVELS, levelOf }
