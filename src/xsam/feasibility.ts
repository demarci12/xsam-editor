import { CATEGORIES, type AttackStep, type Category, type Expr, type FeasibilityLevel } from './types'

/** Attack potential vector; null entries mean "not rated". */
export type Vector = Record<Category, number>

export interface Evaluation {
  vector: Vector | null
  total: number | null
  level: FeasibilityLevel | null
  /** Names of referenced steps that are not in the catalog (e.g. other catalogs). */
  unresolved: string[]
  /** Steps that make up the cheapest path (OR picks its cheapest child). */
  pathSteps: Set<string>
  /** Every path is cut by a control that removes the damage (residual analysis). */
  blocked: boolean
}

const ZERO: Vector = { Knowledge: 0, Opportunity: 0, Expertise: 0, Equipment: 0, Time: 0 }

export const sum = (v: Vector) => CATEGORIES.reduce((a, c) => a + v[c], 0)

/** ISO/SAE 21434 Annex G attack-potential thresholds. */
export function levelOf(total: number): FeasibilityLevel {
  if (total <= 13) return 'High'
  if (total <= 19) return 'Medium'
  if (total <= 24) return 'Low'
  return 'Very low'
}

const maxV = (a: Vector, b: Vector): Vector =>
  Object.fromEntries(CATEGORIES.map((c) => [c, Math.max(a[c], b[c])])) as Vector

export function ownVector(step: AttackStep): Vector | null {
  const rated = CATEGORIES.filter((c) => step.ratings[c] !== undefined)
  if (rated.length === 0) return null
  return Object.fromEntries(CATEGORIES.map((c) => [c, step.ratings[c]?.value ?? 0])) as Vector
}

/**
 * Evaluates attack feasibility over a catalog.
 * AND: attacker needs every child, so each factor is the max over children.
 * OR: attacker takes the easiest child (lowest total attack potential).
 * Own ratings on a refined step are combined like an extra AND child.
 */
type Res = { vector: Vector | null; path: Set<string>; unresolved: string[]; blocked: boolean }

export class FeasibilityEngine {
  private byName = new Map<string, AttackStep>()
  private cache = new Map<string, Res>()
  private blockedSteps: Set<string>

  /** `blocked`: steps cut off by a control (residual analysis); a blocked step can't be used by the attacker. */
  constructor(steps: Iterable<AttackStep>, blocked: Iterable<string> = []) {
    for (const s of steps) this.byName.set(s.name, s)
    this.blockedSteps = new Set(blocked)
  }

  step(name: string) {
    return this.byName.get(name)
  }

  evaluate(name: string): Evaluation {
    const r = this.evalStep(name, new Set())
    const total = r.vector ? sum(r.vector) : null
    return {
      vector: r.blocked ? null : r.vector,
      total: r.blocked ? null : total,
      level: r.blocked || total === null ? null : levelOf(total),
      unresolved: [...new Set(r.unresolved)],
      pathSteps: r.path,
      blocked: r.blocked,
    }
  }

  /** Evaluate an arbitrary expression, e.g. a threat scenario's attack paths. */
  evaluateExpr(e: Expr | null): Evaluation {
    if (!e) return { vector: null, total: null, level: null, unresolved: [], pathSteps: new Set(), blocked: false }
    const r = this.evalExpr(e, new Set())
    const total = r.vector && !r.blocked ? sum(r.vector) : null
    return { vector: r.blocked ? null : r.vector, total, level: total === null ? null : levelOf(total), unresolved: [...new Set(r.unresolved)], pathSteps: r.path, blocked: r.blocked }
  }

  /**
   * Enumerate concrete attack paths: every way of satisfying the expression,
   * expanding refined steps down to leaf steps. Capped to keep it responsive.
   */
  enumeratePaths(e: Expr | null, cap = 500): { leaves: string[]; vector: Vector | null; total: number | null; level: FeasibilityLevel | null }[] {
    const expand = (x: Expr, seen: Set<string>): string[][] => {
      if (x.kind === 'ref') {
        const st = this.byName.get(x.name)
        if (!st || !st.refinedBy || seen.has(x.name)) return [[x.name]]
        const next = new Set(seen).add(x.name)
        return expand(st.refinedBy, next)
      }
      const parts = x.children.map((c) => expand(c, seen))
      if (x.kind === 'or') return parts.flat().slice(0, cap)
      let acc: string[][] = [[]]
      for (const p of parts) {
        const out: string[][] = []
        for (const a of acc) for (const b of p) {
          if (out.length >= cap) break
          out.push([...new Set([...a, ...b])])
        }
        acc = out
      }
      return acc
    }
    if (!e) return []
    return expand(e, new Set())
      .map((leaves) => {
        let v: Vector | null = null
        for (const l of leaves) {
          const st = this.byName.get(l)
          const own = st ? ownVector(st) : null
          if (own) v = v ? maxV(v, own) : own
        }
        const total = v ? sum(v) : null
        return { leaves, vector: v, total, level: total === null ? null : levelOf(total) }
      })
      .sort((a, b) => (a.total ?? 999) - (b.total ?? 999))
  }

  private evalStep(name: string, visiting: Set<string>) {
    const cached = this.cache.get(name)
    if (cached) return cached
    const step = this.byName.get(name)
    if (!step) return { vector: null, path: new Set<string>(), unresolved: [name], blocked: false }
    if (this.blockedSteps.has(name)) return { vector: null, path: new Set<string>(), unresolved: [], blocked: true }
    if (visiting.has(name)) return { vector: null, path: new Set<string>(), unresolved: [], blocked: false }
    visiting.add(name)
    const own = ownVector(step)
    let result: Res
    if (step.refinedBy) {
      const r = this.evalExpr(step.refinedBy, visiting)
      const vector = own && r.vector ? maxV(own, r.vector) : (r.vector ?? own)
      result = { vector: r.blocked ? null : vector, path: new Set([name, ...r.path]), unresolved: r.unresolved, blocked: r.blocked }
    } else {
      result = { vector: own, path: new Set([name]), unresolved: [], blocked: false }
    }
    visiting.delete(name)
    this.cache.set(name, result)
    return result
  }

  private evalExpr(e: Expr, visiting: Set<string>): Res {
    if (e.kind === 'ref') return this.evalStep(e.name, visiting)
    const parts = e.children.map((c) => this.evalExpr(c, visiting))
    const unresolved = parts.flatMap((p) => p.unresolved)
    if (e.kind === 'and') {
      // One blocked condition blocks the whole AND.
      if (parts.some((p) => p.blocked)) return { vector: null, path: new Set(), unresolved, blocked: true }
      let v: Vector | null = null
      const path = new Set<string>()
      for (const p of parts) {
        if (p.vector) v = v ? maxV(v, p.vector) : p.vector
        p.path.forEach((x) => path.add(x))
      }
      return { vector: v, path, unresolved, blocked: false }
    }
    // OR: the attacker takes the easiest branch that isn't blocked.
    const open = parts.filter((p) => !p.blocked)
    if (parts.length && !open.length) return { vector: null, path: new Set(), unresolved, blocked: true }
    let best: (typeof parts)[number] | null = null
    for (const p of open) {
      if (!p.vector) continue
      if (!best || sum(p.vector) < sum(best.vector!)) best = p
    }
    return { vector: best?.vector ?? null, path: best?.path ?? new Set(), unresolved, blocked: false }
  }
}

export { ZERO }
