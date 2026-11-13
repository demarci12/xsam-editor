import { refsOf } from './expr'
import { allSteps } from './feasibility'
import { parseXsam } from './io'
import type { AttackStep, XsamModel } from './types'

export { allSteps, engineFor } from './feasibility'

/** Step names used in attack trees but defined neither in the model nor in its catalog. */
export function unresolvedSteps(m: XsamModel): string[] {
  const known = new Set(allSteps(m).map((s) => s.name))
  const out = new Set<string>()
  for (const s of allSteps(m)) for (const r of refsOf(s.refinedBy)) if (!known.has(r)) out.add(r)
  for (const t of Object.values(m.threatScenarios)) for (const r of refsOf(t.threatenedBy)) if (!known.has(r)) out.add(r)
  return [...out].sort()
}

/**
 * MPS models import attack-step catalogs (e.g. APCatalog1.3) and reference their steps by name.
 * Attach the catalog steps this model needs, transitively, so feasibility can be computed. They are
 * kept apart from the model's own steps and never written to the model's .xsam.
 */
export function attachCatalog(m: XsamModel, catalogXml: string, catalogName: string): XsamModel {
  const missing = unresolvedSteps({ ...m, catalogSteps: undefined })
  if (!missing.length) return m
  const cat = parseXsam(catalogXml)
  const byName = new Map(Object.values(cat.steps).map((s) => [s.name, s]))
  const own = new Set(Object.values(m.steps).map((s) => s.name))
  const need = new Set<string>()
  const stack = [...missing]
  while (stack.length) {
    const n = stack.pop()!
    if (need.has(n) || own.has(n)) continue
    const s = byName.get(n)
    if (!s) continue
    need.add(n)
    stack.push(...refsOf(s.refinedBy))
  }
  if (!need.size) return m
  const catalogSteps: Record<string, AttackStep> = {}
  for (const n of need) {
    const s = byName.get(n)!
    const id = `cat:${s.id}`
    catalogSteps[id] = { ...s, id, chunkId: '' }
  }
  return { ...m, catalogSteps, catalogName }
}
