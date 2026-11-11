// @vitest-environment jsdom
import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { addRef, formatExpr, parseExpr, removeAt, setGate } from './expr'
import { FeasibilityEngine } from './feasibility'
import { impactLevelOf } from './impact'
import { computeRisks } from '../tara/risk'
import { emptyExtras } from '../tara/types'
import { newMpsId, parseXsam, serializeXsam } from './io'

const catalogPath = resolve(__dirname, '../../samples/APCatalog1.3.xsam')
const catalog = readFileSync(catalogPath, 'utf8')
// Confidential customer model: only present on machines that have it (git-ignored).
const privateModel = (v: string) => {
  const p = resolve(__dirname, `../../samples/private/private-model-${v}.xsam`)
  return existsSync(p) ? readFileSync(p, 'utf8') : null
}

describe('mps ids', () => {
  it('generates ids that fit a 64-bit MPS node id', () => {
    for (let i = 0; i < 500; i++) expect(newMpsId()).toMatch(/^[1-7][0-9a-zA-Z$_]{10}$/)
  })
  it('matches the id shape used in the sample', () => {
    const ids = [...catalog.matchAll(/mps:id="([^"]+)"/g)].map((m) => m[1]).filter((id) => id.length === 11)
    expect(ids.length).toBeGreaterThan(100)
    for (const id of ids) expect(id).toMatch(/^[1-9]/)
  })
})

describe('expr', () => {
  it('round-trips nested expressions', () => {
    const s = 'or(and(ASC.0102, ASC.0003), CRYPT.001)'
    expect(formatExpr(parseExpr(s))).toBe(s)
  })
  it('adds, regates and removes', () => {
    let e = addRef(null, [], 'A')
    e = addRef(e, [], 'B')
    expect(formatExpr(e)).toBe('and(A, B)')
    e = setGate(e, [], 'or')!
    expect(formatExpr(e)).toBe('or(A, B)')
    expect(formatExpr(removeAt(e, [0]))).toBe('B')
  })
})

function commonChecks(name: string, xml: () => string, staleLevel: (stepName: string) => boolean = () => false) {
  describe(name, () => {
    it('serializes an unchanged model byte-for-byte', () => {
      const x = xml()
      expect(serializeXsam(parseXsam(x), x)).toBe(x)
    })
    it('reproduces every stored attack feasibility level', () => {
      const m = parseXsam(xml())
      const engine = new FeasibilityEngine(Object.values(m.steps))
      const bad = Object.values(m.steps)
        .map((s) => ({ name: s.name, stored: s.storedLevel, computed: engine.evaluate(s.name).level }))
              .filter((r) => r.stored !== r.computed && !staleLevel(r.name))
      expect(bad).toEqual([])
    })
    it('round-trips an edited model', () => {
      const x = xml()
      const m = parseXsam(x)
      const s = Object.values(m.steps)[0]
      s.title = 'Edited "title" with <xml> & newline\nsecond line'
      s.ratings.Time = { value: 19, rationale: 'r' }
      const again = parseXsam(serializeXsam(m, x))
      expect(again.steps[s.id].title).toBe(s.title)
      expect(again.steps[s.id].ratings.Time).toEqual({ value: 19, rationale: 'r' })
    })
  })
}

commonChecks('APCatalog sample', () => catalog)

for (const version of ['v10', 'v12']) {
  const priv = privateModel(version)
describe.skipIf(!priv)(`private model ${version}`, () => {
  // The AS.TS.* threat-scenario roots are stored as "High" although their children compute
  // to Low/Medium (e.g. AS.TS.5 = ASC.UDS.012 which itself is stored Low): stale in the file.
  commonChecks(`private ${version}`, () => priv!, (n) => n.startsWith('AS.TS.'))
  const m = priv ? parseXsam(priv) : null

  it('parses the whole TARA', () => {
    expect(Object.keys(m!.damageScenarios)).toHaveLength(37)
    expect(Object.keys(m!.threatScenarios)).toHaveLength(37)
    expect(Object.keys(m!.steps)).toHaveLength(100)
    expect(Object.keys(m!.components)).toHaveLength(23)
    expect(Object.keys(m!.data)).toHaveLength(11)
    expect(Object.keys(m!.channels)).toHaveLength(13)
    expect(m!.checklist?.groups).toHaveLength(7)
  })

  it('reproduces every stored impact level', () => {
    // v12 added impact ratings outside MPS without recomputing impactLevel for these.
    const staleV12 = ['DS.EBS.3.1', 'DS.EBS.3.2', 'DS.EBS.3.3', 'DS.EBS.3.4', 'DS.EBS.3.5', 'DS.EBS.3.6', 'DS.EBS.3.7', 'DS.EBS.3.8', 'DS.X.2']
    const bad = Object.values(m!.damageScenarios)
      .map((d) => ({ name: d.name, stored: d.storedImpactLevel ?? null, computed: impactLevelOf(d) }))
      .filter((r) => r.stored !== r.computed && !(version === 'v12' && staleV12.includes(r.name)))
    expect(bad).toEqual([])
  })

  it.runIf(version === 'v12')('reads security controls and mitigations', () => {
    expect(Object.keys(m!.controls)).toHaveLength(9)
    const ctrl = Object.values(m!.controls).find((c) => c.name === 'SC.5.2')!
    expect(ctrl.effects).toEqual(['RemoveAllDamage'])
    const uds012 = Object.values(m!.steps).find((s) => s.name === 'ASC.UDS.012')!
    expect(formatExpr(uds012.mitigatedBy)).toBe('and(SC.1.3, SC.2.0, SC.5.2)')
    expect(Object.values(m!.steps).filter((s) => s.mitigatedBy)).toHaveLength(18)
  })

  it.runIf(version === 'v12')('residual risk removes mitigated paths and never exceeds the risk', () => {
    const rows = computeRisks(m!, emptyExtras(), new FeasibilityEngine(Object.values(m!.steps)))
    for (const r of rows) if (r.risk && r.residualRisk) expect(r.residualRisk).toBeLessThanOrEqual(r.risk)
    // TS.5 = AS.TS.5 = ASC.UDS.012, which is mitigated by applied controls: no path left.
    expect(rows.find((r) => r.ts.name === 'TS.5')!.residualBlocked).toBe(true)
    // A control without RemoveAllDamage and without a bypass rating (e.g. logging) has no effect.
    const noEffect = structuredClone(m!)
    for (const c of Object.values(noEffect.controls)) c.effects = []
    expect(computeRisks(noEffect, emptyExtras(), new FeasibilityEngine(Object.values(noEffect.steps))).some((r) => r.residualBlocked)).toBe(false)
    // Planned controls don't count.
    const extras = emptyExtras()
    for (const c of Object.values(m!.controls)) extras.controlMeta[c.id] = { status: 'Planned', goalIds: [] }
    const planned = computeRisks(m!, extras, new FeasibilityEngine(Object.values(m!.steps)))
    expect(planned.every((r) => !r.residualBlocked && r.residualRisk === r.risk)).toBe(true)
  })

  it.runIf(version === 'v12')('edits, adds and deletes controls and mitigations', () => {
    const mm = structuredClone(m!)
    const ctrlChunk = mm.chunks.find((c) => c.name === 'Controls')!
    mm.controls.NEWC = { id: 'NEWC', name: 'SC.99', title: 'New', description: 'd', chunkId: ctrlChunk.id, classRef: null, effects: ['RemoveAllDamage'], ratings: { Expertise: { value: 6 } }, actedOn: [] }
    ctrlChunk.elementIds.push('NEWC')
    const step = Object.values(mm.steps).find((s) => s.name === 'ASC.CAN.012')!
    step.mitigatedBy = parseExpr('SC.99')
    const old = Object.values(mm.controls).find((c) => c.name === 'SC.9.1')!
    old.title = 'Renamed'
    const gone = Object.values(mm.controls).find((c) => c.name === 'SC.8.1')!
    delete mm.controls[gone.id]
    ctrlChunk.elementIds = ctrlChunk.elementIds.filter((x) => x !== gone.id)
    const again = parseXsam(serializeXsam(mm, priv))
    expect(again.controls.NEWC.ratings.Expertise?.value).toBe(6)
    expect(again.controls.NEWC.effects).toEqual(['RemoveAllDamage'])
    expect(formatExpr(again.steps[step.id].mitigatedBy)).toBe('SC.99')
    expect(again.controls[old.id].title).toBe('Renamed')
    expect(again.controls[gone.id]).toBeUndefined()
    expect(Object.keys(again.controls)).toHaveLength(9)
  })

  it('persists new damage and threat scenarios with links', () => {
    const mm = structuredClone(m!)
    const dsChunk = mm.chunks.find((c) => c.name === 'Damage Scenarios')!
    const tsChunk = mm.chunks.find((c) => c.name === 'Threat Scenarios')!
    const data = Object.values(mm.data)[0]
    mm.damageScenarios.NEWDS = {
      id: 'NEWDS', name: 'DS.NEW.1', title: 'New', description: '', chunkId: dsChunk.id,
      impacts: { S: { option: 'AB.S2', rationale: 'why' } }, assets: [{ id: 'QA1', property: 'Integ', target: { kind: 'data', id: data.id } }],
      scale: Object.values(mm.damageScenarios)[5].scale,
    }
    dsChunk.elementIds.push('NEWDS')
    mm.threatScenarios.NEWTS = {
      id: 'NEWTS', name: 'TS.NEW', title: 'T', description: '', chunkId: tsChunk.id,
      threatenedBy: parseExpr('AS.TS.4'), damageScenarioIds: ['NEWDS'], actedOn: [{ kind: 'data', id: data.id }],
    }
    tsChunk.elementIds.push('NEWTS')
    const again = parseXsam(serializeXsam(mm, priv))
    expect(again.damageScenarios.NEWDS.impacts.S).toEqual({ option: 'AB.S2', rationale: 'why' })
    expect(again.damageScenarios.NEWDS.assets[0].target.id).toBe(data.id)
    expect(impactLevelOf(again.damageScenarios.NEWDS)).toBe('Ser')
    expect(again.threatScenarios.NEWTS.damageScenarioIds).toEqual(['NEWDS'])
    expect(formatExpr(again.threatScenarios.NEWTS.threatenedBy)).toBe('AS.TS.4')
  })

  it('deletes elements', () => {
    const mm = structuredClone(m!)
    const ts = Object.values(mm.threatScenarios)[0]
    delete mm.threatScenarios[ts.id]
    mm.chunks.forEach((c) => (c.elementIds = c.elementIds.filter((x) => x !== ts.id)))
    const again = parseXsam(serializeXsam(mm, priv))
    expect(again.threatScenarios[ts.id]).toBeUndefined()
    expect(Object.keys(again.threatScenarios)).toHaveLength(36)
  })
})
}
