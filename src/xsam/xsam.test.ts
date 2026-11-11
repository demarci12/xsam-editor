// @vitest-environment jsdom
import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { addRef, formatExpr, parseExpr, removeAt, setGate } from './expr'
import { FeasibilityEngine } from './feasibility'
import { impactLevelOf } from './impact'
import { parseXsam, serializeXsam } from './io'

const catalogPath = resolve(__dirname, '../../samples/APCatalog1.3.xsam')
const catalog = readFileSync(catalogPath, 'utf8')
// Confidential customer model: only present on machines that have it (git-ignored).
const privatePath = resolve(__dirname, '../../samples/private/private-model-v10.xsam')
const priv = existsSync(privatePath) ? readFileSync(privatePath, 'utf8') : null

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

describe.skipIf(!priv)('private model', () => {
  // The AS.TS.* threat-scenario roots are stored as "High" although their children compute
  // to Low/Medium (e.g. AS.TS.5 = ASC.UDS.012 which itself is stored Low): stale in the file.
  commonChecks('private', () => priv!, (n) => n.startsWith('AS.TS.'))
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
    const bad = Object.values(m!.damageScenarios)
      .map((d) => ({ name: d.name, stored: d.storedImpactLevel ?? null, computed: impactLevelOf(d) }))
      .filter((r) => r.stored !== r.computed)
    expect(bad).toEqual([])
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
