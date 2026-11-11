// @vitest-environment jsdom
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { addRef, formatExpr, parseExpr, removeAt, setGate } from './expr'
import { FeasibilityEngine } from './feasibility'
import { parseXsam, serializeXsam } from './io'

const sample = readFileSync(resolve(__dirname, '../../samples/APCatalog1.3.xsam'), 'utf8')

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

describe('sample catalog', () => {
  const model = parseXsam(sample)
  const steps = Object.values(model.steps)

  it('parses all chunks and steps', () => {
    expect(model.chunks).toHaveLength(14)
    expect(steps).toHaveLength(124)
  })

  it('reproduces every stored feasibility level', () => {
    const engine = new FeasibilityEngine(steps)
    const mismatches = steps
      .map((s) => ({ name: s.name, stored: s.storedLevel, computed: engine.evaluate(s.name).level }))
      .filter((r) => r.stored !== r.computed)
    expect(mismatches).toEqual([])
  })

  it('round-trips through serialize without changing the model', () => {
    const again = parseXsam(serializeXsam(model, sample))
    expect(again).toEqual(model)
  })

  it('keeps data the editor does not model', () => {
    const out = serializeXsam(model, sample)
    expect(out).toContain('ThreatClassRef')
    expect(out).toContain('ResultReportChunk')
  })

  it('persists threat scenarios and new steps', () => {
    const m = structuredClone(model)
    const chunk = m.chunks[0]
    m.steps['NEWID'] = { id: 'NEWID', name: 'ASC.9999', title: 'New', description: '', chunkId: chunk.id, ratings: { Time: { value: 4 } }, refinedBy: null }
    chunk.stepIds.push('NEWID')
    m.scenarios.push({ id: 'SC1', name: 'TS.001', title: 'Spoof brake', description: 'd', attackPaths: parseExpr('or(ASC.9999, ASC.0103)') })
    const again = parseXsam(serializeXsam(m, sample))
    expect(again.steps['NEWID'].ratings.Time?.value).toBe(4)
    expect(again.scenarios).toEqual(m.scenarios)
    expect(again.chunks).toHaveLength(14)
  })
})
