// @vitest-environment jsdom
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { addRef, formatExpr, parseExpr, removeAt, setGate } from './expr'
import { FeasibilityEngine } from './feasibility'
import { impactLevelOf } from './impact'
import { computeRisks } from '../tara/risk'
import { emptyExtras } from '../tara/types'
import { emptyModel, type XsamModel } from './types'
import { attachCatalog, unresolvedSteps } from './catalog'
import { engineFor } from './feasibility'
import { threatDamageIssues, threatProperty } from '../tara/consistency'
import { newMpsId, parseXsam, serializeXsam } from './io'

const catalogPath = resolve(__dirname, '../../samples/APCatalog1.3.xsam')
const catalog = readFileSync(catalogPath, 'utf8')
// Confidential models are tested in samples/private/*.test.ts (git-ignored).

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


// ---------------------------------------------------------------------------
// A small synthetic TARA, written from scratch, covering the whole element set.

function demoTara(): XsamModel {
  const m = emptyModel()
  m.modelRef = 'r:00000000-0000-4000-8000-000000000000(Demo)'
  m.projectName = 'Demo'
  const chunk = (id: string, name: string, tag: 'SystemChunk' | 'SecurityChunk', elementType: string) => {
    m.chunks.push({ id, name, tag, elementIds: [], virtualPackage: tag === 'SystemChunk' ? 'Item Definition' : 'Security Analysis', elementType })
    return m.chunks[m.chunks.length - 1]
  }
  const cData = chunk('1aaaaaaaaa1', 'Data', 'SystemChunk', 'ElementTypeData')
  const cComp = chunk('1aaaaaaaaa2', 'Components', 'SystemChunk', 'TOEComponentContentSelector')
  const cTs = chunk('1aaaaaaaaa3', 'Threat Scenarios', 'SecurityChunk', 'ElementTypeThreatScenario')
  const cDs = chunk('1aaaaaaaaa4', 'Damage Scenarios', 'SecurityChunk', 'ElementTypeDamageScenario')
  const cAs = chunk('1aaaaaaaaa5', 'Attack Steps', 'SecurityChunk', 'ElementTypeThreat')
  const cCt = chunk('1aaaaaaaaa6', 'Controls', 'SecurityChunk', 'ElementTypeSecurityControl')
  m.data['2bbbbbbbbb1'] = { id: '2bbbbbbbbb1', name: 'Data.1', title: 'Brake signals', description: '', chunkId: cData.id }
  cData.elementIds.push('2bbbbbbbbb1')
  m.components['2bbbbbbbbb2'] = { id: '2bbbbbbbbb2', name: 'Cmp.1', title: 'ECU', description: 'with "quotes" & <tags>\nand a newline', chunkId: cComp.id, parentId: null, storedData: ['2bbbbbbbbb1'] }
  cComp.elementIds.push('2bbbbbbbbb2')
  const step = (id: string, name: string, ratings: Record<string, number>, refinedBy: string | null = null, mitigatedBy: string | null = null) => {
    m.steps[id] = {
      id, name, title: name, description: '', chunkId: cAs.id,
      ratings: Object.fromEntries(Object.entries(ratings).map(([k, v]) => [k, { value: v }])),
      refinedBy: parseExpr(refinedBy), mitigatedBy: parseExpr(mitigatedBy), actedOn: [],
    }
    cAs.elementIds.push(id)
  }
  step('3ccccccccc1', 'ASC.ACCESS', { Knowledge: 0, Opportunity: 0, Expertise: 0, Equipment: 4, Time: 0 })
  step('3ccccccccc2', 'ASC.SPOOF', { Knowledge: 2, Opportunity: 0, Expertise: 3, Equipment: 4, Time: 1 })
  step('3ccccccccc3', 'ASC.FLASH', { Knowledge: 3, Opportunity: 0, Expertise: 6, Equipment: 4, Time: 4 }, null, 'SC.1')
  step('3ccccccccc4', 'AS.TS.1', {}, 'and(ASC.ACCESS, or(ASC.SPOOF, ASC.FLASH))')
  step('3ccccccccc5', 'AS.TS.2', {}, 'and(ASC.ACCESS, ASC.FLASH)')
  m.controls['4ddddddddd1'] = { id: '4ddddddddd1', name: 'SC.1', title: 'Signed software', description: '', chunkId: cCt.id, classRef: null, effects: ['RemoveAllDamage'], ratings: {}, actedOn: [] }
  cCt.elementIds.push('4ddddddddd1')
  m.damageScenarios['5eeeeeeeee1'] = {
    id: '5eeeeeeeee1', name: 'DS.1', title: 'Unintended braking', description: '', chunkId: cDs.id,
    impacts: { S: { option: 'XX.S3', rationale: 'life-threatening' }, F: { option: 'XX.F1' } },
    assets: [{ id: '5eeeeeeeee2', property: 'Integ', target: { kind: 'data', id: '2bbbbbbbbb1' } }], scale: null,
  }
  cDs.elementIds.push('5eeeeeeeee1')
  const ts = (id: string, name: string, title: string, root: string) => {
    m.threatScenarios[id] = { id, name, title, description: '', chunkId: cTs.id, threatenedBy: parseExpr(root), damageScenarioIds: ['5eeeeeeeee1'], actedOn: [{ kind: 'data', id: '2bbbbbbbbb1' }], dampedBy: [], threatClasses: [] }
    cTs.elementIds.push(id)
  }
  ts('6fffffffff1', 'TS.1', 'Tampering (Integrity) on brake signals', 'AS.TS.1')
  ts('6fffffffff2', 'TS.2', 'Tampering (Integrity) on brake software', 'AS.TS.2')
  return m
}

describe('synthetic TARA', () => {
  const m = demoTara()
  const xml = serializeXsam(m, null)
  const back = parseXsam(xml)
  const risks = (mm: XsamModel, x = emptyExtras()) => new Map(computeRisks(mm, x, new FeasibilityEngine(Object.values(mm.steps))).map((r) => [r.ts.name, r]))

  it('writes a model from scratch and reads it back unchanged', () => {
    const stored = new Set(['storedLevel', 'storedImpactLevel', 'storedFeasibility', 'storedImpact', 'storedRisk'])
    const strip = (x: XsamModel) => JSON.parse(JSON.stringify(x, (k, v) => (stored.has(k) ? undefined : v)))
    expect(strip(back)).toEqual(strip(m))
    // MPS stores each threat scenario's computed feasibility; so does the writer.
    expect(back.threatScenarios['6fffffffff2'].storedFeasibility).toBe(engineFor(m).evaluate('AS.TS.2').level)
    expect(back.steps['3ccccccccc4'].storedLevel).toBe(new FeasibilityEngine(Object.values(m.steps)).evaluate('AS.TS.1').level)
    expect(impactLevelOf(back.damageScenarios['5eeeeeeeee1'])).toBe('Sev')
    expect(serializeXsam(back, xml)).toBe(xml)
  })

  it('computes risk, and residual risk with controls', () => {
    const r = risks(back)
    expect(r.get('TS.1')!.risk).toBe(5) // Severe x High
    expect(r.get('TS.1')!.residualBlocked).toBe(false) // spoofing path stays open
    expect(r.get('TS.2')!.residualBlocked).toBe(true) // only path is mitigated by SC.1
    expect(r.get('TS.2')!.residualRisk).toBe(1)
    // Planned controls don't count; a control without RemoveAllDamage or rating has no effect.
    const planned = emptyExtras()
    planned.controlMeta['4ddddddddd1'] = { status: 'Planned', goalIds: [] }
    expect(risks(back, planned).get('TS.2')!.residualBlocked).toBe(false)
    const noEffect = structuredClone(back)
    noEffect.controls['4ddddddddd1'].effects = []
    expect(risks(noEffect).get('TS.2')!.residualBlocked).toBe(false)
    // A bypass rating raises the step instead of removing it.
    const bypass = structuredClone(back)
    bypass.controls['4ddddddddd1'].ratings = { Expertise: { value: 8 }, Equipment: { value: 9 }, Time: { value: 19 } }
    const b = risks(bypass).get('TS.2')!
    expect(b.residualBlocked).toBe(false)
    expect(b.residualFeasibility).toBe('Very low')
  })

  it('checks threat and damage scenarios agree on asset and property', () => {
    expect(threatProperty(back.threatScenarios['6fffffffff1'])).toBe('Integ')
    expect(threatDamageIssues(back).mismatches).toEqual([])
    const bad = structuredClone(back)
    bad.damageScenarios['5eeeeeeeee1'].assets[0].property = 'Avail'
    expect(threatDamageIssues(bad).mismatches).toHaveLength(2)
  })

  it('edits, deletes and adds elements on an existing file', () => {
    const mm = structuredClone(back)
    mm.steps['3ccccccccc2'].ratings.Time = { value: 10, rationale: 'r' }
    delete mm.threatScenarios['6fffffffff2']
    mm.chunks.forEach((c) => (c.elementIds = c.elementIds.filter((x) => x !== '6fffffffff2')))
    mm.steps['3ccccccccc2'].mitigatedBy = parseExpr('or(SC.1, SC.2)')
    const again = parseXsam(serializeXsam(mm, xml))
    expect(again.steps['3ccccccccc2'].ratings.Time).toEqual({ value: 10, rationale: 'r' })
    expect(again.threatScenarios['6fffffffff2']).toBeUndefined()
    expect(formatExpr(again.steps['3ccccccccc2'].mitigatedBy)).toBe('or(SC.1, SC.2)')
    expect(again.components['2bbbbbbbbb2'].description).toBe('with "quotes" & <tags>\nand a newline')
  })
})

describe('reader: MPS features beyond the basic catalog', () => {
  const base = demoTara()
  // Data flow inside the channel, used as a concerned asset and by a threat scenario.
  const withExtras = (() => {
    const xml = serializeXsam(base, null)
    return xml
      .replace(
        '</mps:RootNodes>',
        `    <SystemChunk mps:id="7aaaaaaaaa1" name="Channels" virtualPackage="Item Definition">
        <Elements>
            <Channel description="" mps:id="7aaaaaaaaa2" name="Ch.1" title="CAN">
                <Endpoints/>
                <Technologies/>
                <DataFlows>
                    <DataFlow dataFlowTarget="mps/r:00000000-0000-4000-8000-000000000000(Demo)/2bbbbbbbbb2" dataflowSource="mps/r:00000000-0000-4000-8000-000000000000(Demo)/2bbbbbbbbb2" description="" mps:id="7aaaaaaaaa3" name="DF.1" title="Brake request">
                        <Technologies/>
                        <TransferredData>
                            <DataRef mps:id="7aaaaaaaaa4" target="mps/r:00000000-0000-4000-8000-000000000000(Demo)/2bbbbbbbbb1"/>
                        </TransferredData>
                        <AssignedFunctions/>
                        <Todos/>
                    </DataFlow>
                </DataFlows>
                <AssignedFunctions/>
                <Todos/>
                <PackageIdentifiers/>
            </Channel>
        </Elements>
        <DefaultElementType/>
    </SystemChunk>
    <SecurityChunk mps:id="7aaaaaaaaa5" name="Assumptions" virtualPackage="Security Analysis">
        <Elements>
            <Assumption description="" mps:id="7aaaaaaaaa6" name="Asmp.1" title="Debug disabled">
                <MaxRL/>
                <MaxIL/>
                <MaxAFL>
                    <AttackFeasibilityLevelRef mps:id="7aaaaaaaaa7" target="name/AttackFeasibilityLevel/Very low"/>
                </MaxAFL>
                <Effects/>
                <InstantiatedClasses/>
                <Todos/>
            </Assumption>
        </Elements>
        <DefaultElementType/>
    </SecurityChunk>
</mps:RootNodes>`,
      )
      .replace('name="TS.1" ', 'dampedBy="Asmp.1" name="TS.1" ')
  })()
  const m = parseXsam(withExtras)

  it('reads data flows and DataFlowRef assets', () => {
    expect(m.dataflows['7aaaaaaaaa3']).toMatchObject({ name: 'DF.1', channelId: '7aaaaaaaaa2', transferredData: ['2bbbbbbbbb1'] })
    expect(serializeXsam(m, withExtras)).toBe(withExtras)
    const mm = structuredClone(m)
    mm.threatScenarios['6fffffffff1'].actedOn = [{ kind: 'dataflow', id: '7aaaaaaaaa3' }]
    const again = parseXsam(serializeXsam(mm, withExtras))
    expect(again.threatScenarios['6fffffffff1'].actedOn).toEqual([{ kind: 'dataflow', id: '7aaaaaaaaa3' }])
  })

  it('applies assumption caps (dampedBy)', () => {
    expect(m.assumptions['7aaaaaaaaa6'].maxFeasibility).toBe('Very low')
    expect(m.threatScenarios['6fffffffff1'].dampedBy).toEqual(['Asmp.1'])
    const r = computeRisks(m, emptyExtras(), engineFor(m)).find((x) => x.ts.name === 'TS.1')!
    expect(r.feasibility).toBe('Very low')
    expect(r.damping[0].name).toBe('Asmp.1')
  })

  it('uses the stored bypass level of a control instead of removing the step', () => {
    const mm = structuredClone(base)
    mm.controls['4ddddddddd1'].storedLevel = 'Low'
    const r = computeRisks(mm, emptyExtras(), engineFor(mm)).find((x) => x.ts.name === 'TS.2')!
    expect(r.residualBlocked).toBe(false)
    expect(r.residualFeasibility).toBe('Low')
    mm.controls['4ddddddddd1'].isImpossible = true
    expect(computeRisks(mm, emptyExtras(), engineFor(mm)).find((x) => x.ts.name === 'TS.2')!.residualBlocked).toBe(true)
  })

  it('resolves steps from an imported catalog for calculation only', () => {
    const mm = structuredClone(base)
    mm.steps['3ccccccccc5'].refinedBy = parseExpr('and(ASC.ACCESS, ASC.0003)') // ASC.0003 lives in APCatalog1.3
    expect(unresolvedSteps(mm)).toEqual(['ASC.0003'])
    const withCat = attachCatalog(mm, catalog, 'APCatalog1.3')
    expect(unresolvedSteps(withCat)).toEqual([])
    expect(engineFor(withCat).evaluate('AS.TS.2').level).not.toBeNull()
    const xml = serializeXsam(withCat, null)
    expect(xml).not.toContain('Accessing components on the vehicle frame') // catalog step not written
  })
})
