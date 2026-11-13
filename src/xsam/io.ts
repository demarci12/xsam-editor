import { formatExpr, parseExpr, refsOf } from './expr'
import { engineFor } from './feasibility'
import { impactLevelOf } from './impact'
import {
  CATEGORIES,
  CATEGORY_PREFIX,
  emptyModel,
  IMPACT_CATEGORIES,
  type AttackStep,
  type Category,
  type Channel,
  type Chunk,
  type ChunkTag,
  type Component,
  type DamageScenario,
  type DataElement,
  type ImpactCategory,
  type ImpactEntry,
  type QualifiedAsset,
  type Rating,
  type SecurityControl,
  type ThreatScenario,
  type ToeeRef,
  type XsamModel,
} from './types'

export const XSAM_NS = 'http://www.security-analyst.org/xsam'
export const MPS_NS = 'http://www.itemis.de/mps'

const MPS_ALPHABET = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ$_'
/**
 * MPS node ids are 64-bit numbers in base 64 (11 characters): the first character carries only
 * the top 4 bits. We use 1-7 so the id is a positive long, as in MPS's own exports.
 */
export function newMpsId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(11))
  return Array.from(bytes, (b, i) => MPS_ALPHABET[i === 0 ? 1 + (b % 7) : b % 64]).join('')
}

const CHUNK_TAGS: ChunkTag[] = ['SystemChunk', 'SecurityChunk', 'SecurityConceptChunk']
const REF_KIND: Record<string, ToeeRef['kind']> = { DataRef: 'data', ComponentRef: 'component', ChannelRef: 'channel', DataFlowRef: 'dataflow' }
const KIND_REF: Record<ToeeRef['kind'], string> = { data: 'DataRef', component: 'ComponentRef', channel: 'ChannelRef', dataflow: 'DataFlowRef' }

const kids = (el: Element | undefined | null, local?: string) =>
  el ? Array.from(el.children).filter((c) => !local || c.localName === local) : []
const kid = (el: Element | undefined | null, local: string) => kids(el, local)[0] as Element | undefined
const mpsId = (el: Element) => el.getAttributeNS(MPS_NS, 'id') ?? el.getAttribute('mps:id') ?? ''
const attr = (el: Element, n: string) => el.getAttribute(n) ?? ''
const lastSeg = (s: string) => s.slice(s.lastIndexOf('/') + 1)

function parseDoc(xml: string): Document {
  const doc = new DOMParser().parseFromString(xml, 'application/xml')
  const err = doc.getElementsByTagName('parsererror')[0]
  if (err) throw new Error(`Not a valid XML file: ${err.textContent?.slice(0, 200)}`)
  if (doc.documentElement.localName !== 'RootNodes') throw new Error('Not an XSAM/MPS export (missing mps:RootNodes)')
  return doc
}

/** Local references point at `mps/<modelRef>/<id>`; anything else is kept verbatim. */
function refId(target: string, modelRef: string | null): string {
  if (modelRef && target.startsWith(`mps/${modelRef}/`)) return lastSeg(target)
  return target
}
function refTarget(id: string, modelRef: string | null): string {
  return id.includes('/') || !modelRef ? id : `mps/${modelRef}/${id}`
}

function parseToees(container: Element | undefined, modelRef: string | null): ToeeRef[] {
  return kids(container)
    .filter((r) => REF_KIND[r.localName])
    .map((r) => ({ kind: REF_KIND[r.localName], id: refId(attr(r, 'target'), modelRef) }))
}

function parseOption(option: string | null): number | null {
  const m = /\((-?\d+)\)\s*$/.exec(option ?? '')
  return m ? Number(m[1]) : null
}

function parseRatings(el: Element): Partial<Record<Category, Rating>> {
  const ratings: Partial<Record<Category, Rating>> = {}
  for (const r of kids(kid(el, 'InitialFeasibilityOptions'), 'FeasibilityRating')) {
    const cat = lastSeg(attr(r, 'category')) as Category
    const value = parseOption(r.getAttribute('option'))
    if (!CATEGORIES.includes(cat) || value === null) continue
    const rationale = r.getAttribute('rationale') ?? undefined
    ratings[cat] = rationale ? { value, rationale } : { value }
  }
  return ratings
}

export function parseXsam(xml: string): XsamModel {
  const doc = parseDoc(xml)
  const root = doc.documentElement
  const m = emptyModel()
  m.modelRef = root.getAttributeNS(MPS_NS, 'modelRef') ?? root.getAttribute('mps:modelRef')
  const pn = /\(([^)]*)\)\s*$/.exec(m.modelRef ?? '')
  m.projectName = pn ? pn[1] : 'Untitled TARA'
  const ref = m.modelRef

  const parseComponent = (el: Element, chunkId: string, parentId: string | null) => {
    const c: Component = {
      id: mpsId(el),
      name: attr(el, 'name'),
      title: attr(el, 'title'),
      description: attr(el, 'description'),
      chunkId,
      parentId,
      storedData: kids(kid(el, 'StoredData'), 'DataRef').map((r) => refId(attr(r, 'target'), ref)),
    }
    m.components[c.id] = c
    for (const sub of kids(kid(el, 'SubComponents'), 'Component')) parseComponent(sub, chunkId, c.id)
    return c
  }

  for (const chunkEl of kids(root)) {
    if (chunkEl.localName === 'Checklist') {
      m.checklists.push({
        id: mpsId(chunkEl),
        name: attr(chunkEl, 'name'),
        groups: kids(kid(chunkEl, 'Groups'), 'ChecklistItemGroup').map((g) => ({
          id: mpsId(g),
          name: attr(g, 'name'),
          items: kids(kid(g, 'Items')).map((it) => ({
            id: mpsId(it),
            kind: it.localName === 'ChecklistItemHead' ? ('head' as const) : ('item' as const),
            name: attr(it, 'name'),
            relevant: attr(it, 'relevant') === 'true',
            notRelevant: attr(it, 'notRelevant') === 'true',
            rationale: attr(it, 'rationale'),
          })),
        })),
      })
      continue
    }
    if (!CHUNK_TAGS.includes(chunkEl.localName as ChunkTag)) continue
    const chunk: Chunk = { id: mpsId(chunkEl), name: attr(chunkEl, 'name'), tag: chunkEl.localName as ChunkTag, elementIds: [] }
    const vp = chunkEl.getAttribute('virtualPackage')
    if (vp) chunk.virtualPackage = vp
    const et = kids(kid(chunkEl, 'DefaultElementType'))[0]?.localName
    if (et) chunk.elementType = et
    m.chunks.push(chunk)
    for (const el of kids(kid(chunkEl, 'Elements'))) {
      const id = mpsId(el)
      const base = { id, name: attr(el, 'name'), title: attr(el, 'title'), description: attr(el, 'description'), chunkId: chunk.id }
      switch (el.localName) {
        case 'AttackStep': {
          const s: AttackStep = {
            ...base,
            ratings: parseRatings(el),
            refinedBy: parseExpr(el.getAttribute('refinedBy')),
            mitigatedBy: parseExpr(el.getAttribute('mitigatedBy')),
            actedOn: parseToees(kid(el, 'ActedOnTOEEs'), ref),
            storedLevel: el.getAttribute('attackFeasibilityLevel') ?? undefined,
          }
          m.steps[id] = s
          break
        }
        case 'DamageScenario': {
          const impacts: Partial<Record<ImpactCategory, ImpactEntry>> = {}
          for (const t of kids(kid(el, 'ImpactRatings'), 'ImpactTuple')) {
            const cat = lastSeg(attr(t, 'impactCategory')) as ImpactCategory
            const inner = kid(kid(t, 'ImpactRating'), 'ImpactRating')
            const option = inner?.getAttribute('option')
            const rationale = inner?.getAttribute('rationale') ?? undefined
            impacts[cat] = { option: option ? lastSeg(option) : null, ...(rationale ? { rationale } : {}) }
          }
          const assets: QualifiedAsset[] = kids(kid(kid(kid(el, 'ConcernedAssets'), 'QualifiedAssetList'), 'QualifiedAssets'), 'QualifiedAsset').map(
            (qa) => ({
              id: mpsId(qa),
              property: lastSeg(attr(kid(kid(qa, 'CsProperty'), 'CSPropertyRef')!, 'target')),
              target: parseToees(kid(qa, 'Toee'), ref)[0] ?? { kind: 'data', id: '' },
            }),
          )
          const d: DamageScenario = {
            ...base,
            impacts,
            assets,
            scale: kid(kid(el, 'Scale'), 'ImpactScaleRef')?.getAttribute('impactScale') ?? null,
            storedImpactLevel: el.getAttribute('impactLevel') ?? undefined,
          }
          m.damageScenarios[id] = d
          break
        }
        case 'ThreatScenario': {
          const t: ThreatScenario = {
            ...base,
            threatenedBy: parseExpr(el.getAttribute('threatenedBy')),
            damageScenarioIds: kids(kid(el, 'DamageScenarios'), 'DamageScenarioRef').map((r) => refId(attr(r, 'damageScenario'), ref)),
            actedOn: parseToees(kid(el, 'ActedOnTOEEs'), ref),
            ...(el.getAttribute('attackFeasibilityLevel') ? { storedFeasibility: attr(el, 'attackFeasibilityLevel') } : {}),
            ...(el.getAttribute('impactLevel') ? { storedImpact: attr(el, 'impactLevel') } : {}),
            ...(el.getAttribute('riskLevel') ? { storedRisk: attr(el, 'riskLevel') } : {}),
            dampedBy: refsOf(parseExpr(el.getAttribute('dampedBy'))),
            threatClasses: kids(kid(el, 'CauseOfCompromise'), 'ThreatClassRef').map((r) => attr(r, 'target')),
          }
          m.threatScenarios[id] = t
          break
        }
        case 'Control': {
          const c: SecurityControl = {
            ...base,
            classRef: kid(kid(el, 'InstantiatedControlClass'), 'SecurityControlClassRef')?.getAttribute('target') ?? null,
            effects: kids(kid(el, 'Effects')).map((e) => e.localName),
            ratings: parseRatings(el),
            actedOn: parseToees(kid(el, 'ActedOnTOEEs'), ref),
            ...(el.getAttribute('attackFeasibilityLevel') ? { storedLevel: attr(el, 'attackFeasibilityLevel') } : {}),
            ...(el.getAttribute('isImpossible') === 'true' ? { isImpossible: true } : {}),
            ...(el.getAttribute('dependsOn') ? { dependsOn: attr(el, 'dependsOn') } : {}),
          }
          m.controls[id] = c
          break
        }
        case 'Component':
          parseComponent(el, chunk.id, null)
          break
        case 'Data':
          m.data[id] = base as DataElement
          break
        case 'Channel':
          m.channels[id] = { ...base, endpoints: kids(kid(el, 'Endpoints'), 'ComponentRef').map((r) => refId(attr(r, 'target'), ref)) }
          for (const f of kids(kid(el, 'DataFlows'), 'DataFlow')) {
            const src = f.getAttribute('dataflowSource') ?? f.getAttribute('dataFlowSource')
            const tgt = f.getAttribute('dataFlowTarget') ?? f.getAttribute('dataflowTarget')
            m.dataflows[mpsId(f)] = {
              id: mpsId(f),
              name: attr(f, 'name'),
              title: attr(f, 'title'),
              description: attr(f, 'description'),
              channelId: id,
              source: src ? refId(src, ref) : null,
              target: tgt ? refId(tgt, ref) : null,
              transferredData: kids(kid(f, 'TransferredData'), 'DataRef').map((r) => refId(attr(r, 'target'), ref)),
            }
          }
          break
        case 'Assumption': {
          // Read-only: caps for the threat scenarios that reference it via dampedBy.
          const level = (box: string) => {
            const t = Array.from(kid(el, box)?.querySelectorAll('*') ?? []).find((x) => x.getAttribute('target'))?.getAttribute('target')
            return t ? lastSeg(t) : undefined
          }
          m.assumptions[id] = {
            ...base,
            ...(level('MaxAFL') ? { maxFeasibility: level('MaxAFL') } : {}),
            ...(level('MaxIL') ? { maxImpact: level('MaxIL') } : {}),
            ...(level('MaxRL') ? { maxRisk: level('MaxRL') } : {}),
          }
          continue // left untouched on export
        }
        default:
          continue // not modelled (Scenario, Assumption, …): left untouched on export
      }
      chunk.elementIds.push(id)
    }
  }
  return m
}

// ---------------------------------------------------------------------------
// Serialization

const TEMPLATES: Record<string, string[]> = {
  AttackStep: [
    'InstantiatedClass', 'ActedOnTOEEs', 'InitialFeasibilityOptions', 'ConsecutiveFeasibilityOptions', 'ExplicitInitialFeasibility',
    'ExplicitConsecutiveFeasibility', 'CustomImpactCombinator', 'CustomFeasibilityCombinator', 'FeasibilityModel', 'Todos', 'ImplementedVulnerabilities',
  ],
  DamageScenario: ['ImpactRatings', 'ConcernedAssets', 'Scale', 'Todos'],
  ThreatScenario: ['CauseOfCompromise', 'ActedOnTOEEs', 'CustomImpactCombinator', 'CustomFeasibilityCombinator', 'DamageScenarios', 'Compromises', 'Todos'],
  Component: ['Technologies', 'StoredData', 'SubComponents', 'AssignedFunctions', 'Todos', 'TrustZone', 'PackageIdentifiers'],
  Data: ['SubData', 'AssignedFunctions', 'Todos', 'PackageIdentifiers'],
  Channel: ['Endpoints', 'Technologies', 'DataFlows', 'AssignedFunctions', 'Todos', 'PackageIdentifiers'],
  Control: [
    'InstantiatedControlClass', 'ControlGroups', 'InitialFeasibilityOptions', 'ConsecutiveFeasibilityOptions', 'ActedOnTOEEs', 'Effects',
    'CustomImpactCombinator', 'CustomFeasibilityCombinator', 'FeasibilityModel',
  ],
}

const EMPTY_XSAM = (modelRef: string) => `<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<mps:RootNodes xmlns="${XSAM_NS}" xmlns:mps="${MPS_NS}" mps:coreVersion="96" mps:modelRef="${modelRef}" mps:toolVersion="26.1"/>
`

function removeWithWhitespace(el: Element) {
  const prev = el.previousSibling
  if (prev && prev.nodeType === 3 && !prev.textContent!.trim()) prev.parentNode!.removeChild(prev)
  el.parentNode?.removeChild(el)
}

const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b)

/**
 * Write the model back to XSAM. Starts from the original document; elements whose
 * data did not change are left byte-for-byte as they were, and everything the editor
 * doesn't model (reports, controls scenarios, threat classes…) is preserved.
 */
export interface SerializeOptions {
  /** Rewrite stored attackFeasibilityLevel / impactLevel wherever they differ from the computed value. */
  recomputeLevels?: boolean
}

export function serializeXsam(model: XsamModel, originalXml: string | null, opts: SerializeOptions = {}): string {
  const modelRef = model.modelRef ?? `r:${crypto.randomUUID()}(${model.projectName.replace(/[()]/g, '')})`
  const doc = parseDoc(originalXml || EMPTY_XSAM(modelRef))
  const baseline = originalXml ? parseXsam(originalXml) : emptyModel()
  const root = doc.documentElement
  // Catalog steps (imported by the MPS model) take part in the calculation but are never written.
  const engine = engineFor(model)
  const baseEngine = engineFor({ ...baseline, catalogSteps: model.catalogSteps })
  const mk = (local: string, attrs: Record<string, string> = {}) => {
    const el = doc.createElementNS(XSAM_NS, local)
    for (const [k, v] of Object.entries(attrs)) {
      if (k === 'mps:id') el.setAttributeNS(MPS_NS, 'mps:id', v)
      else el.setAttribute(k, v)
    }
    return el
  }
  const setAttr = (el: Element, k: string, v: string | null | undefined) => {
    if (v === null || v === undefined) el.removeAttribute(k)
    else if (el.getAttribute(k) !== v) el.setAttribute(k, v)
  }
  const ensureKid = (el: Element, local: string) => kid(el, local) ?? el.appendChild(mk(local))
  /** Replace children; keeps the original whitespace when the element list is unchanged. */
  const replaceKids = (el: Element, nodes: Element[]) => {
    const current = Array.from(el.children)
    if (current.length === nodes.length && current.every((c, i) => c === nodes[i])) return
    while (el.firstChild) el.removeChild(el.firstChild)
    nodes.forEach((n) => el.appendChild(n))
  }
  const toeeEls = (refs: ToeeRef[]) => refs.map((r) => mk(KIND_REF[r.kind], { 'mps:id': newMpsId(), target: refTarget(r.id, modelRef) }))

  // Index every modelled element currently in the document.
  const MODELLED = new Set(Object.keys(TEMPLATES))
  const existing = new Map<string, Element>()
  root.querySelectorAll('*').forEach((el) => {
    if (MODELLED.has(el.localName) && mpsId(el)) existing.set(mpsId(el), el)
  })
  const used = new Set<string>()

  const chunkEls = new Map(kids(root).filter((c) => CHUNK_TAGS.includes(c.localName as ChunkTag)).map((c) => [mpsId(c), c]))
  /** `after`: the previous chunk in model order, so new chunks land next to their siblings. */
  const ensureChunk = (chunk: Chunk, after?: Element) => {
    let el = chunkEls.get(chunk.id)
    if (!el) {
      el = mk(chunk.tag, { 'mps:id': chunk.id, name: chunk.name, ...(chunk.virtualPackage ? { virtualPackage: chunk.virtualPackage } : {}) })
      el.appendChild(mk('Elements'))
      const det = el.appendChild(mk('DefaultElementType'))
      if (chunk.elementType) det.appendChild(mk(chunk.elementType, { 'mps:id': newMpsId() }))
      if (after && after.parentNode === root) root.insertBefore(el, after.nextSibling)
      else root.appendChild(el)
      chunkEls.set(chunk.id, el)
    }
    setAttr(el, 'name', chunk.name)
    return el
  }

  const getEl = (tag: string, id: string) => {
    used.add(id)
    const found = existing.get(id)
    if (found) return { el: found, fresh: false }
    const el = mk(tag, { 'mps:id': id })
    for (const c of TEMPLATES[tag]) el.appendChild(mk(c))
    return { el, fresh: true }
  }
  const baseAttrs = (el: Element, x: { name: string; title: string; description: string }) => {
    setAttr(el, 'name', x.name)
    setAttr(el, 'title', x.title)
    setAttr(el, 'description', x.description)
  }

  const writeRatings = (el: Element, ratings: Partial<Record<Category, Rating>>) => {
    const opts = ensureKid(el, 'InitialFeasibilityOptions')
    const byCat = new Map(kids(opts, 'FeasibilityRating').map((r) => [lastSeg(attr(r, 'category')), r]))
    replaceKids(
      opts,
      CATEGORIES.filter((c) => ratings[c]).map((c) => {
        const r = ratings[c]!
        const rEl = byCat.get(c) ?? mk('FeasibilityRating', { category: `name/FeasibilityCategory/${c}`, 'mps:id': newMpsId() })
        rEl.setAttribute('option', `name/FeasibilityOption/${CATEGORY_PREFIX[c]}${r.value}(${r.value})`)
        setAttr(rEl, 'rationale', r.rationale || null)
        return rEl
      }),
    )
  }

  const writeStep = (s: AttackStep) => {
    const { el, fresh } = getEl('AttackStep', s.id)
    const level = engine.evaluate(s.name).level
    const prev = baseline.steps[s.id]
    // Only rewrite the stored level when our edits changed it, so stale values in an untouched
    // file are reported in the UI rather than silently rewritten.
    const levelChanged = fresh || !prev || baseEngine.evaluate(prev.name).level !== level || (!!opts.recomputeLevels && el.getAttribute('attackFeasibilityLevel') !== level)
    if (level && levelChanged) setAttr(el, 'attackFeasibilityLevel', level)
    if (!fresh && prev && same({ ...prev, chunkId: 0, storedLevel: 0 }, { ...s, chunkId: 0, storedLevel: 0 })) return el
    baseAttrs(el, s)
    setAttr(el, 'refinedBy', s.refinedBy ? formatExpr(s.refinedBy) : null)
    setAttr(el, 'mitigatedBy', s.mitigatedBy ? formatExpr(s.mitigatedBy) : null)
    if (!level) el.removeAttribute('attackFeasibilityLevel')
    setAttr(
      el,
      'completeAttackFeasibility',
      CATEGORIES.map((c) => `${c}:${s.ratings[c] ? `${CATEGORY_PREFIX[c]}${s.ratings[c]!.value}(${s.ratings[c]!.value})` : 'null'}`).join(', '),
    )
    if (fresh || !same(prev?.actedOn, s.actedOn)) replaceKids(ensureKid(el, 'ActedOnTOEEs'), toeeEls(s.actedOn))
    if (fresh || !same(prev?.ratings, s.ratings)) writeRatings(el, s.ratings)
    return el
  }

  const writeControl = (c: SecurityControl) => {
    const { el, fresh } = getEl('Control', c.id)
    const prev = baseline.controls[c.id]
    if (!fresh && prev && same({ ...prev, chunkId: 0 }, { ...c, chunkId: 0 })) return el
    baseAttrs(el, c)
    if (fresh || !same(prev?.ratings, c.ratings)) writeRatings(el, c.ratings)
    if (fresh || !same(prev?.actedOn, c.actedOn)) replaceKids(ensureKid(el, 'ActedOnTOEEs'), toeeEls(c.actedOn))
    if (fresh || !same(prev?.effects, c.effects)) {
      const box = ensureKid(el, 'Effects')
      const old = new Map(kids(box).map((e) => [e.localName, e]))
      replaceKids(box, c.effects.map((name) => old.get(name) ?? mk(name, { 'mps:id': newMpsId() })))
    }
    if (c.classRef) {
      const box = ensureKid(el, 'InstantiatedControlClass')
      const r = kid(box, 'SecurityControlClassRef') ?? box.appendChild(mk('SecurityControlClassRef', { 'mps:id': newMpsId() }))
      setAttr(r, 'target', c.classRef)
    }
    return el
  }

  const writeDamage = (d: DamageScenario) => {
    const { el, fresh } = getEl('DamageScenario', d.id)
    const level = impactLevelOf(d)
    const prev = baseline.damageScenarios[d.id]
    if (fresh || !prev || impactLevelOf(prev) !== level || (opts.recomputeLevels && (el.getAttribute('impactLevel') ?? null) !== level)) setAttr(el, 'impactLevel', level)
    if (!fresh && prev && same({ ...prev, chunkId: 0, storedImpactLevel: 0 }, { ...d, chunkId: 0, storedImpactLevel: 0 })) return el
    baseAttrs(el, d)
    if (fresh || !same(prev?.impacts, d.impacts)) {
      const ratings = ensureKid(el, 'ImpactRatings')
      const byCat = new Map(kids(ratings, 'ImpactTuple').map((t) => [lastSeg(attr(t, 'impactCategory')), t]))
      replaceKids(
        ratings,
        IMPACT_CATEGORIES.filter((c) => d.impacts[c]).map((c) => {
          const e = d.impacts[c]!
          const t = byCat.get(c) ?? mk('ImpactTuple', { impactCategory: `name/ImpactCategory/${c}`, 'mps:id': newMpsId() })
          const wrap = ensureKid(t, 'ImpactRating')
          const inner = kid(wrap, 'ImpactRating')
          if (!e.option) {
            if (inner) wrap.removeChild(inner)
            return t
          }
          const i = inner ?? wrap.appendChild(mk('ImpactRating', { 'mps:id': newMpsId() }))
          i.setAttribute('option', `name/ImpactOption/${e.option}`)
          setAttr(i, 'rationale', e.rationale || null)
          return t
        }),
      )
    }
    if (fresh || !same(prev?.assets, d.assets)) {
      const list = ensureKid(ensureKid(el, 'ConcernedAssets'), 'QualifiedAssetList')
      if (!list.getAttributeNS(MPS_NS, 'id')) list.setAttributeNS(MPS_NS, 'mps:id', newMpsId())
      const qas = ensureKid(list, 'QualifiedAssets')
      const byId = new Map(kids(qas, 'QualifiedAsset').map((q) => [mpsId(q), q]))
      const prevById = new Map((prev?.assets ?? []).map((a) => [a.id, a]))
      replaceKids(
        qas,
        d.assets.map((a) => {
          const old = byId.get(a.id)
          if (old && same(prevById.get(a.id), a)) return old
          const q = mk('QualifiedAsset', { 'mps:id': a.id })
          const p = q.appendChild(mk('CsProperty'))
          p.appendChild(mk('CSPropertyRef', { 'mps:id': newMpsId(), target: `name/CyberSecurityProperty/${a.property}` }))
          q.appendChild(mk('Toee')).append(...toeeEls([a.target]))
          return q
        }),
      )
    }
    if (d.scale) {
      const s = ensureKid(el, 'Scale')
      const r = kid(s, 'ImpactScaleRef') ?? s.appendChild(mk('ImpactScaleRef', { 'mps:id': newMpsId() }))
      setAttr(r, 'impactScale', d.scale)
    }
    return el
  }

  const writeThreat = (t: ThreatScenario) => {
    const { el, fresh } = getEl('ThreatScenario', t.id)
    const prev = baseline.threatScenarios[t.id]
    if (!fresh && prev && same({ ...prev, chunkId: 0 }, { ...t, chunkId: 0 })) return el
    baseAttrs(el, t)
    setAttr(el, 'threatenedBy', t.threatenedBy ? formatExpr(t.threatenedBy) : null)
    // With an attack tree MPS stores the tree's level; without one the stored value is kept.
    const ev = t.threatenedBy ? engine.evaluateExpr(t.threatenedBy) : null
    // A tree with references the file can't resolve keeps MPS's stored level.
    const treeLevel = ev && !ev.unresolved.length ? ev.level : null
    setAttr(el, 'attackFeasibilityLevel', treeLevel ?? t.storedFeasibility ?? null)
    setAttr(el, 'impactLevel', t.storedImpact ?? null)
    if (fresh || !same(prev?.damageScenarioIds, t.damageScenarioIds)) {
      const box = ensureKid(el, 'DamageScenarios')
      const old = new Map(kids(box, 'DamageScenarioRef').map((r) => [refId(attr(r, 'damageScenario'), modelRef), r]))
      replaceKids(
        box,
        t.damageScenarioIds.map((id) => old.get(id) ?? mk('DamageScenarioRef', { damageScenario: refTarget(id, modelRef), 'mps:id': newMpsId() })),
      )
    }
    if (fresh || !same(prev?.actedOn, t.actedOn)) replaceKids(ensureKid(el, 'ActedOnTOEEs'), toeeEls(t.actedOn))
    if (fresh) kid(el, 'Compromises')!.appendChild(mk('DeriveCompromisedAssets', { 'mps:id': newMpsId() }))
    return el
  }

  const writeComponent = (c: Component): Element => {
    const { el, fresh } = getEl('Component', c.id)
    const prev = baseline.components[c.id]
    const changed = fresh || !prev || !same({ ...prev, chunkId: 0 }, { ...c, chunkId: 0 })
    if (changed) {
      baseAttrs(el, c)
      if (fresh || !same(prev?.storedData, c.storedData))
        replaceKids(ensureKid(el, 'StoredData'), toeeEls(c.storedData.map((id) => ({ kind: 'data', id }))))
    }
    const subs = Object.values(model.components).filter((x) => x.parentId === c.id)
    const subBox = ensureKid(el, 'SubComponents')
    const subEls = subs.map(writeComponent)
    const current = kids(subBox, 'Component')
    if (!same(current.map(mpsId), subEls.map(mpsId))) replaceKids(subBox, subEls)
    return el
  }

  const writeData = (d: DataElement) => {
    const { el, fresh } = getEl('Data', d.id)
    const prev = baseline.data[d.id]
    if (fresh || !prev || !same({ ...prev, chunkId: 0 }, { ...d, chunkId: 0 })) baseAttrs(el, d)
    return el
  }

  const writeChannel = (c: Channel) => {
    const { el, fresh } = getEl('Channel', c.id)
    const prev = baseline.channels[c.id]
    if (fresh || !prev || !same({ ...prev, chunkId: 0 }, { ...c, chunkId: 0 })) {
      baseAttrs(el, c)
      if (fresh || !same(prev?.endpoints, c.endpoints)) replaceKids(ensureKid(el, 'Endpoints'), toeeEls(c.endpoints.map((id) => ({ kind: 'component', id }))))
    }
    return el
  }

  let prevChunkEl: Element | undefined
  for (const chunk of model.chunks) {
    const chunkEl = ensureChunk(chunk, prevChunkEl)
    prevChunkEl = chunkEl
    const elements = ensureKid(chunkEl, 'Elements')
    const wanted: Element[] = []
    for (const id of chunk.elementIds) {
      if (model.steps[id]) wanted.push(writeStep(model.steps[id]))
      else if (model.damageScenarios[id]) wanted.push(writeDamage(model.damageScenarios[id]))
      else if (model.threatScenarios[id]) wanted.push(writeThreat(model.threatScenarios[id]))
      else if (model.components[id]) wanted.push(writeComponent(model.components[id]))
      else if (model.data[id]) wanted.push(writeData(model.data[id]))
      else if (model.channels[id]) wanted.push(writeChannel(model.channels[id]))
      else if (model.controls[id]) wanted.push(writeControl(model.controls[id]))
    }
    // Keep unmodelled elements first in their original order, then the modelled ones in model order.
    const current = kids(elements)
    const unmodelled = current.filter((e) => !MODELLED.has(e.localName))
    const desired = [...unmodelled, ...wanted]
    if (!same(current.map(mpsId), desired.map(mpsId))) replaceKids(elements, desired)
  }

  // Deleted modelled elements.
  for (const [id, el] of existing) if (!used.has(id)) removeWithWhitespace(el)

  // Checklist answers.
  if (model.checklists.length) {
    const items = new Map<string, Element>()
    root.querySelectorAll('*').forEach((e) => {
      if (e.localName === 'ChecklistItem') items.set(mpsId(e), e)
    })
    for (const g of model.checklists.flatMap((c) => c.groups))
      for (const it of g.items) {
        const e = items.get(it.id)
        if (!e || it.kind !== 'item') continue
        setAttr(e, 'relevant', String(it.relevant))
        setAttr(e, 'notRelevant', String(it.notRelevant))
        setAttr(e, 'rationale', it.rationale)
      }
  }

  const eol = originalXml?.includes('\r\n') ? '\r\n' : '\n'
  const finalEol = originalXml ? /\r?\n$/.test(originalXml) : true
  return writeXml(doc, eol, finalEol)
}

// ---------------------------------------------------------------------------
// XML writer that keeps the original whitespace (so untouched parts stay identical),
// indents new or rebuilt parts MPS-style (4 spaces), self-closes empty elements and
// escapes newlines in attributes as &#10; like MPS does.

const escAttr = (v: string) =>
  v.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/\n/g, '&#10;').replace(/\r/g, '&#13;').replace(/\t/g, '&#9;')
const escText = (v: string) => v.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')

export function writeXml(doc: Document, eol = '\n', finalEol = true): string {
  const out: string[] = ['<?xml version="1.0" encoding="UTF-8" standalone="no"?>\n']
  const walk = (el: Element, depth: number) => {
    const attrs = Array.from(el.attributes).map((a) => ` ${a.name}="${escAttr(a.value)}"`).join('')
    const nodes = Array.from(el.childNodes)
    if (!nodes.length) {
      out.push(`<${el.tagName}${attrs}/>`)
      return
    }
    out.push(`<${el.tagName}${attrs}>`)
    const pad = '    '.repeat(depth + 1)
    nodes.forEach((n, i) => {
      const prev = nodes[i - 1]
      if (n.nodeType === 3) out.push(escText(n.textContent ?? ''))
      else {
        if (!prev || prev.nodeType !== 3) out.push(`\n${pad}`)
        if (n.nodeType === 1) walk(n as Element, depth + 1)
        else if (n.nodeType === 8) out.push(`<!--${n.textContent}-->`)
      }
    })
    if (nodes[nodes.length - 1].nodeType !== 3) out.push(`\n${'    '.repeat(depth)}`)
    out.push(`</${el.tagName}>`)
  }
  walk(doc.documentElement, 0)
  const text = out.join('')
  return (eol === '\n' ? text : text.replace(/\n/g, eol)) + (finalEol ? eol : '')
}
