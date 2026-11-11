import { formatExpr, parseExpr } from './expr'
import { FeasibilityEngine } from './feasibility'
import { CATEGORIES, CATEGORY_PREFIX, type AttackStep, type Category, type Chunk, type Rating, type ThreatScenario, type XsamModel } from './types'

export const XSAM_NS = 'http://www.security-analyst.org/xsam'
export const MPS_NS = 'http://www.itemis.de/mps'

/**
 * Element used for threat scenarios. The sample catalog has none, so this is a
 * provisional shape (our own round-trip format) until a real XSAM scenario sample is available.
 */
export const SCENARIO_TAG = 'ThreatScenario'
export const SCENARIO_CHUNK = 'Threat scenarios'

const MPS_ALPHABET = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ$_'
export function newMpsId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(11))
  return Array.from(bytes, (b) => MPS_ALPHABET[b % 64]).join('')
}

const children = (el: Element, local: string) => Array.from(el.children).filter((c) => c.localName === local)
const child = (el: Element, local: string) => children(el, local)[0] as Element | undefined
const mpsId = (el: Element) => el.getAttributeNS(MPS_NS, 'id') ?? el.getAttribute('mps:id') ?? ''

function parseOption(option: string | null): number | null {
  const m = /\((-?\d+)\)\s*$/.exec(option ?? '')
  return m ? Number(m[1]) : null
}

export function parseXsam(xml: string): XsamModel {
  const doc = new DOMParser().parseFromString(xml, 'application/xml')
  const err = doc.getElementsByTagName('parsererror')[0]
  if (err) throw new Error(`Not a valid XML file: ${err.textContent?.slice(0, 200)}`)
  const root = doc.documentElement
  if (root.localName !== 'RootNodes') throw new Error('Not an XSAM/MPS export (missing mps:RootNodes)')

  const chunks: Chunk[] = []
  const steps: Record<string, AttackStep> = {}
  const scenarios: ThreatScenario[] = []

  for (const chunkEl of children(root, 'SecurityChunk')) {
    const chunk: Chunk = { id: mpsId(chunkEl), name: chunkEl.getAttribute('name') ?? '(unnamed)', stepIds: [] }
    const elements = child(chunkEl, 'Elements')
    const items = elements ? Array.from(elements.children) : []
    for (const el of items) {
      if (el.localName === SCENARIO_TAG) {
        scenarios.push({
          id: mpsId(el) || newMpsId(),
          name: el.getAttribute('name') ?? '',
          title: el.getAttribute('title') ?? '',
          description: el.getAttribute('description') ?? '',
          attackPaths: parseExpr(el.getAttribute('attackPaths')),
        })
        continue
      }
      if (el.localName !== 'AttackStep') continue
      const ratings: Partial<Record<Category, Rating>> = {}
      const opts = child(el, 'InitialFeasibilityOptions')
      for (const r of opts ? children(opts, 'FeasibilityRating') : []) {
        const cat = (r.getAttribute('category') ?? '').split('/').pop() as Category
        const value = parseOption(r.getAttribute('option'))
        if (!CATEGORIES.includes(cat) || value === null) continue
        const rationale = r.getAttribute('rationale') ?? undefined
        ratings[cat] = rationale ? { value, rationale } : { value }
      }
      const step: AttackStep = {
        id: mpsId(el) || newMpsId(),
        name: el.getAttribute('name') ?? '',
        title: el.getAttribute('title') ?? '',
        description: el.getAttribute('description') ?? '',
        chunkId: chunk.id,
        ratings,
        refinedBy: parseExpr(el.getAttribute('refinedBy')),
        storedLevel: el.getAttribute('attackFeasibilityLevel') ?? undefined,
      }
      steps[step.id] = step
      chunk.stepIds.push(step.id)
    }
    // The scenario chunk is ours; don't show it as a step chunk.
    if (!(chunk.name === SCENARIO_CHUNK && chunk.stepIds.length === 0)) chunks.push(chunk)
  }
  return { chunks, steps, scenarios }
}

const STEP_TEMPLATE_CHILDREN = [
  'InstantiatedClass',
  'ActedOnTOEEs',
  'InitialFeasibilityOptions',
  'ConsecutiveFeasibilityOptions',
  'ExplicitInitialFeasibility',
  'ExplicitConsecutiveFeasibility',
  'CustomImpactCombinator',
  'CustomFeasibilityCombinator',
  'FeasibilityModel',
  'Todos',
  'ImplementedVulnerabilities',
]

const EMPTY_XSAM = `<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<mps:RootNodes xmlns="${XSAM_NS}" xmlns:mps="${MPS_NS}" mps:coreVersion="96" mps:toolVersion="26.1">
</mps:RootNodes>`

/**
 * Write the model back to XSAM. Starts from the original document so that
 * everything the editor doesn't model (threat class refs, reports, TOEEs…) survives.
 */
export function serializeXsam(model: XsamModel, originalXml: string | null): string {
  const doc = new DOMParser().parseFromString(originalXml || EMPTY_XSAM, 'application/xml')
  const root = doc.documentElement
  const engine = new FeasibilityEngine(Object.values(model.steps))
  const mk = (local: string) => doc.createElementNS(XSAM_NS, local)
  const indentOf = (el: Element) => {
    const prev = el.previousSibling
    return prev && prev.nodeType === 3 ? (prev.textContent ?? '').replace(/^[^\n]*\n?/, '\n') : '\n'
  }
  const appendIndented = (parent: Element, el: Element) => {
    const last = parent.lastChild
    const parentIndent = indentOf(parent)
    const inner = parentIndent + '    '
    if (last && last.nodeType === 3) parent.insertBefore(doc.createTextNode(inner), last)
    else parent.appendChild(doc.createTextNode(inner))
    if (last && last.nodeType === 3) parent.insertBefore(el, last)
    else {
      parent.appendChild(el)
      parent.appendChild(doc.createTextNode(parentIndent))
    }
  }
  const removeEl = (el: Element) => {
    const prev = el.previousSibling
    if (prev && prev.nodeType === 3) prev.remove()
    el.remove()
  }

  const chunkEls = new Map(children(root, 'SecurityChunk').map((c) => [mpsId(c), c]))
  const existingSteps = new Map<string, Element>()
  for (const c of chunkEls.values()) {
    const els = child(c, 'Elements')
    for (const s of els ? children(els, 'AttackStep') : []) existingSteps.set(mpsId(s), s)
    for (const s of els ? children(els, SCENARIO_TAG) : []) removeEl(s)
  }

  const ensureChunk = (chunk: Chunk) => {
    let el = chunkEls.get(chunk.id)
    if (!el) {
      el = mk('SecurityChunk')
      el.setAttributeNS(MPS_NS, 'mps:id', chunk.id)
      appendIndented(root, el)
      appendIndented(el, mk('Elements'))
      appendIndented(el, mk('DefaultElementType'))
      chunkEls.set(chunk.id, el)
    }
    el.setAttribute('name', chunk.name)
    return el
  }

  for (const chunk of model.chunks) {
    const chunkEl = ensureChunk(chunk)
    const elements = child(chunkEl, 'Elements')!
    for (const id of chunk.stepIds) {
      const step = model.steps[id]
      if (!step) continue
      let el = existingSteps.get(id)
      if (el && el.parentElement !== elements) {
        removeEl(el)
        appendIndented(elements, el)
      }
      if (!el) {
        el = mk('AttackStep')
        el.setAttributeNS(MPS_NS, 'mps:id', id)
        appendIndented(elements, el)
        for (const name of STEP_TEMPLATE_CHILDREN) appendIndented(el, mk(name))
      }
      existingSteps.delete(id)
      writeStep(el, step, engine)
    }
  }
  // Steps deleted in the editor.
  for (const el of existingSteps.values()) removeEl(el)
  // Chunks deleted in the editor.
  const keep = new Set(model.chunks.map((c) => c.id))
  for (const [id, el] of chunkEls) if (!keep.has(id) && el.getAttribute('name') !== SCENARIO_CHUNK) removeEl(el)

  // Threat scenarios.
  let scenChunk = children(root, 'SecurityChunk').find((c) => c.getAttribute('name') === SCENARIO_CHUNK)
  if (model.scenarios.length && !scenChunk) {
    scenChunk = ensureChunk({ id: newMpsId(), name: SCENARIO_CHUNK, stepIds: [] })
  }
  if (scenChunk) {
    const elements = child(scenChunk, 'Elements')!
    for (const sc of model.scenarios) {
      const el = mk(SCENARIO_TAG)
      el.setAttributeNS(MPS_NS, 'mps:id', sc.id)
      el.setAttribute('name', sc.name)
      el.setAttribute('title', sc.title)
      el.setAttribute('description', sc.description)
      if (sc.attackPaths) el.setAttribute('attackPaths', formatExpr(sc.attackPaths))
      appendIndented(elements, el)
    }
    if (!model.scenarios.length) removeEl(scenChunk)
  }

  let out = new XMLSerializer().serializeToString(doc)
  if (!out.startsWith('<?xml')) out = '<?xml version="1.0" encoding="UTF-8" standalone="no"?>\n' + out
  return out
}

function writeStep(el: Element, step: AttackStep, engine: FeasibilityEngine) {
  const evaluation = engine.evaluate(step.name)
  el.setAttribute('name', step.name)
  el.setAttribute('title', step.title)
  el.setAttribute('description', step.description)
  if (step.refinedBy) el.setAttribute('refinedBy', formatExpr(step.refinedBy))
  else el.removeAttribute('refinedBy')
  if (evaluation.level) el.setAttribute('attackFeasibilityLevel', evaluation.level)
  else el.removeAttribute('attackFeasibilityLevel')
  el.setAttribute(
    'completeAttackFeasibility',
    CATEGORIES.map((c) => {
      const r = step.ratings[c]
      return `${c}:${r ? `${CATEGORY_PREFIX[c]}${r.value}(${r.value})` : 'null'}`
    }).join(', '),
  )

  const doc = el.ownerDocument
  let opts = Array.from(el.children).find((c) => c.localName === 'InitialFeasibilityOptions')
  if (!opts) {
    opts = doc.createElementNS(XSAM_NS, 'InitialFeasibilityOptions')
    el.appendChild(opts)
  }
  const existing = new Map(
    Array.from(opts.children)
      .filter((c) => c.localName === 'FeasibilityRating')
      .map((r) => [(r.getAttribute('category') ?? '').split('/').pop(), r]),
  )
  const indent = (() => {
    const prev = opts.previousSibling
    return prev && prev.nodeType === 3 ? (prev.textContent ?? '').replace(/^[^\n]*\n?/, '\n') : '\n'
  })()
  for (const c of CATEGORIES) {
    const r = step.ratings[c]
    let rEl = existing.get(c)
    if (!r) {
      if (rEl) {
        const prev = rEl.previousSibling
        if (prev && prev.nodeType === 3) prev.remove()
        rEl.remove()
      }
      continue
    }
    if (!rEl) {
      rEl = doc.createElementNS(XSAM_NS, 'FeasibilityRating')
      rEl.setAttribute('category', `name/FeasibilityCategory/${c}`)
      rEl.setAttributeNS(MPS_NS, 'mps:id', newMpsId())
      const last = opts.lastChild
      if (last && last.nodeType === 3) {
        opts.insertBefore(doc.createTextNode(indent + '    '), last)
        opts.insertBefore(rEl, last)
      } else {
        opts.appendChild(doc.createTextNode(indent + '    '))
        opts.appendChild(rEl)
        opts.appendChild(doc.createTextNode(indent))
      }
    }
    rEl.setAttribute('option', `name/FeasibilityOption/${CATEGORY_PREFIX[c]}${r.value}(${r.value})`)
    if (r.rationale) rEl.setAttribute('rationale', r.rationale)
    else rEl.removeAttribute('rationale')
  }
}
