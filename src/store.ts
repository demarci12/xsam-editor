import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { DEFAULT_CONTROL_META, emptyExtras, type AssetProperty, type Claim, type ControlMeta, type Goal, type ReviewComment, type ReviewKey, type ReviewRecord, type TaraExtras, type TaraSettings, type Treatment } from './tara/types'
import { addRef, refsOf, removeAt, removeRefsTo, renameRef, setGate, wrapInGate, type ExprPath } from './xsam/expr'
import { FeasibilityEngine } from './xsam/feasibility'
import { newMpsId, parseXsam } from './xsam/io'
import { emptyModel, type AttackStep, type ChecklistEntry, type Chunk, type ElementKind, type Expr, type ToeeRef, type XsamModel } from './xsam/types'

/** Something that owns an expression: a threat scenario's attack tree root or a step's refinement. */
export type Owner = { kind: 'threat'; id: string } | { kind: 'step'; id: string }

export type Selection =
  | { kind: ElementKind; id: string }
  | { kind: 'gate'; owner: Owner; path: ExprPath }
  | null

export interface DocState {
  model: XsamModel
  extras: TaraExtras
  originalXml: string | null
  fileName: string
}

export const COLLECTION = {
  step: 'steps',
  damage: 'damageScenarios',
  threat: 'threatScenarios',
  component: 'components',
  data: 'data',
  channel: 'channels',
  control: 'controls',
} as const satisfies Record<ElementKind, keyof XsamModel>

const PREFIX: Record<ElementKind, string> = { step: 'ASC.', damage: 'DS.', threat: 'TS.', component: 'Cmp.', data: 'Data.', channel: 'Ch.', control: 'SC.' }
/** Default chunk name per kind when the model has to create one. */
const CHUNK_FOR: Record<ElementKind, { name: string; tag: Chunk['tag'] }> = {
  step: { name: 'Attack Steps', tag: 'SecurityChunk' },
  damage: { name: 'Damage Scenarios', tag: 'SecurityChunk' },
  threat: { name: 'Threat Scenarios', tag: 'SecurityChunk' },
  component: { name: 'Components', tag: 'SystemChunk' },
  data: { name: 'Data', tag: 'SystemChunk' },
  channel: { name: 'Channels', tag: 'SystemChunk' },
  control: { name: 'Controls', tag: 'SecurityChunk' },
}

const EMPTY: DocState = { model: emptyModel(), extras: emptyExtras(), originalXml: null, fileName: 'untitled.xsam' }

// ---- persistence (IndexedDB; real TARA models are too large for localStorage comfort) ----
const DB = 'xsam-tara'
function idb(): Promise<IDBDatabase> {
  return new Promise((res, rej) => {
    const r = indexedDB.open(DB, 1)
    r.onupgradeneeded = () => r.result.createObjectStore('kv')
    r.onsuccess = () => res(r.result)
    r.onerror = () => rej(r.error)
  })
}
async function idbGet<T>(key: string): Promise<T | undefined> {
  const db = await idb()
  return new Promise((res, rej) => {
    const r = db.transaction('kv').objectStore('kv').get(key)
    r.onsuccess = () => res(r.result as T)
    r.onerror = () => rej(r.error)
  })
}
async function idbSet(key: string, value: unknown) {
  const db = await idb()
  return new Promise<void>((res, rej) => {
    const tx = db.transaction('kv', 'readwrite')
    tx.objectStore('kv').put(value, key)
    tx.oncomplete = () => res()
    tx.onerror = () => rej(tx.error)
  })
}

/** Fill in fields added in later versions so older autosaves and project files keep working. */
export function migrateDoc(d: Partial<DocState>): DocState {
  return {
    ...EMPTY,
    ...d,
    model: { ...emptyModel(), ...d.model },
    extras: { ...emptyExtras(), ...d.extras, settings: { ...emptyExtras().settings, ...d.extras?.settings } },
  } as DocState
}

export function nextName(existing: string[], prefix: string): string {
  let max = 0
  const re = new RegExp(`^${prefix.replace(/\./g, '\\.')}(\\d+)$`)
  for (const n of existing) {
    const m = re.exec(n)
    if (m) max = Math.max(max, Number(m[1]))
  }
  return `${prefix}${prefix === 'ASC.' ? String(max + 1).padStart(4, '0') : max + 1}`
}

const sameRef = (a: ToeeRef, kind: ToeeRef['kind'], id: string) => a.kind === kind && a.id === id

export function elementHash(x: unknown) {
  const s = JSON.stringify(x, (k, v) => (k === 'storedLevel' || k === 'storedImpactLevel' ? undefined : v))
  let h = 0
  for (let i = 0; i < s.length; i++) h = (Math.imul(31, h) + s.charCodeAt(i)) | 0
  return (h >>> 0).toString(36)
}

export function useDoc() {
  const [state, setState] = useState<DocState>(EMPTY)
  const [loaded, setLoaded] = useState(false)
  const [past, setPast] = useState<DocState[]>([])
  const [future, setFuture] = useState<DocState[]>([])
  const [saveError, setSaveError] = useState<string | null>(null)

  useEffect(() => {
    idbGet<DocState>('doc')
      .then((d) => d && setState(migrateDoc(d)))
      .catch(() => {})
      .finally(() => setLoaded(true))
  }, [])

  const first = useRef(true)
  useEffect(() => {
    if (!loaded) return
    if (first.current) {
      first.current = false
      return
    }
    const t = setTimeout(() => {
      idbSet('doc', state).then(
        () => setSaveError(null),
        (e) => setSaveError(String(e)),
      )
    }, 400)
    return () => clearTimeout(t)
  }, [state, loaded])

  const commit = useCallback((fn: (s: DocState) => DocState) => {
    setState((s) => {
      const next = fn(s)
      if (next === s) return s
      setPast((p) => [...p.slice(-99), s])
      setFuture([])
      return next
    })
  }, [])
  const commitModel = useCallback((fn: (m: XsamModel) => XsamModel) => commit((s) => ({ ...s, model: fn(s.model) })), [commit])
  const commitExtras = useCallback((fn: (x: TaraExtras) => TaraExtras) => commit((s) => ({ ...s, extras: fn(s.extras) })), [commit])

  const undo = useCallback(() => {
    setPast((p) => {
      if (!p.length) return p
      const prev = p[p.length - 1]
      setState((s) => {
        setFuture((f) => [s, ...f])
        return prev
      })
      return p.slice(0, -1)
    })
  }, [])
  const redo = useCallback(() => {
    setFuture((f) => {
      if (!f.length) return f
      const next = f[0]
      setState((s) => {
        setPast((p) => [...p, s])
        return next
      })
      return f.slice(1)
    })
  }, [])
  const replaceDoc = useCallback((doc: DocState) => commit(() => doc), [commit])

  const { model, extras } = state
  const engine = useMemo(() => new FeasibilityEngine(Object.values(model.steps)), [model.steps])
  const stepByName = useMemo(() => new Map(Object.values(model.steps).map((s) => [s.name, s])), [model.steps])
  /** The model as imported, for change tracking. */
  const baseline = useMemo(() => {
    try {
      return state.originalXml ? parseXsam(state.originalXml) : null
    } catch {
      return null
    }
  }, [state.originalXml])

  const getExpr = (m: XsamModel, o: Owner): Expr | null => (o.kind === 'threat' ? m.threatScenarios[o.id]?.threatenedBy : m.steps[o.id]?.refinedBy) ?? null
  const setExpr = (m: XsamModel, o: Owner, e: Expr | null): XsamModel =>
    o.kind === 'threat'
      ? { ...m, threatScenarios: { ...m.threatScenarios, [o.id]: { ...m.threatScenarios[o.id], threatenedBy: e } } }
      : { ...m, steps: { ...m.steps, [o.id]: { ...m.steps[o.id], refinedBy: e } } }

  const baselineEngine = useMemo(() => (baseline ? new FeasibilityEngine(Object.values(baseline.steps)) : null), [baseline])

  const createsCycle = useCallback(
    (owner: Owner, name: string) => {
      if (owner.kind === 'threat') return false
      const self = model.steps[owner.id]?.name
      const seen = new Set<string>()
      const stack = [name]
      while (stack.length) {
        const n = stack.pop()!
        if (n === self) return true
        if (seen.has(n)) continue
        seen.add(n)
        stack.push(...refsOf(stepByName.get(n)?.refinedBy ?? null))
      }
      return false
    },
    [model.steps, stepByName],
  )

  const actions = useMemo(() => {
    const ensureChunk = (m: XsamModel, kind: ElementKind, chunkId?: string): [XsamModel, string] => {
      if (chunkId && m.chunks.some((c) => c.id === chunkId)) return [m, chunkId]
      const want = CHUNK_FOR[kind]
      const existing = m.chunks.find((c) => c.name === want.name) ?? m.chunks.find((c) => c.elementIds.some((id) => m[COLLECTION[kind]][id]))
      if (existing) return [m, existing.id]
      const chunk: Chunk = { id: newMpsId(), name: want.name, tag: want.tag, elementIds: [] }
      return [{ ...m, chunks: [...m.chunks, chunk] }, chunk.id]
    }

    return {
      // ---------- expressions ----------
      addChild(owner: Owner, path: ExprPath, name: string, gate: 'and' | 'or' = 'and') {
        commitModel((m) => setExpr(m, owner, addRef(getExpr(m, owner), path, name, gate)))
      },
      removeNode(owner: Owner, path: ExprPath) {
        commitModel((m) => setExpr(m, owner, removeAt(getExpr(m, owner), path)))
      },
      setGate(owner: Owner, path: ExprPath, kind: 'and' | 'or') {
        commitModel((m) => setExpr(m, owner, setGate(getExpr(m, owner), path, kind)))
      },
      wrap(owner: Owner, path: ExprPath, kind: 'and' | 'or') {
        commitModel((m) => setExpr(m, owner, wrapInGate(getExpr(m, owner), path, kind)))
      },
      setExpr(owner: Owner, e: Expr | null) {
        commitModel((m) => setExpr(m, owner, e))
      },

      // ---------- generic elements ----------
      update<K extends ElementKind>(kind: K, id: string, patch: Partial<XsamModel[(typeof COLLECTION)[K]][string]>) {
        commit((s) => {
          const m = s.model
          const coll = m[COLLECTION[kind]] as Record<string, { name: string; chunkId: string }>
          const old = coll[id]
          if (!old) return s
          let next: XsamModel = { ...m, [COLLECTION[kind]]: { ...coll, [id]: { ...old, ...patch } } }
          let extras = s.extras
          const p = patch as { name?: string; chunkId?: string }
          if (kind === 'step' && p.name && p.name !== old.name) {
            const from = old.name
            const to = p.name
            next = {
              ...next,
              steps: Object.fromEntries(Object.entries(next.steps).map(([k, st]) => [k, { ...st, refinedBy: renameRef(st.refinedBy, from, to) }])),
              threatScenarios: Object.fromEntries(
                Object.entries(next.threatScenarios).map(([k, t]) => [k, { ...t, threatenedBy: renameRef(t.threatenedBy, from, to) }]),
              ),
            }
          }
          if (kind === 'control' && p.name && p.name !== old.name) {
            const from = old.name
            const to = p.name
            next = { ...next, steps: Object.fromEntries(Object.entries(next.steps).map(([k, st]) => [k, { ...st, mitigatedBy: renameRef(st.mitigatedBy, from, to) }])) }
          }
          if (p.chunkId && p.chunkId !== old.chunkId) {
            next = {
              ...next,
              chunks: next.chunks.map((c) =>
                c.id === old.chunkId ? { ...c, elementIds: c.elementIds.filter((x) => x !== id) } : c.id === p.chunkId ? { ...c, elementIds: [...c.elementIds, id] } : c,
              ),
            }
          }
          return { ...s, model: next, extras }
        })
      },

      add<K extends ElementKind>(kind: K, init: Partial<XsamModel[(typeof COLLECTION)[K]][string]> & { chunkId?: string; parentId?: string | null } = {}) {
        const id = newMpsId()
        const names = Object.values(model[COLLECTION[kind]] as Record<string, { name: string }>).map((x) => x.name)
        let name = nextName(names, PREFIX[kind])
        if (kind === 'component' && init.parentId) {
          const parent = model.components[init.parentId]
          const sibs = Object.values(model.components).filter((c) => c.parentId === init.parentId).map((c) => c.name)
          name = nextName(sibs, `${parent.name}.`)
        }
        const base = { id, name, title: '', description: '' }
        const defaults: Record<ElementKind, object> = {
          step: {
            ...base,
            title: 'New attack step',
            ratings: { Knowledge: { value: 0 }, Opportunity: { value: 0 }, Expertise: { value: 0 }, Equipment: { value: 0 }, Time: { value: 0 } },
            refinedBy: null,
            mitigatedBy: null,
            actedOn: [],
          },
          damage: { ...base, title: 'New damage scenario', impacts: {}, assets: [], scale: null },
          threat: { ...base, title: 'New threat scenario', threatenedBy: null, damageScenarioIds: [], actedOn: [] },
          component: { ...base, title: 'New component', parentId: null, storedData: [] },
          data: { ...base, title: 'New data' },
          channel: { ...base, title: 'New channel', endpoints: [] },
          control: { ...base, title: 'New control', classRef: null, effects: ['RemoveAllDamage'], ratings: {}, actedOn: [] },
        }
        commitModel((m0) => {
          const [m, chunkId] = ensureChunk(m0, kind, init.chunkId)
          const el = { ...defaults[kind], ...init, chunkId } as { parentId?: string | null }
          const top = !(kind === 'component' && el.parentId)
          return {
            ...m,
            [COLLECTION[kind]]: { ...m[COLLECTION[kind]], [id]: el },
            chunks: top ? m.chunks.map((c) => (c.id === chunkId ? { ...c, elementIds: [...c.elementIds, id] } : c)) : m.chunks,
          }
        })
        return { id, name }
      },

      remove(kind: ElementKind, id: string) {
        commit((s) => {
          let m = s.model
          const el = (m[COLLECTION[kind]] as Record<string, { name: string }>)[id]
          if (!el) return s
          let ids = [id]
          if (kind === 'component') {
            // Delete the whole sub-tree.
            const all = Object.values(m.components)
            for (let i = 0; i < ids.length; i++) all.filter((c) => c.parentId === ids[i]).forEach((c) => ids.push(c.id))
          }
          ids = [...new Set(ids)]
          const drop = <T,>(r: Record<string, T>) => Object.fromEntries(Object.entries(r).filter(([k]) => !ids.includes(k)))
          m = { ...m, [COLLECTION[kind]]: drop(m[COLLECTION[kind]] as Record<string, unknown>), chunks: m.chunks.map((c) => ({ ...c, elementIds: c.elementIds.filter((x) => !ids.includes(x)) })) }
          let extras = s.extras
          if (kind === 'step') {
            m = {
              ...m,
              steps: Object.fromEntries(Object.entries(m.steps).map(([k, st]) => [k, { ...st, refinedBy: removeRefsTo(st.refinedBy, el.name) }])),
              threatScenarios: Object.fromEntries(
                Object.entries(m.threatScenarios).map(([k, t]) => [k, { ...t, threatenedBy: removeRefsTo(t.threatenedBy, el.name) }]),
              ),
            }
          }
          if (kind === 'control') {
            m = { ...m, steps: Object.fromEntries(Object.entries(m.steps).map(([k, st]) => [k, { ...st, mitigatedBy: removeRefsTo(st.mitigatedBy, el.name) }])) }
            const { [id]: _m, ...controlMeta } = extras.controlMeta ?? {}
            void _m
            extras = { ...extras, controlMeta }
          }
          if (kind === 'damage') {
            m = { ...m, threatScenarios: Object.fromEntries(Object.entries(m.threatScenarios).map(([k, t]) => [k, { ...t, damageScenarioIds: t.damageScenarioIds.filter((x) => x !== id) }])) }
          }
          if (kind === 'threat') {
            const { [id]: _t, ...rest } = extras.treatments
            void _t
            extras = { ...extras, treatments: rest }
          }
          if (kind === 'component' || kind === 'data' || kind === 'channel') {
            const k = kind
            const keep = (r: ToeeRef) => !ids.some((x) => sameRef(r, k, x))
            m = {
              ...m,
              damageScenarios: Object.fromEntries(Object.entries(m.damageScenarios).map(([key, d]) => [key, { ...d, assets: d.assets.filter((a) => keep(a.target)) }])),
              threatScenarios: Object.fromEntries(Object.entries(m.threatScenarios).map(([key, t]) => [key, { ...t, actedOn: t.actedOn.filter(keep) }])),
              steps: Object.fromEntries(Object.entries(m.steps).map(([key, st]) => [key, { ...st, actedOn: st.actedOn.filter(keep) }])),
              components: Object.fromEntries(
                Object.entries(m.components).map(([key, c]) => [key, kind === 'data' ? { ...c, storedData: c.storedData.filter((x) => !ids.includes(x)) } : c]),
              ),
              channels: Object.fromEntries(
                Object.entries(m.channels).map(([key, c]) => [key, kind === 'component' ? { ...c, endpoints: c.endpoints.filter((x) => !ids.includes(x)) } : c]),
              ),
            }
          }
          const gone = (k: string) => ids.some((x) => k === `${kind}:${x}`)
          const reviews = Object.fromEntries(Object.entries(extras.reviews).filter(([k]) => !gone(k)))
          const assetProperties = Object.fromEntries(Object.entries(extras.assetProperties ?? {}).filter(([k]) => !gone(k)))
          return { ...s, model: m, extras: { ...extras, reviews, assetProperties } }
        })
      },

      updateChecklist(itemId: string, patch: Partial<ChecklistEntry>) {
        commitModel((m) =>
          m.checklist
            ? { ...m, checklist: { ...m.checklist, groups: m.checklist.groups.map((g) => ({ ...g, items: g.items.map((i) => (i.id === itemId ? { ...i, ...patch } : i)) })) } }
            : m,
        )
      },
      renameProject(name: string) {
        commitModel((m) => ({ ...m, projectName: name }))
      },

      // ---------- extras ----------
      setTreatment(tsId: string, patch: Partial<Treatment>) {
        commitExtras((x) => ({
          ...x,
          treatments: { ...x.treatments, [tsId]: Object.assign({ decision: null, rationale: '', goalIds: [], claimIds: [] } as Treatment, x.treatments[tsId], patch) },
        }))
      },
      addGoal(init: Partial<Goal> = {}): Goal {
        const g: Goal = { id: newMpsId(), name: nextName(Object.values(extras.goals).map((x) => x.name), 'CSG.'), title: 'New cybersecurity goal', description: '', cal: null, ...init }
        commitExtras((x) => ({ ...x, goals: { ...x.goals, [g.id]: g } }))
        return g
      },
      updateGoal(id: string, patch: Partial<Goal>) {
        commitExtras((x) => ({ ...x, goals: { ...x.goals, [id]: { ...x.goals[id], ...patch } } }))
      },
      removeGoal(id: string) {
        commitExtras((x) => {
          const { [id]: _g, ...goals } = x.goals
          void _g
          return {
            ...x,
            goals,
            treatments: Object.fromEntries(Object.entries(x.treatments).map(([k, t]) => [k, { ...t, goalIds: t.goalIds.filter((g) => g !== id) }])),
            controlMeta: Object.fromEntries(Object.entries(x.controlMeta ?? {}).map(([k, c]) => [k, { ...c, goalIds: c.goalIds.filter((g) => g !== id) }])),
          }
        })
      },
      addClaim(init: Partial<Claim> = {}): Claim {
        const c: Claim = { id: newMpsId(), name: nextName(Object.values(extras.claims).map((x) => x.name), 'CSC.'), title: 'New cybersecurity claim', description: '', ...init }
        commitExtras((x) => ({ ...x, claims: { ...x.claims, [c.id]: c } }))
        return c
      },
      updateClaim(id: string, patch: Partial<Claim>) {
        commitExtras((x) => ({ ...x, claims: { ...x.claims, [id]: { ...x.claims[id], ...patch } } }))
      },
      removeClaim(id: string) {
        commitExtras((x) => {
          const { [id]: _c, ...claims } = x.claims
          void _c
          return { ...x, claims, treatments: Object.fromEntries(Object.entries(x.treatments).map(([k, t]) => [k, { ...t, claimIds: t.claimIds.filter((c) => c !== id) }])) }
        })
      },
      setControlMeta(id: string, patch: Partial<ControlMeta>) {
        commitExtras((x) => ({ ...x, controlMeta: { ...x.controlMeta, [id]: { ...DEFAULT_CONTROL_META, ...(x.controlMeta?.[id] ?? {}), ...patch } } }))
      },
      /** Add or remove a control from a step's mitigatedBy (several controls are combined with AND, as MPS does). */
      setMitigation(stepId: string, controlName: string, on: boolean) {
        commitModel((m) => {
          const st = m.steps[stepId]
          if (!st) return m
          const has = refsOf(st.mitigatedBy).includes(controlName)
          if (on === has) return m
          const mitigatedBy = on ? addRef(st.mitigatedBy, [], controlName, 'and') : removeRefsTo(st.mitigatedBy, controlName)
          return { ...m, steps: { ...m.steps, [stepId]: { ...st, mitigatedBy } } }
        })
      },
      setAssetProperty(assetKey: string, property: string, patch: Partial<AssetProperty> | null) {
        commitExtras((x) => {
          const cur = { ...(x.assetProperties?.[assetKey] ?? {}) }
          if (patch === null) delete cur[property]
          else cur[property] = { relevant: false, rationale: '', ...cur[property], ...patch }
          return { ...x, assetProperties: { ...x.assetProperties, [assetKey]: cur } }
        })
      },
      setSettings(patch: Partial<TaraSettings>) {
        commitExtras((x) => ({ ...x, settings: { ...x.settings, ...patch } }))
      },

      // ---------- review ----------
      setReview(key: ReviewKey, patch: Partial<ReviewRecord>) {
        commitExtras((x) => ({ ...x, reviews: { ...x.reviews, [key]: Object.assign({ status: 'Open', checks: {}, comments: [] } as ReviewRecord, x.reviews[key], patch) } }))
      },
      addComment(key: ReviewKey, text: string) {
        const c: ReviewComment = { id: newMpsId(), author: extras.settings.reviewer || 'Reviewer', at: new Date().toISOString(), text }
        commitExtras((x) => {
          const r: ReviewRecord = Object.assign({ status: 'Open', checks: {}, comments: [] } as ReviewRecord, x.reviews[key])
          return { ...x, reviews: { ...x.reviews, [key]: { ...r, comments: [...r.comments, c], status: r.status === 'Open' ? 'In review' : r.status } } }
        })
      },
      updateComment(key: ReviewKey, commentId: string, patch: Partial<ReviewComment>) {
        commitExtras((x) => {
          const r = x.reviews[key]
          if (!r) return x
          return { ...x, reviews: { ...x.reviews, [key]: { ...r, comments: r.comments.map((c) => (c.id === commentId ? { ...c, ...patch } : c)) } } }
        })
      },
    }
  }, [commit, commitModel, commitExtras, model, extras.goals, extras.claims, extras.settings.reviewer])

  return {
    ...state,
    loaded,
    saveError,
    engine,
    stepByName,
    baseline,
    baselineEngine,
    actions,
    createsCycle,
    replaceDoc,
    undo,
    redo,
    canUndo: past.length > 0,
    canRedo: future.length > 0,
  }
}

export type Doc = ReturnType<typeof useDoc>
export type { AttackStep }
