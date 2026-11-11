import { useCallback, useEffect, useMemo, useState } from 'react'
import { addRef, refsOf, removeAt, removeRefsTo, renameRef, setGate, wrapInGate, type ExprPath } from './xsam/expr'
import { FeasibilityEngine } from './xsam/feasibility'
import { newMpsId } from './xsam/io'
import type { AttackStep, Chunk, Expr, ThreatScenario, XsamModel } from './xsam/types'

/** Something that owns an expression: a threat scenario's attack paths or a step's refinement. */
export type Owner = { kind: 'scenario'; id: string } | { kind: 'step'; id: string }

export type Selection =
  | { kind: 'scenario'; id: string }
  | { kind: 'step'; id: string }
  | { kind: 'gate'; owner: Owner; path: ExprPath }
  | null

interface DocState {
  model: XsamModel
  originalXml: string | null
  fileName: string
}

const STORAGE_KEY = 'xsam-editor/doc/v1'
const EMPTY: DocState = { model: { chunks: [], steps: {}, scenarios: [] }, originalXml: null, fileName: 'untitled.xsam' }

function load(): DocState {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (raw) return JSON.parse(raw) as DocState
  } catch {
    /* ignore */
  }
  return EMPTY
}

export function nextName(existing: string[], prefix: string): string {
  let max = 0
  const re = new RegExp(`^${prefix.replace('.', '\\.')}(\\d+)$`)
  for (const n of existing) {
    const m = re.exec(n)
    if (m) max = Math.max(max, Number(m[1]))
  }
  return `${prefix}${String(max + 1).padStart(4, '0')}`
}

export function useDoc() {
  const [state, setState] = useState<DocState>(load)
  const [past, setPast] = useState<DocState[]>([])
  const [future, setFuture] = useState<DocState[]>([])

  useEffect(() => {
    const t = setTimeout(() => {
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(state))
      } catch {
        /* quota or private mode: autosave is best effort */
      }
    }, 300)
    return () => clearTimeout(t)
  }, [state])

  const commit = useCallback((fn: (m: XsamModel) => XsamModel) => {
    setState((s) => {
      const model = fn(s.model)
      if (model === s.model) return s
      setPast((p) => [...p.slice(-99), s])
      setFuture([])
      return { ...s, model }
    })
  }, [])

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

  const replaceDoc = useCallback((doc: DocState) => {
    setState((s) => {
      setPast((p) => [...p.slice(-99), s])
      setFuture([])
      return doc
    })
  }, [])

  const engine = useMemo(() => new FeasibilityEngine(Object.values(state.model.steps)), [state.model.steps])
  const stepByName = useMemo(() => {
    const m = new Map<string, AttackStep>()
    for (const s of Object.values(state.model.steps)) m.set(s.name, s)
    return m
  }, [state.model.steps])

  // ---- expression editing (shared by scenarios and steps) ----
  const getExpr = (m: XsamModel, o: Owner): Expr | null =>
    o.kind === 'scenario' ? (m.scenarios.find((s) => s.id === o.id)?.attackPaths ?? null) : (m.steps[o.id]?.refinedBy ?? null)

  const setExpr = (m: XsamModel, o: Owner, e: Expr | null): XsamModel =>
    o.kind === 'scenario'
      ? { ...m, scenarios: m.scenarios.map((s) => (s.id === o.id ? { ...s, attackPaths: e } : s)) }
      : { ...m, steps: { ...m.steps, [o.id]: { ...m.steps[o.id], refinedBy: e } } }

  /** Would making `owner` depend on `name` create a cycle? */
  const createsCycle = useCallback(
    (owner: Owner, name: string) => {
      if (owner.kind === 'scenario') return false
      const self = state.model.steps[owner.id]?.name
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
    [state.model.steps, stepByName],
  )

  const actions = useMemo(
    () => ({
      addChild(owner: Owner, path: ExprPath, name: string, gate: 'and' | 'or' = 'and') {
        commit((m) => setExpr(m, owner, addRef(getExpr(m, owner), path, name, gate)))
      },
      removeNode(owner: Owner, path: ExprPath) {
        commit((m) => setExpr(m, owner, removeAt(getExpr(m, owner), path)))
      },
      setGate(owner: Owner, path: ExprPath, kind: 'and' | 'or') {
        commit((m) => setExpr(m, owner, setGate(getExpr(m, owner), path, kind)))
      },
      wrap(owner: Owner, path: ExprPath, kind: 'and' | 'or') {
        commit((m) => setExpr(m, owner, wrapInGate(getExpr(m, owner), path, kind)))
      },
      setExpr(owner: Owner, e: Expr | null) {
        commit((m) => setExpr(m, owner, e))
      },

      updateStep(id: string, patch: Partial<AttackStep>) {
        commit((m) => {
          const old = m.steps[id]
          if (!old) return m
          let steps = { ...m.steps, [id]: { ...old, ...patch } }
          let scenarios = m.scenarios
          if (patch.name && patch.name !== old.name) {
            // Keep references pointing at the renamed step.
            steps = Object.fromEntries(
              Object.entries(steps).map(([k, s]) => [k, { ...s, refinedBy: renameRef(s.refinedBy, old.name, patch.name!) }]),
            )
            scenarios = scenarios.map((s) => ({ ...s, attackPaths: renameRef(s.attackPaths, old.name, patch.name!) }))
          }
          let chunks = m.chunks
          if (patch.chunkId && patch.chunkId !== old.chunkId) {
            chunks = chunks.map((c) =>
              c.id === old.chunkId
                ? { ...c, stepIds: c.stepIds.filter((x) => x !== id) }
                : c.id === patch.chunkId
                  ? { ...c, stepIds: [...c.stepIds, id] }
                  : c,
            )
          }
          return { ...m, steps, scenarios, chunks }
        })
      },
      addStep(chunkId: string, init?: Partial<AttackStep>): AttackStep {
        const id = newMpsId()
        const step: AttackStep = {
          id,
          name: nextName(Object.values(state.model.steps).map((s) => s.name), 'ASC.'),
          title: 'New attack step',
          description: '',
          chunkId,
          ratings: { Knowledge: { value: 0 }, Opportunity: { value: 0 }, Expertise: { value: 0 }, Equipment: { value: 0 }, Time: { value: 0 } },
          refinedBy: null,
          ...init,
        }
        commit((m) => ({
          ...m,
          steps: { ...m.steps, [id]: step },
          chunks: m.chunks.map((c) => (c.id === chunkId ? { ...c, stepIds: [...c.stepIds, id] } : c)),
        }))
        return step
      },
      deleteStep(id: string) {
        commit((m) => {
          const step = m.steps[id]
          if (!step) return m
          const { [id]: _removed, ...rest } = m.steps
          void _removed
          const steps = Object.fromEntries(
            Object.entries(rest).map(([k, s]) => [k, { ...s, refinedBy: removeRefsTo(s.refinedBy, step.name) }]),
          )
          return {
            ...m,
            steps,
            chunks: m.chunks.map((c) => ({ ...c, stepIds: c.stepIds.filter((x) => x !== id) })),
            scenarios: m.scenarios.map((s) => ({ ...s, attackPaths: removeRefsTo(s.attackPaths, step.name) })),
          }
        })
      },
      addChunk(name: string): Chunk {
        const chunk: Chunk = { id: newMpsId(), name, stepIds: [] }
        commit((m) => ({ ...m, chunks: [...m.chunks, chunk] }))
        return chunk
      },
      renameChunk(id: string, name: string) {
        commit((m) => ({ ...m, chunks: m.chunks.map((c) => (c.id === id ? { ...c, name } : c)) }))
      },

      addScenario(): ThreatScenario {
        const sc: ThreatScenario = {
          id: newMpsId(),
          name: nextName(state.model.scenarios.map((s) => s.name), 'TS.'),
          title: 'New threat scenario',
          description: '',
          attackPaths: null,
        }
        commit((m) => ({ ...m, scenarios: [...m.scenarios, sc] }))
        return sc
      },
      updateScenario(id: string, patch: Partial<ThreatScenario>) {
        commit((m) => ({ ...m, scenarios: m.scenarios.map((s) => (s.id === id ? { ...s, ...patch } : s)) }))
      },
      deleteScenario(id: string) {
        commit((m) => ({ ...m, scenarios: m.scenarios.filter((s) => s.id !== id) }))
      },
    }),
    [commit, state.model.steps, state.model.scenarios],
  )

  return {
    ...state,
    engine,
    stepByName,
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
