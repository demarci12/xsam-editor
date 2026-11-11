import { useMemo, useState } from 'react'
import { DND_STEP, useDocCtx, useUI } from '../context'
import { LevelBadge } from './Level'

export function Catalog() {
  const doc = useDocCtx()
  const { root, setRoot, select } = useUI()
  const [q, setQ] = useState('')
  const [open, setOpen] = useState<Record<string, boolean>>({})
  const query = q.trim().toLowerCase()

  const evals = useMemo(() => {
    const m = new Map<string, ReturnType<typeof doc.engine.evaluate>>()
    for (const s of Object.values(doc.model.steps)) m.set(s.id, doc.engine.evaluate(s.name))
    return m
  }, [doc.engine, doc.model.steps])

  const matches = (...xs: string[]) => !query || xs.some((x) => x.toLowerCase().includes(query))

  const openStep = (id: string) => {
    setRoot({ kind: 'step', id })
    select({ kind: 'step', id })
  }

  return (
    <aside className="catalog">
      <input className="search" placeholder="Search steps & scenarios…" value={q} onChange={(e) => setQ(e.target.value)} />

      <section>
        <header>
          <h3>Threat scenarios</h3>
          <button
            className="mini"
            onClick={() => {
              const sc = doc.actions.addScenario()
              setRoot({ kind: 'scenario', id: sc.id })
              select({ kind: 'scenario', id: sc.id })
            }}
          >
            + New
          </button>
        </header>
        {doc.model.scenarios.length === 0 ? <p className="muted small">None yet. A threat scenario is the attacker goal at the top of an attack tree.</p> : null}
        <ul>
          {doc.model.scenarios
            .filter((s) => matches(s.name, s.title))
            .map((s) => {
              const ev = doc.engine.evaluateExpr(s.attackPaths)
              const active = root?.kind === 'scenario' && root.id === s.id
              return (
                <li
                  key={s.id}
                  className={active ? 'active' : ''}
                  onClick={() => {
                    setRoot({ kind: 'scenario', id: s.id })
                    select({ kind: 'scenario', id: s.id })
                  }}
                >
                  <code>{s.name}</code>
                  <span className="t">{s.title}</span>
                  <LevelBadge level={ev.level} />
                </li>
              )
            })}
        </ul>
      </section>

      <section>
        <header>
          <h3>Attack steps</h3>
          <button
            className="mini"
            onClick={() => {
              const name = prompt('Chunk name', `${String(doc.model.chunks.length * 10).padStart(2, '0')}-New group`)
              if (name) doc.actions.addChunk(name)
            }}
            title="Add a group (SecurityChunk)"
          >
            + Group
          </button>
        </header>
        {doc.model.chunks.length === 0 ? <p className="muted small">Open an .xsam file or load the sample catalog.</p> : null}
        {doc.model.chunks.map((c) => {
          const steps = c.stepIds.map((id) => doc.model.steps[id]).filter((s) => s && matches(s.name, s.title, s.description))
          if (query && !steps.length) return null
          const isOpen = query ? true : (open[c.id] ?? false)
          return (
            <div key={c.id} className="chunk">
              <div className="chunk-head" onClick={() => setOpen((o) => ({ ...o, [c.id]: !isOpen }))}>
                <span>{isOpen ? '▾' : '▸'}</span>
                <span className="t">{c.name}</span>
                <span className="muted small">{c.stepIds.length}</span>
                <button
                  className="mini"
                  title="Add attack step to this group"
                  onClick={(e) => {
                    e.stopPropagation()
                    const st = doc.actions.addStep(c.id)
                    setOpen((o) => ({ ...o, [c.id]: true }))
                    openStep(st.id)
                  }}
                >
                  +
                </button>
              </div>
              {isOpen ? (
                <ul>
                  {steps.map((s) => {
                    const ev = evals.get(s.id)
                    const active = root?.kind === 'step' && root.id === s.id
                    return (
                      <li
                        key={s.id}
                        className={active ? 'active' : ''}
                        draggable
                        onDragStart={(e) => {
                          e.dataTransfer.setData(DND_STEP, s.name)
                          e.dataTransfer.effectAllowed = 'copy'
                        }}
                        onClick={() => openStep(s.id)}
                        title={`${s.description}\n\nDrag onto a node in the canvas to add it to that attack path.`}
                      >
                        <code>{s.name}</code>
                        <span className="t">{s.title}</span>
                        {s.refinedBy ? <span className="tag">{s.refinedBy.kind === 'ref' ? '→' : s.refinedBy.kind.toUpperCase()}</span> : null}
                        <LevelBadge level={ev?.level} />
                      </li>
                    )
                  })}
                </ul>
              ) : null}
            </div>
          )
        })}
      </section>
    </aside>
  )
}
