import { useMemo, useState } from 'react'
import { DND_STEP, useDocCtx, useUI } from '../context'
import { LevelBadge } from './Level'

/** Left list in the attack tree view: threat scenarios and the attack step catalog. */
export function Catalog() {
  const doc = useDocCtx()
  const { root, setRoot, select } = useUI()
  const [q, setQ] = useState('')
  const [open, setOpen] = useState<Record<string, boolean>>({})
  const query = q.trim().toLowerCase()
  const matches = (...xs: string[]) => !query || xs.some((x) => x.toLowerCase().includes(query))

  const evals = useMemo(() => {
    const m = new Map<string, ReturnType<typeof doc.engine.evaluate>>()
    for (const s of Object.values(doc.model.steps)) m.set(s.id, doc.engine.evaluate(s.name))
    return m
  }, [doc.engine, doc.model.steps])

  const stepChunks = doc.model.chunks.filter((c) => c.elementIds.some((id) => doc.model.steps[id]) || c.name === 'Attack Steps')
  const threats = Object.values(doc.model.threatScenarios).filter((t) => matches(t.name, t.title))

  return (
    <aside className="catalog">
      <input className="search" placeholder="Search…" value={q} onChange={(e) => setQ(e.target.value)} />
      <section>
        <header>
          <h3>Threat scenarios</h3>
          <button
            className="mini"
            onClick={() => {
              const t = doc.actions.add('threat')
              setRoot({ kind: 'threat', id: t.id })
              select({ kind: 'threat', id: t.id })
            }}
          >
            + New
          </button>
        </header>
        <ul>
          {threats.map((t) => {
            const ev = doc.engine.evaluateExpr(t.threatenedBy)
            const active = root?.kind === 'threat' && root.id === t.id
            return (
              <li
                key={t.id}
                className={active ? 'active' : ''}
                onClick={() => {
                  setRoot({ kind: 'threat', id: t.id })
                  select({ kind: 'threat', id: t.id })
                }}
                title={t.title}
              >
                <code>{t.name}</code>
                <span className="t">{t.title}</span>
                <span />
                <LevelBadge level={t.explicitFeasibility ?? ev.level} />
              </li>
            )
          })}
        </ul>
      </section>

      <section>
        <header>
          <h3>Attack steps</h3>
          <span className="muted small">drag onto a node</span>
        </header>
        {stepChunks.map((c) => {
          const steps = c.elementIds.map((id) => doc.model.steps[id]).filter((s) => s && matches(s.name, s.title, s.description))
          if (query && !steps.length) return null
          const isOpen = query ? true : (open[c.id] ?? stepChunks.length === 1)
          return (
            <div key={c.id} className="chunk">
              <div className="chunk-head" onClick={() => setOpen((o) => ({ ...o, [c.id]: !isOpen }))}>
                <span>{isOpen ? '▾' : '▸'}</span>
                <span className="t">{c.name}</span>
                <span className="muted small">{steps.length}</span>
                <button
                  className="mini"
                  title="Add attack step"
                  onClick={(e) => {
                    e.stopPropagation()
                    const st = doc.actions.add('step', { chunkId: c.id })
                    setOpen((o) => ({ ...o, [c.id]: true }))
                    select({ kind: 'step', id: st.id })
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
                        onClick={() => {
                          setRoot({ kind: 'step', id: s.id })
                          select({ kind: 'step', id: s.id })
                        }}
                        title={`${s.title}\n\n${s.description}`}
                      >
                        <code>{s.name}</code>
                        <span className="t">{s.title}</span>
                        {s.refinedBy ? <span className="tag">{s.refinedBy.kind === 'ref' ? '→' : s.refinedBy.kind.toUpperCase()}</span> : <span />}
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
