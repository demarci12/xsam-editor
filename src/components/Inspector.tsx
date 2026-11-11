import { useMemo, useState } from 'react'
import { useDocCtx, useUI } from '../context'
import type { Owner } from '../store'
import { getAt, refsOf, type ExprPath } from '../xsam/expr'
import { CATEGORIES, CATEGORY_LABEL, CATEGORY_PREFIX, type AttackStep, type Expr, type ThreatScenario } from '../xsam/types'
import { LevelBadge, VectorChips } from './Level'

/** Typical ISO/SAE 21434 Annex G values per factor; any integer is accepted. */
const PRESETS: Record<string, [number, string][]> = {
  Time: [[0, '≤ 1 day'], [1, '≤ 1 week'], [4, '≤ 1 month'], [10, '≤ 6 months'], [19, '> 6 months']],
  Expertise: [[0, 'Layman'], [3, 'Proficient'], [6, 'Expert'], [8, 'Multiple experts']],
  Knowledge: [[0, 'Public'], [3, 'Restricted'], [7, 'Confidential'], [11, 'Strictly confidential']],
  Opportunity: [[0, 'Unlimited'], [1, 'Easy'], [4, 'Moderate'], [10, 'Difficult']],
  Equipment: [[0, 'Standard'], [4, 'Specialized'], [7, 'Bespoke'], [9, 'Multiple bespoke']],
}

export function Inspector() {
  const { selection } = useUI()
  const doc = useDocCtx()
  if (!selection) return <aside className="inspector"><Help /></aside>
  if (selection.kind === 'step') {
    const st = doc.model.steps[selection.id]
    return <aside className="inspector">{st ? <StepPanel step={st} /> : <Help />}</aside>
  }
  if (selection.kind === 'scenario') {
    const sc = doc.model.scenarios.find((s) => s.id === selection.id)
    return <aside className="inspector">{sc ? <ScenarioPanel sc={sc} /> : <Help />}</aside>
  }
  return <aside className="inspector"><GatePanel owner={selection.owner} path={selection.path} /></aside>
}

function Help() {
  return (
    <div className="help">
      <h3>XSAM attack path editor</h3>
      <ol>
        <li>Create a <b>threat scenario</b> (left, Threat scenarios → + New).</li>
        <li>Drag <b>attack steps</b> from the catalog onto its node, or use “Add step” here.</li>
        <li>Group them with <b>AND</b> (all needed) or <b>OR</b> (any one is enough) gates.</li>
        <li><b>Rate</b> leaf steps with the five attack-potential factors; the feasibility of every refined step and scenario is computed.</li>
        <li>The highlighted path is the cheapest attack. It decides the scenario's feasibility.</li>
        <li>Export back to <code>.xsam</code> at the top right.</li>
      </ol>
    </div>
  )
}

function Field({ label, value, onChange, multiline }: { label: string; value: string; onChange: (v: string) => void; multiline?: boolean }) {
  return (
    <label className="field">
      <span>{label}</span>
      {multiline ? (
        <textarea value={value} rows={4} onChange={(e) => onChange(e.target.value)} />
      ) : (
        <input value={value} onChange={(e) => onChange(e.target.value)} />
      )}
    </label>
  )
}

function StepPanel({ step }: { step: AttackStep }) {
  const doc = useDocCtx()
  const { setRoot, select, root } = useUI()
  const ev = doc.engine.evaluate(step.name)
  const owner: Owner = { kind: 'step', id: step.id }
  const usedBy = useMemo(
    () => [
      ...doc.model.scenarios.filter((s) => refsOf(s.attackPaths).includes(step.name)).map((s) => ({ kind: 'scenario' as const, id: s.id, name: s.name, title: s.title })),
      ...Object.values(doc.model.steps)
        .filter((s) => refsOf(s.refinedBy).includes(step.name))
        .map((s) => ({ kind: 'step' as const, id: s.id, name: s.name, title: s.title })),
    ],
    [doc.model, step.name],
  )
  const [nameDraft, setNameDraft] = useState(step.name)
  const [lastId, setLastId] = useState(step.id)
  if (lastId !== step.id) {
    setLastId(step.id)
    setNameDraft(step.name)
  }

  return (
    <div className="panel">
      <div className="panel-head">
        <span className="kind">Attack step</span>
        <LevelBadge level={ev.level} total={ev.total} />
      </div>
      <label className="field">
        <span>ID</span>
        <input
          value={nameDraft}
          onChange={(e) => setNameDraft(e.target.value)}
          onBlur={() => {
            const n = nameDraft.trim()
            if (!n || n === step.name) return setNameDraft(step.name)
            if (doc.stepByName.has(n)) {
              alert(`${n} already exists`)
              return setNameDraft(step.name)
            }
            doc.actions.updateStep(step.id, { name: n })
          }}
        />
      </label>
      <Field label="Title" value={step.title} onChange={(v) => doc.actions.updateStep(step.id, { title: v })} />
      <Field label="Description" multiline value={step.description} onChange={(v) => doc.actions.updateStep(step.id, { description: v })} />
      <label className="field">
        <span>Group</span>
        <select value={step.chunkId} onChange={(e) => doc.actions.updateStep(step.id, { chunkId: e.target.value })}>
          {doc.model.chunks.map((c) => (
            <option key={c.id} value={c.id}>{c.name}</option>
          ))}
        </select>
      </label>

      <h4>Rating {step.refinedBy ? <span className="muted small">(refined steps are usually rated through their children)</span> : null}</h4>
      <div className="ratings">
        {CATEGORIES.map((c) => {
          const r = step.ratings[c]
          return (
            <div key={c} className="rating">
              <label title={CATEGORY_LABEL[c]}>
                <span className="cat">{CATEGORY_PREFIX[c]}</span>
                <span className="catname">{CATEGORY_LABEL[c]}</span>
              </label>
              <input
                type="number"
                min={0}
                value={r?.value ?? ''}
                placeholder="–"
                onChange={(e) => {
                  const ratings = { ...step.ratings }
                  if (e.target.value === '') delete ratings[c]
                  else ratings[c] = { ...r, value: Math.max(0, Math.round(Number(e.target.value))) }
                  doc.actions.updateStep(step.id, { ratings })
                }}
              />
              <select
                value=""
                onChange={(e) => {
                  if (e.target.value === '') return
                  doc.actions.updateStep(step.id, { ratings: { ...step.ratings, [c]: { ...r, value: Number(e.target.value) } } })
                }}
                title="ISO/SAE 21434 preset"
              >
                <option value="">preset</option>
                {PRESETS[c].map(([v, l]) => (
                  <option key={v} value={v}>{v} · {l}</option>
                ))}
              </select>
              <input
                className="rationale"
                placeholder="Rationale"
                value={r?.rationale ?? ''}
                disabled={!r}
                onChange={(e) =>
                  doc.actions.updateStep(step.id, { ratings: { ...step.ratings, [c]: { value: r!.value, rationale: e.target.value || undefined } } })
                }
              />
            </div>
          )
        })}
      </div>
      <div className="computed">
        <span className="muted">Computed:</span> <VectorChips vector={ev.vector} /> <LevelBadge level={ev.level} total={ev.total} />
        {step.storedLevel && step.storedLevel !== ev.level ? <span className="warn">imported as {step.storedLevel}</span> : null}
      </div>
      {ev.unresolved.length ? <p className="warn">Not in this catalog: {ev.unresolved.join(', ')}</p> : null}

      <h4>Refined by</h4>
      <ExprEditor owner={owner} expr={step.refinedBy} selfName={step.name} />

      {usedBy.length ? (
        <>
          <h4>Used by</h4>
          <ul className="links">
            {usedBy.map((u) => (
              <li key={u.kind + u.id}>
                <a
                  onClick={() => {
                    setRoot(u)
                    select(u)
                  }}
                >
                  <code>{u.name}</code> {u.title}
                </a>
              </li>
            ))}
          </ul>
        </>
      ) : null}

      <div className="actions">
        {!(root?.kind === 'step' && root.id === step.id) ? (
          <button onClick={() => setRoot({ kind: 'step', id: step.id })}>Open as tree</button>
        ) : null}
        <button
          className="danger"
          onClick={() => {
            if (!confirm(`Delete ${step.name}? It is removed from ${usedBy.length} place(s) that use it.`)) return
            if (root?.kind === 'step' && root.id === step.id) setRoot(null)
            select(null)
            doc.actions.deleteStep(step.id)
          }}
        >
          Delete step
        </button>
      </div>
    </div>
  )
}

function ScenarioPanel({ sc }: { sc: ThreatScenario }) {
  const doc = useDocCtx()
  const { setRoot, select, root } = useUI()
  const ev = doc.engine.evaluateExpr(sc.attackPaths)
  const paths = useMemo(() => doc.engine.enumeratePaths(sc.attackPaths, 200), [doc.engine, sc.attackPaths])
  const owner: Owner = { kind: 'scenario', id: sc.id }
  return (
    <div className="panel">
      <div className="panel-head">
        <span className="kind">Threat scenario</span>
        <LevelBadge level={ev.level} total={ev.total} />
      </div>
      <Field label="ID" value={sc.name} onChange={(v) => doc.actions.updateScenario(sc.id, { name: v })} />
      <Field label="Title" value={sc.title} onChange={(v) => doc.actions.updateScenario(sc.id, { title: v })} />
      <Field label="Description" multiline value={sc.description} onChange={(v) => doc.actions.updateScenario(sc.id, { description: v })} />

      <h4>Attack tree</h4>
      <ExprEditor owner={owner} expr={sc.attackPaths} />

      <h4>
        Attack paths <span className="muted small">{paths.length}{paths.length >= 200 ? '+' : ''}, easiest first</span>
      </h4>
      {paths.length === 0 ? <p className="muted small">Add attack steps to see the paths.</p> : null}
      <ol className="paths">
        {paths.slice(0, 50).map((p, i) => (
          <li key={i}>
            <div className="path-head">
              <LevelBadge level={p.level} total={p.total} />
              <VectorChips vector={p.vector} />
            </div>
            <div className="path-steps">
              {p.leaves.map((l) => {
                const st = doc.stepByName.get(l)
                return (
                  <a key={l} title={st?.title} onClick={() => st && select({ kind: 'step', id: st.id })} className={st ? '' : 'ext'}>
                    {l}
                  </a>
                )
              })}
            </div>
          </li>
        ))}
      </ol>

      <div className="actions">
        {!(root?.kind === 'scenario' && root.id === sc.id) ? <button onClick={() => setRoot(owner)}>Open as tree</button> : null}
        <button
          className="danger"
          onClick={() => {
            if (!confirm(`Delete threat scenario ${sc.name}? Its attack steps stay in the catalog.`)) return
            if (root?.kind === 'scenario' && root.id === sc.id) setRoot(null)
            select(null)
            doc.actions.deleteScenario(sc.id)
          }}
        >
          Delete scenario
        </button>
      </div>
    </div>
  )
}

function GatePanel({ owner, path }: { owner: Owner; path: ExprPath }) {
  const doc = useDocCtx()
  const { select } = useUI()
  const expr = owner.kind === 'scenario' ? doc.model.scenarios.find((s) => s.id === owner.id)?.attackPaths : doc.model.steps[owner.id]?.refinedBy
  const gate = getAt(expr ?? null, path)
  if (!gate || gate.kind === 'ref') return <Help />
  const ownerLabel = owner.kind === 'scenario' ? doc.model.scenarios.find((s) => s.id === owner.id)?.name : doc.model.steps[owner.id]?.name
  const ev = doc.engine.evaluateExpr(gate)
  return (
    <div className="panel">
      <div className="panel-head">
        <span className="kind">{gate.kind.toUpperCase()} gate</span>
        <LevelBadge level={ev.level} total={ev.total} />
      </div>
      <p className="muted small">
        In <a onClick={() => select(owner)}><code>{ownerLabel}</code></a>.{' '}
        {gate.kind === 'and' ? 'The attacker needs every child: each factor is the highest among them.' : 'The attacker takes the easiest child.'}
      </p>
      <ExprEditor owner={owner} expr={gate} basePath={path} />
    </div>
  )
}

/** Nested AND/OR editor for an expression owned by a scenario or step. */
function ExprEditor({ owner, expr, basePath = [], selfName }: { owner: Owner; expr: Expr | null; basePath?: ExprPath; selfName?: string }) {
  const doc = useDocCtx()
  if (!expr) {
    return (
      <div className="expr empty-expr">
        <span className="muted small">{owner.kind === 'step' ? 'Leaf step (rated directly).' : 'Empty.'}</span>
        <StepPicker owner={owner} path={basePath} exclude={selfName} />
      </div>
    )
  }
  return <ExprNode owner={owner} e={expr} path={basePath} isTop selfName={selfName} doc={doc} />
}

function ExprNode({ owner, e, path, isTop, selfName, doc }: { owner: Owner; e: Expr; path: ExprPath; isTop?: boolean; selfName?: string; doc: ReturnType<typeof useDocCtx> }) {
  const { select } = useUI()
  if (e.kind === 'ref') {
    const st = doc.stepByName.get(e.name)
    const ev = st ? doc.engine.evaluate(e.name) : null
    return (
      <div className="expr-ref">
        <a onClick={() => st && select({ kind: 'step', id: st.id })} className={st ? '' : 'ext'}>
          <code>{e.name}</code> <span className="t">{st?.title ?? 'not in catalog'}</span>
        </a>
        <LevelBadge level={ev?.level} />
        <span className="row-actions">
          <button className="mini" title="Group with a sibling under AND" onClick={() => doc.actions.wrap(owner, path, 'and')}>⊕AND</button>
          <button className="mini" title="Group with a sibling under OR" onClick={() => doc.actions.wrap(owner, path, 'or')}>⊕OR</button>
          <button className="mini danger" title="Remove from this attack path" onClick={() => doc.actions.removeNode(owner, path)}>✕</button>
        </span>
        {isTop ? <StepPicker owner={owner} path={path} exclude={selfName} label="+ step (makes AND)" /> : null}
      </div>
    )
  }
  return (
    <div className={`expr gate-${e.kind}`}>
      <div className="expr-gate">
        <div className="seg">
          <button className={e.kind === 'and' ? 'on' : ''} onClick={() => doc.actions.setGate(owner, path, 'and')}>AND</button>
          <button className={e.kind === 'or' ? 'on' : ''} onClick={() => doc.actions.setGate(owner, path, 'or')}>OR</button>
        </div>
        <span className="muted small">{e.kind === 'and' ? 'all of' : 'any of'}</span>
        <span className="row-actions">
          <button className="mini" title="Add a nested AND gate" onClick={() => doc.actions.setExpr(owner, insertGate(rootExprOf(doc, owner), path, 'and'))}>+AND</button>
          <button className="mini" title="Add a nested OR gate" onClick={() => doc.actions.setExpr(owner, insertGate(rootExprOf(doc, owner), path, 'or'))}>+OR</button>
          <button className="mini danger" title="Remove this gate and everything under it" onClick={() => doc.actions.removeNode(owner, path)}>✕</button>
        </span>
      </div>
      <div className="expr-children">
        {e.children.map((c, i) => (
          <ExprNode key={i} owner={owner} e={c} path={[...path, i]} selfName={selfName} doc={doc} />
        ))}
        {e.children.length === 0 ? <span className="muted small">Empty gate: add steps.</span> : null}
        <StepPicker owner={owner} path={path} exclude={selfName} />
      </div>
    </div>
  )
}

function rootExprOf(doc: ReturnType<typeof useDocCtx>, owner: Owner): Expr | null {
  return owner.kind === 'scenario' ? (doc.model.scenarios.find((s) => s.id === owner.id)?.attackPaths ?? null) : (doc.model.steps[owner.id]?.refinedBy ?? null)
}

/** Insert an empty sub-gate into the gate at `path`. Empty gates are kept until edited. */
function insertGate(root: Expr | null, path: ExprPath, kind: 'and' | 'or'): Expr | null {
  const go = (e: Expr, p: ExprPath): Expr => {
    if (e.kind === 'ref') return e
    if (p.length === 0) return { ...e, children: [...e.children, { kind, children: [] }] }
    const [h, ...rest] = p
    return { ...e, children: e.children.map((c, i) => (i === h ? go(c, rest) : c)) }
  }
  return root ? go(root, path) : null
}

function StepPicker({ owner, path, exclude, label = '+ Add step' }: { owner: Owner; path: ExprPath; exclude?: string; label?: string }) {
  const doc = useDocCtx()
  const [open, setOpen] = useState(false)
  const [q, setQ] = useState('')
  const [err, setErr] = useState<string | null>(null)
  const results = useMemo(() => {
    const s = q.trim().toLowerCase()
    return Object.values(doc.model.steps)
      .filter((st) => st.name !== exclude && (!s || st.name.toLowerCase().includes(s) || st.title.toLowerCase().includes(s)))
      .slice(0, 30)
  }, [doc.model.steps, q, exclude])

  if (!open) return <button className="mini add" onClick={() => setOpen(true)}>{label}</button>
  const pick = (name: string) => {
    if (doc.createsCycle(owner, name)) return setErr(`${name} would create a cycle`)
    doc.actions.addChild(owner, path, name)
    setOpen(false)
    setQ('')
    setErr(null)
  }
  return (
    <div className="picker">
      <input
        autoFocus
        placeholder="Search, or type a new step title + Enter"
        value={q}
        onChange={(e) => setQ(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Escape') setOpen(false)
          if (e.key === 'Enter') {
            if (results[0] && (results[0].name.toLowerCase() === q.trim().toLowerCase() || results.length === 1)) pick(results[0].name)
            else if (q.trim()) {
              const chunkId =
                (owner.kind === 'step' ? doc.model.steps[owner.id]?.chunkId : undefined) ?? doc.model.chunks[0]?.id ?? doc.actions.addChunk('00-Attack steps').id
              const st = doc.actions.addStep(chunkId, { title: q.trim() })
              doc.actions.addChild(owner, path, st.name)
              setOpen(false)
              setQ('')
            }
          }
        }}
      />
      {err ? <div className="warn small">{err}</div> : null}
      <ul>
        {results.map((st) => (
          <li key={st.id} onClick={() => pick(st.name)}>
            <code>{st.name}</code> <span className="t">{st.title}</span>
          </li>
        ))}
        {q.trim() && !results.length ? <li className="muted small">Enter creates new step “{q.trim()}”</li> : null}
      </ul>
      <button className="mini" onClick={() => setOpen(false)}>Cancel</button>
    </div>
  )
}
