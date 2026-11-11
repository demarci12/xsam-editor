import { useMemo, useState } from 'react'
import { reviewState, useFilter, EditedMark, ToeeChip } from '../components/common'
import { ImpactBadge, LevelBadge, ReviewChip, RiskBadge } from '../components/Level'
import { useDocCtx, useUI } from '../context'
import { computeRisks, type RiskRow } from '../tara/risk'
import { impactIndex, impactLevelOf } from '../xsam/impact'
import { CATEGORIES, CATEGORY_PREFIX, IMPACT_CATEGORIES, IMPACT_LEVELS, type Component } from '../xsam/types'

const natural = (a: string, b: string) => a.localeCompare(b, undefined, { numeric: true })

function Toolbar({ title, count, box, onAdd, addLabel, children }: { title: string; count: number; box: React.ReactNode; onAdd?: () => void; addLabel?: string; children?: React.ReactNode }) {
  return (
    <div className="toolbar">
      <h2>
        {title} <span className="muted">{count}</span>
      </h2>
      {box}
      {children}
      <span className="grow" />
      {onAdd ? (
        <button className="primary" onClick={onAdd}>
          + {addLabel}
        </button>
      ) : null}
    </div>
  )
}

function Rv({ kind, id }: { kind: Parameters<typeof reviewState>[1]; id: string }) {
  const doc = useDocCtx()
  const r = reviewState(doc, kind, id)
  const open = (r.record?.comments ?? []).filter((c) => !c.resolved).length
  return (
    <span className="rv">
      <ReviewChip status={r.record?.status} stale={r.stale} />
      {open ? <span className="ccount" title="Open comments">💬{open}</span> : null}
    </span>
  )
}

// ---------------------------------------------------------------------------

export function DamageView() {
  const doc = useDocCtx()
  const { selection, select } = useUI()
  const rows = useMemo(() => Object.values(doc.model.damageScenarios).sort((a, b) => natural(a.name, b.name)), [doc.model.damageScenarios])
  const tsCount = useMemo(() => {
    const m = new Map<string, number>()
    for (const t of Object.values(doc.model.threatScenarios)) for (const id of t.damageScenarioIds) m.set(id, (m.get(id) ?? 0) + 1)
    return m
  }, [doc.model.threatScenarios])
  const { filtered, box } = useFilter(rows, (d) => `${d.name} ${d.title} ${d.description}`)
  return (
    <div className="view">
      <Toolbar title="Damage scenarios" count={rows.length} box={box} addLabel="Damage scenario" onAdd={() => select({ kind: 'damage', id: doc.actions.add('damage', { scale: rows.find((r) => r.scale)?.scale ?? null }).id })} />
      <table className="grid">
        <thead>
          <tr>
            <th>ID</th>
            <th>Damage scenario</th>
            {IMPACT_CATEGORIES.map((c) => (
              <th key={c} className="c" title={c}>
                {c}
              </th>
            ))}
            <th>Impact</th>
            <th className="c">Assets</th>
            <th className="c">TS</th>
            <th>Review</th>
          </tr>
        </thead>
        <tbody>
          {filtered.map((d) => (
            <tr key={d.id} className={selection?.kind === 'damage' && 'id' in selection && selection.id === d.id ? 'sel' : ''} onClick={() => select({ kind: 'damage', id: d.id })}>
              <td>
                <code>{d.name}</code> <EditedMark kind="damage" id={d.id} />
              </td>
              <td className="wide">{d.title}</td>
              {IMPACT_CATEGORIES.map((c) => {
                const i = impactIndex(d.impacts[c]?.option)
                return (
                  <td key={c} className="c">
                    {i !== null ? <span className={`dot imp-${IMPACT_LEVELS[i].toLowerCase()}`} title={`${d.impacts[c]?.option}${d.impacts[c]?.rationale ? `: ${d.impacts[c]?.rationale}` : ''}`}>{i}</span> : <span className="muted">·</span>}
                  </td>
                )
              })}
              <td>
                <ImpactBadge level={impactLevelOf(d)} />
              </td>
              <td className="c">{d.assets.length}</td>
              <td className="c">{tsCount.get(d.id) ?? 0}</td>
              <td>
                <Rv kind="damage" id={d.id} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ---------------------------------------------------------------------------

export function ThreatView() {
  const doc = useDocCtx()
  const { selection, select } = useUI()
  const risks = useMemo(() => computeRisks(doc.model, doc.extras, doc.engine).sort((a, b) => natural(a.ts.name, b.ts.name)), [doc.model, doc.extras, doc.engine])
  const { filtered, box } = useFilter(risks, (r) => `${r.ts.name} ${r.ts.title} ${r.ts.description}`)
  return (
    <div className="view">
      <Toolbar title="Threat scenarios" count={risks.length} box={box} addLabel="Threat scenario" onAdd={() => select({ kind: 'threat', id: doc.actions.add('threat').id })} />
      <table className="grid">
        <thead>
          <tr>
            <th>ID</th>
            <th>Threat scenario</th>
            <th>Asset</th>
            <th>Attack tree</th>
            <th className="c">DS</th>
            <th>Feasibility</th>
            <th>Impact</th>
            <th>Risk</th>
            <th>Review</th>
          </tr>
        </thead>
        <tbody>
          {filtered.map((r) => (
            <tr key={r.ts.id} className={selection?.kind === 'threat' && 'id' in selection && selection.id === r.ts.id ? 'sel' : ''} onClick={() => select({ kind: 'threat', id: r.ts.id })}>
              <td>
                <code>{r.ts.name}</code> <EditedMark kind="threat" id={r.ts.id} />
              </td>
              <td className="wide">{r.ts.title}</td>
              <td>
                {r.ts.actedOn.slice(0, 2).map((a, i) => (
                  <ToeeChip key={i} r={a} />
                ))}
              </td>
              <td>{r.ts.threatenedBy ? <code className="muted">{r.ts.threatenedBy.kind === 'ref' ? r.ts.threatenedBy.name : r.ts.threatenedBy.kind}</code> : <span className="warn small">none</span>}</td>
              <td className="c">{r.ts.damageScenarioIds.length}</td>
              <td>
                <LevelBadge level={r.feasibility} title={r.feasibilitySource === 'explicit' ? 'Set explicitly in MPS' : undefined} />
                {r.staleRoot ? <span className="warn small" title={`Stored in file as ${r.staleRoot.stored}`}> ⚠</span> : null}
              </td>
              <td>
                <ImpactBadge level={r.impact} />
              </td>
              <td>
                <RiskBadge value={r.risk} />
              </td>
              <td>
                <Rv kind="threat" id={r.ts.id} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ---------------------------------------------------------------------------

export function StepsView() {
  const doc = useDocCtx()
  const { selection, select } = useUI()
  const rows = useMemo(() => Object.values(doc.model.steps).sort((a, b) => natural(a.name, b.name)), [doc.model.steps])
  const [onlyLeaves, setOnlyLeaves] = useState(false)
  const { filtered, box } = useFilter(onlyLeaves ? rows.filter((s) => !s.refinedBy) : rows, (s) => `${s.name} ${s.title} ${s.description}`)
  return (
    <div className="view">
      <Toolbar title="Attack steps" count={rows.length} box={box} addLabel="Attack step" onAdd={() => select({ kind: 'step', id: doc.actions.add('step').id })}>
        <label className="small">
          <input type="checkbox" checked={onlyLeaves} onChange={(e) => setOnlyLeaves(e.target.checked)} /> rated leaves only
        </label>
      </Toolbar>
      <table className="grid">
        <thead>
          <tr>
            <th>ID</th>
            <th>Attack step</th>
            {CATEGORIES.map((c) => (
              <th key={c} className="c" title={c}>
                {CATEGORY_PREFIX[c]}
              </th>
            ))}
            <th>Refined by</th>
            <th>Feasibility</th>
            <th>Review</th>
          </tr>
        </thead>
        <tbody>
          {filtered.map((s) => {
            const ev = doc.engine.evaluate(s.name)
            return (
              <tr key={s.id} className={selection?.kind === 'step' && 'id' in selection && selection.id === s.id ? 'sel' : ''} onClick={() => select({ kind: 'step', id: s.id })}>
                <td>
                  <code>{s.name}</code> <EditedMark kind="step" id={s.id} />
                </td>
                <td className="wide">{s.title}</td>
                {CATEGORIES.map((c) => (
                  <td key={c} className="c num" title={s.ratings[c]?.rationale}>
                    {s.ratings[c]?.value ?? <span className="muted">·</span>}
                  </td>
                ))}
                <td className="expr-cell">{s.refinedBy ? <code className="muted">{s.refinedBy.kind === 'ref' ? s.refinedBy.name : `${s.refinedBy.kind}(${s.refinedBy.children.length})`}</code> : null}</td>
                <td>
                  <LevelBadge level={ev.level} total={ev.total} />
                </td>
                <td>
                  <Rv kind="step" id={s.id} />
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

// ---------------------------------------------------------------------------

export function ItemView() {
  const doc = useDocCtx()
  const { selection, select } = useUI()
  const comps = Object.values(doc.model.components)
  const roots = comps.filter((c) => !c.parentId)
  const isSel = (k: string, id: string) => !!selection && selection.kind === k && 'id' in selection && selection.id === id
  const tree = (c: Component, depth: number): React.ReactNode => (
    <div key={c.id}>
      <div className={`tree-row ${isSel('component', c.id) ? 'sel' : ''}`} style={{ paddingLeft: 8 + depth * 16 }} onClick={() => select({ kind: 'component', id: c.id })}>
        <code>{c.name}</code> <span className="t">{c.title}</span>
        {c.storedData.length ? <span className="muted small">{c.storedData.length} data</span> : null}
        <EditedMark kind="component" id={c.id} />
        <Rv kind="component" id={c.id} />
      </div>
      {comps.filter((x) => x.parentId === c.id).sort((a, b) => natural(a.name, b.name)).map((x) => tree(x, depth + 1))}
    </div>
  )
  return (
    <div className="view item-view">
      <div className="col">
        <Toolbar title="Components" count={comps.length} box={null} addLabel="Component" onAdd={() => select({ kind: 'component', id: doc.actions.add('component').id })} />
        <div className="tree">{roots.map((r) => tree(r, 0))}</div>
      </div>
      <div className="col">
        <Toolbar title="Data" count={Object.keys(doc.model.data).length} box={null} addLabel="Data" onAdd={() => select({ kind: 'data', id: doc.actions.add('data').id })} />
        <table className="grid">
          <tbody>
            {Object.values(doc.model.data)
              .sort((a, b) => natural(a.name, b.name))
              .map((d) => (
                <tr key={d.id} className={isSel('data', d.id) ? 'sel' : ''} onClick={() => select({ kind: 'data', id: d.id })}>
                  <td>
                    <code>{d.name}</code> <EditedMark kind="data" id={d.id} />
                  </td>
                  <td className="wide">{d.title}</td>
                  <td>
                    <Rv kind="data" id={d.id} />
                  </td>
                </tr>
              ))}
          </tbody>
        </table>
        <Toolbar title="Channels" count={Object.keys(doc.model.channels).length} box={null} addLabel="Channel" onAdd={() => select({ kind: 'channel', id: doc.actions.add('channel').id })} />
        <table className="grid">
          <tbody>
            {Object.values(doc.model.channels)
              .sort((a, b) => natural(a.name, b.name))
              .map((c) => (
                <tr key={c.id} className={isSel('channel', c.id) ? 'sel' : ''} onClick={() => select({ kind: 'channel', id: c.id })}>
                  <td>
                    <code>{c.name}</code> <EditedMark kind="channel" id={c.id} />
                  </td>
                  <td className="wide">{c.title}</td>
                  <td className="small muted">{c.endpoints.map((e) => doc.model.components[e]?.name ?? '?').join(' ↔ ')}</td>
                  <td>
                    <Rv kind="channel" id={c.id} />
                  </td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------

export function RiskMatrix({ rows, residual, onCell }: { rows: RiskRow[]; residual?: boolean; onCell?: (impact: string, feas: string) => void }) {
  const doc = useDocCtx()
  const m = doc.extras.settings.riskMatrix
  const feas = ['Very low', 'Low', 'Medium', 'High'] as const
  const imps = ['Sev', 'Ser', 'Mod', 'Neg'] as const
  const count = (i: string, f: string) => rows.filter((r) => r.impact === i && (residual ? r.residualFeasibility : r.feasibility) === f).length
  return (
    <table className="matrix">
      <thead>
        <tr>
          <th className="corner">Impact ↓ / Feasibility →</th>
          {feas.map((f) => (
            <th key={f}>{f}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {imps.map((i) => (
          <tr key={i}>
            <th>
              <ImpactBadge level={i} />
            </th>
            {feas.map((f) => {
              const n = count(i, f)
              return (
                <td key={f} className={`risk-${m[i][f]} ${n ? 'has' : ''}`} onClick={() => onCell?.(i, f)} title={`Risk ${m[i][f]}: ${n} threat scenario(s)`}>
                  <span className="rv-val">R{m[i][f]}</span>
                  {n ? <b>{n}</b> : null}
                </td>
              )
            })}
          </tr>
        ))}
      </tbody>
    </table>
  )
}

export function RisksView() {
  const doc = useDocCtx()
  const { selection, select } = useUI()
  const risks = useMemo(() => computeRisks(doc.model, doc.extras, doc.engine), [doc.model, doc.extras, doc.engine])
  const [cell, setCell] = useState<{ i: string; f: string } | null>(null)
  const sorted = useMemo(() => [...risks].sort((a, b) => (b.risk ?? 0) - (a.risk ?? 0) || natural(a.ts.name, b.ts.name)), [risks])
  const inCell = cell ? sorted.filter((r) => r.impact === cell.i && r.feasibility === cell.f) : sorted
  const { filtered, box } = useFilter(inCell, (r) => `${r.ts.name} ${r.ts.title}`)
  const th = doc.extras.settings.acceptThreshold
  return (
    <div className="view">
      <div className="risk-top">
        <div>
          <h3>Risk matrix</h3>
          <RiskMatrix rows={risks} onCell={(i, f) => setCell(cell && cell.i === i && cell.f === f ? null : { i, f })} />
        </div>
        <div>
          <h3>Residual (with controls)</h3>
          <RiskMatrix rows={risks} residual />
        </div>
      </div>
      <Toolbar title="Risk assessment & treatment" count={filtered.length} box={box}>
        {cell ? (
          <button className="mini" onClick={() => setCell(null)}>
            Clear cell filter ({cell.i} × {cell.f})
          </button>
        ) : null}
      </Toolbar>
      <table className="grid">
        <thead>
          <tr>
            <th>TS</th>
            <th>Threat scenario</th>
            <th>Impact</th>
            <th>Feasibility</th>
            <th>Risk</th>
            <th>Treatment</th>
            <th>Goals / claims</th>
            <th>Residual</th>
            <th>Review</th>
          </tr>
        </thead>
        <tbody>
          {filtered.map((r) => {
            const t = doc.extras.treatments[r.ts.id]
            const missing = (r.risk ?? 0) >= th && !t?.decision
            return (
              <tr key={r.ts.id} className={selection?.kind === 'risk' && 'id' in selection && selection.id === r.ts.id ? 'sel' : ''} onClick={() => select({ kind: 'risk', id: r.ts.id })}>
                <td>
                  <code>{r.ts.name}</code>
                </td>
                <td className="wide">{r.ts.title}</td>
                <td>
                  <ImpactBadge level={r.impact} />
                </td>
                <td>
                  <LevelBadge level={r.feasibility} />
                </td>
                <td>
                  <RiskBadge value={r.risk} />
                </td>
                <td>{t?.decision ? <span className="tag">{t.decision}</span> : missing ? <span className="warn small">needed</span> : <span className="muted">–</span>}</td>
                <td className="small">
                  {(t?.goalIds ?? []).map((g) => doc.extras.goals[g]?.name).filter(Boolean).join(', ')}
                  {(t?.claimIds ?? []).length ? ` ${(t?.claimIds ?? []).map((g) => doc.extras.claims[g]?.name).join(', ')}` : ''}
                </td>
                <td>
                  <RiskBadge value={r.residualRisk} />
                </td>
                <td>
                  <Rv kind="risk" id={r.ts.id} />
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

// ---------------------------------------------------------------------------

export function ConceptView() {
  const doc = useDocCtx()
  const { selection, select } = useUI()
  const goals = Object.values(doc.extras.goals).sort((a, b) => natural(a.name, b.name))
  const claims = Object.values(doc.extras.claims).sort((a, b) => natural(a.name, b.name))
  const used = (gid: string) => Object.values(doc.extras.treatments).filter((t) => t.goalIds.includes(gid)).length
  const isSel = (k: string, id: string) => !!selection && selection.kind === k && 'id' in selection && selection.id === id
  return (
    <div className="view">
      <Toolbar title="Cybersecurity goals" count={goals.length} box={null} addLabel="Goal" onAdd={() => select({ kind: 'goal', id: doc.actions.addGoal().id })} />
      {goals.length === 0 ? <p className="muted empty-note">No goals yet. Create them here or from a risk with treatment “Reduce”.</p> : null}
      <table className="grid">
        <tbody>
          {goals.map((g) => (
            <tr key={g.id} className={isSel('goal', g.id) ? 'sel' : ''} onClick={() => select({ kind: 'goal', id: g.id })}>
              <td>
                <code>{g.name}</code>
              </td>
              <td className="wide">{g.title}</td>
              <td>{g.cal ? <span className="tag">CAL {g.cal}</span> : null}</td>
              <td className="small muted">{used(g.id)} TS</td>
              <td>
                <Rv kind="goal" id={g.id} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <Toolbar title="Cybersecurity claims" count={claims.length} box={null} addLabel="Claim" onAdd={() => select({ kind: 'claim', id: doc.actions.addClaim().id })} />
      <table className="grid">
        <tbody>
          {claims.map((c) => (
            <tr key={c.id} className={isSel('claim', c.id) ? 'sel' : ''} onClick={() => select({ kind: 'claim', id: c.id })}>
              <td>
                <code>{c.name}</code>
              </td>
              <td className="wide">{c.title}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function ControlsView() {
  const doc = useDocCtx()
  const { selection, select } = useUI()
  const controls = Object.values(doc.extras.controls).sort((a, b) => natural(a.name, b.name))
  return (
    <div className="view">
      <Toolbar title="Controls" count={controls.length} box={null} addLabel="Control" onAdd={() => select({ kind: 'control', id: doc.actions.addControl().id })} />
      {controls.length === 0 ? (
        <p className="muted empty-note">
          A control raises the attack potential of the attack steps it mitigates (e.g. secure boot: Expertise ≥ 6, Equipment ≥ 7). Residual risk is recomputed from that.
        </p>
      ) : null}
      <table className="grid">
        <thead>
          <tr>
            <th>ID</th>
            <th>Control</th>
            <th>Effect</th>
            <th className="c">Steps</th>
            <th>Status</th>
            <th>Review</th>
          </tr>
        </thead>
        <tbody>
          {controls.map((c) => (
            <tr key={c.id} className={selection?.kind === 'control' && 'id' in selection && selection.id === c.id ? 'sel' : ''} onClick={() => select({ kind: 'control', id: c.id })}>
              <td>
                <code>{c.name}</code>
              </td>
              <td className="wide">{c.title}</td>
              <td className="small">
                {CATEGORIES.filter((k) => c.floors[k] !== undefined)
                  .map((k) => `${CATEGORY_PREFIX[k]}≥${c.floors[k]}`)
                  .join(' ')}
              </td>
              <td className="c">{c.stepNames.length}</td>
              <td>
                <span className="tag">{c.status}</span>
              </td>
              <td>
                <Rv kind="control" id={c.id} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function R155View() {
  const doc = useDocCtx()
  const cl = doc.model.checklist
  if (!cl) return <div className="view"><p className="muted empty-note">This model has no UN R155 checklist.</p></div>
  const items = cl.groups.flatMap((g) => g.items.filter((i) => i.kind === 'item'))
  const answered = items.filter((i) => i.relevant || i.notRelevant).length
  return (
    <div className="view">
      <div className="toolbar">
        <h2>
          {cl.name} <span className="muted">{answered}/{items.length} answered</span>
        </h2>
      </div>
      {cl.groups.map((g) => (
        <div key={g.id} className="r155-group">
          <h3>{g.name}</h3>
          {g.items.map((it) =>
            it.kind === 'head' ? (
              <h4 key={it.id} className="r155-head">
                {it.name}
              </h4>
            ) : (
              <div key={it.id} className="r155-item">
                <span className="t">{it.name}</span>
                <div className="seg">
                  <button className={it.relevant ? 'on' : ''} onClick={() => doc.actions.updateChecklist(it.id, { relevant: !it.relevant, notRelevant: false })}>
                    Relevant
                  </button>
                  <button className={it.notRelevant ? 'on' : ''} onClick={() => doc.actions.updateChecklist(it.id, { notRelevant: !it.notRelevant, relevant: false })}>
                    Not relevant
                  </button>
                </div>
                <input placeholder="Rationale" value={it.rationale} onChange={(e) => doc.actions.updateChecklist(it.id, { rationale: e.target.value })} />
              </div>
            ),
          )}
        </div>
      ))}
    </div>
  )
}
