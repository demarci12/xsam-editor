import { useMemo, useState } from 'react'
import { reviewState, toeeName } from '../components/common'
import { propertySummary } from '../components/SecurityProperties'
import { threatDamageIssues } from '../tara/consistency'
import { ImpactBadge, LevelBadge, ReviewChip, RiskBadge } from '../components/Level'
import { useDocCtx, useUI, type View } from '../context'
import { computeRisks } from '../tara/risk'
import { DEFAULT_RISK_MATRIX, REVIEW_STATUSES, type ReviewKind } from '../tara/types'
import { impactLevelOf } from '../xsam/impact'
import { IMPACT_LABEL, type FeasibilityLevel, type ImpactLevel } from '../xsam/types'
import { RiskMatrix } from './Tables'

const KIND_LABEL: Record<ReviewKind, string> = {
  damage: 'Damage scenarios',
  threat: 'Threat scenarios',
  step: 'Attack steps',
  risk: 'Risks',
  goal: 'Goals',
  control: 'Controls',
  component: 'Components',
  data: 'Data',
  channel: 'Channels',
}
const KIND_VIEW: Record<ReviewKind, View> = { damage: 'damage', threat: 'threat', step: 'steps', risk: 'risks', goal: 'concept', control: 'controls', component: 'item', data: 'item', channel: 'item' }

function useReviewItems() {
  const doc = useDocCtx()
  return useMemo(() => {
    const m = doc.model
    const list: { kind: ReviewKind; id: string; name: string; title: string }[] = [
      ...Object.values(m.damageScenarios).map((x) => ({ kind: 'damage' as const, id: x.id, name: x.name, title: x.title })),
      ...Object.values(m.threatScenarios).map((x) => ({ kind: 'threat' as const, id: x.id, name: x.name, title: x.title })),
      ...Object.values(m.threatScenarios).map((x) => ({ kind: 'risk' as const, id: x.id, name: x.name, title: `Risk: ${x.title}` })),
      ...Object.values(m.steps).map((x) => ({ kind: 'step' as const, id: x.id, name: x.name, title: x.title })),
      ...Object.values(doc.extras.goals).map((x) => ({ kind: 'goal' as const, id: x.id, name: x.name, title: x.title })),
      ...Object.values(m.controls).map((x) => ({ kind: 'control' as const, id: x.id, name: x.name, title: x.title })),
      ...Object.values(m.components).map((x) => ({ kind: 'component' as const, id: x.id, name: x.name, title: x.title })),
      ...Object.values(m.data).map((x) => ({ kind: 'data' as const, id: x.id, name: x.name, title: x.title })),
      ...Object.values(m.channels).map((x) => ({ kind: 'channel' as const, id: x.id, name: x.name, title: x.title })),
    ]
    return list.map((i) => ({ ...i, ...reviewState(doc, i.kind, i.id) }))
  }, [doc])
}

export function Dashboard() {
  const doc = useDocCtx()
  const { setView, select } = useUI()
  const risks = useMemo(() => computeRisks(doc.model, doc.extras, doc.engine), [doc.model, doc.extras, doc.engine])
  const items = useReviewItems()
  const m = doc.model
  const th = doc.extras.settings.acceptThreshold
  const untreated = risks.filter((r) => (r.risk ?? 0) >= th && !doc.extras.treatments[r.ts.id]?.decision)
  const stale = risks.filter((r) => r.staleRoot)
  const noTree = risks.filter((r) => !r.ts.threatenedBy && r.feasibilitySource !== 'stored')
  const noDs = Object.values(m.threatScenarios).filter((t) => !t.damageScenarioIds.length)
  const unratedDs = Object.values(m.damageScenarios).filter((d) => !impactLevelOf(d))
  // Stored impactLevel in the imported file that doesn't match that file's own ratings.
  const staleImpact = Object.values(doc.baseline?.damageScenarios ?? {}).filter((d) => (d.storedImpactLevel ?? null) !== impactLevelOf(d))
  const props = useMemo(() => propertySummary(doc), [doc])
  const links = useMemo(() => threatDamageIssues(doc.model), [doc.model])
  const top = [...risks].sort((a, b) => (b.risk ?? 0) - (a.risk ?? 0)).slice(0, 8)
  const approved = items.filter((i) => i.status === 'Approved').length

  const stat = (label: string, value: number | string, v: View, sub?: string) => (
    <button className="stat" onClick={() => setView(v)}>
      <b>{value}</b>
      <span>{label}</span>
      {sub ? <em>{sub}</em> : null}
    </button>
  )

  return (
    <div className="view dashboard">
      <div className="toolbar">
        <h2>{m.projectName}</h2>
        <span className="muted">{doc.fileName}</span>
      </div>
      <div className="stats">
        {stat('Assets (data · components · channels)', `${Object.keys(m.data).length} · ${Object.keys(m.components).length} · ${Object.keys(m.channels).length}`, 'item')}
        {stat('Damage scenarios', Object.keys(m.damageScenarios).length, 'damage', unratedDs.length ? `${unratedDs.length} without impact` : undefined)}
        {stat('Threat scenarios', Object.keys(m.threatScenarios).length, 'threat')}
        {stat('Attack steps', Object.keys(m.steps).length, 'steps')}
        {stat('Goals · controls', `${Object.keys(doc.extras.goals).length} · ${Object.keys(m.controls).length}`, 'concept')}
        {stat('Reviewed', `${Math.round((approved / Math.max(1, items.length)) * 100)}%`, 'review', `${approved}/${items.length} approved`)}
      </div>

      <div className="dash-grid">
        <div className="card">
          <h3>Risk matrix</h3>
          <RiskMatrix rows={risks} onCell={() => setView('risks')} />
        </div>
        <div className="card">
          <h3>Highest risks</h3>
          <table className="grid compact">
            <tbody>
              {top.map((r) => (
                <tr
                  key={r.ts.id}
                  onClick={() => {
                    setView('risks')
                    select({ kind: 'risk', id: r.ts.id })
                  }}
                >
                  <td>
                    <RiskBadge value={r.risk} />
                  </td>
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
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="card">
          <h3>Findings</h3>
          <ul className="findings">
            {stale.length ? (
              <li className="warn">
                <b>{stale.length}</b> threat-scenario root steps are stored as a different feasibility than their attack trees compute (e.g. {stale[0].ts.threatenedBy?.kind === 'ref' ? stale[0].ts.threatenedBy.name : ''}: stored{' '}
                {stale[0].staleRoot?.stored}, computed {stale[0].staleRoot?.computed}). Risks here use the computed value. <a onClick={() => setView('threat')}>Show</a>
              </li>
            ) : null}
            {untreated.length ? (
              <li className="warn">
                <b>{untreated.length}</b> risks at R{th}+ have no treatment decision. <a onClick={() => setView('risks')}>Treat</a>
              </li>
            ) : null}
            {staleImpact.length ? (
              <li className="warn">
                <b>{staleImpact.length}</b> damage scenarios have a stored impact level that doesn't match their ratings in the file ({staleImpact
                  .slice(0, 3)
                  .map((d) => `${d.name}: stored ${d.storedImpactLevel ?? 'none'}, rated ${impactLevelOf(d)}`)
                  .join('; ')}
                {staleImpact.length > 3 ? '…' : ''}). The tool uses the ratings; let MPS recompute. <a onClick={() => setView('damage')}>Show</a>
              </li>
            ) : null}
            {risks.some((r) => r.unresolved.length) ? (
              <li className="warn">
                <b>{risks.filter((r) => r.unresolved.length).length}</b> threat scenarios have attack trees with broken references in the export (
                {[...new Set(risks.flatMap((r) => r.unresolved))].slice(0, 4).join(', ')}): MPS's stored feasibility is used for them. Fix the references in MPS.{' '}
                <a onClick={() => setView('threat')}>Show</a>
              </li>
            ) : null}
            {risks.some((r) => r.storedMismatch) ? (
              <li className="warn">
                <b>{risks.filter((r) => r.storedMismatch).length}</b> threat scenarios: stored MPS values differ from what this tool computes (marked ≠ in Threat scenarios).
              </li>
            ) : null}
            {doc.model.catalogSteps ? (
              <li>
                {Object.keys(doc.model.catalogSteps).length} attack steps come from the imported catalog {doc.model.catalogName} (used for calculation, read-only).
              </li>
            ) : null}
            {links.mismatches.length ? (
              <li className="warn">
                <b>{links.mismatches.length}</b> threat → damage scenario links where the damage scenario doesn't list the threat's asset and property (e.g.{' '}
                {links.mismatches
                  .slice(0, 2)
                  .map((x) => `${x.ts.name} → ${doc.model.damageScenarios[x.dsId]?.name}: ${toeeName(doc, x.asset).name}/${x.property}`)
                  .join('; ')}
                ). <a onClick={() => setView('threat')}>Show</a>
              </li>
            ) : null}
            {links.uncovered.length ? (
              <li>
                <b>{links.uncovered.length}</b> damage-scenario asset/property pairs are not reached by any linked threat scenario.
              </li>
            ) : null}
            {props.conflict || props.gap ? (
              <li className="warn">
                Security properties: {props.conflict ? `${props.conflict} marked not relevant although damage scenarios use them` : ''}
                {props.conflict && props.gap ? '; ' : ''}
                {props.gap ? `${props.gap} marked relevant without a damage scenario` : ''}. <a onClick={() => setView('item')}>Review</a>
              </li>
            ) : null}
            {noTree.length ? <li><b>{noTree.length}</b> threat scenarios have no attack tree.</li> : null}
            {noDs.length ? <li><b>{noDs.length}</b> threat scenarios are not linked to a damage scenario.</li> : null}
            {unratedDs.length ? <li><b>{unratedDs.length}</b> damage scenarios have no impact rating (out of scope?).</li> : null}
            {!stale.length && !staleImpact.length && !risks.some((r) => r.unresolved.length || r.storedMismatch) && !untreated.length && !links.mismatches.length && !links.uncovered.length && !props.conflict && !props.gap && !noTree.length && !noDs.length && !unratedDs.length ? <li className="ok">No findings.</li> : null}
          </ul>
        </div>
        <div className="card">
          <h3>Review progress</h3>
          <ReviewProgress items={items} />
        </div>
      </div>
    </div>
  )
}

function ReviewProgress({ items }: { items: ReturnType<typeof useReviewItems> }) {
  const { setView } = useUI()
  const kinds = [...new Set(items.map((i) => i.kind))]
  return (
    <div className="progress-list">
      {kinds.map((k) => {
        const of = items.filter((i) => i.kind === k)
        const n = (s: string) => of.filter((i) => i.status === s).length
        const pct = (s: string) => `${(n(s) / of.length) * 100}%`
        return (
          <div key={k} className="progress-row" onClick={() => setView(KIND_VIEW[k])}>
            <span>{KIND_LABEL[k]}</span>
            <div className="bar">
              <i className="rs-approved" style={{ width: pct('Approved') }} />
              <i className="rs-in-review" style={{ width: pct('In review') }} />
              <i className="rs-rework" style={{ width: pct('Rework') }} />
              <i className="stale" style={{ width: pct('Changed') }} />
            </div>
            <span className="muted small">
              {n('Approved')}/{of.length}
            </span>
          </div>
        )
      })}
    </div>
  )
}

export function ReviewView() {
  const doc = useDocCtx()
  const { select } = useUI()
  const items = useReviewItems()
  const [kind, setKind] = useState<ReviewKind | 'all'>('all')
  const [status, setStatus] = useState<string>('not-approved')
  const [q, setQ] = useState('')
  const s = q.trim().toLowerCase()
  const rows = items.filter(
    (i) =>
      (kind === 'all' || i.kind === kind) &&
      (status === 'all' || (status === 'not-approved' ? i.status !== 'Approved' : status === 'comments' ? (i.record?.comments ?? []).some((c) => !c.resolved) : i.status === status)) &&
      (!s || `${i.name} ${i.title}`.toLowerCase().includes(s)),
  )
  const allComments = items.flatMap((i) => (i.record?.comments ?? []).filter((c) => !c.resolved).map((c) => ({ ...c, item: i })))
  return (
    <div className="view">
      <div className="toolbar">
        <h2>
          Review <span className="muted">{rows.length}</span>
        </h2>
        <input className="search" placeholder="Filter…" value={q} onChange={(e) => setQ(e.target.value)} />
        <select className="slim" value={kind} onChange={(e) => setKind(e.target.value as ReviewKind | 'all')}>
          <option value="all">All elements</option>
          {Object.entries(KIND_LABEL).map(([k, l]) => (
            <option key={k} value={k}>
              {l}
            </option>
          ))}
        </select>
        <select className="slim" value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="not-approved">Not approved</option>
          <option value="all">Any status</option>
          <option value="comments">With open comments</option>
          {[...REVIEW_STATUSES, 'Changed'].map((x) => (
            <option key={x} value={x}>
              {x}
            </option>
          ))}
        </select>
        <span className="grow" />
        {!doc.extras.settings.reviewer ? <span className="warn small">Set your reviewer name in Settings</span> : <span className="muted small">Reviewing as {doc.extras.settings.reviewer}</span>}
      </div>
      <div className="review-layout">
        <table className="grid">
          <thead>
            <tr>
              <th>Type</th>
              <th>ID</th>
              <th>Title</th>
              <th>Status</th>
              <th>Checks</th>
              <th>Comments</th>
              <th>Approved by</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((i) => {
              const checks = Object.values(i.record?.checks ?? {}).filter(Boolean).length
              const open = (i.record?.comments ?? []).filter((c) => !c.resolved).length
              return (
                <tr key={`${i.kind}:${i.id}`} onClick={() => select({ kind: i.kind, id: i.id })}>
                  <td className="small muted">{KIND_LABEL[i.kind]}</td>
                  <td>
                    <code>{i.name}</code>
                  </td>
                  <td className="wide">{i.title}</td>
                  <td>
                    <ReviewChip status={i.record?.status} stale={i.stale} />
                  </td>
                  <td className="small">{checks || ''}</td>
                  <td className="small">{open ? `💬 ${open}` : ''}</td>
                  <td className="small muted">{i.record?.status === 'Approved' ? i.record.approvedBy : ''}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
        {allComments.length ? (
          <div className="card comments-feed">
            <h3>Open comments ({allComments.length})</h3>
            {allComments
              .sort((a, b) => b.at.localeCompare(a.at))
              .slice(0, 50)
              .map((c) => (
                <div key={c.id} className="comment" onClick={() => select({ kind: c.item.kind, id: c.item.id })}>
                  <div className="comment-head">
                    <b>{c.author}</b> <code>{c.item.name}</code>
                  </div>
                  <div className="comment-text">{c.text}</div>
                </div>
              ))}
          </div>
        ) : null}
      </div>
    </div>
  )
}

export function SettingsView() {
  const doc = useDocCtx()
  const st = doc.extras.settings
  const feas: FeasibilityLevel[] = ['Very low', 'Low', 'Medium', 'High']
  const imps: ImpactLevel[] = ['Sev', 'Ser', 'Mod', 'Neg']
  return (
    <div className="view settings">
      <div className="toolbar">
        <h2>Settings</h2>
      </div>
      <div className="card">
        <label className="field">
          <span>Project name</span>
          <input value={doc.model.projectName} onChange={(e) => doc.actions.renameProject(e.target.value)} />
        </label>
        <label className="field">
          <span>Your name (shown on review comments and approvals)</span>
          <input value={st.reviewer} placeholder="e.g. Jane Doe" onChange={(e) => doc.actions.setSettings({ reviewer: e.target.value })} />
        </label>
        <label className="field">
          <span>Risks at or above this value need a treatment decision</span>
          <select value={st.acceptThreshold} onChange={(e) => doc.actions.setSettings({ acceptThreshold: Number(e.target.value) })}>
            {[2, 3, 4, 5].map((v) => (
              <option key={v} value={v}>
                R{v}
              </option>
            ))}
          </select>
        </label>
      </div>
      <div className="card">
        <h3>Risk matrix</h3>
        <p className="muted small">Risk value (1–5) for each impact level and attack feasibility. Default: ISO/SAE 21434 Annex H example.</p>
        <table className="matrix edit">
          <thead>
            <tr>
              <th />
              {feas.map((f) => (
                <th key={f}>{f}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {imps.map((i) => (
              <tr key={i}>
                <th>{IMPACT_LABEL[i]}</th>
                {feas.map((f) => (
                  <td key={f} className={`risk-${st.riskMatrix[i][f]}`}>
                    <select
                      value={st.riskMatrix[i][f]}
                      onChange={(e) => doc.actions.setSettings({ riskMatrix: { ...st.riskMatrix, [i]: { ...st.riskMatrix[i], [f]: Number(e.target.value) } } })}
                    >
                      {[1, 2, 3, 4, 5].map((v) => (
                        <option key={v}>{v}</option>
                      ))}
                    </select>
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
        <button className="mini" onClick={() => doc.actions.setSettings({ riskMatrix: DEFAULT_RISK_MATRIX })}>
          Reset to ISO 21434 Annex H
        </button>
      </div>
    </div>
  )
}
