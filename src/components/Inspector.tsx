import { useMemo, useState } from 'react'
import { useDocCtx, useUI } from '../context'
import type { Owner } from '../store'
import { threatDamageIssues, threatProperty } from '../tara/consistency'
import { computeRisks } from '../tara/risk'
import { DEFAULT_CONTROL_META, TREATMENTS, type TreatmentDecision } from '../tara/types'
import { formatExpr, getAt, refsOf, type ExprPath } from '../xsam/expr'
import { newMpsId } from '../xsam/io'
import { impactIndex, impactLevelOf, learnScales } from '../xsam/impact'
import {
  CATEGORIES,
  CATEGORY_LABEL,
  CATEGORY_PREFIX,
  CS_PROPERTIES,
  CS_PROPERTY_LABEL,
  IMPACT_CATEGORIES,
  IMPACT_CATEGORY_LABEL,
  IMPACT_LEVELS,
  IMPACT_LABEL,
  type AttackStep,
  type Channel,
  type Component,
  type DamageScenario,
  type DataElement,
  type Expr,
  type SecurityControl,
  type ThreatScenario,
  type ToeeRef,
} from '../xsam/types'
import { EditedMark, Field, MultiPicker, Section, ToeeChip, toeeName, type PickOption } from './common'
import { ImpactBadge, LevelBadge, RiskBadge, VectorChips } from './Level'
import { ReviewBox } from './ReviewBox'
import { SecurityPropertiesEditor } from './SecurityProperties'

/** Typical ISO/SAE 21434 Annex G values per factor; any integer is accepted. */
const PRESETS: Record<string, [number, string][]> = {
  Time: [[0, '≤ 1 day'], [1, '≤ 1 week'], [4, '≤ 1 month'], [10, '≤ 6 months'], [19, '> 6 months']],
  Expertise: [[0, 'Layman'], [3, 'Proficient'], [6, 'Expert'], [8, 'Multiple experts']],
  Knowledge: [[0, 'Public'], [3, 'Restricted'], [7, 'Confidential'], [11, 'Strictly confidential']],
  Opportunity: [[0, 'Unlimited'], [1, 'Easy'], [4, 'Moderate'], [10, 'Difficult']],
  Equipment: [[0, 'Standard'], [4, 'Specialized'], [7, 'Bespoke'], [9, 'Multiple bespoke']],
}

export function Inspector({ onClose }: { onClose?: () => void }) {
  const { selection } = useUI()
  const doc = useDocCtx()
  let body: React.ReactNode = null
  if (selection) {
    if (selection.kind === 'gate') body = <GatePanel owner={selection.owner} path={selection.path} />
    else {
      const id = selection.id
      const m = doc.model
      const x = doc.extras
      switch (selection.kind) {
        case 'step':
          body = m.steps[id] && <StepPanel step={m.steps[id]} />
          break
        case 'damage':
          body = m.damageScenarios[id] && <DamagePanel d={m.damageScenarios[id]} />
          break
        case 'threat':
          body = m.threatScenarios[id] && <ThreatPanel t={m.threatScenarios[id]} />
          break
        case 'risk':
          body = m.threatScenarios[id] && <RiskPanel t={m.threatScenarios[id]} />
          break
        case 'component':
          body = m.components[id] && <ComponentPanel c={m.components[id]} />
          break
        case 'data':
          body = m.data[id] && <DataPanel d={m.data[id]} />
          break
        case 'channel':
          body = m.channels[id] && <ChannelPanel c={m.channels[id]} />
          break
        case 'goal':
          body = x.goals[id] && <GoalPanel id={id} />
          break
        case 'claim':
          body = x.claims[id] && <ClaimPanel id={id} />
          break
        case 'control':
          body = m.controls[id] && <ControlPanel id={id} />
          break
      }
    }
  }
  return (
    <aside className="inspector">
      {onClose && selection ? (
        <button className="mini close" onClick={onClose} title="Close">
          ✕
        </button>
      ) : null}
      {body ?? <Help />}
    </aside>
  )
}

function Help() {
  return (
    <div className="help">
      <h3>Details</h3>
      <p className="muted">Select a row or a node to edit it here and review it with the checklist.</p>
    </div>
  )
}

function Head({ kind, name, right }: { kind: string; name: string; right?: React.ReactNode }) {
  return (
    <div className="panel-head">
      <span className="kind">{kind}</span>
      <code>{name}</code>
      <span className="grow" />
      {right}
    </div>
  )
}

function NameField({ value, onCommit, taken }: { value: string; onCommit: (v: string) => void; taken: (v: string) => boolean }) {
  const [draft, setDraft] = useState(value)
  const [last, setLast] = useState(value)
  if (last !== value) {
    setLast(value)
    setDraft(value)
  }
  return (
    <label className="field">
      <span>ID</span>
      <input
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        onBlur={() => {
          const n = draft.trim()
          if (!n || n === value) return setDraft(value)
          if (taken(n)) {
            alert(`${n} already exists`)
            return setDraft(value)
          }
          onCommit(n)
        }}
      />
    </label>
  )
}

function Danger({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <div className="actions">
      <button className="danger" onClick={onClick}>
        {label}
      </button>
    </div>
  )
}

function useToeeOptions(): PickOption[] {
  const doc = useDocCtx()
  return useMemo(
    () => [
      ...Object.values(doc.model.data).map((d) => ({ id: `data|${d.id}`, label: d.name, sub: d.title })),
      ...Object.values(doc.model.components).map((c) => ({ id: `component|${c.id}`, label: c.name, sub: c.title })),
      ...Object.values(doc.model.channels).map((c) => ({ id: `channel|${c.id}`, label: c.name, sub: c.title })),
    ],
    [doc.model.data, doc.model.components, doc.model.channels],
  )
}
const toKey = (r: ToeeRef) => `${r.kind}|${r.id}`
const fromKey = (k: string): ToeeRef => {
  const [kind, ...rest] = k.split('|')
  return { kind: kind as ToeeRef['kind'], id: rest.join('|') }
}

function ToeePicker({ value, onChange }: { value: ToeeRef[]; onChange: (v: ToeeRef[]) => void }) {
  const opts = useToeeOptions()
  return <MultiPicker options={opts} value={value.map(toKey)} onChange={(v) => onChange(v.map(fromKey))} placeholder="asset" render={(k) => <ToeeChip r={fromKey(k)} />} />
}

// ---------------------------------------------------------------------------
// Attack step

function StepPanel({ step }: { step: AttackStep }) {
  const doc = useDocCtx()
  const { setRoot, select, root, setView } = useUI()
  const ev = doc.engine.evaluate(step.name)
  const owner: Owner = { kind: 'step', id: step.id }
  const usedBy = useMemo(
    () => [
      ...Object.values(doc.model.threatScenarios)
        .filter((s) => refsOf(s.threatenedBy).includes(step.name))
        .map((s) => ({ kind: 'threat' as const, id: s.id, name: s.name, title: s.title })),
      ...Object.values(doc.model.steps)
        .filter((s) => refsOf(s.refinedBy).includes(step.name))
        .map((s) => ({ kind: 'step' as const, id: s.id, name: s.name, title: s.title })),
    ],
    [doc.model, step.name],
  )
  const controlOpts = useMemo(() => Object.values(doc.model.controls).map((c) => ({ id: c.name, label: c.name, sub: c.title })), [doc.model.controls])
  const controlByName = useMemo(() => new Map(Object.values(doc.model.controls).map((c) => [c.name, c])), [doc.model.controls])
  const mitigatedBy = refsOf(step.mitigatedBy)
  const upd = (p: Partial<AttackStep>) => doc.actions.update('step', step.id, p)
  // Stored level in the imported file vs. what that file's own tree computes.
  const importedLevel = doc.baseline?.steps[step.id] ? doc.baselineEngine?.evaluate(step.name).level : null
  const stale = !!step.storedLevel && !!importedLevel && step.storedLevel !== importedLevel

  return (
    <div className="panel">
      <Head kind="Attack step" name={step.name} right={<><EditedMark kind="step" id={step.id} /><LevelBadge level={ev.level} total={ev.total} /></>} />
      <NameField value={step.name} taken={(n) => doc.stepByName.has(n)} onCommit={(n) => upd({ name: n })} />
      <Field label="Title" value={step.title} onChange={(v) => upd({ title: v })} />
      <Field label="Description" multiline value={step.description} onChange={(v) => upd({ description: v })} />

      <Section title={<>Feasibility rating {step.refinedBy ? <span className="muted small">(refined: usually derived from children)</span> : null}</>}>
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
                  aria-label={CATEGORY_LABEL[c]}
                  value={r?.value ?? ''}
                  placeholder="–"
                  onChange={(e) => {
                    const ratings = { ...step.ratings }
                    if (e.target.value === '') delete ratings[c]
                    else ratings[c] = { ...r, value: Math.max(0, Math.round(Number(e.target.value))) }
                    upd({ ratings })
                  }}
                />
                <select value="" onChange={(e) => e.target.value !== '' && upd({ ratings: { ...step.ratings, [c]: { ...r, value: Number(e.target.value) } } })} title="ISO/SAE 21434 preset">
                  <option value="">preset</option>
                  {PRESETS[c].map(([v, l]) => (
                    <option key={v} value={v}>
                      {v} · {l}
                    </option>
                  ))}
                </select>
                <input
                  className="rationale"
                  placeholder="Rationale"
                  value={r?.rationale ?? ''}
                  disabled={!r}
                  onChange={(e) => upd({ ratings: { ...step.ratings, [c]: { value: r!.value, rationale: e.target.value || undefined } } })}
                />
              </div>
            )
          })}
        </div>
        <div className="computed">
          <span className="muted">Computed:</span> <VectorChips vector={ev.vector} /> <LevelBadge level={ev.level} total={ev.total} />
        </div>
        {stale ? (
          <p className="warn small">
            The imported file stores this step as <b>{step.storedLevel}</b>, but its own attack tree computes <b>{importedLevel}</b>. The stored value is probably stale: check it in MPS.
          </p>
        ) : null}
        {ev.unresolved.length ? <p className="warn small">Not in this model: {ev.unresolved.join(', ')}</p> : null}
      </Section>

      <Section title="Refined by">
        <ExprEditor owner={owner} expr={step.refinedBy} selfName={step.name} />
      </Section>

      <Section title="Acts on">
        <ToeePicker value={step.actedOn} onChange={(v) => upd({ actedOn: v })} />
      </Section>

      <Section title="Mitigated by (security controls)">
        <MultiPicker
          options={controlOpts}
          value={mitigatedBy}
          onChange={(v) => {
            for (const n of mitigatedBy) if (!v.includes(n)) doc.actions.setMitigation(step.id, n, false)
            for (const n of v) if (!mitigatedBy.includes(n)) doc.actions.setMitigation(step.id, n, true)
          }}
          placeholder="control"
          render={(n) => {
            const c = controlByName.get(n)
            return (
              <a className={c ? '' : 'ext'} title={c?.title ?? 'not in model'} onClick={() => c && select({ kind: 'control', id: c.id })}>
                🛡 {n}
              </a>
            )
          }}
        />
        {step.mitigatedBy && step.mitigatedBy.kind !== 'ref' ? <p className="muted small">In XSAM: <code>{formatExpr(step.mitigatedBy)}</code></p> : null}
      </Section>

      {usedBy.length ? (
        <Section title="Used by">
          <ul className="links">
            {usedBy.map((u) => (
              <li key={u.kind + u.id}>
                <a onClick={() => select(u)}>
                  <code>{u.name}</code> {u.title}
                </a>
              </li>
            ))}
          </ul>
        </Section>
      ) : null}

      <div className="actions">
        {!(root?.kind === 'step' && root.id === step.id) ? (
          <button
            onClick={() => {
              setRoot({ kind: 'step', id: step.id })
              setView('trees')
            }}
          >
            Open attack tree
          </button>
        ) : null}
      </div>
      <ReviewBox kind="step" id={step.id} />
      <Danger
        label="Delete step"
        onClick={() => {
          if (!confirm(`Delete ${step.name}? It is removed from ${usedBy.length} place(s) that use it.`)) return
          if (root?.kind === 'step' && root.id === step.id) setRoot(null)
          select(null)
          doc.actions.remove('step', step.id)
        }}
      />
    </div>
  )
}

// ---------------------------------------------------------------------------
// Damage scenario

function DamagePanel({ d }: { d: DamageScenario }) {
  const doc = useDocCtx()
  const { select } = useUI()
  const upd = (p: Partial<DamageScenario>) => doc.actions.update('damage', d.id, p)
  const scales = useMemo(() => learnScales(doc.model), [doc.model])
  const scale = scales.find((s) => s.id === (d.scale ?? '')) ?? scales[0]
  const level = impactLevelOf(d)
  const threats = Object.values(doc.model.threatScenarios).filter((t) => t.damageScenarioIds.includes(d.id))
  return (
    <div className="panel">
      <Head kind="Damage scenario" name={d.name} right={<><EditedMark kind="damage" id={d.id} /><ImpactBadge level={level} /></>} />
      <NameField value={d.name} taken={(n) => Object.values(doc.model.damageScenarios).some((x) => x.name === n)} onCommit={(n) => upd({ name: n })} />
      <Field label="Title" value={d.title} onChange={(v) => upd({ title: v })} />
      <Field label="Description" multiline value={d.description} onChange={(v) => upd({ description: v })} />

      <Section
        title="Impact rating"
        right={
          scales.length > 1 ? (
            <select className="slim" value={d.scale ?? ''} onChange={(e) => upd({ scale: e.target.value || null })} title="Impact scale (from the assessment model)">
              {scales.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.label} · {s.count} DS
                </option>
              ))}
            </select>
          ) : null
        }
      >
        <div className="impacts">
          {IMPACT_CATEGORIES.map((c) => {
            const e = d.impacts[c]
            const idx = impactIndex(e?.option)
            return (
              <div key={c} className="impact">
                <span className="cat" title={IMPACT_CATEGORY_LABEL[c]}>
                  {c}
                </span>
                <span className="catname">{IMPACT_CATEGORY_LABEL[c]}</span>
                <div className="seg imp-seg">
                  {IMPACT_LEVELS.map((l, i) => (
                    <button
                      key={l}
                      className={idx === i ? `on imp-${l.toLowerCase()}` : ''}
                      title={`${IMPACT_LABEL[l]} (${scale?.options[c]?.[i] ?? ''})`}
                      onClick={() => {
                        const impacts = { ...d.impacts }
                        if (idx === i) delete impacts[c]
                        else impacts[c] = { ...e, option: scale?.options[c]?.[i] ?? `RU.${c}${i}` }
                        upd({ impacts, scale: d.scale ?? scale?.id ?? null })
                      }}
                    >
                      {l}
                    </button>
                  ))}
                </div>
                <input
                  className="rationale"
                  placeholder="Rationale"
                  disabled={!e?.option}
                  value={e?.rationale ?? ''}
                  onChange={(ev) => upd({ impacts: { ...d.impacts, [c]: { ...e!, rationale: ev.target.value || undefined } } })}
                />
              </div>
            )
          })}
        </div>
        <p className="muted small">Impact level = the highest category ({level ? IMPACT_LABEL[level] : 'none'}).</p>
      </Section>

      <Section title={`Concerned assets (${d.assets.length})`}>
        <table className="mini-table">
          <tbody>
            {d.assets.map((a, i) => (
              <tr key={a.id}>
                <td>
                  <ToeeChip r={a.target} />
                </td>
                <td className="t">{toeeName(doc, a.target).title}</td>
                <td>
                  <select
                    className="slim"
                    value={a.property}
                    onChange={(e) => upd({ assets: d.assets.map((x, j) => (j === i ? { ...x, property: e.target.value } : x)) })}
                  >
                    {CS_PROPERTIES.map((p) => (
                      <option key={p} value={p}>
                        {CS_PROPERTY_LABEL[p]}
                      </option>
                    ))}
                  </select>
                </td>
                <td>
                  <button className="mini danger" onClick={() => upd({ assets: d.assets.filter((_, j) => j !== i) })}>
                    ✕
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <AddAsset onAdd={(target, property) => upd({ assets: [...d.assets, { id: newMpsId(), property, target }] })} />
      </Section>

      <Section title={`Threat scenarios (${threats.length})`}>
        <ul className="links">
          {threats.map((t) => (
            <li key={t.id}>
              <a onClick={() => select({ kind: 'threat', id: t.id })}>
                <code>{t.name}</code> {t.title}
              </a>
            </li>
          ))}
        </ul>
      </Section>
      <ReviewBox kind="damage" id={d.id} />
      <Danger
        label="Delete damage scenario"
        onClick={() => {
          if (!confirm(`Delete ${d.name}? It is unlinked from ${threats.length} threat scenario(s).`)) return
          select(null)
          doc.actions.remove('damage', d.id)
        }}
      />
    </div>
  )
}

function AddAsset({ onAdd }: { onAdd: (t: ToeeRef, p: string) => void }) {
  const opts = useToeeOptions()
  const [t, setT] = useState('')
  const [p, setP] = useState('Integ')
  return (
    <div className="add-row">
      <select className="slim" value={t} onChange={(e) => setT(e.target.value)}>
        <option value="">Asset…</option>
        {opts.map((o) => (
          <option key={o.id} value={o.id}>
            {o.label} · {o.sub}
          </option>
        ))}
      </select>
      <select className="slim" value={p} onChange={(e) => setP(e.target.value)}>
        {CS_PROPERTIES.map((x) => (
          <option key={x} value={x}>
            {CS_PROPERTY_LABEL[x]}
          </option>
        ))}
      </select>
      <button
        className="mini"
        disabled={!t}
        onClick={() => {
          onAdd(fromKey(t), p)
          setT('')
        }}
      >
        Add
      </button>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Threat scenario

function ThreatPanel({ t }: { t: ThreatScenario }) {
  const doc = useDocCtx()
  const { select, setRoot, setView } = useUI()
  const upd = (p: Partial<ThreatScenario>) => doc.actions.update('threat', t.id, p)
  const risk = useMemo(() => computeRisks({ ...doc.model, threatScenarios: { [t.id]: t } }, doc.extras, doc.engine)[0], [doc.model, doc.extras, doc.engine, t])
  const dsOpts = useMemo(() => Object.values(doc.model.damageScenarios).map((d) => ({ id: d.id, label: d.name, sub: d.title })), [doc.model.damageScenarios])
  const paths = useMemo(() => doc.engine.enumeratePaths(t.threatenedBy, 200), [doc.engine, t.threatenedBy])
  const owner: Owner = { kind: 'threat', id: t.id }
  return (
    <div className="panel">
      <Head kind="Threat scenario" name={t.name} right={<><EditedMark kind="threat" id={t.id} /><RiskBadge value={risk.risk} /></>} />
      <NameField value={t.name} taken={(n) => Object.values(doc.model.threatScenarios).some((x) => x.name === n)} onCommit={(n) => upd({ name: n })} />
      <Field label="Title" value={t.title} onChange={(v) => upd({ title: v })} />
      <Field label="Description" multiline value={t.description} onChange={(v) => upd({ description: v })} />

      <div className="kv">
        <span>Feasibility</span>
        <span>
          <LevelBadge level={risk.feasibility} total={risk.evaluation?.total} /> {risk.feasibilitySource === 'explicit' ? <span className="muted small">set explicitly in MPS</span> : null}
        </span>
        <span>Impact</span>
        <span>
          <ImpactBadge level={risk.impact} /> {risk.worstDs ? <span className="muted small">from {doc.model.damageScenarios[risk.worstDs]?.name}</span> : null}
        </span>
        <span>Risk</span>
        <span>
          <RiskBadge value={risk.risk} /> <a onClick={() => select({ kind: 'risk', id: t.id })}>treatment →</a>
        </span>
      </div>
      {risk.staleRoot ? (
        <p className="warn small">
          Root step stored as <b>{risk.staleRoot.stored}</b> in the file, but the tree computes <b>{risk.staleRoot.computed}</b>.
        </p>
      ) : null}

      <Section title="Asset (acts on)">
        <ToeePicker value={t.actedOn} onChange={(v) => upd({ actedOn: v })} />
      </Section>

      {(() => {
        const prop = threatProperty(t)
        const bad = threatDamageIssues({ ...doc.model, threatScenarios: { [t.id]: t } }).mismatches
        return (
          <p className={bad.length ? 'warn small' : 'muted small'}>
            Violated property: <b>{prop ? CS_PROPERTY_LABEL[prop] : 'unknown (no STRIDE category in the title)'}</b>.
            {bad.length
              ? ` ${bad.length} linked damage scenario(s) don't list ${t.actedOn.map((a) => toeeName(doc, a).name).join(', ')} / ${prop}: ${[...new Set(bad.map((x) => doc.model.damageScenarios[x.dsId]?.name))].join(', ')}.`
              : prop && t.damageScenarioIds.length
                ? ' All linked damage scenarios list this asset and property.'
                : ''}
          </p>
        )
      })()}
      <Section title={`Damage scenarios (${t.damageScenarioIds.length})`}>
        <MultiPicker
          options={dsOpts}
          value={t.damageScenarioIds}
          onChange={(v) => upd({ damageScenarioIds: v })}
          placeholder="damage scenario"
          render={(id) => {
            const d = doc.model.damageScenarios[id]
            return (
              <span className="ds-chip" onClick={() => select({ kind: 'damage', id })} title={d?.title}>
                {d?.name ?? id} <ImpactBadge level={d ? impactLevelOf(d) : null} />
              </span>
            )
          }}
        />
      </Section>

      <Section
        title="Attack tree"
        right={
          <button
            className="mini"
            onClick={() => {
              setRoot({ kind: 'threat', id: t.id })
              setView('trees')
            }}
          >
            Open visual editor
          </button>
        }
      >
        {t.threatenedBy ? (
          <ExprEditor owner={owner} expr={t.threatenedBy} />
        ) : (
          <div className="empty-expr">
            <span className="muted small">No attack tree yet.</span>
            <button
              className="mini"
              onClick={() => {
                const name = `AS.${t.name}`
                const existing = doc.stepByName.get(name)
                const stepName = existing ? existing.name : doc.actions.add('step', { name, title: t.title, ratings: {}, description: `Attack tree root for ${t.name}.` }).name
                upd({ threatenedBy: { kind: 'ref', name: stepName } })
              }}
            >
              Create root step AS.{t.name}
            </button>
            <StepPicker owner={owner} path={[]} label="or link an existing step" />
          </div>
        )}
      </Section>

      <Section title={<>Attack paths <span className="muted small">{paths.length}{paths.length >= 200 ? '+' : ''}, easiest first</span></>}>
        <ol className="paths">
          {paths.slice(0, 30).map((p, i) => (
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
      </Section>
      <ReviewBox kind="threat" id={t.id} />
      <Danger
        label="Delete threat scenario"
        onClick={() => {
          if (!confirm(`Delete ${t.name}? Its attack steps stay in the model.`)) return
          select(null)
          doc.actions.remove('threat', t.id)
        }}
      />
    </div>
  )
}

// ---------------------------------------------------------------------------
// Risk & treatment

function RiskPanel({ t }: { t: ThreatScenario }) {
  const doc = useDocCtx()
  const { select } = useUI()
  const risk = useMemo(() => computeRisks({ ...doc.model, threatScenarios: { [t.id]: t } }, doc.extras, doc.engine)[0], [doc.model, doc.extras, doc.engine, t])
  const tr = doc.extras.treatments[t.id] ?? { decision: null, rationale: '', goalIds: [], claimIds: [] }
  const goalOpts = Object.values(doc.extras.goals).map((g) => ({ id: g.id, label: g.name, sub: g.title }))
  const claimOpts = Object.values(doc.extras.claims).map((g) => ({ id: g.id, label: g.name, sub: g.title }))
  const needs = (risk.risk ?? 0) >= doc.extras.settings.acceptThreshold
  return (
    <div className="panel">
      <Head kind="Risk" name={t.name} right={<RiskBadge value={risk.risk} />} />
      <p className="lead">
        <a onClick={() => select({ kind: 'threat', id: t.id })}>{t.title}</a>
      </p>
      <div className="kv">
        <span>Impact</span>
        <span>
          <ImpactBadge level={risk.impact} /> {risk.worstDs ? <span className="muted small">{doc.model.damageScenarios[risk.worstDs]?.name}</span> : null}
        </span>
        <span>Feasibility</span>
        <span>
          <LevelBadge level={risk.feasibility} />
        </span>
        <span>Risk value</span>
        <span>
          <RiskBadge value={risk.risk} /> {needs ? <span className="warn small">above acceptance threshold (R{doc.extras.settings.acceptThreshold})</span> : null}
        </span>
        <span>Residual</span>
        <span>
          {risk.residualBlocked ? <span className="small">🛡 all attack paths removed by controls</span> : <LevelBadge level={risk.residualFeasibility} />}{' '}
          <RiskBadge value={risk.residualRisk} title="Residual risk with controls applied" />
        </span>
      </div>

      <Section title="Treatment decision">
        <div className="seg">
          {TREATMENTS.map((d) => (
            <button key={d} className={tr.decision === d ? 'on' : ''} onClick={() => doc.actions.setTreatment(t.id, { decision: tr.decision === d ? null : (d as TreatmentDecision) })}>
              {d}
            </button>
          ))}
        </div>
        <Field label="Rationale" multiline value={tr.rationale} onChange={(v) => doc.actions.setTreatment(t.id, { rationale: v })} />
        {tr.decision === 'Retain' && needs ? <p className="warn small">Retaining a risk above the acceptance threshold needs a strong rationale and a claim.</p> : null}
      </Section>

      <Section
        title="Cybersecurity goals"
        right={
          <button
            className="mini"
            onClick={() => {
              const g = doc.actions.addGoal({ title: `Protect against: ${t.title}` })
              doc.actions.setTreatment(t.id, { goalIds: [...tr.goalIds, g.id] })
            }}
          >
            + New goal
          </button>
        }
      >
        <MultiPicker
          options={goalOpts}
          value={tr.goalIds}
          onChange={(v) => doc.actions.setTreatment(t.id, { goalIds: v })}
          placeholder="goal"
          render={(id) => <a onClick={() => select({ kind: 'goal', id })}>{doc.extras.goals[id]?.name}</a>}
        />
      </Section>
      <Section
        title="Cybersecurity claims"
        right={
          <button
            className="mini"
            onClick={() => {
              const c = doc.actions.addClaim({ title: `Claim for ${t.name}` })
              doc.actions.setTreatment(t.id, { claimIds: [...tr.claimIds, c.id] })
            }}
          >
            + New claim
          </button>
        }
      >
        <MultiPicker
          options={claimOpts}
          value={tr.claimIds}
          onChange={(v) => doc.actions.setTreatment(t.id, { claimIds: v })}
          placeholder="claim"
          render={(id) => <a onClick={() => select({ kind: 'claim', id })}>{doc.extras.claims[id]?.name}</a>}
        />
      </Section>
      <ReviewBox kind="risk" id={t.id} />
    </div>
  )
}

function GoalPanel({ id }: { id: string }) {
  const doc = useDocCtx()
  const { select } = useUI()
  const g = doc.extras.goals[id]
  const upd = (p: Parameters<typeof doc.actions.updateGoal>[1]) => doc.actions.updateGoal(id, p)
  const threats = Object.entries(doc.extras.treatments).filter(([, t]) => t.goalIds.includes(id)).map(([k]) => doc.model.threatScenarios[k]).filter(Boolean)
  const controls = Object.values(doc.model.controls).filter((c) => doc.extras.controlMeta?.[c.id]?.goalIds.includes(id))
  return (
    <div className="panel">
      <Head kind="Cybersecurity goal" name={g.name} />
      <Field label="ID" value={g.name} onChange={(v) => upd({ name: v })} />
      <Field label="Goal" value={g.title} onChange={(v) => upd({ title: v })} />
      <Field label="Description" multiline value={g.description} onChange={(v) => upd({ description: v })} />
      <label className="field">
        <span>CAL</span>
        <select value={g.cal ?? ''} onChange={(e) => upd({ cal: e.target.value ? Number(e.target.value) : null })}>
          <option value="">–</option>
          {[1, 2, 3, 4].map((c) => (
            <option key={c} value={c}>
              CAL {c}
            </option>
          ))}
        </select>
      </label>
      <Section title={`Threat scenarios (${threats.length})`}>
        <ul className="links">
          {threats.map((t) => (
            <li key={t.id}>
              <a onClick={() => select({ kind: 'risk', id: t.id })}>
                <code>{t.name}</code> {t.title}
              </a>
            </li>
          ))}
        </ul>
      </Section>
      <Section title={`Controls (${controls.length})`}>
        <ul className="links">
          {controls.map((c) => (
            <li key={c.id}>
              <a onClick={() => select({ kind: 'control', id: c.id })}>
                <code>{c.name}</code> {c.title}
              </a>
            </li>
          ))}
        </ul>
      </Section>
      <ReviewBox kind="goal" id={id} />
      <Danger
        label="Delete goal"
        onClick={() => {
          if (!confirm(`Delete ${g.name}?`)) return
          select(null)
          doc.actions.removeGoal(id)
        }}
      />
    </div>
  )
}

function ClaimPanel({ id }: { id: string }) {
  const doc = useDocCtx()
  const { select } = useUI()
  const c = doc.extras.claims[id]
  const upd = (p: Parameters<typeof doc.actions.updateClaim>[1]) => doc.actions.updateClaim(id, p)
  return (
    <div className="panel">
      <Head kind="Cybersecurity claim" name={c.name} />
      <Field label="ID" value={c.name} onChange={(v) => upd({ name: v })} />
      <Field label="Claim" value={c.title} onChange={(v) => upd({ title: v })} />
      <Field label="Description" multiline value={c.description} onChange={(v) => upd({ description: v })} />
      <Danger
        label="Delete claim"
        onClick={() => {
          if (!confirm(`Delete ${c.name}?`)) return
          select(null)
          doc.actions.removeClaim(id)
        }}
      />
    </div>
  )
}

function ControlPanel({ id }: { id: string }) {
  const doc = useDocCtx()
  const { select } = useUI()
  const c = doc.model.controls[id]
  const meta = { ...DEFAULT_CONTROL_META, ...(doc.extras.controlMeta?.[id] ?? {}) }
  const upd = (p: Partial<SecurityControl>) => doc.actions.update('control', id, p)
  const stepOpts = useMemo(() => Object.values(doc.model.steps).map((s) => ({ id: s.id, label: s.name, sub: s.title })), [doc.model.steps])
  const mitigated = Object.values(doc.model.steps).filter((s) => refsOf(s.mitigatedBy).includes(c.name))
  const goalOpts = Object.values(doc.extras.goals).map((g) => ({ id: g.id, label: g.name, sub: g.title }))
  const rated = CATEGORIES.some((k) => c.ratings[k])
  const removes = c.effects.includes('RemoveAllDamage')
  const risksAffected = useMemo(() => {
    const names = new Set(mitigated.map((s) => s.name))
    // Any step anywhere in the tree (mitigations usually sit on refined, intermediate steps).
    const inTree = (e: Expr | null, seen = new Set<string>()): boolean =>
      refsOf(e).some((n) => {
        if (names.has(n)) return true
        if (seen.has(n)) return false
        seen.add(n)
        return inTree(doc.stepByName.get(n)?.refinedBy ?? null, seen)
      })
    return Object.values(doc.model.threatScenarios).filter((t) => inTree(t.threatenedBy))
  }, [doc.model.threatScenarios, doc.stepByName, mitigated])
  return (
    <div className="panel">
      <Head kind="Security control" name={c.name} right={<EditedMark kind="control" id={c.id} />} />
      <NameField value={c.name} taken={(n) => Object.values(doc.model.controls).some((x) => x.name === n)} onCommit={(n) => upd({ name: n })} />
      <Field label="Title" value={c.title} onChange={(v) => upd({ title: v })} />
      <Field label="Description" multiline value={c.description} onChange={(v) => upd({ description: v })} />
      {c.classRef ? <p className="muted small">Catalog class: <code>{c.classRef.replace(/^mps\/r:[^(]*/, '')}</code></p> : null}
      <label className="field">
        <span>Status (counts for residual risk unless Planned)</span>
        <select value={meta.status} onChange={(e) => doc.actions.setControlMeta(id, { status: e.target.value as typeof meta.status })}>
          {['Planned', 'Implemented', 'Verified'].map((s) => (
            <option key={s}>{s}</option>
          ))}
        </select>
      </label>

      <Section title="Effect">
        <label className="check">
          <input type="checkbox" checked={removes} onChange={(e) => upd({ effects: e.target.checked ? [...c.effects.filter((x) => x !== 'RemoveAllDamage'), 'RemoveAllDamage'] : c.effects.filter((x) => x !== 'RemoveAllDamage') })} />
          <span>Removes all damage (XSAM <code>RemoveAllDamage</code>)</span>
        </label>
        <p className="muted small">Attack potential to bypass the control (optional). If set, residual risk raises the mitigated steps to at least these values; if empty, the mitigated steps are removed from the attack paths.</p>
        <div className="floors">
          {CATEGORIES.map((cat) => (
            <label key={cat} title={CATEGORY_LABEL[cat]}>
              <span className="cat">{CATEGORY_PREFIX[cat]}</span>
              <input
                type="number"
                min={0}
                placeholder="–"
                value={c.ratings[cat]?.value ?? ''}
                onChange={(e) => {
                  const ratings = { ...c.ratings }
                  if (e.target.value === '') delete ratings[cat]
                  else ratings[cat] = { ...ratings[cat], value: Math.max(0, Number(e.target.value)) }
                  upd({ ratings })
                }}
              />
            </label>
          ))}
        </div>
        <p className="small">{rated ? 'Residual: bypass needs this attack potential.' : 'Residual: mitigated steps are cut off.'}</p>
      </Section>

      <Section title={`Mitigates attack steps (${mitigated.length})`}>
        <MultiPicker
          options={stepOpts}
          value={mitigated.map((s) => s.id)}
          onChange={(v) => {
            for (const s of mitigated) if (!v.includes(s.id)) doc.actions.setMitigation(s.id, c.name, false)
            for (const sid of v) if (!mitigated.some((s) => s.id === sid)) doc.actions.setMitigation(sid, c.name, true)
          }}
          placeholder="attack step"
          render={(sid) => <a onClick={() => select({ kind: 'step', id: sid })}>{doc.model.steps[sid]?.name}</a>}
        />
        <p className="muted small">Stored on each step as <code>mitigatedBy</code>; several controls on one step are combined with AND.</p>
      </Section>

      <Section title={`Threat scenarios affected (${risksAffected.length})`}>
        <div className="path-steps">
          {risksAffected.map((t) => (
            <a key={t.id} title={t.title} onClick={() => select({ kind: 'risk', id: t.id })}>
              {t.name}
            </a>
          ))}
        </div>
      </Section>

      <Section title="Acts on">
        <ToeePicker value={c.actedOn} onChange={(v) => upd({ actedOn: v })} />
      </Section>
      <Section title="Fulfils goals">
        <MultiPicker options={goalOpts} value={meta.goalIds} onChange={(v) => doc.actions.setControlMeta(id, { goalIds: v })} placeholder="goal" render={(gid) => <a onClick={() => select({ kind: 'goal', id: gid })}>{doc.extras.goals[gid]?.name}</a>} />
      </Section>
      <ReviewBox kind="control" id={id} />
      <Danger
        label="Delete control"
        onClick={() => {
          if (!confirm(`Delete ${c.name}? It is removed from ${mitigated.length} attack step(s).`)) return
          select(null)
          doc.actions.remove('control', id)
        }}
      />
    </div>
  )
}

// ---------------------------------------------------------------------------
// Item definition

function ComponentPanel({ c }: { c: Component }) {
  const doc = useDocCtx()
  const { select } = useUI()
  const upd = (p: Partial<Component>) => doc.actions.update('component', c.id, p)
  const dataOpts = Object.values(doc.model.data).map((d) => ({ id: d.id, label: d.name, sub: d.title }))
  const channels = Object.values(doc.model.channels).filter((ch) => ch.endpoints.includes(c.id))
  const parent = c.parentId ? doc.model.components[c.parentId] : null
  return (
    <div className="panel">
      <Head kind="Component" name={c.name} right={<EditedMark kind="component" id={c.id} />} />
      <Field label="ID" value={c.name} onChange={(v) => upd({ name: v })} />
      <Field label="Title" value={c.title} onChange={(v) => upd({ title: v })} />
      <Field label="Description" multiline value={c.description} onChange={(v) => upd({ description: v })} />
      {parent ? (
        <p className="muted small">
          Part of <a onClick={() => select({ kind: 'component', id: parent.id })}>{parent.name} {parent.title}</a>
        </p>
      ) : null}
      <Section title="Security properties">
        <SecurityPropertiesEditor target={{ kind: 'component', id: c.id }} />
      </Section>
      <Section title="Stored data">
        <MultiPicker options={dataOpts} value={c.storedData} onChange={(v) => upd({ storedData: v })} placeholder="data" render={(id) => <a onClick={() => select({ kind: 'data', id })}>{doc.model.data[id]?.name ?? id}</a>} />
      </Section>
      <Section title={`Channels (${channels.length})`}>
        <ul className="links">
          {channels.map((ch) => (
            <li key={ch.id}>
              <a onClick={() => select({ kind: 'channel', id: ch.id })}>
                <code>{ch.name}</code> {ch.title}
              </a>
            </li>
          ))}
        </ul>
      </Section>
      <div className="actions">
        <button onClick={() => select({ kind: 'component', id: doc.actions.add('component', { parentId: c.id }).id })}>+ Sub-component</button>
      </div>
      <ReviewBox kind="component" id={c.id} />
      <Danger
        label="Delete component"
        onClick={() => {
          if (!confirm(`Delete ${c.name} and its sub-components?`)) return
          select(null)
          doc.actions.remove('component', c.id)
        }}
      />
    </div>
  )
}

function DataPanel({ d }: { d: DataElement }) {
  const doc = useDocCtx()
  const { select } = useUI()
  const upd = (p: Partial<DataElement>) => doc.actions.update('data', d.id, p)
  const where = Object.values(doc.model.components).filter((c) => c.storedData.includes(d.id))
  const ds = Object.values(doc.model.damageScenarios).filter((x) => x.assets.some((a) => a.target.kind === 'data' && a.target.id === d.id))
  const ts = Object.values(doc.model.threatScenarios).filter((x) => x.actedOn.some((a) => a.kind === 'data' && a.id === d.id))
  return (
    <div className="panel">
      <Head kind="Data" name={d.name} right={<EditedMark kind="data" id={d.id} />} />
      <Field label="ID" value={d.name} onChange={(v) => upd({ name: v })} />
      <Field label="Title" value={d.title} onChange={(v) => upd({ title: v })} />
      <Field label="Description" multiline value={d.description} onChange={(v) => upd({ description: v })} />
      <Section title="Security properties">
        <SecurityPropertiesEditor target={{ kind: 'data', id: d.id }} />
      </Section>
      <Section title="Stored in">
        <ul className="links">
          {where.map((c) => (
            <li key={c.id}>
              <a onClick={() => select({ kind: 'component', id: c.id })}>
                <code>{c.name}</code> {c.title}
              </a>
            </li>
          ))}
        </ul>
      </Section>
      <Section title={`Threat scenarios on this asset (${ts.length})`}>
        <ul className="links">
          {ts.map((t) => (
            <li key={t.id}>
              <a onClick={() => select({ kind: 'threat', id: t.id })}>
                <code>{t.name}</code> {t.title}
              </a>
            </li>
          ))}
        </ul>
      </Section>
      <p className="muted small">Concerned asset in {ds.length} damage scenario(s).</p>
      <ReviewBox kind="data" id={d.id} />
      <Danger
        label="Delete data"
        onClick={() => {
          if (!confirm(`Delete ${d.name}? It is removed from ${ds.length} damage scenario(s) and ${ts.length} threat scenario(s).`)) return
          select(null)
          doc.actions.remove('data', d.id)
        }}
      />
    </div>
  )
}

function ChannelPanel({ c }: { c: Channel }) {
  const doc = useDocCtx()
  const { select } = useUI()
  const upd = (p: Partial<Channel>) => doc.actions.update('channel', c.id, p)
  const compOpts = Object.values(doc.model.components).map((x) => ({ id: x.id, label: x.name, sub: x.title }))
  return (
    <div className="panel">
      <Head kind="Channel" name={c.name} right={<EditedMark kind="channel" id={c.id} />} />
      <Field label="ID" value={c.name} onChange={(v) => upd({ name: v })} />
      <Field label="Title" value={c.title} onChange={(v) => upd({ title: v })} />
      <Field label="Description" multiline value={c.description} onChange={(v) => upd({ description: v })} />
      <Section title="Security properties">
        <SecurityPropertiesEditor target={{ kind: 'channel', id: c.id }} />
      </Section>
      <Section title="Endpoints">
        <MultiPicker options={compOpts} value={c.endpoints} onChange={(v) => upd({ endpoints: v })} placeholder="component" render={(id) => <a onClick={() => select({ kind: 'component', id })}>{doc.model.components[id]?.name ?? id}</a>} />
      </Section>
      <ReviewBox kind="channel" id={c.id} />
      <Danger
        label="Delete channel"
        onClick={() => {
          if (!confirm(`Delete ${c.name}?`)) return
          select(null)
          doc.actions.remove('channel', c.id)
        }}
      />
    </div>
  )
}

// ---------------------------------------------------------------------------
// AND/OR expression editing

function GatePanel({ owner, path }: { owner: Owner; path: ExprPath }) {
  const doc = useDocCtx()
  const { select } = useUI()
  const expr = owner.kind === 'threat' ? doc.model.threatScenarios[owner.id]?.threatenedBy : doc.model.steps[owner.id]?.refinedBy
  const gate = getAt(expr ?? null, path)
  if (!gate || gate.kind === 'ref') return <Help />
  const ownerLabel = owner.kind === 'threat' ? doc.model.threatScenarios[owner.id]?.name : doc.model.steps[owner.id]?.name
  const ev = doc.engine.evaluateExpr(gate)
  return (
    <div className="panel">
      <Head kind={`${gate.kind.toUpperCase()} gate`} name={ownerLabel ?? ''} right={<LevelBadge level={ev.level} total={ev.total} />} />
      <p className="muted small">
        In <a onClick={() => select(owner)}>{ownerLabel}</a>. {gate.kind === 'and' ? 'The attacker needs every child: each factor is the highest among them.' : 'The attacker takes the easiest child.'}
      </p>
      <ExprEditor owner={owner} expr={gate} basePath={path} />
    </div>
  )
}

export function ExprEditor({ owner, expr, basePath = [], selfName }: { owner: Owner; expr: Expr | null; basePath?: ExprPath; selfName?: string }) {
  if (!expr) {
    return (
      <div className="expr empty-expr">
        <span className="muted small">{owner.kind === 'step' ? 'Leaf step (rated directly).' : 'Empty.'}</span>
        <StepPicker owner={owner} path={basePath} exclude={selfName} />
      </div>
    )
  }
  return <ExprNode owner={owner} e={expr} path={basePath} isTop selfName={selfName} />
}

function rootExprOf(doc: ReturnType<typeof useDocCtx>, owner: Owner): Expr | null {
  return (owner.kind === 'threat' ? doc.model.threatScenarios[owner.id]?.threatenedBy : doc.model.steps[owner.id]?.refinedBy) ?? null
}

function insertGate(root: Expr | null, path: ExprPath, kind: 'and' | 'or'): Expr | null {
  const go = (e: Expr, p: ExprPath): Expr => {
    if (e.kind === 'ref') return e
    if (p.length === 0) return { ...e, children: [...e.children, { kind, children: [] }] }
    const [h, ...rest] = p
    return { ...e, children: e.children.map((c, i) => (i === h ? go(c, rest) : c)) }
  }
  return root ? go(root, path) : null
}

function ExprNode({ owner, e, path, isTop, selfName }: { owner: Owner; e: Expr; path: ExprPath; isTop?: boolean; selfName?: string }) {
  const doc = useDocCtx()
  const { select } = useUI()
  // A threat scenario's root is a single step in XSAM: grow the tree under that step instead.
  const topOfThreat = owner.kind === 'threat' && isTop
  if (e.kind === 'ref') {
    const st = doc.stepByName.get(e.name)
    const ev = st ? doc.engine.evaluate(e.name) : null
    return (
      <div className="expr-ref">
        <a onClick={() => st && select({ kind: 'step', id: st.id })} className={st ? '' : 'ext'}>
          <code>{e.name}</code> <span className="t">{st?.title ?? 'not in model'}</span>
        </a>
        <LevelBadge level={ev?.level} />
        <span className="row-actions">
          {!topOfThreat ? (
            <>
              <button className="mini" title="Group with a sibling under AND" onClick={() => doc.actions.wrap(owner, path, 'and')}>
                ⊕AND
              </button>
              <button className="mini" title="Group with a sibling under OR" onClick={() => doc.actions.wrap(owner, path, 'or')}>
                ⊕OR
              </button>
            </>
          ) : null}
          <button className="mini danger" title="Remove from this attack path" onClick={() => doc.actions.removeNode(owner, path)}>
            ✕
          </button>
        </span>
        {topOfThreat && st ? (
          <div className="nested">
            <ExprEditor owner={{ kind: 'step', id: st.id }} expr={st.refinedBy} selfName={st.name} />
          </div>
        ) : isTop ? (
          <StepPicker owner={owner} path={path} exclude={selfName} label="+ step (makes AND)" />
        ) : null}
      </div>
    )
  }
  return (
    <div className={`expr gate-${e.kind}`}>
      <div className="expr-gate">
        <div className="seg">
          <button className={e.kind === 'and' ? 'on' : ''} onClick={() => doc.actions.setGate(owner, path, 'and')}>
            AND
          </button>
          <button className={e.kind === 'or' ? 'on' : ''} onClick={() => doc.actions.setGate(owner, path, 'or')}>
            OR
          </button>
        </div>
        <span className="muted small">{e.kind === 'and' ? 'all of' : 'any of'}</span>
        <span className="row-actions">
          <button className="mini" title="Add a nested AND gate" onClick={() => doc.actions.setExpr(owner, insertGate(rootExprOf(doc, owner), path, 'and'))}>
            +AND
          </button>
          <button className="mini" title="Add a nested OR gate" onClick={() => doc.actions.setExpr(owner, insertGate(rootExprOf(doc, owner), path, 'or'))}>
            +OR
          </button>
          <button className="mini danger" title="Remove this gate and everything under it" onClick={() => doc.actions.removeNode(owner, path)}>
            ✕
          </button>
        </span>
      </div>
      <div className="expr-children">
        {e.children.map((c, i) => (
          <ExprNode key={i} owner={owner} e={c} path={[...path, i]} selfName={selfName} />
        ))}
        {e.children.length === 0 ? <span className="muted small">Empty gate: add steps.</span> : null}
        <StepPicker owner={owner} path={path} exclude={selfName} />
      </div>
    </div>
  )
}

export function StepPicker({ owner, path, exclude, label = '+ Add step' }: { owner: Owner; path: ExprPath; exclude?: string; label?: string }) {
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

  if (!open)
    return (
      <button className="mini add" onClick={() => setOpen(true)}>
        {label}
      </button>
    )
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
              const chunkId = owner.kind === 'step' ? doc.model.steps[owner.id]?.chunkId : undefined
              const st = doc.actions.add('step', { title: q.trim(), ...(chunkId ? { chunkId } : {}) })
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
      <button className="mini" onClick={() => setOpen(false)}>
        Cancel
      </button>
    </div>
  )
}
