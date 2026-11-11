import { useMemo, useState, type ReactNode } from 'react'
import { useDocCtx, type Selection } from '../context'
import { COLLECTION, elementHash, type Doc } from '../store'
import type { ReviewKind, ReviewRecord } from '../tara/types'
import type { ToeeRef } from '../xsam/types'
import { refsOf } from '../xsam/expr'

export function Field({ label, value, onChange, multiline, placeholder }: { label: string; value: string; onChange: (v: string) => void; multiline?: boolean; placeholder?: string }) {
  return (
    <label className="field">
      <span>{label}</span>
      {multiline ? (
        <textarea value={value} rows={4} placeholder={placeholder} onChange={(e) => onChange(e.target.value)} />
      ) : (
        <input value={value} placeholder={placeholder} onChange={(e) => onChange(e.target.value)} />
      )}
    </label>
  )
}

export function Section({ title, children, right }: { title: ReactNode; children: ReactNode; right?: ReactNode }) {
  return (
    <section className="sect">
      <header>
        <h4>{title}</h4>
        {right}
      </header>
      {children}
    </section>
  )
}

/** The element a review key points at, for approval fingerprints. */
export function reviewTarget(doc: Doc, kind: ReviewKind, id: string): unknown {
  if (kind === 'risk') return { t: doc.extras.treatments[id], ts: doc.model.threatScenarios[id] }
  if (kind === 'goal') return doc.extras.goals[id]
  if (kind === 'control') {
    const meta = doc.extras.controlMeta?.[id]
    const steps = Object.values(doc.model.steps).filter((s) => refsOf(s.mitigatedBy).includes(doc.model.controls[id]?.name ?? '')).map((s) => s.name)
    return { el: doc.model.controls[id], steps, ...(meta ? { meta } : {}) }
  }
  const el = (doc.model[COLLECTION[kind]] as Record<string, unknown>)[id]
  if (kind === 'component' || kind === 'data' || kind === 'channel') {
    // Keep the plain element fingerprint until properties are set, so earlier approvals stay valid.
    const props = doc.extras.assetProperties?.[`${kind}:${id}`]
    return props && Object.keys(props).length ? { el, props } : el
  }
  return el
}

export function useReview(kind: ReviewKind, id: string): { key: string; record: ReviewRecord | undefined; stale: boolean; hash: string } {
  const doc = useDocCtx()
  const key = `${kind}:${id}`
  const record = doc.extras.reviews[key]
  const hash = elementHash(reviewTarget(doc, kind, id))
  const stale = record?.status === 'Approved' && !!record.approvedHash && record.approvedHash !== hash
  return { key, record, stale, hash }
}

export function reviewState(doc: Doc, kind: ReviewKind, id: string) {
  const record = doc.extras.reviews[`${kind}:${id}`]
  const stale = record?.status === 'Approved' && !!record.approvedHash && record.approvedHash !== elementHash(reviewTarget(doc, kind, id))
  return { record, stale, status: stale ? ('Changed' as const) : (record?.status ?? 'Open') }
}

export function toeeName(doc: Doc, r: ToeeRef): { name: string; title: string; missing: boolean } {
  const coll = r.kind === 'data' ? doc.model.data : r.kind === 'component' ? doc.model.components : doc.model.channels
  const el = coll[r.id]
  return el ? { name: el.name, title: el.title, missing: false } : { name: r.id.slice(-12), title: 'external / missing', missing: true }
}

export function ToeeChip({ r, onClick }: { r: ToeeRef; onClick?: () => void }) {
  const doc = useDocCtx()
  const n = toeeName(doc, r)
  return (
    <span className={`tchip t-${r.kind} ${n.missing ? 'missing' : ''}`} title={`${r.kind}: ${n.title}`} onClick={onClick}>
      {n.name}
    </span>
  )
}

export interface PickOption {
  id: string
  label: string
  sub?: string
}

/** Searchable multi-select used for links (damage scenarios, assets, endpoints, steps…). */
export function MultiPicker({ options, value, onChange, placeholder = 'Add…', render }: { options: PickOption[]; value: string[]; onChange: (v: string[]) => void; placeholder?: string; render?: (id: string) => ReactNode }) {
  const [q, setQ] = useState('')
  const [open, setOpen] = useState(false)
  const byId = useMemo(() => new Map(options.map((o) => [o.id, o])), [options])
  const s = q.trim().toLowerCase()
  const results = options.filter((o) => !value.includes(o.id) && (!s || o.label.toLowerCase().includes(s) || o.sub?.toLowerCase().includes(s))).slice(0, 40)
  return (
    <div className="mpick">
      <div className="mpick-vals">
        {value.map((id) => (
          <span key={id} className="mval">
            {render ? render(id) : <span title={byId.get(id)?.sub}>{byId.get(id)?.label ?? id}</span>}
            <button className="x" title="Remove" onClick={() => onChange(value.filter((v) => v !== id))}>
              ×
            </button>
          </span>
        ))}
        {!open ? (
          <button className="mini add" onClick={() => setOpen(true)}>
            + {placeholder}
          </button>
        ) : null}
      </div>
      {open ? (
        <div className="picker">
          <input autoFocus placeholder="Search…" value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === 'Escape' && setOpen(false)} />
          <ul>
            {results.map((o) => (
              <li key={o.id} onClick={() => onChange([...value, o.id])}>
                <code>{o.label}</code> <span className="t">{o.sub}</span>
              </li>
            ))}
            {!results.length ? <li className="muted small">No matches</li> : null}
          </ul>
          <button className="mini" onClick={() => setOpen(false)}>
            Done
          </button>
        </div>
      ) : null}
    </div>
  )
}

/** Table filter box + count. */
export function useFilter<T>(rows: T[], text: (r: T) => string) {
  const [q, setQ] = useState('')
  const s = q.trim().toLowerCase()
  const filtered = s ? rows.filter((r) => text(r).toLowerCase().includes(s)) : rows
  const box = <input className="search" placeholder="Filter…" value={q} onChange={(e) => setQ(e.target.value)} />
  return { filtered, box }
}

export const isSelected = (sel: Selection, kind: string, id: string) => !!sel && sel.kind === kind && 'id' in sel && sel.id === id

/** Was this element changed compared with the imported file? */
export function isEdited(doc: Doc, kind: keyof typeof COLLECTION, id: string): 'new' | 'edited' | null {
  if (!doc.baseline) return null
  const coll = COLLECTION[kind]
  const before = (doc.baseline[coll] as Record<string, unknown>)[id]
  const now = (doc.model[coll] as Record<string, unknown>)[id]
  if (!before) return 'new'
  return elementHash({ ...(before as object), chunkId: 0 }) === elementHash({ ...(now as object), chunkId: 0 }) ? null : 'edited'
}

export function EditedMark({ kind, id }: { kind: keyof typeof COLLECTION; id: string }) {
  const doc = useDocCtx()
  const e = isEdited(doc, kind, id)
  return e ? <span className={`edited ${e}`} title={e === 'new' ? 'New since import' : 'Edited since import'}>{e === 'new' ? 'new' : '●'}</span> : null
}

/** How often each asset × security property is used by damage scenarios (concerned assets). */
export function propertyUsage(doc: Doc): Map<string, Map<string, string[]>> {
  const m = new Map<string, Map<string, string[]>>()
  for (const d of Object.values(doc.model.damageScenarios))
    for (const a of d.assets) {
      const key = `${a.target.kind}:${a.target.id}`
      const pm = m.get(key) ?? new Map<string, string[]>()
      pm.set(a.property, [...(pm.get(a.property) ?? []), d.name])
      m.set(key, pm)
    }
  return m
}
