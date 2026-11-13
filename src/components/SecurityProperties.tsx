import { useMemo } from 'react'
import { useDocCtx, useUI } from '../context'
import { CS_PROPERTIES, CS_PROPERTY_LABEL, type ToeeRef } from '../xsam/types'
import { propertyUsage } from './common'

export const PROPERTY_SHORT: Record<string, string> = { Confi: 'C', Integ: 'I', Avail: 'A', Authe: 'Au', Autho: 'Az', NonRe: 'NR' }

/**
 * The damage scenarios' concerned assets (asset × property) are the source of truth: a property
 * a damage scenario uses is relevant. Manual decisions only matter for properties no damage
 * scenario uses.
 */
export type CellState = 'from-ds' | 'conflict' | 'gap' | 'not-relevant' | 'unset'

export function cellState(relevant: boolean | undefined, uses: number): CellState {
  if (uses) return relevant === false ? 'conflict' : 'from-ds'
  if (relevant === true) return 'gap'
  if (relevant === false) return 'not-relevant'
  return 'unset'
}

export const CELL_TITLE: Record<CellState, string> = {
  'from-ds': 'Relevant: used by damage scenarios',
  conflict: 'Marked not relevant, but damage scenarios use it',
  gap: 'Marked relevant, but no damage scenario covers it yet',
  'not-relevant': 'Not relevant',
  unset: 'Not used by any damage scenario, not decided',
}

export const CELL_MARK: Record<CellState, string> = { 'from-ds': '●', conflict: '!', gap: '◐', 'not-relevant': '○', unset: '·' }

/** Counts for the whole item: gaps and conflicts are what needs attention. */
export function propertySummary(doc: Parameters<typeof propertyUsage>[0]) {
  const usage = propertyUsage(doc)
  const assets = [
    ...Object.keys(doc.model.data).map((id) => `data:${id}`),
    ...Object.keys(doc.model.components).map((id) => `component:${id}`),
    ...Object.keys(doc.model.channels).map((id) => `channel:${id}`),
    ...Object.keys(doc.model.dataflows ?? {}).map((id) => `dataflow:${id}`),
  ]
  const n: Record<CellState, number> = { 'from-ds': 0, conflict: 0, gap: 0, 'not-relevant': 0, unset: 0 }
  for (const key of assets) for (const p of CS_PROPERTIES) n[cellState(doc.extras.assetProperties?.[key]?.[p]?.relevant, usage.get(key)?.get(p)?.length ?? 0)]++
  return n
}

/** Security properties of one asset, shown in its detail panel. */
export function SecurityPropertiesEditor({ target }: { target: ToeeRef }) {
  const doc = useDocCtx()
  const { open } = useUI()
  const key = `${target.kind}:${target.id}`
  const props = doc.extras.assetProperties?.[key] ?? {}
  const usage = useMemo(() => propertyUsage(doc).get(key), [doc, key])
  const dsLink = (n: string) => {
    const d = Object.values(doc.model.damageScenarios).find((x) => x.name === n)
    return (
      <a key={n} title={d?.title} onClick={() => d && open({ kind: 'damage', id: d.id })}>
        {n}
      </a>
    )
  }
  return (
    <div className="props-editor">
      {CS_PROPERTIES.map((p) => {
        const e = props[p]
        const uses = usage?.get(p) ?? []
        const st = cellState(e?.relevant, uses.length)
        return (
          <div key={p} className={`prop-row ps-${st}`}>
            <span className="prop-name" title={CELL_TITLE[st]}>
              <b>{PROPERTY_SHORT[p]}</b> {CS_PROPERTY_LABEL[p]}
            </span>
            {uses.length ? (
              <span className="prop-state">{st === 'conflict' ? <span className="warn">Contradiction</span> : <span className="ok">Relevant</span>}</span>
            ) : (
              <div className="seg">
                <button className={e?.relevant === true ? 'on' : ''} title="Relevant, but no damage scenario covers it yet" onClick={() => doc.actions.setAssetProperty(key, p, e?.relevant === true ? null : { relevant: true })}>
                  Relevant
                </button>
                <button className={e?.relevant === false ? 'on off' : ''} onClick={() => doc.actions.setAssetProperty(key, p, e?.relevant === false ? null : { relevant: false })}>
                  Not relevant
                </button>
              </div>
            )}
            <span className="uses" title={uses.join(', ')}>
              {uses.length ? `${uses.length} DS` : '–'}
            </span>
            {uses.length ? (
              <span className="prop-note small">
                {uses.slice(0, 6).map((n, i) => (
                  <span key={n}>
                    {i ? ', ' : ''}
                    {dsLink(n)}
                  </span>
                ))}
                {uses.length > 6 ? ` +${uses.length - 6}` : ''}
              </span>
            ) : null}
            {st === 'conflict' ? (
              <span className="warn small prop-note">
                Marked not relevant earlier, but the damage scenarios above use it.{' '}
                <a onClick={() => doc.actions.setAssetProperty(key, p, null)}>Clear the old decision</a>
              </span>
            ) : null}
            {st === 'gap' ? <span className="warn small prop-note">No damage scenario covers this yet: add this asset and property to a damage scenario, or mark it not relevant.</span> : null}
            {e && !uses.length ? (
              <input className="rationale" placeholder="Rationale" value={e.rationale} onChange={(ev) => doc.actions.setAssetProperty(key, p, { rationale: ev.target.value })} />
            ) : null}
          </div>
        )
      })}
      <p className="muted small">Relevant properties come from the damage scenarios that list this asset (stored in the .xsam). For properties no damage scenario uses, record whether they are relevant; that decision is saved in the project file.</p>
    </div>
  )
}
