import { useMemo } from 'react'
import { useDocCtx, useUI } from '../context'
import { CS_PROPERTIES, CS_PROPERTY_LABEL, type ToeeRef } from '../xsam/types'
import { propertyUsage } from './common'

export const PROPERTY_SHORT: Record<string, string> = { Confi: 'C', Integ: 'I', Avail: 'A', Authe: 'Au', Autho: 'Az', NonRe: 'NR' }

export type CellState = 'relevant' | 'not-relevant' | 'used-unset' | 'used-excluded' | 'unset'

/** Explicit decision wins; otherwise a property used by a damage scenario is "used but not decided". */
export function cellState(relevant: boolean | undefined, uses: number): CellState {
  if (relevant === true) return 'relevant'
  if (relevant === false) return uses ? 'used-excluded' : 'not-relevant'
  return uses ? 'used-unset' : 'unset'
}

export const CELL_TITLE: Record<CellState, string> = {
  relevant: 'Relevant',
  'not-relevant': 'Not relevant',
  'used-unset': 'Used by damage scenarios but not decided yet',
  'used-excluded': 'Marked not relevant, but damage scenarios use it',
  unset: 'Not decided',
}

/** Security properties of one asset, edited in its detail panel. */
export function SecurityPropertiesEditor({ target }: { target: ToeeRef }) {
  const doc = useDocCtx()
  const { open } = useUI()
  const key = `${target.kind}:${target.id}`
  const props = doc.extras.assetProperties?.[key] ?? {}
  const usage = useMemo(() => propertyUsage(doc).get(key), [doc, key])
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
            <div className="seg">
              <button className={e?.relevant === true ? 'on' : ''} onClick={() => doc.actions.setAssetProperty(key, p, e?.relevant === true ? null : { relevant: true })}>
                Relevant
              </button>
              <button className={e?.relevant === false ? 'on off' : ''} onClick={() => doc.actions.setAssetProperty(key, p, e?.relevant === false ? null : { relevant: false })}>
                Not relevant
              </button>
            </div>
            {uses.length ? (
              <span className="uses" title={uses.join(', ')}>
                {uses.length} DS
              </span>
            ) : (
              <span className="uses muted">–</span>
            )}
            {e ? (
              <input className="rationale" placeholder="Rationale" value={e.rationale} onChange={(ev) => doc.actions.setAssetProperty(key, p, { rationale: ev.target.value })} />
            ) : null}
            {st === 'used-excluded' ? (
              <span className="warn small prop-note">
                Not relevant, but used in{' '}
                {uses.slice(0, 3).map((n) => {
                  const d = Object.values(doc.model.damageScenarios).find((x) => x.name === n)
                  return (
                    <a key={n} onClick={() => d && open({ kind: 'damage', id: d.id })}>
                      {n}{' '}
                    </a>
                  )
                })}
                {uses.length > 3 ? `+${uses.length - 3}` : ''}
              </span>
            ) : null}
          </div>
        )
      })}
      <p className="muted small">“DS” shows how many damage scenarios list this asset with that property. Decisions are saved in the project file.</p>
    </div>
  )
}
