import { IMPACT_LABEL, type FeasibilityLevel, type ImpactLevel } from '../xsam/types'
import { CATEGORIES, CATEGORY_PREFIX } from '../xsam/types'
import type { Vector } from '../xsam/feasibility'
import type { ReviewStatus } from '../tara/types'

export const levelClass = (l: FeasibilityLevel | string | null | undefined) => (l ? `lvl-${l.toLowerCase().replace(' ', '-')}` : 'lvl-none')

export function LevelBadge({ level, total, title }: { level: FeasibilityLevel | string | null | undefined; total?: number | null; title?: string }) {
  return (
    <span className={`badge ${levelClass(level)}`} title={title ?? 'Attack feasibility (ISO/SAE 21434 attack potential)'}>
      {level ?? 'unrated'}
      {total !== undefined && total !== null ? <b>{total}</b> : null}
    </span>
  )
}

export function ImpactBadge({ level }: { level: ImpactLevel | string | null | undefined }) {
  return (
    <span className={`badge imp-${(level ?? 'none').toLowerCase()}`} title="Impact level">
      {level ? (IMPACT_LABEL[level as ImpactLevel] ?? level) : 'not rated'}
    </span>
  )
}

export function RiskBadge({ value, title }: { value: number | null | undefined; title?: string }) {
  return (
    <span className={`badge risk risk-${value ?? 0}`} title={title ?? 'Risk value (1–5)'}>
      {value ? `R${value}` : '–'}
    </span>
  )
}

export function ReviewChip({ status, stale }: { status: ReviewStatus | undefined; stale?: boolean }) {
  const s = status ?? 'Open'
  return (
    <span className={`rchip rs-${s.toLowerCase().replace(' ', '-')} ${stale ? 'stale' : ''}`} title={stale ? 'Changed after approval: review again' : `Review: ${s}`}>
      {stale ? 'Changed' : s}
    </span>
  )
}

export function VectorChips({ vector }: { vector: Vector | null }) {
  if (!vector) return <span className="muted">no ratings</span>
  return (
    <span className="chips">
      {CATEGORIES.map((c) => (
        <span key={c} className="chip" title={c}>
          {CATEGORY_PREFIX[c]}
          {vector[c]}
        </span>
      ))}
    </span>
  )
}
