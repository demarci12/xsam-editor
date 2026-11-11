import { CATEGORIES, CATEGORY_PREFIX, type FeasibilityLevel } from '../xsam/types'
import type { Vector } from '../xsam/feasibility'

export const levelClass = (l: FeasibilityLevel | null | undefined) =>
  l ? `lvl-${l.toLowerCase().replace(' ', '-')}` : 'lvl-none'

export function LevelBadge({ level, total }: { level: FeasibilityLevel | null | undefined; total?: number | null }) {
  return (
    <span className={`badge ${levelClass(level)}`} title="Attack feasibility (ISO/SAE 21434 attack potential)">
      {level ?? 'unrated'}
      {total !== undefined && total !== null ? <b>{total}</b> : null}
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
