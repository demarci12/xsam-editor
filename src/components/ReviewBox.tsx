import { useState } from 'react'
import { useDocCtx } from '../context'
import { CHECKLISTS, REVIEW_STATUSES, type ReviewKind, type ReviewStatus } from '../tara/types'
import { useReview } from './common'
import { ReviewChip } from './Level'

const fmt = (iso: string) => new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })

export function ReviewBox({ kind, id }: { kind: ReviewKind; id: string }) {
  const doc = useDocCtx()
  const { key, record, stale, hash } = useReview(kind, id)
  const [text, setText] = useState('')
  const checks = CHECKLISTS[kind]
  const done = checks.filter((c) => record?.checks[c.id]).length
  const status: ReviewStatus = record?.status ?? 'Open'
  const openComments = (record?.comments ?? []).filter((c) => !c.resolved).length
  const reviewer = doc.extras.settings.reviewer

  const setStatus = (s: ReviewStatus) => {
    if (s === 'Approved') {
      if (done < checks.length && !confirm(`${checks.length - done} checklist item(s) not ticked. Approve anyway?`)) return
      if (openComments && !confirm(`${openComments} open comment(s). Approve anyway?`)) return
      doc.actions.setReview(key, { status: s, approvedBy: reviewer || 'Reviewer', approvedAt: new Date().toISOString(), approvedHash: hash })
    } else doc.actions.setReview(key, { status: s, approvedBy: undefined, approvedAt: undefined, approvedHash: undefined })
  }

  return (
    <div className={`review ${stale ? 'is-stale' : ''}`}>
      <div className="review-head">
        <h4>Review</h4>
        <ReviewChip status={status} stale={stale} />
        <span className="muted small">
          {done}/{checks.length} checks{openComments ? ` · ${openComments} open comment${openComments > 1 ? 's' : ''}` : ''}
        </span>
      </div>
      {stale ? <p className="warn small">Edited after approval by {record?.approvedBy}: review again.</p> : null}
      {status === 'Approved' && !stale ? (
        <p className="ok small">
          Approved by {record?.approvedBy} · {record?.approvedAt ? fmt(record.approvedAt) : ''}
        </p>
      ) : null}
      <ul className="checklist">
        {checks.map((c) => (
          <li key={c.id}>
            <label>
              <input type="checkbox" checked={!!record?.checks[c.id]} onChange={(e) => doc.actions.setReview(key, { checks: { ...record?.checks, [c.id]: e.target.checked } })} />
              <span>{c.text}</span>
            </label>
          </li>
        ))}
      </ul>
      <div className="seg status-seg">
        {REVIEW_STATUSES.map((s) => (
          <button key={s} className={status === s ? `on rs-${s.toLowerCase().replace(' ', '-')}` : ''} onClick={() => setStatus(s)}>
            {s === 'Approved' ? '✓ Approve' : s}
          </button>
        ))}
      </div>
      <div className="comments">
        {(record?.comments ?? []).map((c) => (
          <div key={c.id} className={`comment ${c.resolved ? 'resolved' : ''}`}>
            <div className="comment-head">
              <b>{c.author}</b>
              <span className="muted small">{fmt(c.at)}</span>
              <button className="mini" onClick={() => doc.actions.updateComment(key, c.id, { resolved: !c.resolved })}>
                {c.resolved ? 'Reopen' : 'Resolve'}
              </button>
            </div>
            <div className="comment-text">{c.text}</div>
          </div>
        ))}
        <textarea
          rows={2}
          placeholder={reviewer ? `Comment as ${reviewer}… (⌘↵ to send)` : 'Comment… (set your name in Settings)'}
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && (e.metaKey || e.ctrlKey) && text.trim()) {
              doc.actions.addComment(key, text.trim())
              setText('')
            }
          }}
        />
        <button
          className="mini"
          disabled={!text.trim()}
          onClick={() => {
            doc.actions.addComment(key, text.trim())
            setText('')
          }}
        >
          Add comment
        </button>
      </div>
    </div>
  )
}
