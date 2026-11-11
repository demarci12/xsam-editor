import type { Expr } from './types'

/** Parse an XSAM refinedBy string such as `or(and(ASC.0102, ASC.0003), CRYPT.001)`. */
export function parseExpr(src: string | null | undefined): Expr | null {
  if (!src || !src.trim()) return null
  let i = 0
  const s = src
  const ws = () => {
    while (i < s.length && /\s/.test(s[i])) i++
  }
  const parse = (): Expr => {
    ws()
    const m = /^[^\s(),]+/.exec(s.slice(i))
    if (!m) throw new Error(`Unexpected "${s.slice(i, i + 10)}" in refinedBy "${src}"`)
    i += m[0].length
    ws()
    const word = m[0]
    if (s[i] === '(' && (word === 'and' || word === 'or')) {
      i++
      const children: Expr[] = []
      ws()
      if (s[i] !== ')') {
        for (;;) {
          children.push(parse())
          ws()
          if (s[i] === ',') {
            i++
            continue
          }
          break
        }
      }
      ws()
      if (s[i] !== ')') throw new Error(`Missing ")" in refinedBy "${src}"`)
      i++
      return { kind: word, children }
    }
    return { kind: 'ref', name: word }
  }
  const e = parse()
  ws()
  if (i !== s.length) throw new Error(`Trailing input in refinedBy "${src}"`)
  return e
}

export function formatExpr(e: Expr | null): string {
  if (!e) return ''
  if (e.kind === 'ref') return e.name
  return `${e.kind}(${e.children.map(formatExpr).join(', ')})`
}

export function refsOf(e: Expr | null, out: string[] = []): string[] {
  if (!e) return out
  if (e.kind === 'ref') out.push(e.name)
  else e.children.forEach((c) => refsOf(c, out))
  return out
}

/** Path into an expression: indices into `children`, [] = root. */
export type ExprPath = number[]

export function getAt(e: Expr | null, path: ExprPath): Expr | null {
  let cur = e
  for (const idx of path) {
    if (!cur || cur.kind === 'ref') return null
    cur = cur.children[idx] ?? null
  }
  return cur
}

function replaceAt(e: Expr, path: ExprPath, fn: (x: Expr) => Expr | null): Expr | null {
  if (path.length === 0) return fn(e)
  if (e.kind === 'ref') return e
  const [head, ...rest] = path
  const children = e.children
    .map((c, i) => (i === head ? replaceAt(c, rest, fn) : c))
    .filter((c): c is Expr => c !== null)
  return { ...e, children }
}

/** Remove empty gates and collapse single-child gates so the expression stays clean. */
export function normalize(e: Expr | null): Expr | null {
  if (!e || e.kind === 'ref') return e
  const children = e.children.map(normalize).filter((c): c is Expr => c !== null)
  if (children.length === 0) return null
  if (children.length === 1) return children[0]
  return { kind: e.kind, children }
}

export function updateAt(e: Expr | null, path: ExprPath, fn: (x: Expr) => Expr | null): Expr | null {
  if (!e) return path.length === 0 ? fn({ kind: 'and', children: [] }) : null
  return replaceAt(e, path, fn)
}

/** Add a reference to a step under the gate at `path` (or the root). */
export function addRef(e: Expr | null, path: ExprPath, name: string, defaultGate: 'and' | 'or' = 'and'): Expr {
  const ref: Expr = { kind: 'ref', name }
  if (!e) return ref
  const target = getAt(e, path)
  if (!target) return e
  const next = replaceAt(e, path, (x) =>
    x.kind === 'ref' ? { kind: defaultGate, children: [x, ref] } : { ...x, children: [...x.children, ref] },
  )
  return next ?? ref
}

export function removeAt(e: Expr | null, path: ExprPath): Expr | null {
  if (!e) return null
  if (path.length === 0) return null
  return normalize(replaceAt(e, path, () => null))
}

export function setGate(e: Expr | null, path: ExprPath, kind: 'and' | 'or'): Expr | null {
  return updateAt(e, path, (x) => (x.kind === 'ref' ? x : { ...x, kind }))
}

/** Wrap the node at `path` together with a new empty slot into a sub-gate. */
export function wrapInGate(e: Expr | null, path: ExprPath, kind: 'and' | 'or'): Expr | null {
  return updateAt(e, path, (x) => ({ kind, children: [x] }))
}

export function renameRef(e: Expr | null, from: string, to: string): Expr | null {
  if (!e) return null
  if (e.kind === 'ref') return e.name === from ? { kind: 'ref', name: to } : e
  return { ...e, children: e.children.map((c) => renameRef(c, from, to)!) }
}

export function removeRefsTo(e: Expr | null, name: string): Expr | null {
  if (!e) return null
  if (e.kind === 'ref') return e.name === name ? null : e
  return normalize({ ...e, children: e.children.map((c) => removeRefsTo(c, name)).filter((c): c is Expr => !!c) })
}
