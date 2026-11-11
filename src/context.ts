import { createContext, useContext } from 'react'
import type { Root } from './graph'
import type { Doc, Owner } from './store'
import type { ExprPath } from './xsam/expr'
import type { ElementKind } from './xsam/types'

export type View =
  | 'dashboard'
  | 'item'
  | 'damage'
  | 'threat'
  | 'trees'
  | 'steps'
  | 'risks'
  | 'concept'
  | 'controls'
  | 'review'
  | 'r155'
  | 'settings'

export type Selection =
  | { kind: ElementKind | 'risk' | 'goal' | 'claim' | 'control'; id: string }
  | { kind: 'gate'; owner: Owner; path: ExprPath }
  | null

export interface UI {
  view: View
  setView: (v: View) => void
  selection: Selection
  select: (s: Selection) => void
  /** Open an element in its natural view. */
  open: (s: NonNullable<Selection>) => void
  root: Root | null
  setRoot: (r: Root | null) => void
  collapsed: Set<string>
  toggleCollapsed: (name: string) => void
}

export const DocContext = createContext<Doc | null>(null)
export const UIContext = createContext<UI | null>(null)

export const useDocCtx = () => useContext(DocContext)!
export const useUI = () => useContext(UIContext)!

/** MIME type for dragging steps from the catalog onto the canvas. */
export const DND_STEP = 'application/x-xsam-step'
