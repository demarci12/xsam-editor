import { createContext, useContext } from 'react'
import type { Root } from './graph'
import type { Doc, Selection } from './store'

export interface UI {
  selection: Selection
  select: (s: Selection) => void
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
