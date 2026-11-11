import { ReactFlowProvider } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { useEffect, useMemo, useRef, useState } from 'react'
import sampleXml from '../samples/APCatalog1.3.xsam?raw'
import { Canvas } from './components/Canvas'
import { Catalog } from './components/Catalog'
import { Inspector } from './components/Inspector'
import { DocContext, UIContext, type UI } from './context'
import type { Root } from './graph'
import { useDoc, type Selection } from './store'
import { parseXsam, serializeXsam } from './xsam/io'

export default function App() {
  const doc = useDoc()
  const [selection, select] = useState<Selection>(null)
  const [root, setRoot] = useState<Root | null>(null)
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set())
  const fileRef = useRef<HTMLInputElement>(null)

  const ui: UI = useMemo(
    () => ({
      selection,
      select,
      root,
      setRoot,
      collapsed,
      toggleCollapsed: (n) =>
        setCollapsed((s) => {
          const x = new Set(s)
          if (x.has(n)) x.delete(n)
          else x.add(n)
          return x
        }),
    }),
    [selection, root, collapsed],
  )

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement).tagName
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'z') {
        e.preventDefault()
        if (e.shiftKey) doc.redo()
        else doc.undo()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [doc])

  const openXml = (xml: string, fileName: string) => {
    try {
      const model = parseXsam(xml)
      doc.replaceDoc({ model, originalXml: xml, fileName })
      setRoot(model.scenarios[0] ? { kind: 'scenario', id: model.scenarios[0].id } : null)
      select(null)
    } catch (err) {
      alert((err as Error).message)
    }
  }

  const exportXsam = () => {
    const xml = serializeXsam(doc.model, doc.originalXml)
    const blob = new Blob([xml], { type: 'application/xml' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = doc.fileName.endsWith('.xsam') ? doc.fileName : `${doc.fileName}.xsam`
    a.click()
    URL.revokeObjectURL(a.href)
  }

  const stepCount = Object.keys(doc.model.steps).length

  return (
    <DocContext.Provider value={doc}>
      <UIContext.Provider value={ui}>
        <div className="app">
          <header className="topbar">
            <div className="brand">
              <span className="logo">⟁</span> XSAM Attack Path Editor
              <span className="file">{doc.fileName}</span>
              <span className="muted small">
                {doc.model.scenarios.length} scenarios · {stepCount} steps
              </span>
            </div>
            <div className="tools">
              <button onClick={doc.undo} disabled={!doc.canUndo} title="Undo (⌘Z)">↶</button>
              <button onClick={doc.redo} disabled={!doc.canRedo} title="Redo (⇧⌘Z)">↷</button>
              <button
                onClick={() => {
                  if (confirm('Start a new empty catalog? The current one stays in undo history.')) {
                    doc.replaceDoc({ model: { chunks: [], steps: {}, scenarios: [] }, originalXml: null, fileName: 'untitled.xsam' })
                    setRoot(null)
                    select(null)
                  }
                }}
              >
                New
              </button>
              <button onClick={() => fileRef.current?.click()}>Open .xsam…</button>
              <button onClick={() => openXml(sampleXml, 'APCatalog1.3.xsam')}>Load sample</button>
              <button className="primary" onClick={exportXsam} disabled={!stepCount && !doc.model.scenarios.length}>
                Export .xsam
              </button>
              <input
                ref={fileRef}
                type="file"
                accept=".xsam,.xml"
                hidden
                onChange={async (e) => {
                  const f = e.target.files?.[0]
                  if (f) openXml(await f.text(), f.name)
                  e.target.value = ''
                }}
              />
            </div>
          </header>
          <main className="workspace">
            <Catalog />
            <ReactFlowProvider>
              <Canvas />
            </ReactFlowProvider>
            <Inspector />
          </main>
        </div>
      </UIContext.Provider>
    </DocContext.Provider>
  )
}
