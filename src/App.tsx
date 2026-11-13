import { ReactFlowProvider } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { useEffect, useMemo, useRef, useState } from 'react'
import sampleXml from '../samples/APCatalog1.3.xsam?raw'
import { Canvas } from './components/Canvas'
import { Catalog } from './components/Catalog'
import { reviewState } from './components/common'
import { Inspector } from './components/Inspector'
import { DocContext, UIContext, type Selection, type Theme, type UI, type View } from './context'
import type { Root } from './graph'
import { elementHash, idbGet, idbSet, migrateDoc, useDoc, type DocState } from './store'
import { canSaveInPlace, download, isAbort, pickFileToOpen, pickFileToSave, writeFile, type FileHandle } from './files'
import { computeRisks } from './tara/risk'
import { emptyExtras } from './tara/types'
import { Dashboard, ReviewView, SettingsView } from './views/Overview'
import { ConceptView, ControlsView, DamageView, ItemView, R155View, RisksView, StepsView, ThreatView } from './views/Tables'
import { attachCatalog } from './xsam/catalog'
import { parseXsam, serializeXsam } from './xsam/io'
import { emptyModel } from './xsam/types'

const NAV: { view: View; label: string; group?: string }[] = [
  { view: 'dashboard', label: 'Overview' },
  { view: 'item', label: 'Item definition', group: 'Analysis' },
  { view: 'damage', label: 'Damage scenarios' },
  { view: 'threat', label: 'Threat scenarios' },
  { view: 'trees', label: 'Attack trees' },
  { view: 'steps', label: 'Attack steps' },
  { view: 'risks', label: 'Risks & treatment', group: 'Treatment' },
  { view: 'concept', label: 'Goals & claims' },
  { view: 'controls', label: 'Controls' },
  { view: 'review', label: 'Review', group: 'Quality' },
  { view: 'r155', label: 'UN R155 checklist' },
  { view: 'settings', label: 'Settings' },
]

const KIND_VIEW: Record<string, View> = { step: 'steps', damage: 'damage', threat: 'threat', risk: 'risks', component: 'item', data: 'item', channel: 'item', goal: 'concept', claim: 'concept', control: 'controls', gate: 'trees' }

const PROJECT_FORMAT = 'xsam-tara-project'


export default function App() {
  const doc = useDoc()
  const [view, setView] = useState<View>(() => (location.hash.slice(1) as View) || 'dashboard')
  const [selection, select] = useState<Selection>(null)
  const [root, setRoot] = useState<Root | null>(null)
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set())
  const fileRef = useRef<HTMLInputElement>(null)

  // ---- files: handles of the opened/saved .xsam and project file, and what was last saved ----
  const [handles, setHandles] = useState<{ xsam?: FileHandle; project?: FileHandle }>({})
  const [savedModel, setSavedModel] = useState<unknown>(null)
  const [savedProject, setSavedProject] = useState<{ m: unknown; x: unknown } | null>(null)
  const [saveMsg, setSaveMsg] = useState<string | null>(null)
  const restored = useRef(false)
  const modelHash = (m: unknown) => elementHash(m)
  useEffect(() => {
    // Restore file handles and the saved state after a reload (handles live in IndexedDB).
    if (!doc.loaded || restored.current) return
    restored.current = true
    idbGet<{ xsam?: FileHandle; project?: FileHandle; modelHash?: string; projectHash?: string }>('files')
      .then((f) => {
        if (!f) return
        setHandles({ xsam: f.xsam, project: f.project })
        if (f.modelHash && f.modelHash === modelHash(doc.model)) setSavedModel(doc.model)
        if (f.projectHash && f.projectHash === modelHash({ m: doc.model, x: doc.extras })) setSavedProject({ m: doc.model, x: doc.extras })
      })
      .catch(() => {})
  }, [doc.loaded]) // eslint-disable-line react-hooks/exhaustive-deps
  const persistFiles = (h: { xsam?: FileHandle; project?: FileHandle }, model: unknown, project: { m: unknown; x: unknown } | null) =>
    idbSet('files', { ...h, modelHash: model ? modelHash(model) : undefined, projectHash: project ? modelHash(project) : undefined }).catch(() => {})
  const modelDirty = savedModel !== doc.model
  const projectDirty = !savedProject || savedProject.m !== doc.model || savedProject.x !== doc.extras
  const flash = (msg: string) => {
    setSaveMsg(msg)
    setTimeout(() => setSaveMsg(null), 3000)
  }
  const [theme, setTheme] = useState<Theme>(() => {
    try {
      return localStorage.getItem('tara-theme') === 'dark' ? 'dark' : 'light'
    } catch {
      return 'light'
    }
  })
  useEffect(() => {
    document.documentElement.dataset.theme = theme
    try {
      localStorage.setItem('tara-theme', theme)
    } catch {
      /* per-viewer convenience only */
    }
  }, [theme])

  useEffect(() => {
    history.replaceState(null, '', `#${view}`)
  }, [view])

  const ui: UI = useMemo(
    () => ({
      theme,
      view,
      setView,
      selection,
      select,
      open: (s) => {
        setView(KIND_VIEW[s.kind] ?? 'dashboard')
        select(s)
      },
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
    [theme, view, selection, root, collapsed],
  )

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement).tagName
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 's') {
        e.preventDefault()
        saveRef.current(e.shiftKey)
        return
      }
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'z') {
        e.preventDefault()
        if (e.shiftKey) doc.redo()
        else doc.undo()
      }
      if (e.key === 'Escape') select(null)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [doc])

  /** Returns what was opened (and whether TARA data was kept), or null when opening failed. */
  const openText = (text: string, fileName: string): { kind: 'project' | 'xsam'; keptExtras: boolean } | null => {
    try {
      if (fileName.endsWith('.json')) {
        const p = JSON.parse(text)
        if (p.format !== PROJECT_FORMAT) throw new Error('Not a TARA project file')
        const migrated = migrateDoc({ model: p.model, extras: p.extras, originalXml: p.originalXml, fileName: p.fileName })
        doc.replaceDoc({ ...migrated, model: attachCatalog(migrated.model, sampleXml, 'APCatalog1.3') })
        setRoot(null)
        select(null)
        setView('dashboard')
        return { kind: 'project', keptExtras: true }
      } else {
        // Steps from the bundled APCatalog1.3 that the model references but doesn't define.
        const model = attachCatalog(parseXsam(text), sampleXml, 'APCatalog1.3')
        // A new version of the same MPS model: keep review, treatment, goals and properties
        // (they are keyed by stable MPS ids); approvals of changed elements show as "Changed".
        const hasWork = Object.keys(doc.extras.reviews).length + Object.keys(doc.extras.treatments).length + Object.keys(doc.extras.goals).length + Object.keys(doc.extras.assetProperties ?? {}).length > 0
        const sameModel = !!model.modelRef && model.modelRef === doc.model.modelRef
        const keep = sameModel && hasWork && confirm(`${fileName} is a version of the open model (${model.projectName}). Keep your review, treatment, goals and security properties?`)
        doc.replaceDoc({ model, extras: keep ? doc.extras : emptyExtras(), originalXml: text, fileName })
        setRoot(null)
        select(null)
        setView('dashboard')
        return { kind: 'xsam', keptExtras: keep }
      }
    } catch (err) {
      alert((err as Error).message)
      return null
    }
  }

  const pendingOpen = useRef<{ kind: 'project' | 'xsam'; handles: { xsam?: FileHandle; project?: FileHandle } } | null>(null)
  const openFile = async () => {
    if (!canSaveInPlace()) return fileRef.current?.click()
    try {
      const f = await pickFileToOpen()
      if (!f) return
      const r = openText(f.text, f.name)
      if (!r) return
      const h = r.kind === 'project' ? { project: f.handle } : { xsam: f.handle, ...(r.keptExtras ? { project: handles.project } : {}) }
      setHandles(h)
      pendingOpen.current = { kind: r.kind, handles: h }
    } catch (e) {
      if (!isAbort(e)) alert((e as Error).message)
    }
  }
  useEffect(() => {
    // After opening a file, the opened content is the saved state.
    const p = pendingOpen.current
    if (!p) return
    pendingOpen.current = null
    if (p.kind === 'xsam') {
      setSavedModel(doc.model)
      setSavedProject(null)
      persistFiles(p.handles, doc.model, null)
    } else {
      setSavedModel(null)
      setSavedProject({ m: doc.model, x: doc.extras })
      persistFiles(p.handles, null, { m: doc.model, x: doc.extras })
    }
  }, [doc.model]) // eslint-disable-line react-hooks/exhaustive-deps

  const xsamName = () => (doc.fileName.endsWith('.xsam') ? doc.fileName : `${doc.fileName.replace(/\.(xml|json)$/, '').replace(/\.tara$/, '')}.xsam`)
  const projectName = () => `${xsamName().replace(/\.xsam$/, '')}.tara.json`
  const projectJson = () =>
    JSON.stringify({
      format: PROJECT_FORMAT,
      version: 1,
      savedAt: new Date().toISOString(),
      model: doc.model,
      extras: doc.extras,
      originalXml: doc.originalXml,
      fileName: doc.fileName,
    } satisfies DocState & { format: string; version: number; savedAt: string })

  /** Save the model to its .xsam (in place when it was opened from disk); otherwise download it. */
  const saveXsam = async (as: boolean): Promise<FileHandle | undefined> => {
    const xml = serializeXsam(doc.model, doc.originalXml)
    if (!canSaveInPlace()) {
      download(xsamName(), xml, 'application/xml')
      return undefined
    }
    const handle = !as && handles.xsam ? handles.xsam : await pickFileToSave('xsam', xsamName())
    await writeFile(handle, xml)
    // The saved file is the new baseline for change tracking.
    doc.setFileInfo({ originalXml: xml, fileName: handle.name })
    setSavedModel(doc.model)
    return handle
  }
  /** Save model + review, treatment, goals… as a project file. */
  const saveProject = async (as: boolean): Promise<FileHandle | undefined> => {
    const json = projectJson()
    if (!canSaveInPlace()) {
      download(projectName(), json, 'application/json')
      return undefined
    }
    const handle = !as && handles.project ? handles.project : await pickFileToSave('project', projectName())
    await writeFile(handle, json)
    setSavedProject({ m: doc.model, x: doc.extras })
    return handle
  }
  /** ⌘S: the .xsam, plus the project file when one is linked. ⇧⌘S: save the .xsam as… */
  const save = async (as = false) => {
    try {
      const x = await saveXsam(as)
      const p = handles.project && !as ? await saveProject(false) : undefined
      const h = { ...handles, ...(x ? { xsam: x } : {}), ...(p ? { project: p } : {}) }
      setHandles(h)
      persistFiles(h, doc.model, p ? { m: doc.model, x: doc.extras } : savedProject)
      flash(x ? `Saved ${[x.name, p?.name].filter(Boolean).join(' and ')}` : `Downloaded ${xsamName()}`)
    } catch (e) {
      if (!isAbort(e)) alert(`Saving failed: ${(e as Error).message}`)
    }
  }
  const saveProjectNow = async (as: boolean) => {
    try {
      const p = await saveProject(as)
      const h = { ...handles, ...(p ? { project: p } : {}) }
      setHandles(h)
      persistFiles(h, savedModel, { m: doc.model, x: doc.extras })
      flash(p ? `Saved ${p.name}` : `Downloaded ${projectName()}`)
    } catch (e) {
      if (!isAbort(e)) alert(`Saving failed: ${(e as Error).message}`)
    }
  }
  const saveRef = useRef(save)
  useEffect(() => {
    saveRef.current = save
  })

  const exportRiskCsv = () => {
    const rows = computeRisks(doc.model, doc.extras, doc.engine)
    const q = (s: unknown) => `"${String(s ?? '').replace(/"/g, '""')}"`
    const head = ['TS', 'Threat scenario', 'Damage scenarios', 'Impact', 'Feasibility', 'Risk', 'Treatment', 'Rationale', 'Goals', 'Claims', 'Residual feasibility', 'Residual risk', 'Review', 'Approved by']
    const lines = rows.map((r) => {
      const t = doc.extras.treatments[r.ts.id]
      const rv = reviewState(doc, 'risk', r.ts.id)
      return [
        r.ts.name,
        r.ts.title,
        r.ts.damageScenarioIds.map((id) => doc.model.damageScenarios[id]?.name).join(' '),
        r.impact,
        r.feasibility,
        r.risk,
        t?.decision,
        t?.rationale,
        (t?.goalIds ?? []).map((g) => doc.extras.goals[g]?.name).join(' '),
        (t?.claimIds ?? []).map((g) => doc.extras.claims[g]?.name).join(' '),
        r.residualFeasibility,
        r.residualRisk,
        rv.status,
        rv.record?.approvedBy,
      ]
        .map(q)
        .join(',')
    })
    download(`${doc.model.projectName}-risks.csv`, [head.map(q).join(','), ...lines].join('\n'), 'text/csv')
  }

  const showInspector = view !== 'dashboard' && view !== 'settings' && view !== 'r155'

  return (
    <DocContext.Provider value={doc}>
      <UIContext.Provider value={ui}>
        <div className="app">
          <header className="topbar">
            <div className="brand">
              <span className="logo">⟁</span> TARA Studio
              <span className="file" title={doc.fileName}>
                {doc.model.projectName}
              </span>
              <span className="small muted" title={handles.xsam ? `Saves to ${handles.xsam.name}` : 'Not saved to a file yet'}>
                {handles.xsam?.name ?? doc.fileName}
                {modelDirty ? <span className="dirty" title="Unsaved changes"> ●</span> : null}
              </span>
              {saveMsg ? <span className="ok small">{saveMsg}</span> : null}
              {doc.saveError ? <span className="warn small">Autosave failed</span> : null}
            </div>
            <div className="tools">
              <button className="theme-toggle" onClick={() => setTheme(theme === 'light' ? 'dark' : 'light')} title={theme === 'light' ? 'Switch to dark theme' : 'Switch to light theme'}>
                {theme === 'light' ? '☾' : '☀'}
              </button>
              <button onClick={doc.undo} disabled={!doc.canUndo} title="Undo (⌘Z)">
                ↶
              </button>
              <button onClick={doc.redo} disabled={!doc.canRedo} title="Redo (⇧⌘Z)">
                ↷
              </button>
              <button onClick={openFile} title="Open an .xsam model or a saved .tara.json project">
                Open…
              </button>
              <button onClick={() => save(true)} title="Save the model as a new .xsam file (⇧⌘S)">
                Save as…
              </button>
              <button
                onClick={() => saveProjectNow(!handles.project)}
                title={handles.project ? `Save review, treatment, goals… to ${handles.project.name}` : 'Save model + review, treatment, goals, controls as a project file'}
              >
                Save project{handles.project && projectDirty ? ' ●' : ''}
              </button>
              <button onClick={exportRiskCsv} title="Risk table as CSV">
                Risks CSV
              </button>
              <button className="primary" onClick={() => save(false)} title={handles.xsam ? `Save to ${handles.xsam.name} (⌘S)` : 'Save the model as .xsam for MPS (⌘S)'}>
                Save{modelDirty ? ' ●' : ''}
              </button>
              <input
                ref={fileRef}
                type="file"
                accept=".xsam,.xml,.json"
                hidden
                onChange={async (e) => {
                  const f = e.target.files?.[0]
                  if (f) openText(await f.text(), f.name)
                  e.target.value = ''
                }}
              />
            </div>
          </header>
          <div className="shell">
            <nav className="nav">
              {NAV.map((n) => (
                <div key={n.view}>
                  {n.group ? <div className="nav-group">{n.group}</div> : null}
                  <button
                    className={view === n.view ? 'active' : ''}
                    onClick={() => {
                      setView(n.view)
                      if (n.view !== 'trees') select(null)
                    }}
                  >
                    {n.label}
                  </button>
                </div>
              ))}
              <div className="nav-foot">
                <button
                  className="mini"
                  onClick={() => {
                    if (confirm('Start a new empty TARA? The current one stays in undo history.')) {
                      doc.replaceDoc({ model: emptyModel(), extras: emptyExtras(), originalXml: null, fileName: 'untitled.xsam' })
                      setRoot(null)
                      select(null)
                    }
                  }}
                >
                  New empty
                </button>
                <button className="mini" onClick={() => openText(sampleXml, 'APCatalog1.3.xsam')}>
                  Load sample catalog
                </button>
              </div>
            </nav>
            {!doc.loaded ? (
              <main className="main">
                <p className="muted empty-note">Loading…</p>
              </main>
            ) : view === 'trees' ? (
              <main className="workspace">
                <Catalog />
                <ReactFlowProvider>
                  <Canvas />
                </ReactFlowProvider>
                <Inspector />
              </main>
            ) : (
              <main className={`main ${showInspector && selection ? 'with-inspector' : ''}`}>
                <div className="main-scroll">
                  {Object.keys(doc.model.steps).length === 0 && Object.keys(doc.model.threatScenarios).length === 0 && view === 'dashboard' ? (
                    <div className="welcome">
                      <h2>Open a TARA model</h2>
                      <p>Open an MPS/XSAM export (.xsam) or a saved project (.tara.json). Everything stays in this browser.</p>
                      <button className="primary" onClick={openFile}>
                        Open…
                      </button>
                    </div>
                  ) : (
                    {
                      dashboard: <Dashboard />,
                      item: <ItemView />,
                      damage: <DamageView />,
                      threat: <ThreatView />,
                      steps: <StepsView />,
                      risks: <RisksView />,
                      concept: <ConceptView />,
                      controls: <ControlsView />,
                      review: <ReviewView />,
                      r155: <R155View />,
                      settings: <SettingsView />,
                      trees: null,
                    }[view]
                  )}
                </div>
                {showInspector && selection ? <Inspector onClose={() => select(null)} /> : null}
              </main>
            )}
          </div>
        </div>
      </UIContext.Provider>
    </DocContext.Provider>
  )
}
