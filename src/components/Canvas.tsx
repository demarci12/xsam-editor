import {
  Background,
  Controls,
  MiniMap,
  ReactFlow,
  useNodesState,
  useReactFlow,
  type Connection,
  type Edge,
  type NodeChange,
} from '@xyflow/react'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { DND_STEP, useDocCtx, useUI } from '../context'
import { buildGraph, type AnyNodeData, type FlowNode } from '../graph'
import type { Owner } from '../store'
import type { ExprPath } from '../xsam/expr'
import { nodeTypes } from './nodes'

/** Which expression a connection/drop from this node edits. */
function ownerOf(node: FlowNode | undefined, stepIdByName: (n: string) => string | undefined): { owner: Owner; path: ExprPath } | null {
  if (!node) return null
  const d = node.data as AnyNodeData
  if (d.kind === 'scenario') {
    // XSAM threat scenarios point at one root attack step (AS.TS.n); grow that step's tree.
    const root = d.scenario.threatenedBy
    const rootId = root?.kind === 'ref' ? stepIdByName(root.name) : undefined
    if (rootId) return { owner: { kind: 'step', id: rootId }, path: [] }
    return { owner: { kind: 'threat', id: d.scenario.id }, path: [] }
  }
  if (d.kind === 'gate') return { owner: d.owner, path: d.path }
  if (d.kind === 'step' && d.step) return { owner: { kind: 'step', id: d.step.id }, path: [] }
  return null
}

export function Canvas() {
  const doc = useDocCtx()
  const { root, selection, select, setRoot, collapsed, theme } = useUI()
  const { screenToFlowPosition, getIntersectingNodes, fitView } = useReactFlow()
  const [toast, setToast] = useState<string | null>(null)

  const graph = useMemo(
    () => (root ? buildGraph(root, doc.model, doc.engine, collapsed) : { nodes: [], edges: [] }),
    [root, doc.model, doc.engine, collapsed],
  )
  const [nodes, setNodes, onNodesChangeBase] = useNodesState<FlowNode>([])

  useEffect(() => {
    // Mark the inspector's selection on the canvas.
    const selId =
      selection?.kind === 'gate'
        ? `gate:${selection.owner.kind}:${selection.owner.id}:${selection.path.join('.')}`
        : selection?.kind === 'step'
          ? `step:${doc.model.steps[selection.id]?.name}`
              : selection?.kind === 'threat'
            ? `scenario:${selection.id}`
            : null
    setNodes(graph.nodes.map((n) => ({ ...n, selected: n.id === selId })))
  }, [graph, selection, doc.model.steps, setNodes])

  const rootKey = root ? `${root.kind}:${root.id}` : ''
  useEffect(() => {
    const t = setTimeout(() => fitView({ padding: 0.15, duration: 250 }), 30)
    return () => clearTimeout(t)
  }, [rootKey, fitView])

  const flash = (msg: string) => {
    setToast(msg)
    setTimeout(() => setToast(null), 2500)
  }

  const link = useCallback(
    (from: FlowNode | undefined, stepName: string) => {
      const target = ownerOf(from, (n) => doc.stepByName.get(n)?.id)
      if (!target) return flash('Drop onto a scenario, gate or step')
      if (target.owner.kind === 'step' && doc.model.steps[target.owner.id]?.name === stepName)
        return flash('A step cannot refine itself')
      if (doc.createsCycle(target.owner, stepName)) return flash(`Adding ${stepName} here would create a cycle`)
      doc.actions.addChild(target.owner, target.path, stepName)
    },
    [doc],
  )

  const onConnect = useCallback(
    (c: Connection) => {
      const src = nodes.find((n) => n.id === c.source)
      const tgt = nodes.find((n) => n.id === c.target)
      const td = tgt?.data as AnyNodeData | undefined
      if (td?.kind !== 'step') return flash('Connect to an attack step')
      link(src, td.name)
    },
    [nodes, link],
  )

  const onNodesChange = useCallback(
    (changes: NodeChange<FlowNode>[]) => onNodesChangeBase(changes.filter((c) => c.type !== 'remove')),
    [onNodesChangeBase],
  )

  const onDelete = useCallback(
    ({ nodes: ns, edges: es }: { nodes: FlowNode[]; edges: Edge[] }) => {
      for (const n of ns) {
        const d = n.data as AnyNodeData
        if (d.kind === 'gate') doc.actions.removeNode(d.owner, d.path)
        else if (d.kind === 'step' && d.parent) doc.actions.removeNode(d.parent.owner, d.parent.path)
      }
      if (!ns.length)
        for (const e of es) {
          const m = e.data as { owner: Owner; path: ExprPath } | undefined
          if (m) doc.actions.removeNode(m.owner, m.path)
        }
    },
    [doc.actions],
  )

  const onDrop = useCallback(
    (ev: React.DragEvent) => {
      ev.preventDefault()
      const name = ev.dataTransfer.getData(DND_STEP)
      if (!name) return
      const p = screenToFlowPosition({ x: ev.clientX, y: ev.clientY })
      const hit = getIntersectingNodes({ x: p.x - 1, y: p.y - 1, width: 2, height: 2 })[0] as FlowNode | undefined
      if (!root) {
        const st = doc.stepByName.get(name)
        if (st) setRoot({ kind: 'step', id: st.id })
        return
      }
      link(hit ?? nodes.find((n) => n.id === (root.kind === 'threat' ? `scenario:${root.id}` : `step:${doc.model.steps[root.id]?.name}`)), name)
    },
    [screenToFlowPosition, getIntersectingNodes, root, nodes, link, doc, setRoot],
  )

  return (
    <div className="canvas" onDragOver={(e) => e.preventDefault()} onDrop={onDrop}>
      {!root ? (
        <div className="empty">
          <h2>No attack tree open</h2>
          <p>Pick a threat scenario or attack step on the left, or drag a step here.</p>
        </div>
      ) : null}
      <ReactFlow
        nodes={nodes}
        edges={graph.edges}
        nodeTypes={nodeTypes}
        onNodesChange={onNodesChange}
        onConnect={onConnect}
        onDelete={onDelete}
        deleteKeyCode={['Delete', 'Backspace']}
        onNodeClick={(_, n) => {
          const d = n.data as AnyNodeData
          if (d.kind === 'scenario') select({ kind: 'threat', id: d.scenario.id })
          else if (d.kind === 'gate') select({ kind: 'gate', owner: d.owner, path: d.path })
          else if (d.step) select({ kind: 'step', id: d.step.id })
        }}
        onNodeDoubleClick={(_, n) => {
          const d = n.data as AnyNodeData
          if (d.kind === 'step' && d.step && !d.isRoot) setRoot({ kind: 'step', id: d.step.id })
        }}
        onPaneClick={() => select(null)}
        minZoom={0.1}
        proOptions={{ hideAttribution: true }}
        colorMode={theme}
      >
        <Background gap={24} size={1} />
        <Controls />
        <MiniMap pannable zoomable nodeStrokeWidth={3} />
      </ReactFlow>
      {toast ? <div className="toast">{toast}</div> : null}
      {root ? (
        <div className="legend">
          <span><i className="hot" /> cheapest path (decides feasibility)</span>
          <span>Drag handle ↓ to a step to add it · Del removes · double-click gate toggles AND/OR · double-click step opens it</span>
        </div>
      ) : null}
    </div>
  )
}
