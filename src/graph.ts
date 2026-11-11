import dagre from '@dagrejs/dagre'
import type { Edge, Node } from '@xyflow/react'
import type { ExprPath } from './xsam/expr'
import type { Evaluation, FeasibilityEngine } from './xsam/feasibility'
import type { AttackStep, Expr, ThreatScenario } from './xsam/types'
import type { Owner } from './store'

export type StepNodeData = {
  kind: 'step'
  step: AttackStep | null
  name: string
  evaluation: Evaluation | null
  isRoot: boolean
  onPath: boolean
  /** Where this occurrence sits in its parent, so it can be detached. */
  parent: { owner: Owner; path: ExprPath } | null
  expandable: boolean
}
export type GateNodeData = { kind: 'gate'; gate: 'and' | 'or'; owner: Owner; path: ExprPath; onPath: boolean }
export type ScenarioNodeData = { kind: 'scenario'; scenario: ThreatScenario; evaluation: Evaluation }
export type AnyNodeData = StepNodeData | GateNodeData | ScenarioNodeData

export type FlowNode = Node<AnyNodeData>

const SIZE = {
  step: { w: 250, h: 96 },
  gate: { w: 56, h: 56 },
  scenario: { w: 290, h: 96 },
}

export const stepNodeId = (name: string) => `step:${name}`
export const gateNodeId = (owner: Owner, path: ExprPath) => `gate:${owner.kind}:${owner.id}:${path.join('.')}`

export type Root = { kind: 'threat'; id: string } | { kind: 'step'; id: string }

/**
 * Build the visual attack tree for a root. Steps referenced from several places are
 * drawn once (the tree becomes a DAG); gates are drawn per occurrence.
 */
export function buildGraph(
  root: Root,
  data: { steps: Record<string, AttackStep>; threatScenarios: Record<string, ThreatScenario> },
  engine: FeasibilityEngine,
  collapsed: Set<string>,
): { nodes: FlowNode[]; edges: Edge[] } {
  const nodes = new Map<string, FlowNode>()
  const edges: Edge[] = []
  const byName = new Map(Object.values(data.steps).map((s) => [s.name, s]))

  let rootEval: Evaluation
  let rootId: string
  let rootOwner: Owner
  let rootExpr: Expr | null

  if (root.kind === 'threat') {
    const sc = data.threatScenarios[root.id]
    if (!sc) return { nodes: [], edges: [] }
    rootEval = engine.evaluateExpr(sc.threatenedBy)
    rootId = `scenario:${sc.id}`
    rootOwner = { kind: 'threat', id: sc.id }
    rootExpr = sc.threatenedBy
    nodes.set(rootId, { id: rootId, type: 'scenario', position: { x: 0, y: 0 }, data: { kind: 'scenario', scenario: sc, evaluation: rootEval } })
  } else {
    const st = data.steps[root.id]
    if (!st) return { nodes: [], edges: [] }
    rootEval = engine.evaluate(st.name)
    rootId = stepNodeId(st.name)
    rootOwner = { kind: 'step', id: st.id }
    rootExpr = st.refinedBy
    nodes.set(rootId, {
      id: rootId,
      type: 'step',
      position: { x: 0, y: 0 },
      data: { kind: 'step', step: st, name: st.name, evaluation: rootEval, isRoot: true, onPath: true, parent: null, expandable: false },
    })
  }
  const onPath = rootEval.pathSteps

  // Which gates lie on the cheapest path: an OR's chosen child is the one whose steps are on the path.
  const exprOnPath = (e: Expr): boolean => {
    if (e.kind === 'ref') return onPath.has(e.name)
    return e.children.some(exprOnPath)
  }

  const expanded = new Set<string>()

  const addEdge = (source: string, target: string, hot: boolean, meta: { owner: Owner; path: ExprPath }) => {
    const id = `e:${source}->${target}:${meta.path.join('.')}`
    if (edges.some((e) => e.id === id)) return
    edges.push({
      id,
      source,
      target,
      type: 'smoothstep',
      className: hot ? 'edge-hot' : 'edge-cold',
      data: meta,
      animated: hot,
    })
  }

  const walk = (owner: Owner, e: Expr, path: ExprPath, parentNode: string, parentHot: boolean) => {
    const hot = parentHot && exprOnPath(e)
    if (e.kind === 'ref') {
      const id = stepNodeId(e.name)
      const st = byName.get(e.name) ?? null
      const isCollapsed = collapsed.has(e.name)
      if (!nodes.has(id)) {
        nodes.set(id, {
          id,
          type: 'step',
          position: { x: 0, y: 0 },
          data: {
            kind: 'step',
            step: st,
            name: e.name,
            evaluation: st ? engine.evaluate(e.name) : null,
            isRoot: false,
            onPath: onPath.has(e.name),
            parent: { owner, path },
            expandable: !!st?.refinedBy,
          },
        })
      }
      addEdge(parentNode, id, hot, { owner, path })
      if (st?.refinedBy && !expanded.has(e.name) && !isCollapsed) {
        expanded.add(e.name)
        walk({ kind: 'step', id: st.id }, st.refinedBy, [], id, hot)
      }
      return
    }
    const id = gateNodeId(owner, path)
    nodes.set(id, { id, type: 'gate', position: { x: 0, y: 0 }, data: { kind: 'gate', gate: e.kind, owner, path, onPath: hot } })
    addEdge(parentNode, id, hot, { owner, path })
    e.children.forEach((c, i) => walk(owner, c, [...path, i], id, hot))
  }

  if (rootExpr) walk(rootOwner, rootExpr, [], rootId, true)

  // Layout top-down: goal on top, leaf steps at the bottom.
  const g = new dagre.graphlib.Graph()
  g.setGraph({ rankdir: 'TB', nodesep: 28, ranksep: 56, marginx: 20, marginy: 20 })
  g.setDefaultEdgeLabel(() => ({}))
  for (const n of nodes.values()) {
    const s = SIZE[n.type as keyof typeof SIZE]
    g.setNode(n.id, { width: s.w, height: s.h })
  }
  for (const e of edges) g.setEdge(e.source, e.target)
  dagre.layout(g)
  const laid = [...nodes.values()].map((n) => {
    const p = g.node(n.id)
    const s = SIZE[n.type as keyof typeof SIZE]
    return { ...n, position: { x: p.x - s.w / 2, y: p.y - s.h / 2 } }
  })
  return { nodes: laid, edges }
}
