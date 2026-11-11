import { Handle, Position, type NodeProps } from '@xyflow/react'
import { useDocCtx, useUI } from '../context'
import { formatExpr, refsOf } from '../xsam/expr'
import type { FlowNode, GateNodeData, ScenarioNodeData, StepNodeData } from '../graph'
import { LevelBadge, levelClass, VectorChips } from './Level'

export function StepNode({ data, selected }: NodeProps<FlowNode>) {
  const d = data as StepNodeData
  const { collapsed, toggleCollapsed } = useUI()
  const external = !d.step
  return (
    <div
      className={[
        'node step',
        levelClass(d.evaluation?.level),
        d.onPath ? 'on-path' : '',
        selected ? 'selected' : '',
        external ? 'external' : '',
        d.isRoot ? 'root' : '',
      ].join(' ')}
    >
      <Handle type="target" position={Position.Top} />
      <div className="node-head">
        <code>{d.name}</code>
        <LevelBadge level={d.evaluation?.level} total={d.evaluation?.total} />
      </div>
      <div className="node-title" title={d.step?.description}>
        {external ? 'Not in this catalog' : d.step!.title || <i>untitled</i>}
      </div>
      <div className="node-foot">
        {d.step?.refinedBy ? <span className="muted">refined</span> : <VectorChips vector={d.evaluation?.vector ?? null} />}
        {d.step?.mitigatedBy ? (
          <span className="shield" title={`Mitigated by ${formatExpr(d.step.mitigatedBy)}`}>
            🛡 {refsOf(d.step.mitigatedBy).join(' ')}
          </span>
        ) : null}
        {d.expandable && !d.isRoot ? (
          <button
            className="mini nodrag"
            onClick={(e) => {
              e.stopPropagation()
              toggleCollapsed(d.name)
            }}
            title={collapsed.has(d.name) ? 'Expand refinement' : 'Collapse refinement'}
          >
            {collapsed.has(d.name) ? '▸' : '▾'}
          </button>
        ) : null}
      </div>
      <Handle type="source" position={Position.Bottom} />
    </div>
  )
}

export function GateNode({ data, selected }: NodeProps<FlowNode>) {
  const d = data as GateNodeData
  const { actions } = useDocCtx()
  return (
    <div
      className={`node gate gate-${d.gate} ${d.onPath ? 'on-path' : ''} ${selected ? 'selected' : ''}`}
      title="Double-click to switch AND/OR"
      onDoubleClick={(e) => {
        e.stopPropagation()
        actions.setGate(d.owner, d.path, d.gate === 'and' ? 'or' : 'and')
      }}
    >
      <Handle type="target" position={Position.Top} />
      {d.gate.toUpperCase()}
      <Handle type="source" position={Position.Bottom} />
    </div>
  )
}

export function ScenarioNode({ data, selected }: NodeProps<FlowNode>) {
  const d = data as ScenarioNodeData
  return (
    <div className={`node scenario ${levelClass(d.evaluation.level)} ${selected ? 'selected' : ''}`}>
      <div className="node-head">
        <code>{d.scenario.name}</code>
        <LevelBadge level={d.evaluation.level} total={d.evaluation.total} />
      </div>
      <div className="node-title">{d.scenario.title || <i>untitled</i>}</div>
      <div className="node-foot muted">Threat scenario · {d.scenario.damageScenarioIds.length} damage scenarios</div>
      <Handle type="source" position={Position.Bottom} />
    </div>
  )
}

export const nodeTypes = { step: StepNode, gate: GateNode, scenario: ScenarioNode }
