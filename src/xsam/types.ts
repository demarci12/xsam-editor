// Domain model for XSAM (security-analyst.org, itemis MPS export) TARA models.

export const CATEGORIES = ['Knowledge', 'Opportunity', 'Expertise', 'Equipment', 'Time'] as const
export type Category = (typeof CATEGORIES)[number]

/** Option-code prefix used by XSAM for each category, e.g. K1(1), W5(5), Ex0(0), Eq2(2), T0(0). */
export const CATEGORY_PREFIX: Record<Category, string> = {
  Knowledge: 'K',
  Opportunity: 'W',
  Expertise: 'Ex',
  Equipment: 'Eq',
  Time: 'T',
}

export const CATEGORY_LABEL: Record<Category, string> = {
  Knowledge: 'Knowledge of TOE',
  Opportunity: 'Window of opportunity',
  Expertise: 'Specialist expertise',
  Equipment: 'Equipment',
  Time: 'Elapsed time',
}

export type FeasibilityLevel = 'High' | 'Medium' | 'Low' | 'Very low'
export const FEASIBILITY_LEVELS: FeasibilityLevel[] = ['Very low', 'Low', 'Medium', 'High']

/** XSAM impact levels: Negligible, Moderate, Serious (ISO "major"), Severe. */
export type ImpactLevel = 'Neg' | 'Mod' | 'Ser' | 'Sev'
export const IMPACT_LEVELS: ImpactLevel[] = ['Neg', 'Mod', 'Ser', 'Sev']
export const IMPACT_LABEL: Record<ImpactLevel, string> = { Neg: 'Negligible', Mod: 'Moderate', Ser: 'Major', Sev: 'Severe' }

/** Impact categories: Safety, Financial, Operational, Privacy. */
export const IMPACT_CATEGORIES = ['S', 'F', 'O', 'P'] as const
export type ImpactCategory = (typeof IMPACT_CATEGORIES)[number]
export const IMPACT_CATEGORY_LABEL: Record<ImpactCategory, string> = { S: 'Safety', F: 'Financial', O: 'Operational', P: 'Privacy' }

/** Cybersecurity properties as named in XSAM. */
export const CS_PROPERTIES = ['Confi', 'Integ', 'Avail', 'Authe', 'Autho', 'NonRe'] as const
export type CsProperty = (typeof CS_PROPERTIES)[number] | (string & {})
export const CS_PROPERTY_LABEL: Record<string, string> = {
  Confi: 'Confidentiality',
  Integ: 'Integrity',
  Avail: 'Availability',
  Authe: 'Authenticity',
  Autho: 'Authorization',
  NonRe: 'Non-repudiation',
}

export interface Rating {
  value: number
  rationale?: string
}

/** A refinement expression: how a step is achieved by other steps. */
export type Expr =
  | { kind: 'ref'; name: string }
  | { kind: 'and' | 'or'; children: Expr[] }

/** Reference to an item-definition element (target of evaluation). */
export interface ToeeRef {
  kind: 'data' | 'component' | 'channel' | 'dataflow'
  /** MPS id of the referenced element (local model) or the full target string when external. */
  id: string
}

export interface AttackStep {
  id: string
  name: string
  title: string
  description: string
  chunkId: string
  ratings: Partial<Record<Category, Rating>>
  refinedBy: Expr | null
  /** Security controls that mitigate this step, e.g. `and(SC.1.3, SC.2.0)`. */
  mitigatedBy: Expr | null
  actedOn: ToeeRef[]
  storedLevel?: string
}

/** XSAM security control (instance of a control-catalog class). */
export interface SecurityControl {
  id: string
  name: string
  title: string
  description: string
  chunkId: string
  /** Reference to the catalog control class (external), kept verbatim. */
  classRef: string | null
  /** Effect element names, e.g. ['RemoveAllDamage']. */
  effects: string[]
  /** Attack potential an attacker needs to overcome the control (optional). */
  ratings: Partial<Record<Category, Rating>>
  actedOn: ToeeRef[]
  /** Feasibility of bypassing the control as stored by MPS. */
  storedLevel?: string
  /** The control cannot be bypassed. */
  isImpossible?: boolean
  /** Bypassing the control means achieving this threat scenario (e.g. TS.9.1). */
  dependsOn?: string
}

export interface ImpactEntry {
  /** Full option code without prefix path, e.g. AB.S3 or XY.F1.0. */
  option: string | null
  rationale?: string
}

export interface QualifiedAsset {
  id: string
  property: CsProperty
  target: ToeeRef
}

export interface DamageScenario {
  id: string
  name: string
  title: string
  description: string
  chunkId: string
  impacts: Partial<Record<ImpactCategory, ImpactEntry>>
  assets: QualifiedAsset[]
  /** Impact scale reference (external AssessmentModel node). */
  scale: string | null
  storedImpactLevel?: string
}

export interface ThreatScenario {
  id: string
  name: string
  title: string
  description: string
  chunkId: string
  /** Attack tree root, normally a single AS.TS.n attack step. */
  threatenedBy: Expr | null
  damageScenarioIds: string[]
  actedOn: ToeeRef[]
  /**
   * Levels stored by MPS. With an attack tree they are MPS's own result (used for comparison);
   * without one, the stored feasibility is the only value and is used as is.
   */
  storedFeasibility?: string
  storedImpact?: string
  storedRisk?: string
  /** Assumptions that cap this scenario's feasibility / impact / risk (XSAM `dampedBy`). */
  dampedBy: string[]
  /** Threat classes (CauseOfCompromise), e.g. GenericCatalog STRIDE classes; references kept verbatim. */
  threatClasses?: string[]
}

/** XSAM assumption; can cap feasibility, impact and risk of the threat scenarios it damps. */
export interface Assumption {
  id: string
  name: string
  title: string
  description: string
  chunkId: string
  maxFeasibility?: string
  maxImpact?: string
  maxRisk?: string
}

/** Data flow inside a channel (read-only in the editor). */
export interface DataFlow {
  id: string
  name: string
  title: string
  description: string
  channelId: string
  source: string | null
  target: string | null
  transferredData: string[]
}

export interface Component {
  id: string
  name: string
  title: string
  description: string
  chunkId: string
  parentId: string | null
  storedData: string[]
}

export interface DataElement {
  id: string
  name: string
  title: string
  description: string
  chunkId: string
}

export interface Channel {
  id: string
  name: string
  title: string
  description: string
  chunkId: string
  endpoints: string[]
}

export interface ChecklistEntry {
  id: string
  kind: 'head' | 'item'
  name: string
  relevant: boolean
  notRelevant: boolean
  rationale: string
}
export interface ChecklistGroup {
  id: string
  name: string
  items: ChecklistEntry[]
}

export type ChunkTag = 'SystemChunk' | 'SecurityChunk' | 'SecurityConceptChunk'
export interface Chunk {
  id: string
  name: string
  tag: ChunkTag
  /** Top-level elements in order (sub-components live under their parent). */
  elementIds: string[]
  /** MPS folder, e.g. "Security Analysis". */
  virtualPackage?: string
  /** DefaultElementType child, e.g. "ElementTypeThreat" for attack steps. */
  elementType?: string
}

export interface XsamModel {
  modelRef: string | null
  projectName: string
  chunks: Chunk[]
  steps: Record<string, AttackStep>
  damageScenarios: Record<string, DamageScenario>
  threatScenarios: Record<string, ThreatScenario>
  components: Record<string, Component>
  data: Record<string, DataElement>
  channels: Record<string, Channel>
  controls: Record<string, SecurityControl>
  dataflows: Record<string, DataFlow>
  assumptions: Record<string, Assumption>
  checklists: Checklist[]
  /**
   * Attack steps from an imported catalog (e.g. APCatalog1.3) that this model references but
   * doesn't define. Used for calculation only, never written back.
   */
  catalogSteps?: Record<string, AttackStep>
  catalogName?: string
}

export interface Checklist {
  id: string
  name: string
  groups: ChecklistGroup[]
}

export const emptyModel = (): XsamModel => ({
  modelRef: null,
  projectName: 'Untitled TARA',
  chunks: [],
  steps: {},
  damageScenarios: {},
  threatScenarios: {},
  components: {},
  data: {},
  channels: {},
  controls: {},
  dataflows: {},
  assumptions: {},
  checklists: [],
})

export type ElementKind = 'step' | 'damage' | 'threat' | 'component' | 'data' | 'channel' | 'control'
