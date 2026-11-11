// TARA data that XSAM files from this model don't carry yet (treatment, goals, claims,
// controls, review). Stored in the project file next to the .xsam.

import type { Category, ElementKind, FeasibilityLevel, ImpactLevel } from '../xsam/types'

export type TreatmentDecision = 'Avoid' | 'Reduce' | 'Share' | 'Retain'
export const TREATMENTS: TreatmentDecision[] = ['Reduce', 'Avoid', 'Share', 'Retain']

export interface Treatment {
  decision: TreatmentDecision | null
  rationale: string
  goalIds: string[]
  claimIds: string[]
}

export interface Goal {
  id: string
  name: string
  title: string
  description: string
  /** Cybersecurity assurance level 1-4 (ISO/SAE 21434 Annex E), optional. */
  cal: number | null
}

export interface Claim {
  id: string
  name: string
  title: string
  description: string
}

/** A control raises the attack potential of the steps it mitigates (residual risk). */
export interface Control {
  id: string
  name: string
  title: string
  description: string
  /** Attack step names this control applies to. */
  stepNames: string[]
  /** Minimum factor values an attacker faces once the control is in place. */
  floors: Partial<Record<Category, number>>
  goalIds: string[]
  status: 'Planned' | 'Implemented' | 'Verified'
}

export type ReviewStatus = 'Open' | 'In review' | 'Rework' | 'Approved'
export const REVIEW_STATUSES: ReviewStatus[] = ['Open', 'In review', 'Rework', 'Approved']

export interface ReviewComment {
  id: string
  author: string
  at: string
  text: string
  resolved?: boolean
}

export interface ReviewRecord {
  status: ReviewStatus
  checks: Record<string, boolean>
  comments: ReviewComment[]
  approvedBy?: string
  approvedAt?: string
  /** Fingerprint of the element when approved; a later edit reopens the review. */
  approvedHash?: string
}

export type ReviewKind = ElementKind | 'risk' | 'goal' | 'control'

/** Review key: `${kind}:${id}`. */
export type ReviewKey = string

/** ISO/SAE 21434 Annex H example risk matrix: risk[impact][feasibility] in 1..5. */
export type RiskMatrix = Record<ImpactLevel, Record<FeasibilityLevel, number>>

export const DEFAULT_RISK_MATRIX: RiskMatrix = {
  Sev: { 'Very low': 2, Low: 3, Medium: 4, High: 5 },
  Ser: { 'Very low': 1, Low: 2, Medium: 3, High: 4 },
  Mod: { 'Very low': 1, Low: 2, Medium: 2, High: 3 },
  Neg: { 'Very low': 1, Low: 1, Medium: 1, High: 1 },
}

export interface TaraSettings {
  reviewer: string
  riskMatrix: RiskMatrix
  /** Risk values at or above this need treatment other than Retain. */
  acceptThreshold: number
}

export interface TaraExtras {
  treatments: Record<string, Treatment>
  goals: Record<string, Goal>
  claims: Record<string, Claim>
  controls: Record<string, Control>
  reviews: Record<ReviewKey, ReviewRecord>
  settings: TaraSettings
}

export const emptyExtras = (): TaraExtras => ({
  treatments: {},
  goals: {},
  claims: {},
  controls: {},
  reviews: {},
  settings: { reviewer: '', riskMatrix: DEFAULT_RISK_MATRIX, acceptThreshold: 3 },
})

/** Review checklist per element kind. */
export const CHECKLISTS: Record<ReviewKind, { id: string; text: string }[]> = {
  damage: [
    { id: 'desc', text: 'Damage is described from the road user / stakeholder perspective' },
    { id: 'impact', text: 'All relevant impact categories (S, F, O, P) are rated' },
    { id: 'rationale', text: 'Every impact rating has a rationale' },
    { id: 'assets', text: 'Concerned assets and cybersecurity properties are complete' },
  ],
  threat: [
    { id: 'asset', text: 'Asset and violated cybersecurity property are correct (STRIDE fits)' },
    { id: 'ds', text: 'Linked to all damage scenarios it can lead to, and only those' },
    { id: 'path', text: 'Attack tree covers realistic attack paths' },
    { id: 'desc', text: 'Description is understandable without the model' },
  ],
  step: [
    { id: 'ratings', text: 'All five feasibility factors rated (or derived via refinement)' },
    { id: 'rationale', text: 'Ratings have a rationale' },
    { id: 'refine', text: 'Refinement (AND/OR) is complete and correct' },
  ],
  risk: [
    { id: 'value', text: 'Risk value is plausible for impact and feasibility' },
    { id: 'decision', text: 'Treatment decision is recorded with rationale' },
    { id: 'goal', text: 'Reduce → cybersecurity goal; Retain/Share → claim' },
    { id: 'residual', text: 'Residual risk after controls is acceptable' },
  ],
  goal: [
    { id: 'clear', text: 'Goal is stated as a security objective, not a solution' },
    { id: 'cal', text: 'CAL assigned where required' },
  ],
  control: [
    { id: 'effect', text: 'Effect on feasibility (floors) is justified' },
    { id: 'steps', text: 'Applied to the right attack steps' },
  ],
  component: [{ id: 'desc', text: 'Component and its boundary are described' }],
  data: [{ id: 'desc', text: 'Data asset is described and stored where expected' }],
  channel: [{ id: 'desc', text: 'Channel endpoints and technology are correct' }],
}
