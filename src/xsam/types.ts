// Domain model for XSAM (security-analyst.org, itemis MPS export) attack step catalogs.

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

export interface Rating {
  value: number
  rationale?: string
}

/** A refinement expression: how a step is achieved by other steps. */
export type Expr =
  | { kind: 'ref'; name: string }
  | { kind: 'and' | 'or'; children: Expr[] }

export interface AttackStep {
  /** MPS node id, stable across edits; generated for new steps. */
  id: string
  /** Catalog identifier, e.g. ASC.0001. Used in refinedBy expressions. */
  name: string
  title: string
  description: string
  chunkId: string
  ratings: Partial<Record<Category, Rating>>
  refinedBy: Expr | null
  /** Level as stored in the imported file (for comparison only). */
  storedLevel?: string
}

export interface Chunk {
  id: string
  name: string
  stepIds: string[]
}

/**
 * A threat scenario: the attacker goal at the top of an attack tree.
 * Its attack paths are an AND/OR expression over attack steps.
 */
export interface ThreatScenario {
  id: string
  name: string
  title: string
  description: string
  attackPaths: Expr | null
}

export interface XsamModel {
  chunks: Chunk[]
  steps: Record<string, AttackStep>
  scenarios: ThreatScenario[]
}
