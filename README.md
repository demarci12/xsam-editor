# XSAM Attack Path Editor

A visual editor for XSAM attack step catalogs (security-analyst.org / itemis MPS export, `.xsam`).
It lets you build threat scenarios and attack trees with AND/OR gates, rate attack steps with
ISO/SAE 21434 attack-potential factors, and see the resulting feasibility and attack paths live.

```bash
npm install
npm run dev      # http://localhost:5173
npm test         # parser, feasibility engine, round-trip tests against samples/
```

## What it does

- **Open / export `.xsam`**: export starts from the original file, so data the editor doesn't model
  (threat class refs, TOEEs, reports…) is kept. Autosaves to the browser.
- **Threat scenarios**: create and delete them, and give each an AND/OR attack tree over attack steps.
- **Attack steps**: add, rename, move between groups (SecurityChunks), delete (references to the step are removed too).
- **AND / OR**: in the inspector (AND/OR toggle, ⊕AND/⊕OR to group, +AND/+OR for nested gates) or on
  the canvas (double-click a gate to toggle it; drag from a node's bottom handle to a step; drag a
  catalog step onto a node; Del to remove).
- **Rating**: the five factors (K, W, Ex, Eq, T) with rationale, plus ISO 21434 presets.
- **Feasibility**: AND = max per factor, OR = easiest child, level from the attack-potential sum
  (≤13 High, ≤19 Medium, ≤24 Low, else Very low). This reproduces all 124 stored levels in
  `samples/APCatalog1.3.xsam`.
- **Attack paths**: every concrete path of a scenario, easiest first. The cheapest path is highlighted on the canvas.

## Open points

- **Threat scenario XML shape is provisional.** The sample has no threat scenarios, so they are
  written as `<ThreatScenario name title description attackPaths="or(...)">` in a
  `Threat scenarios` chunk. Replace this with the real XSAM schema once a sample is available (`src/xsam/io.ts`).
- Steps from other catalogs (e.g. `CRYPT.001`) are shown as unresolved, dashed nodes.
- `ConsecutiveFeasibilityOptions` are not edited yet.

## Layout

- `src/xsam/`: format and logic (`io.ts` parse/serialize, `expr.ts` and/or expressions, `feasibility.ts` engine)
- `src/store.ts`: document state, undo/redo, edit actions
- `src/graph.ts`: attack tree → React Flow nodes with dagre layout
- `src/components/`: Catalog (left), Canvas (middle), Inspector (right)
