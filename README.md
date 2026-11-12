# TARA Studio (XSAM)

An ISO/SAE 21434 TARA tool that works directly on XSAM files (security-analyst.org / itemis MPS
exports, `.xsam`). You can edit, assess and review a whole TARA in the browser, then write it back
to `.xsam` for MPS.

```bash
npm install
npm run dev      # http://localhost:5173
npm test         # parser, feasibility engine, round-trip tests against samples/
```

Everything stays in the browser: it autosaves to IndexedDB, and nothing is uploaded.

## Workflow

| Step | View | Stored in |
| --- | --- | --- |
| Item definition: components (tree), data, channels | Item definition | `.xsam` |
| Damage scenarios: S/F/O/P impact with rationale, concerned assets × CS property | Damage scenarios | `.xsam` |
| Threat scenarios: asset, linked damage scenarios, attack tree root (`threatenedBy`) | Threat scenarios | `.xsam` |
| Attack trees: visual AND/OR editor, cheapest path highlighted, path enumeration | Attack trees | `.xsam` (`refinedBy`) |
| Attack feasibility: K/W/Ex/Eq/T ratings with rationale | Attack steps | `.xsam` |
| Risk determination: impact × feasibility through a configurable risk matrix (Annex H default) | Risks & treatment | computed |
| Risk treatment: Reduce/Avoid/Share/Retain, rationale, goals, claims | Risks & treatment | project file |
| Cybersecurity goals (with CAL) and claims | Goals & claims | project file |
| Security controls (XSAM `Control`, `mitigatedBy` on attack steps) → residual risk | Controls | `.xsam` (status, goals: project file) |
| Review: status, checklist per element type, comments, approval (reopens on edit) | every detail panel, Review | project file |
| UN R155 Annex 5 checklist: relevant / not relevant + rationale | UN R155 checklist | `.xsam` |

**Files**
- **Export .xsam** writes the model back for MPS. Elements you didn't change stay byte-for-byte
  identical, including CRLF line endings and MPS whitespace. Anything the tool doesn't model
  (reports, control scenarios, threat classes, project info) is kept as it was.
- **Save project** writes a `.tara.json` file: the original `.xsam`, the edited model, and the
  treatment, goals, claims, controls and review data, which the XSAM files seen so far have no
  elements for. Open it again with **Open…**.
- **Risks CSV** exports the risk table.

## Calculations

- Attack feasibility: AND takes the highest value of each factor, OR takes the child with the
  lowest total. The sum maps to a level: ≤13 High, ≤19 Medium, ≤24 Low, otherwise Very low. This
  reproduces every stored step level in the sample catalog.
- Impact level: the highest impact category (option index 0–3 → Neg/Mod/Ser/Sev). This reproduces
  every stored level.
- Threat scenario risk uses the worst linked damage scenario and the attack tree's feasibility.
  Explicit levels set in MPS take precedence.
- Residual risk applies every control that isn't marked Planned. A step whose `mitigatedBy`
  holds (several controls combine with AND) either has its path removed (the control has no
  rating, XSAM `RemoveAllDamage`) or needs at least the control's rated attack potential to bypass.
  An AND branch through a removed step fails, and an OR takes the next branch. If every path is
  removed, the residual risk is R1.

**Stale stored levels.** MPS exports can carry stored levels that don't match the model, for
example after edits outside MPS. The dashboard flags `attackFeasibilityLevel` and `impactLevel`
values that differ from what the model computes, and the tool uses the computed values.

**Opening a newer version** of the same MPS model (same `modelRef`) offers to keep review,
treatment, goals and security properties. They're keyed by MPS ids, and approvals of elements
that changed show as "Changed".

## Confidential models

Put customer models in `samples/private/`. That folder is git-ignored; model-specific tests
and edit scripts can live there too (`samples/private/*.test.ts`) and run with the normal test
command. The repository's own tests use the public catalog sample and a synthetic TARA.

## Layout

- `src/xsam/`: XSAM format (`io.ts`), AND/OR expressions, feasibility engine, impact scales
- `src/tara/`: risk computation, treatment/goal/control/review types and checklists
- `src/store.ts`: document state, undo/redo, edit actions, IndexedDB autosave
- `src/views/`: dashboard, tables, risk matrix, review, settings
- `src/components/`: attack tree canvas, inspector panels, review box
