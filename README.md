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
| Controls: per-factor minimum attack potential on mitigated steps → residual risk | Controls | project file |
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
  reproduces every stored step level in both sample files, except the threat-scenario roots
  described below.
- Impact level: the highest impact category (option index 0–3 → Neg/Mod/Ser/Sev). This reproduces
  every stored level.
- Threat scenario risk uses the worst linked damage scenario and the attack tree's feasibility.
  Explicit levels set in MPS take precedence.

**Known data finding:** in `private model v10`, the 23 `AS.TS.*` root steps are stored as "High",
but their own trees compute Low or Medium. For example, `AS.TS.5 = ASC.UDS.012`, and
`ASC.UDS.012` is itself stored as Low. The tool flags these and uses the computed value. Check
them in MPS.

## Confidential models

Put customer models in `samples/private/`. That folder is git-ignored, and the private tests only
run when the file is present there.

## Layout

- `src/xsam/`: XSAM format (`io.ts`), AND/OR expressions, feasibility engine, impact scales
- `src/tara/`: risk computation, treatment/goal/control/review types and checklists
- `src/store.ts`: document state, undo/redo, edit actions, IndexedDB autosave
- `src/views/`: dashboard, tables, risk matrix, review, settings
- `src/components/`: attack tree canvas, inspector panels, review box
