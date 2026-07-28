# ADR-0001: Reader/analyzer split (wire-desktop-core + wire-desktop-forensic)

## Status
Accepted.

## Context
The fleet crate-structure standard (ADR-0008) splits every format into a raw
reader (`<x>-core`) and an anomaly analyzer (`<x>-forensic`). Wire desktop is a
single-format repo (one artifact family: the Wire Chromium IndexedDB store), so
it is a Pattern-A repo (ADR-0009).

## Decision
Two workspace members:

- **`wire-desktop-core`** — interprets the decoded IndexedDB records into typed
  Wire records (conversations, events, users, clients) and a timeline. Exposes
  navigation/records; emits **no** findings.
- **`wire-desktop-forensic`** — depends on `-core` and audits an interpreted
  store into canonical `forensicnomicon::report::Finding`s.

## Consequences
- A consumer that only needs the records (e.g. a timeline view) links the lean
  reader without the analyzer.
- The analyzer keeps its own typed `AnomalyKind` (domain knowledge) and converts
  to the normalized report model, so Wire findings aggregate alongside every
  other fleet analyzer (ADR-0007).
- Crate names follow the naming grammar (ADR-0009): reader `-core`, analyzer
  `-forensic`.
