# Documentation Boundaries

**Status:** Draft. Use this note when deciding whether project notes belong in
the public repository or in local/private storage.

## Public Repository Docs

Committed docs should be safe for a public reader. They can describe what Praxis
is, how it works, and which contracts operators or contributors need to rely on.

Good candidates:

- Architecture and trust boundaries.
- Public-safe product framing.
- Wire protocols and API contracts.
- Audit schemas, evidence maps, and compliance limitations.
- Operator-facing setup and behavior.
- Implementation decisions that are already visible in code.
- Development notes that explain non-sensitive technical choices.

Public docs should avoid naming internal tools or assistants unless the document
is explicitly about internal workflow and is intended to stay private.

## Private Notes

Keep notes private when they would be awkward, misleading, or strategically
unhelpful in a public repository.

Private candidates:

- Competitor comparisons.
- Market wedge, positioning, and "why we beat X" notes.
- Pricing, packaging, tiering, and licensing strategy.
- Roadmap sequencing that has not been made public.
- Private business constraints.
- Personal workflow preferences, API keys, account IDs, and credentials.
- Internal assistant/tooling workflow notes.

## Local Storage

Use `project-docs/` for private project notes in this workspace. That directory
is ignored by `.gitignore`, so files there should not appear in normal git
status output.

Before committing docs, run:

```sh
git status --short --untracked-files=all
git check-ignore -v project-docs/<file>
```

If a private note appears as untracked, stop and either move it under
`project-docs/` or add a more specific ignore rule before continuing.

## Public Framing Guardrails

Praxis should be framed as a Linux fleet lifecycle manager. Access brokering is
part of the product, but not the whole product.

Public docs should describe concrete product and architecture facts:

- Host enrollment and identity.
- Inventory and facts.
- SSH and optional agent transports.
- Package/content lifecycle.
- Patch planning and execution.
- Compliance evidence and remediation.
- Audit and approval flows.

Avoid public framing that defines Praxis mainly by comparison to another
product. Comparisons can be useful in private strategy, but public docs should
stand on Praxis' own model.
