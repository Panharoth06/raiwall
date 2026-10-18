---
trigger: always_on
description: Consult the graphify knowledge graph at graphify-out/ for codebase and architecture questions.
---

## graphify

This project has a graphify knowledge graph at `graphify-out/`.

Rules:
- For codebase or architecture questions, when `graphify-out/graph.json` exists, first run `graphify query "<question>"` or check the graph before scanning raw files.
- Use `graphify path "<A>" "<B>"` for tracing relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, significantly smaller and more focused than raw grep output.
- Read `graphify-out/GRAPH_REPORT.md` for broad architecture review, community clusters, and god nodes.
- After modifying code files in this session, run `graphify update .` to keep the graph current (AST-only, no API cost).
