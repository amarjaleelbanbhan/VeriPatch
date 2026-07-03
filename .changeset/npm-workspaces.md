---
'veripatch': minor
---

npm workspaces are now scanned correctly from the monorepo root: workspace members'
dependencies (including cross-workspace references through link entries) appear in the graph
with provenance chains that name the owning workspace, e.g. `root > @ws/lib > vulnerable-dep`.
Workspace members themselves are never reported as vulnerabilities — they are first-party code.
