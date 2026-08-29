# Architecture Overview

OpenShomer operates as a multi-tier autonomous platform that bridges security analysis with automated code remediation.

---

## Component Topology

```
+------------------------------------------------------------------------+
|                          FastAPI Control Plane                         |
+-------------------+--------------------+-------------------------------+
                    |                    |
                    v                    v
         +--------------------+  +----------------------+
         | Investigation Unit |  |  Remediation Engine  |
         +--------------------+  +----------------------+
                    |                    |
                    +---------+----------+
                              |
                              v
                 +--------------------------+
                 | Validation Sandbox       |
                 | - Deterministic Policies |
                 | - Adversarial Red-Team   |
                 +--------------------------+
                              |
                              v
                 +--------------------------+
                 | Evidence-Backed PR Maker |
                 +--------------------------+
```

---

## Key Modules

- **app/api:** REST endpoints for finding lifecycle management (`/findings/ingest`, `/findings/{id}/investigate`, `/findings/{id}/remediate`, `/findings/{id}/validate`, `/findings/{id}/resolve`).
- **app/agents:** Read-only inspection agents and minimal patch generators.
- **app/validation:** Static security policies and red-team test runners.
- **app/github:** Git branch management, atomic commits, and pull request generation with structured evidence attachments.
