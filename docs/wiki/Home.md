# Welcome to the OpenShomer Wiki

OpenShomer is an open-source autonomous security engineering platform designed to detect, investigate, rewrite, and validate security risks across LLM system prompts, agent configurations, tool definitions, and Model Context Protocol (MCP) servers.

---

## Documentation Index

- [Architecture Overview](Architecture.md)
- [Project Roadmap (v0.1 to v0.5)](Roadmap.md)
- [Threat Models and Risk Taxonomy](Threat-Model.md)
- [Developer Environment & Setup](Developer-Setup.md)

---

## Core Operational Workflow

OpenShomer executes an end-to-end autonomous remediation pipeline:

1. **Ingest / Discover:** Capture agent configuration findings from static scans or issue trackers.
2. **Deep Investigation:** Inspect prompt structures, tool bindings, and permission boundaries using strictly read-only tools.
3. **Minimal Safe Rewrite:** Generate targeted patches that eliminate security vulnerabilities while preserving agent functionality.
4. **Isolated Docker Sandbox & Red-Teaming:** Execute deterministic policy checks and adversarial injection/abuse test suites.
5. **Evidence-Backed Pull Request:** Submit a fully documented GitHub pull request containing cryptographically verifiable evidence.

---

## Technical Architecture Summary

- **Control Plane:** FastAPI application exposing REST endpoints for autonomous lifecycle operations.
- **Package Manager:** Astral uv with deterministic lockfiles.
- **Validation Engine:** Multi-stage static analysis and adversarial simulation.

---

## External Resources

- [Main Repository](https://github.com/kavix/OpenShomer)
- [Issue Tracker](https://github.com/kavix/OpenShomer/issues)
- [Discussions Forum](https://github.com/kavix/OpenShomer/discussions)
- [Contributing Guide](https://github.com/kavix/OpenShomer/blob/main/CONTRIBUTING.md)
