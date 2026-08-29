# Contributing to OpenShomer

Thank you for your interest in contributing to OpenShomer! We welcome contributions from security researchers, AI engineers, and open-source developers.

---

## 🛠️ Development Setup

1. **Install [uv](https://docs.astral.sh/uv/)** (if you do not already have it):

   ```bash
   # macOS / Linux
   curl -LsSf https://astral.sh/uv/install.sh | sh

   # macOS (Homebrew)
   brew install uv

   # Windows
   winget install astral-sh.uv
   ```

2. **Clone the repository:**
   ```bash
   git clone https://github.com/kavix/OpenShomer.git
   cd OpenShomer
   ```

3. **Install dependencies and run the suite:**
   ```bash
   make install
   make test
   make run
   ```

   Without Make, the same steps are:

   ```bash
   uv sync
   uv run pytest -v
   uv run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```

---

## 🎯 How to Contribute

- **New Detection & Ingestion Rules:** Add new agent finding types in `app/models/findings.py`.
- **Red-Team Test Cases:** Add adversarial injection and tool abuse scenarios in `redteam/suites/`.
- **Validation Guardrails:** Enhance deterministic security checks in `app/validation/guardrails.py`.
- **Framework Support:** Add parser tools for LangChain, LlamaIndex, or CrewAI configs.

---

## 📋 Pull Request Guidelines

1. Create a feature branch (`git checkout -b feat/your-feature-name`).
2. Ensure all tests pass (`make test` or `uv run pytest -v`).
3. Commit with clear, descriptive messages following [Conventional Commits](https://www.conventionalcommits.org/).
4. Push your branch and open a PR with the PR template checklist completed.

---

## 📜 Code of Conduct

Please adhere to our [Code of Conduct](CODE_OF_CONDUCT.md) in all project interactions.
