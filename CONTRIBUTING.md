# Contributing to OpenShomer

Thank you for your interest in contributing to OpenShomer! We welcome contributions from security researchers, AI engineers, and open-source developers.

---

## 🛠️ Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/kavix/OpenShomer.git
   cd OpenShomer
   ```

2. **Create a virtual environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Run the test suite:**
   ```bash
   pytest -v
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
2. Ensure all tests pass (`pytest`).
3. Commit with clear, descriptive messages following [Conventional Commits](https://www.conventionalcommits.org/).
4. Push your branch and open a PR with the PR template checklist completed.

---

## 📜 Code of Conduct

Please adhere to our [Code of Conduct](CODE_OF_CONDUCT.md) in all project interactions.
