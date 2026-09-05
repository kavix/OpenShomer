# OpenShomer — 3-Minute Demo Video Script & Production Guide

This guide gives you:
1. **The Exact 3-Minute Second-by-Second Recording Script** (what to show on screen + what to say).
2. **A Ready-to-Use Prompt for AI Voiceover / Video Tools** (ElevenLabs, Descript, InVideo, HeyGen, etc.).

---

## Part 1: Second-by-Second Video Recording Plan (3 Minutes Max)

### **Scene 1: The Problem & Vulnerability Overview (0:00 – 0:45)**
- **What to show on screen:**
  - Open VS Code with `demo/vulnerable-agent/`.
  - Show `prompts/system.md` (highlighting the permissive prompt vulnerable to jailbreaks/prompt injection).
  - Show `agent/tools.yaml` (highlighting unrestricted shell/exec privileges without human approval gates).
- **Voiceover / Narration:**
  > *"Hi everyone, we are team KODEGAS, presenting **OpenShomer** for the AI Buildathon.  
  > Today, developers are rapidly building autonomous AI agents with tools, LangChain, CrewAI, and Model Context Protocol servers. But these agents introduce critical security blind spots: over-privileged shell access, hardcoded secrets, and susceptibility to prompt injections.  
  > Traditional security tools only dump noisy alerts. They don't fix the code, and they don't prove if a fix breaks agent functionality. OpenShomer changes this by closing the loop: Find, Investigate, Rewrite, Red-team in sandbox, and open an evidence-backed Pull Request."*

---

### **Scene 2: OpenShomer Scan & Autonomous Investigation (0:45 – 1:30)**
- **What to show on screen:**
  - Switch to your terminal.
  - Run the scan / TUI:
    ```bash
    uv run openshomer tui demo/vulnerable-agent
    ```
    *(Or run the CLI fix command with Alibaba provider:)*
    ```bash
    uv run openshomer fix demo/vulnerable-agent --provider alibaba --model qwen-plus
    ```
  - Show the TUI or terminal output: the autonomous investigation agent parsing the AST, identifying `OVER_PERMISSIONED_TOOL` and `PROMPT_INJECTION_SURFACE`, and synthesizing safe patches using Alibaba Cloud Qwen-2.5-Coder.
- **Voiceover / Narration:**
  > *"Here, we launch OpenShomer against our vulnerable agent.  
  > Powered by Alibaba Cloud Model Studio and the Qwen model family, OpenShomer's investigation agent inspects the full agent configuration and code syntax tree.  
  > It pinpoints the exact root causes, assesses the blast radius, and synthesizes a minimal safe rewrite—hardening the system prompt boundaries and replacing unrestricted shell execution with scoped commands and approval gates, all while preserving developer intent."*

---

### **Scene 3: Isolated Docker Sandbox & Adversarial Red-Teaming (1:30 – 2:15)**
- **What to show on screen:**
  - Show the validation sandbox running in Docker.
  - Highlight the terminal output showing:
    1. Static policy checks passed.
    2. Permission surface reduction diff generated.
    3. Live red-team benchmark running adversarial prompt injection attacks against the newly patched prompt (all blocked / passed).
- **Voiceover / Narration:**
  > *"Detection and rewrites are not enough without proof. OpenShomer boots an isolated Docker sandbox to validate the patch.  
  > It verifies deterministic permission reductions and runs an automated adversarial red-team suite—blasting the patched agent with prompt injections and tool abuse payloads.  
  > Only when every single security test passes does OpenShomer certify the patch."*

---

### **Scene 4: Automated GitHub Pull Request & Conclusion (2:15 – 3:00)**
- **What to show on screen:**
  - Switch to browser on GitHub (`https://github.com/kavix/OpenShomer` or your test agent PR page).
  - Open the newly generated Pull Request.
  - Scroll through the PR description: show the git diff, the before-and-after risk score, and the attached sandbox execution evidence log.
- **Voiceover / Narration:**
  > *"Once validated, OpenShomer automatically cuts a Git branch and opens a GitHub Pull Request.  
  > As you can see, the PR doesn't just show the diff—it includes cryptographic proof, sandbox logs, and adversarial test results, allowing security teams to merge with complete confidence.  
  > Built with Python, FastAPI, and Alibaba Cloud Qwen AI, OpenShomer transforms AI security from manual alert triage into autonomous, verified remediation. Thank you!"*

---

## Part 2: Prompt for AI Voice Generator (ElevenLabs, Descript, TTS)

If you want an AI tool to generate clear, professional voiceover audio, copy and paste this exact prompt:

```text
[Tone: Confident, energetic, professional tech presenter. Pace: Natural, well-paced (approx. 140 words/min). Total duration: ~2.5 minutes.]

Hi everyone, we are team KODEGAS, presenting OpenShomer for the AI Buildathon.

Today, developers are rapidly building autonomous AI agents with tools, LangChain, CrewAI, and Model Context Protocol servers. But these agents introduce critical security blind spots: over-privileged shell access, hardcoded secrets, and susceptibility to prompt injections.

Traditional security tools only dump noisy alerts. They don't fix the code, and they don't prove if a fix breaks agent functionality. OpenShomer changes this by closing the loop: Find, Investigate, Rewrite, Red-team in sandbox, and open an evidence-backed Pull Request.

Here, we launch OpenShomer against our vulnerable agent.

Powered by Alibaba Cloud Model Studio and the Qwen model family, OpenShomer's investigation agent inspects the full agent configuration and code syntax tree. It pinpoints the exact root causes, assesses the blast radius, and synthesizes a minimal safe rewrite—hardening the system prompt boundaries and replacing unrestricted shell execution with scoped commands and approval gates, all while preserving developer intent.

Detection and rewrites are not enough without proof. OpenShomer boots an isolated Docker sandbox to validate the patch. It verifies deterministic permission reductions and runs an automated adversarial red-team suite—blasting the patched agent with prompt injections and tool abuse payloads. Only when every single security test passes does OpenShomer certify the patch.

Once validated, OpenShomer automatically cuts a Git branch and opens a GitHub Pull Request. As you can see, the PR doesn't just show the diff—it includes cryptographic proof, sandbox logs, and adversarial test results, allowing security teams to merge with complete confidence.

Built with Python, FastAPI, and Alibaba Cloud Qwen AI, OpenShomer transforms AI security from manual alert triage into autonomous, verified remediation.

Thank you!
```

---

## Part 3: Prompt for AI Video Tools (InVideo, HeyGen, Synthesia, CapCut)

If you are using an AI video creation tool like InVideo AI, use this prompt:

```text
Create a 3-minute fast-paced tech demo and product showcase video about "OpenShomer - Autonomous Agentic Security Engineer for LLM Systems".

The video should follow this exact 4-stage narrative:
1. (0:00 - 0:45) Introduction to AI agent security risks: Explain that modern LLMs, MCP servers, and tool-calling agents have dangerous vulnerabilities like prompt injection, over-permissioned shell tools, and leaking credentials. Show that current tools only send noisy alerts.
2. (0:45 - 1:30) OpenShomer in action: An autonomous security agent powered by Alibaba Cloud Qwen LLMs scans the agent codebase, analyzes syntax trees, and writes safe minimal code patches preserving developer functionality.
3. (1:30 - 2:15) Automated Red-Teaming in Docker Sandbox: Explain how the patch is tested inside an isolated sandbox using adversarial prompt injection attacks and tool abuse payloads to verify that the attack is blocked.
4. (2:15 - 3:00) Evidence-backed Pull Request on GitHub: Show the final GitHub PR created automatically with test logs, before-and-after diffs, and proof of safety.

Visual style: Modern cybersecurity SaaS, dark mode terminal code aesthetic, glowing blue and green accents, clean software UI captures, professional narration, upbeat modern tech background music.
```
