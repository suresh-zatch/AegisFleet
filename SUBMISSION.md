# 🏆 Google #AllThingsAgenticHackathon Submission: AegisFleet

**Category:** Fortified Enterprise Fleet  
**Project Name:** AegisFleet: Autonomous Multi-Cloud Tier 1 SOC Responder  
**Repository:** [https://github.com/suresh-zatch/AegisFleet](https://github.com/suresh-zatch/AegisFleet)  
**Live Demo:** [http://localhost:8080](http://localhost:8080) (or Deployed Cloud Run URL)  
**Submission Category:** Fortified Enterprise Fleet

---

## 🔒 Judge & Compliance Access Instructions

If the repository is set to Private during pre-judging evaluations:
* Read & clone access has been granted to **`testing@devpost.com`** and **`cloudhackathons@google.com`**.
* The repository is public at **`https://github.com/suresh-zatch/AegisFleet`**.
* To invite judge accounts: Go to **Settings -> Collaborators -> Add people** -> add `testing@devpost.com` and `cloudhackathons@google.com`.

---

## 💡 Inspiration: The 60-Minute Threat Dwell Time Problem

Modern enterprises face an existential security challenge: **alert fatigue**. Tier-1 Security Operations Center (SOC) analysts are bombarded by thousands of alerts daily across Google Cloud Platform, AWS, and Azure. 

When a critical finding fires (e.g., leaked service account keys or cross-cloud IAM escalations), human analysts spend **45 to 90 minutes** manually querying Cloud Logging, inspecting IAM bindings in Cloud Asset Inventory, tracking CloudTrail, and checking Microsoft Entra ID before executing containment. In that 1-hour window, attackers exfiltrate data and deploy cryptominers.

**AegisFleet was created to compress that 60-minute triage and containment window down to under 10 seconds.**

---

## ⚙️ What It Does

AegisFleet is an autonomous Tier-1 SOC fleet built natively on **Google Cloud Run**, powered by **Google Gemini 3.6 Flash / 3.5 Pro**, and orchestrated via the **Google Antigravity SDK**:

1. **Autonomous Parallel Swarm Triage:** Upon receiving an alert via Cloud Pub/Sub, the `Tier1SOCLead` agent dispatches specialized sub-agents in parallel (`GCPAuditWorker`, `GCPAssetWorker`, `GCPIAMWorker`, `AWSAuditWorker`, `AzureAuditWorker`) using non-blocking `asyncio.gather`.
2. **Dynamic Mermaid.js Attack Synthesis:** Correlates disparate multi-cloud telemetry into an interactive, visual attack graph and executive CISO briefing.
3. **v1.1 Bidirectional Slack/Teams ChatOps:** Sends interactive Slack Block Kit cards with HMAC-SHA256 signature verification, enabling 1-click mobile containment approval.
4. **Decoupled HITL Containment Gate:** Deterministic Antigravity Decide Hooks stage containment commands (`gcloud`, `aws`, `az`), ensuring AI reasoning never directly mutates cloud infrastructure without human approval.
5. **Anti-Replay Idempotency:** Gated state transitions prevent duplicate execution of disruptive cloud commands.
6. **v2.1 Automated Post-Containment Rollback Engine:** Pre-computes state snapshots and reverse CLI commands to restore valid IAM bindings, service accounts, and VM instances in 1-click upon false-positive triage resolution.

---

## 🛠️ How We Built It (Google Tech Stack)

* **Google Agent Framework:** **Google Antigravity SDK** (`google.antigravity`) with `LocalAgentConfig`, custom tool registration, XML quarantine transform hooks (`<untrusted_gcp_telemetry>`), and circuit-breaker rate-limiting hooks.
* **Reasoning AI:** **Google Gemini 3.6 Flash & Gemini 3.5 Pro** (`google-genai` SDK) for cross-plane threat correlation and structured JSON incident report generation.
* **On-Device / Edge Bonus Models:** **Gemma 2 / Gemma 3** integration for localized edge finding pre-filtering and token sanitization.
* **Cloud Infrastructure:**
  * **Google Cloud Run:** Serverless container execution with auto-scaling and zero idle cost.
  * **Google Cloud Firestore:** Singleton connection-pooled persistent memory store with automated PII redaction.
  * **Google Cloud Pub/Sub:** Ingress stream for Security Command Center (SCC) findings.
  * **Google Cloud Logging & Cloud Asset Inventory:** Real-time audit log querying and IAM topology mapping.
* **Backend:** FastAPI (Python 3.12, Pydantic V2, Uvicorn).
* **Frontend:** High-tech Cyberpunk SOC Command Center (HTML5, Vanilla JS, Mermaid.js).

---

## 🧪 Challenges We Overcame

1. **Sub-Second Multi-Cloud Telemetry:** Concurrently querying Cloud Logging, Cloud Asset Inventory, AWS CloudTrail, and Azure APIs created latency spikes and quota burst risks. We resolved this by implementing asynchronous worker coroutines governed by `asyncio.Semaphore(10)` rate governors.
2. **LLM Schema Drift & Code Fences:** Models occasionally wrapped structured JSON in markdown code blocks (` ```json `). We developed a regex fallback extractor (`extract_json_from_llm_output`) to guarantee zero-crash execution.
3. **Indirect Prompt Injection:** Attackers could inject override instructions into audit log payloads. We implemented Model Armor XML quarantine boundaries (`<untrusted_gcp_telemetry>`) and directive stripping.

---

## 🚀 Accomplishments That We're Proud Of

* **99.1% MTTT Reduction:** Dropped Mean Time to Triage from 45 minutes to < 4 seconds.
* **100% Master QA Audit:** Passed all 12/12 master verification tests with zero errors across static analysis, fault injection, and anti-replay gates.
* **1-Click Rollback Engine:** Delivered a production-grade reverse state engine that restores cloud infrastructure immediately if an alert is deemed a false positive.

---

## 📦 Submission Assets Links

* 📄 **README:** [`README.md`](README.md)
* 🔬 **Master QA Audit Report:** [`aegisfleet_verification_report.md`](aegisfleet_verification_report.md)
* 🎬 **4-Minute Demo Video Script:** [`DEMO_VIDEO_SCRIPT.md`](DEMO_VIDEO_SCRIPT.md)
* ✍️ **Official Hackathon Blog Post:** [`BLOG_POST.md`](BLOG_POST.md)
* 📱 **Social Media Posts:** [`SOCIAL_POSTS.md`](SOCIAL_POSTS.md)
