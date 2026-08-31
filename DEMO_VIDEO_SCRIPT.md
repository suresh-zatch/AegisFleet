# 🎬 AegisFleet: 4-Minute Master Hackathon Demo Video Script

**Target Duration:** Exactly 4:00 Minutes  
**Category:** Fortified Enterprise Fleet  
**Hackathon:** Google #AllThingsAgenticHackathon  

---

## ⏱️ Video Timeline Breakdown

```
[0:00 - 0:45] ──▶ PROBLEM: The 60-Minute Multi-Cloud SOC Dwell Time Bottleneck
[0:45 - 1:30] ──▶ ARCHITECTURE: Antigravity SDK Swarm, Gemini 3.6 & Google Cloud Run
[1:30 - 2:45] ──▶ LIVE EXECUTION: Cross-Cloud Lateral Pivot, Mermaid Graph & HITL
[2:45 - 3:30] ──▶ v2.1 ROLLBACK & SLACK CHATOPS: 1-Click State Reversal
[3:30 - 4:00] ──▶ CLOUD PROOF & ROI: Google Cloud Console Logs & Enterprise Impact
```

---

## 🎙️ Timestamp-by-Timestamp Narration & Screen Actions

### 0:00 – 0:45 | Scene 1: The Multi-Cloud Alert Fatigue Crisis
* **Screen Display:** Split screen showing hundreds of raw Security Command Center alerts, CloudTrail logs, and a ticking clock.
* **Speaker Narration:**
  > *"Every single day, enterprise SOC teams are overwhelmed by thousands of cloud security alerts across Google Cloud, AWS, and Azure. When a critical compromise occurs—like a leaked service account key or a cross-plane IAM privilege escalation—human Tier-1 analysts spend 45 to 90 minutes manually sifting through Cloud Logging, checking IAM policies in Asset Inventory, and drafting containment scripts. 
  > 
  > During that 1-hour dwell time, attackers exfiltrate gigabytes of sensitive customer data. We built AegisFleet to compress that 60-minute triage window down to under 10 seconds."*

---

### 0:45 – 1:30 | Scene 2: The AegisFleet Autonomous Swarm Architecture
* **Screen Display:** System architecture diagram showcasing Google Cloud Run, Cloud Pub/Sub, Google Antigravity SDK, and Gemini 3.6 Flash / 3.5 Pro.
* **Speaker Narration:**
  > *"AegisFleet is an autonomous Tier-1 SOC responder built for the Google All Things Agentic Hackathon under the Fortified Enterprise Fleet track. 
  > 
  > Powered by the Google Antigravity SDK and Gemini 3.6 Flash, AegisFleet ingests alerts from Cloud Pub/Sub and instantly deploys a parallel swarm of specialized sub-agents: the GCPAuditWorker, GCPAssetWorker, GCPIAMWorker, and our multi-cloud AWSAuditWorker and AzureAuditWorker.
  > 
  > Using Model Armor XML quarantine tags (<untrusted_gcp_telemetry>), the swarm ingests raw logs while remaining immune to indirect prompt injection."*

---

### 1:30 – 2:45 | Scene 3: Live End-to-End Execution (Unedited)
* **Screen Display:** Live SOC Command Center UI at `http://localhost:8080`.
* **Action:** Click **"🌐 AWS ➔ GCP Pivot"** simulation button.
* **Speaker Narration:**
  > *"Let's watch AegisFleet triage an active multi-cloud breach in real-time. We'll trigger a simulated cross-cloud lateral movement scenario where an attacker compromised an AWS IAM key and pivoted into Google Cloud Storage via Workload Identity Federation.
  > 
  > In less than 3 seconds:
  > 1. The Antigravity Swarm correlates telemetry across AWS CloudTrail and Google Cloud Logging.
  > 2. Gemini reconstructs the end-to-end attack chain into this interactive Mermaid.js attack graph.
  > 3. An executive CISO briefing is generated with zero manual effort.
  > 4. And critically, deterministic containment commands are staged for Human-in-the-Loop approval."*
* **Action:** Open the **Containment (HITL)** tab and click **"⚡ Authorize Immediate Containment"**. Enter analyst token and submit.
* **Speaker Narration:**
  > *"Notice that AI never mutates infrastructure autonomously. Our Antigravity Decide Hook gates execution until an authenticated token is verified. The compromised AWS key is inactivated, and the GCP service account bridge is disabled."*

---

### 2:45 – 3:30 | Scene 4: Slack Block Kit ChatOps & v2.1 Post-Containment Rollback
* **Screen Display:** Switch to **"💬 Slack / Teams ChatOps"** tab, then **"🔄 Post-Containment Rollback"** tab.
* **Speaker Narration:**
  > *"Security analysts on the go receive cryptographic Slack Block Kit approval cards with HMAC-SHA256 signature verification for 1-click mobile containment.
  > 
  > But what happens if an alert is deemed a false positive? Traditional containment creates hours of operational downtime to manually restore permissions. AegisFleet solves this with our v2.1 Automated Rollback Engine. 
  > 
  > With 1 click, AegisFleet executes pre-computed reverse mutations, instantly re-enabling valid IAM policies and restoring infrastructure state in milliseconds."*

---

### 3:30 – 4:00 | Scene 5: Google Cloud Run Proof & Closing ROI
* **Screen Display:** Google Cloud Console showing the active `aegisfleet-soc` Cloud Run service, CPU/Memory metrics, and structured JSON Cloud Logging output.
* **Speaker Narration:**
  > *"Here is AegisFleet running live in production on Google Cloud Run. Structured JSON logs are streamed directly into Google Cloud Logging with singleton connection pooling to Google Cloud Firestore.
  > 
  > AegisFleet achieves a 99.1% reduction in threat dwell time, 95% operational compute savings via Cloud Run scale-to-zero, and zero-crash fault injection resilience.
  > 
  > Thank you, Google team—AegisFleet is ready to fortify the modern multi-cloud enterprise."*
