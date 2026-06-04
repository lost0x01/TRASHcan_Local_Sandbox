# [Requirements] RAIccoon Malware Sandbox POC

**Labels:** `requirements` `epic` `malware-analysis` `purple-team`
**TLP:** TLP:AMBER

## Summary

Functional requirements for the RAIccoon automated malware analysis sandbox. The system ingests a submitted sample, detonates it in an isolated REMnux + FlareVM environment, collects static and dynamic artifacts, runs AI-assisted analysis (Claude primary, Ollama fallback), auto-generates detection rules, produces branded reports, and ingests results into MISP.

This issue tracks the functional requirements the POC must satisfy. Each requirement is testable and maps to existing or planned modules in this repo.

## Architecture (as built)

```
Submission API ──▶ Job Queue (Redis/SQLite) ──▶ VM Manager
      │                                              │
      ▼                                              ▼
Static Analysis                          Snapshot Restore ──▶ FlareVM Detonation
      │                                              │
      │                                   REMnux Network Simulation (INetSim)
      │                                              │
      └────────────▶ Artifact Collector ◀───────────┘
                            │
                     Dynamic Analysis
                            │
                  AI Engine (Claude / Ollama)
                            │
                     Rule Generator (YARA/Sigma/KQL)
                            │
                  Report Generator (docx/pdf/json/md)
                            │
                       MISP Ingest
```

## Functional Requirements

### FR-1 — Sample Submission API
- The orchestrator MUST expose a FastAPI `POST /submit` endpoint accepting a multipart file upload.
- It MUST compute the SHA-256 of the uploaded bytes, assign a UUID `job_id`, and return `job_id` + `sha256` immediately with status `queued`.
- It MUST reject files exceeding the configured `upload_max_mb` limit (default 50 MB) with HTTP 413.
- Analysis MUST run asynchronously; the caller polls for results rather than blocking.
- *Modules:* `orchestrator/main.py`

### FR-2 — Job Status & Listing
- `GET /jobs/{job_id}` MUST return current status (`queued` | `running` | `complete` | `failed`), verdict, family, report URL, MISP event ID, and timestamps.
- `GET /jobs` MUST return all jobs.
- `GET /health` MUST report `queued_jobs` and `running_jobs` counts for liveness probes.
- *Modules:* `orchestrator/main.py`

### FR-3 — Authentication
- All endpoints except `/health` MUST require an `X-API-Key` header validated against `SANDBOX_API_KEY`.
- If no key is configured, the system MUST run in dev mode and log a warning (no silent bypass in production).
- *Modules:* `orchestrator/main.py`

### FR-4 — Job Queue & Concurrency
- The system MUST limit concurrent detonations via a semaphore set to `max_concurrent_jobs` (default 3).
- It MUST support Redis as the queue backend (SQLite for single-node).
- It MUST enforce a per-job detonation timeout (`job_timeout_seconds`, default 300s).
- *Modules:* `orchestrator/main.py`, `docker-compose.yml`

### FR-5 — Static Analysis (pre-detonation)
- The system MUST analyze the raw sample on the orchestrator host (never inside the guest) for: file type, hashes (MD5/SHA1/SHA256), PE headers, imports/exports, section entropy, packer indicators, and embedded strings/IOCs.
- It MUST use `pefile`, `LIEF`, and `python-magic`.
- *Modules:* `analysis/static_analyzer.py`

### FR-6 — VM Lifecycle & Snapshot Hygiene
- Before every detonation the system MUST restore FlareVM to a known-clean snapshot.
- After every detonation — including on failure/exception — it MUST revert FlareVM to clean.
- It MUST start REMnux network simulation before copying the sample to the guest.
- It MUST support AWS as the primary cloud backend (Azure/GCP optional) and a local VirtualBox path for lab use.
- *Modules:* `orchestrator/vm_manager.py`, `scripts/local_vbox_detonate.py`

### FR-7 — Network Isolation & Simulation
- The analysis subnet MUST have NO internet egress; all guest network traffic MUST route through REMnux.
- REMnux MUST simulate internet services via INetSim/FakeNet (http, https, dns, smtp, ftp, irc, tftp), resolving all DNS to the REMnux IP.
- Suricata MUST run on the REMnux interface facing FlareVM, logging to EVE JSON.
- Full PCAP MUST be captured on the analysis interface for the detonation window.
- *Modules:* `scripts/setup_remnux.sh`, `config/config.yaml`

### FR-8 — Detonation & Artifact Collection
- The system MUST copy the sample to FlareVM, execute it, and observe for `analysis_duration` (default 180s).
- It MUST collect: PCAP, Sysmon EVTX, ProcMon PML, memory dump (winpmem), periodic screenshots, and Suricata EVE JSON.
- Collected artifacts MUST be uploaded to object storage (S3/blob) with structured metadata returned to the pipeline.
- It MUST support an emergency kill if ransomware IOCs are detected mid-run (`kill_on_ransom_detect`).
- *Modules:* `orchestrator/artifact_collector.py`, `scripts/setup_flarevm.ps1`

### FR-9 — Dynamic Analysis (artifact parsing)
- The system MUST parse collected artifacts into a unified structured result: process tree, network connections, registry/file events (Sysmon EVTX); IDS alerts, DNS queries, HTTP flows, TLS metadata (Suricata EVE); contacted-services summary (INetSim).
- *Modules:* `analysis/dynamic_analyzer.py`

### FR-10 — AI Analysis Engine
- The system MUST send combined static + dynamic results to an AI backend for: verdict (clean/suspicious/malicious), family classification, executive summary, MITRE ATT&CK TTP mapping, and IOC extraction/enrichment.
- Claude (`claude-opus-4-6`, temp 0.1) MUST be the primary backend; Ollama MUST be the offline/air-gapped fallback with identical prompts for hot-swap.
- On primary failure it MUST automatically retry with the fallback; if both fail it MUST return an `unknown` verdict rather than crash the pipeline.
- It MUST apply a configurable `confidence_threshold` (default 0.70) for auto-classification.
- *Modules:* `ai/claude_analyzer.py`, `ai/ollama_analyzer.py`

### FR-11 — Detection Rule Generation
- The system MUST auto-generate YARA, Sigma, and KQL detections from analysis results.
- Rules MUST combine AI-generated behavioural rules with deterministic string/import-based construction.
- All generated rules MUST be syntactically validated before being written to storage.
- *Modules:* `ai/rule_generator.py`

### FR-12 — Report Generation
- The system MUST produce reports in docx, pdf, json, and markdown.
- The docx MUST use the Lost Boys Cyber house style, carry the configured TLP marking, and include an AI-usage disclosure.
- Each report MUST cover: Executive Summary, Technical Analysis, IOC Inventory, MITRE ATT&CK Matrix, Detection Rules, and Recommended Actions.
- *Modules:* `reporting/report_generator.py`

### FR-13 — MISP / STIX Ingestion
- When enabled, the system MUST create one MISP event per run containing file-hash attributes, network IOCs, host IOCs, ATT&CK galaxy clusters, YARA/Sigma attachments, the full JSON report, and tags (TLP, source, verdict, family).
- It MUST default to manual review before publishing (`auto_publish: false`).
- It MUST optionally emit a STIX 2.1 bundle.
- *Modules:* `reporting/misp_ingest.py`

### FR-14 — Storage & Retention
- Artifacts MUST be retained per config (PCAPs, memory dumps, raw samples) in S3/blob/local with encryption at rest (SSE-KMS on AWS).
- Storage paths MUST follow the configured layout (samples/, pcaps/, reports/, memory/, rules/, logs/).
- *Modules:* `config/config.yaml`

### FR-15 — Alerting
- The system SHOULD post high-severity findings to a configurable Slack/Teams webhook and optionally email on critical verdicts.
- *Modules:* `config/config.yaml`

### FR-16 — Deployment
- The orchestrator stack (FastAPI + Redis + Ollama + Nginx TLS) MUST be deployable via `docker-compose`.
- AWS infra MUST be provisionable via `scripts/deploy_aws.sh` (isolated VPC, mgmt + analysis subnets, no analysis egress).
- Secrets MUST be supplied via environment (`ANTHROPIC_API_KEY`, `SANDBOX_API_KEY`, `MISP_API_KEY`) — never committed.
- *Modules:* `docker-compose.yml`, `scripts/deploy_aws.sh`

## Known Gaps / TODO

- [ ] **`orchestrator/sample_handler.py` is missing** — `main.py` imports `SampleHandler` but no module exists. Required for FR-1/FR-8 (sample storage). **Blocking.**
- [ ] No `docker/Dockerfile.orchestrator`, `docker/nginx.conf`, or `docker/ssl/` referenced by `docker-compose.yml`.
- [ ] No `.env.example` referenced by the compose usage instructions.
- [ ] Job state is in-memory (`JOBS` dict) — needs Redis hash for multi-worker durability (noted in code).
- [ ] No automated test suite yet (pytest is in requirements but no tests present).
- [ ] REMnux/FlareVM AMI IDs and snapshot IDs are empty placeholders in `config.yaml`.

## Acceptance Criteria

- [ ] A benign EICAR-style sample submitted via `/submit` runs end-to-end and returns a `complete` job with a verdict, a report, and (if enabled) a MISP event.
- [ ] FlareVM is verifiably reverted to clean after a run, including after a forced pipeline failure.
- [ ] No analysis-subnet traffic reaches the real internet (verified by PCAP review).
- [ ] Generated YARA/Sigma/KQL rules pass syntax validation.
- [ ] AI fallback path works with the Claude backend disabled.

---
*Requirements derived from the existing POC codebase. AI-assisted drafting; review before use.*
