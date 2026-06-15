# AI-Powered Vulnerability Triage Agent

An LLM agent that ingests CVE/vulnerability data, retrieves relevant
historical context via RAG (Retrieval-Augmented Generation), and produces
structured, prioritized remediation reports — turning raw vulnerability
scan output into actionable triage decisions for a security team.

## Why this exists

Security teams are flooded with CVE alerts. Manually triaging each one
against an asset inventory, assessing real-world exploitability, and
deciding what to patch first is slow and inconsistent. This project
demonstrates how an LLM agent, grounded with retrieval over historical
vulnerability data, can automate that first-pass triage — producing
structured priority levels (P0–P3), exploitability reasoning, business
impact assessment, and concrete remediation steps.

## Architecture

```
                ┌─────────────────────┐
  NVD CVE Feed  │  ingest_cves.py      │
  ────────────► │  Fetches & normalizes│
                │  CVE data            │
                └──────────┬───────────┘
                            │
                            ▼
                ┌─────────────────────┐
                │  vector_store.py     │
                │  Embeds CVE          │
                │  descriptions into   │
                │  ChromaDB             │
                └──────────┬───────────┘
                            │ RAG retrieval
                            ▼
                ┌─────────────────────┐
   Asset        │  triage_agent.py     │
   Inventory ──►│  Claude (tool use):  │
                │  - Retrieves similar │
                │    historical CVEs   │
                │  - Reasons about     │
                │    exploitability    │
                │  - Outputs structured│
                │    triage assessment │
                └──────────┬───────────┘
                            │
                            ▼
                ┌─────────────────────┐
                │  api.py (FastAPI)    │
                │  /triage endpoint    │
                └─────────────────────┘
```

## Components

| File | Purpose |
|---|---|
| `src/ingest_cves.py` | Fetches recent CVEs from the NVD API and saves normalized JSON |
| `src/vector_store.py` | Builds a ChromaDB vector store of CVE descriptions for RAG retrieval |
| `src/triage_agent.py` | Core agent: uses Claude with tool use to produce structured triage assessments, grounded with RAG context |
| `src/api.py` | FastAPI service exposing `/triage` and `/rebuild-index` endpoints |
| `data/cves_raw.json` | Sample CVE dataset (10 real, well-known CVEs from 2023-2024) for demo/testing |

## Key techniques demonstrated

- **Tool use / structured output**: the agent uses Claude's tool-calling to
  return strictly-typed triage assessments (priority enum, reasoning,
  remediation steps) rather than free-text.
- **RAG**: before triaging a new CVE, the agent retrieves the most similar
  historical CVEs from a vector store, giving it pattern-matching context
  (e.g., "this looks like the ScreenConnect auth bypass pattern").
- **Asset-aware reasoning**: the agent cross-references CVEs against a
  provided asset inventory (CPE strings) to contextualize impact.
- **Production framing**: exposed via FastAPI so it can be integrated into
  existing SOC tooling (e.g., triggered by a vulnerability scanner webhook).

## Setup

```bash
# Clone and install dependencies
pip install -r requirements.txt

# Set your Anthropic API key
cp .env.example .env
# edit .env and add your key, then:
export ANTHROPIC_API_KEY=your_key_here
```

## Usage

### 1. Ingest fresh CVE data (optional — sample data is included)

```bash
python src/ingest_cves.py
```

Fetches CVEs published in the last 7 days from the NVD API and saves to
`data/cves_raw.json`.

### 2. Build the vector store

```bash
python src/vector_store.py
```

Embeds CVE descriptions into a local ChromaDB collection at
`data/chroma_db/`.

### 3. Run triage on the sample CVEs

```bash
python src/triage_agent.py
```

Outputs prioritized triage assessments for the sample CVEs, e.g.:

```
[P0_IMMEDIATE] CVE-2024-3094
  Impact: Remote code execution via backdoored xz/liblzma library
  Reasoning: Matches known supply-chain compromise pattern...
  Remediation:
    - Immediately downgrade xz to a version prior to 5.6.0
    - Audit systems for indicators of compromise
    - ...
```

### 4. Run as an API

```bash
uvicorn src.api:app --reload
```

Visit `http://localhost:8000/docs` for interactive Swagger documentation.
Example request to `/triage`:

```json
{
  "cves": [
    {
      "cve_id": "CVE-2024-3400",
      "description": "A command injection vulnerability in...",
      "cvss_score": 10.0,
      "severity": "CRITICAL"
    }
  ],
  "asset_inventory": [
    "cpe:2.3:o:paloaltonetworks:pan-os:11.1:*:*:*:*:*:*:*"
  ]
}
```

## Embedding model note

By default this project uses a lightweight offline TF-IDF embedding for
the vector store (zero external downloads, good for demos/restricted
environments). For production-quality semantic retrieval, set
`USE_LOCAL_EMBEDDINGS = False` in `vector_store.py` to use
sentence-transformers (`all-MiniLM-L6-v2`), or swap in an API-based
embedding model (e.g., Voyage AI embeddings, which pair well with Claude).

## Possible extensions

- Slack/email notification for P0 findings
- Integration with vulnerability scanners (Nessus, Qualys, Tenable) via
  their export APIs as the ingestion source
- Eval harness to measure triage consistency across model runs
- Multi-agent setup: a separate "asset inventory agent" that queries a
  live CMDB instead of a static list

## Tech stack

Python, Anthropic Claude API (tool use), ChromaDB, FastAPI, scikit-learn,
NVD CVE API
