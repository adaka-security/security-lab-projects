"""
Vulnerability Triage API
FastAPI service exposing the triage agent. Accepts a list of CVEs
(and optional asset inventory) and returns prioritized triage assessments.

Run with:
    uvicorn src.api:app --reload

Then visit http://localhost:8000/docs for interactive API docs.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Optional
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from triage_agent import triage_batch
from vector_store import build_vector_store, load_cves

app = FastAPI(
    title="AI Vulnerability Triage Agent",
    description="Triages CVEs using an LLM agent with RAG over historical CVE data.",
    version="0.1.0",
)


class CVEInput(BaseModel):
    cve_id: str
    description: str
    cvss_score: Optional[float] = None
    severity: Optional[str] = None
    published: Optional[str] = None
    affected_products: list[str] = Field(default_factory=list)


class TriageRequest(BaseModel):
    cves: list[CVEInput]
    asset_inventory: list[str] = Field(
        default_factory=list,
        description="CPE strings representing the organization's asset inventory."
    )


class TriageResponse(BaseModel):
    cve_id: str
    priority: str
    exploitability_reasoning: str
    business_impact: str
    remediation_steps: list[str]
    asset_context_note: Optional[str] = None


@app.get("/")
def root():
    return {
        "service": "AI Vulnerability Triage Agent",
        "endpoints": {
            "/triage": "POST - Triage a batch of CVEs",
            "/rebuild-index": "POST - Rebuild the CVE vector store from data/cves_raw.json",
            "/docs": "Interactive API documentation",
        },
    }


@app.post("/triage", response_model=list[TriageResponse])
def triage(request: TriageRequest):
    if not request.cves:
        raise HTTPException(status_code=400, detail="No CVEs provided.")

    cve_dicts = [c.model_dump() for c in request.cves]
    try:
        results = triage_batch(cve_dicts, asset_inventory=request.asset_inventory)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return results


@app.post("/rebuild-index")
def rebuild_index():
    """Rebuild the CVE vector store from data/cves_raw.json."""
    try:
        cves = load_cves()
        build_vector_store(cves)
        return {"status": "ok", "indexed_count": len(cves)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
