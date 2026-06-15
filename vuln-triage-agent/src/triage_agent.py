"""
Vulnerability Triage Agent
Core agent that takes a CVE, retrieves similar historical CVEs via RAG,
and uses Claude (with tool use) to produce a structured triage assessment:
priority level, exploitability reasoning, and recommended remediation.

Set ANTHROPIC_API_KEY in your environment before running.
"""

import os
import json
import sys
from pathlib import Path

import anthropic

sys.path.insert(0, str(Path(__file__).parent))
from vector_store import query_similar_cves

MODEL = "claude-sonnet-4-6"

# Tool definition: the agent calls this to record its structured triage decision.
TRIAGE_TOOL = {
    "name": "record_triage_assessment",
    "description": (
        "Record the structured triage assessment for a vulnerability, "
        "including priority, exploitability reasoning, and remediation guidance."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "cve_id": {"type": "string"},
            "priority": {
                "type": "string",
                "enum": ["P0_IMMEDIATE", "P1_URGENT", "P2_SCHEDULED", "P3_BACKLOG"],
                "description": "P0 = patch within 24h, P1 = within 1 week, "
                               "P2 = next maintenance window, P3 = track only."
            },
            "exploitability_reasoning": {
                "type": "string",
                "description": "Brief reasoning on real-world exploitability, "
                               "referencing similar known CVEs if relevant."
            },
            "business_impact": {
                "type": "string",
                "description": "Likely impact if exploited (e.g., RCE, data exfil, DoS)."
            },
            "remediation_steps": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Concrete, ordered remediation steps."
            },
            "asset_context_note": {
                "type": "string",
                "description": "How this CVE relates to the provided asset inventory, if any."
            },
        },
        "required": ["cve_id", "priority", "exploitability_reasoning",
                      "business_impact", "remediation_steps"],
    },
}


def build_triage_prompt(cve: dict, similar_cves: list[dict], asset_inventory: list[str] = None) -> str:
    asset_context = ""
    if asset_inventory:
        asset_context = (
            f"\n\nOrganization's asset inventory (affected products to check against):\n"
            + "\n".join(f"- {a}" for a in asset_inventory)
        )

    similar_context = ""
    if similar_cves:
        similar_context = "\n\nSimilar historical CVEs (for exploitability pattern context):\n"
        for s in similar_cves:
            similar_context += (
                f"- {s['cve_id']} (severity={s['metadata']['severity']}): "
                f"{s['description'][:150]}...\n"
            )

    return f"""Triage the following vulnerability for a security operations team.

CVE ID: {cve['cve_id']}
CVSS Score: {cve.get('cvss_score')}
Severity: {cve.get('severity')}
Published: {cve.get('published')}
Description: {cve['description']}
Affected products: {', '.join(cve.get('affected_products', [])) or 'Not specified'}
{similar_context}{asset_context}

Use the record_triage_assessment tool to provide your structured assessment.
Consider: is this CVE part of a known exploitation pattern (e.g., similar to
the historical CVEs above)? What's the realistic exploitability given the
attack vector? What should the security team do first?"""


def triage_cve(cve: dict, asset_inventory: list[str] = None) -> dict:
    """
    Run the full triage pipeline for a single CVE:
    1. Retrieve similar CVEs from the vector store (RAG)
    2. Call Claude with tool use to get a structured assessment
    3. Return the parsed assessment
    """
    client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from env

    try:
        similar = query_similar_cves(cve["description"], top_k=3)
        # Exclude the CVE itself from its own "similar" list
        similar = [s for s in similar if s["cve_id"] != cve["cve_id"]]
    except Exception:
        similar = []

    prompt = build_triage_prompt(cve, similar, asset_inventory)

    response = client.messages.create(
        model=MODEL,
        max_tokens=1500,
        tools=[TRIAGE_TOOL],
        tool_choice={"type": "tool", "name": "record_triage_assessment"},
        messages=[{"role": "user", "content": prompt}],
    )

    for block in response.content:
        if block.type == "tool_use" and block.name == "record_triage_assessment":
            return block.input

    raise RuntimeError("Agent did not return a triage assessment.")


def triage_batch(cves: list[dict], asset_inventory: list[str] = None) -> list[dict]:
    """Triage a batch of CVEs and return assessments sorted by priority."""
    priority_order = {"P0_IMMEDIATE": 0, "P1_URGENT": 1, "P2_SCHEDULED": 2, "P3_BACKLOG": 3}
    assessments = []
    for cve in cves:
        print(f"Triaging {cve['cve_id']}...")
        try:
            assessment = triage_cve(cve, asset_inventory)
            assessments.append(assessment)
        except Exception as e:
            print(f"  Error triaging {cve['cve_id']}: {e}")

    assessments.sort(key=lambda a: priority_order.get(a["priority"], 99))
    return assessments


if __name__ == "__main__":
    DATA_DIR = Path(__file__).parent.parent / "data"
    with open(DATA_DIR / "cves_raw.json") as f:
        cves = json.load(f)

    # Example asset inventory - replace with your org's actual inventory
    sample_inventory = [
        "cpe:2.3:a:atlassian:confluence:8.5.0:*:*:*:*:*:*:*",
        "cpe:2.3:a:microsoft:outlook:2019:*:*:*:*:*:*:*",
        "cpe:2.3:o:paloaltonetworks:pan-os:11.1:*:*:*:*:*:*:*",
    ]

    results = triage_batch(cves[:3], asset_inventory=sample_inventory)

    print("\n" + "=" * 60)
    print("TRIAGE RESULTS (sorted by priority)")
    print("=" * 60)
    for r in results:
        print(f"\n[{r['priority']}] {r['cve_id']}")
        print(f"  Impact: {r['business_impact']}")
        print(f"  Reasoning: {r['exploitability_reasoning']}")
        print(f"  Remediation:")
        for step in r["remediation_steps"]:
            print(f"    - {step}")
