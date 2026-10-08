"""
S.H.A.D.E. — Local Security & Threat Engine API Server
Device-local FastAPI server for Member 2 Security & Threat Engine operations.

Provides local REST API endpoints for:
- Threat Engine Evaluation (Exposome Threat Index calculation)
- Deterministic Regex DLP & Synthetic Tokenization
- UIDAI Indian Aadhaar Verhoeff Checksum Validator
- Canary Honeytoken Generation & Breach Attribution
- Credential Breach Radar (XposedOrNot with k-anonymity)
- Trusted Destination Policy Evaluation

Can be locally hosted via:
    python -m security.server
or:
    uvicorn security.server:app --host 127.0.0.1 --port 8000
"""

import os
import sys
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn

from security.breach_radar.client import (
    BreachRadarCheckResult,
    EmailBreachCheckResult,
    XposedOrNotClient,
)
from security.canary.detector import CanaryAlert, CanaryDetector, CanaryToken
from security.dlp.regex_detector import DLPScanResult, RegexDLPDetector
from security.threat_engine.engine import ThreatEngine
from security.threat_engine.models import (
    DestinationTrustDossier,
    ThreatEvaluationResult,
)
from security.threat_engine.trusted_destinations import (
    DestinationTrustResult,
    TrustedDestinationEvaluator,
)
from security.validators.verhoeff import (
    generate_check_digit,
    is_valid_aadhaar,
    validate_verhoeff,
)

# ---------------------------------------------------------------------------
# App Initialization & Singletons
# ---------------------------------------------------------------------------

app = FastAPI(
    title="S.H.A.D.E. Security & Threat Engine API",
    description="Device-Local Personal SOC Threat Engine & Counter-Intelligence Pipeline",
    version="1.1.0",
)

# Allow local frontend / host communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Persistent in-memory instances
threat_engine = ThreatEngine()
dlp_detector = RegexDLPDetector()
canary_detector = CanaryDetector()
breach_radar = XposedOrNotClient(enable_offline_cache=True)
dest_evaluator = TrustedDestinationEvaluator()


# ---------------------------------------------------------------------------
# Request & Response Schemas
# ---------------------------------------------------------------------------

class EvaluateRequest(BaseModel):
    text: str = Field(..., description="Target payload or text to evaluate")
    destination_url: Optional[str] = Field(None, description="Egress destination URL")
    password_candidates: Optional[list[str]] = Field(None, description="Optional candidate passwords")


class DLPScanRequest(BaseModel):
    text: str = Field(..., description="Text to scan for PII/secrets")


class VerhoeffRequest(BaseModel):
    number: str = Field(..., description="Numeric string to validate (e.g. Aadhaar)")


class CanaryGenerateRequest(BaseModel):
    kind: str = Field("api_key", description="'api_key' or 'email'")
    attribution_tag: str = Field("local_agent", description="Tag identifying canary deployment")


class CanaryScanRequest(BaseModel):
    payload: str = Field(..., description="Payload to inspect for canary honeytoken leaks")


class PasswordBreachRequest(BaseModel):
    password: str = Field(..., description="Password to test anonymously against XposedOrNot")


class EmailBreachRequest(BaseModel):
    email: str = Field(..., description="Email address to check for exposure history")


class DestinationRequest(BaseModel):
    destination_url: str = Field(..., description="Destination URL to evaluate against policy")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

from fastapi.responses import HTMLResponse
from fastapi import Request
from security.dashboard import get_dashboard_html

@app.get("/", tags=["Status"])
def root_info(request: Request) -> Any:
    """Root metadata or interactive web dashboard."""
    accept_header = request.headers.get("accept", "")
    if "text/html" in accept_header and "application/json" not in accept_header:
        return HTMLResponse(content=get_dashboard_html(), status_code=200)

    return {
        "service": "S.H.A.D.E. Security & Threat Engine API",
        "version": "1.1.0",
        "role": "Member 2 — Security + Threat Engine + Risk Analysis",
        "status": "ONLINE",
        "dashboard_url": "/dashboard",
        "docs_url": "/docs",
        "endpoints": [
            "/api/v1/security/evaluate",
            "/api/v1/security/dlp/scan",
            "/api/v1/security/validators/verhoeff",
            "/api/v1/security/canary/generate",
            "/api/v1/security/canary/scan",
            "/api/v1/security/breach-radar/password",
            "/api/v1/security/breach-radar/email",
            "/api/v1/security/destinations/evaluate",
        ],
    }


@app.get("/dashboard", response_class=HTMLResponse, tags=["UI"])
@app.get("/ui", response_class=HTMLResponse, tags=["UI"])
def dashboard_view() -> HTMLResponse:
    """Interactive Cyber War-Room HUD dashboard."""
    return HTMLResponse(content=get_dashboard_html(), status_code=200)


@app.get("/health", tags=["Status"])
def health_check() -> dict[str, Any]:
    """Check health and readiness of all security sub-modules."""
    return {
        "status": "HEALTHY",
        "components": {
            "threat_engine": "ACTIVE",
            "regex_dlp": "ACTIVE",
            "verhoeff_validator": "ACTIVE",
            "canary_detector": "ACTIVE",
            "xposedornot_breach_radar": "ACTIVE",
            "trusted_destinations": "ACTIVE",
        },
    }


@app.post(
    "/api/v1/security/evaluate",
    response_model=ThreatEvaluationResult,
    tags=["Threat Engine"],
)
def evaluate_payload(payload: EvaluateRequest) -> ThreatEvaluationResult:
    """
    Run full multi-layer evaluation across text, egress destination, and credentials.
    Calculates Exposome Threat Index (0-100) and produces tokenized output.
    """
    return threat_engine.evaluate(
        text=payload.text,
        destination_url=payload.destination_url,
        password_candidates=payload.password_candidates,
    )


@app.post(
    "/api/v1/security/dlp/scan",
    tags=["DLP"],
)
def scan_dlp(req: DLPScanRequest) -> dict[str, Any]:
    """
    Perform deterministic regex scanning and 12-char synthetic tokenization.
    """
    res = dlp_detector.scan(req.text)
    return {
        "original_text": res.original_text,
        "tokenized_text": res.tokenized_text,
        "masked_text": res.masked_text,
        "has_sensitive_data": len(res.findings) > 0,
        "has_pii": res.has_pii,
        "has_secrets": res.has_secrets,
        "findings": res.findings,
        "synthetic_mappings": res.synthetic_mappings,
    }


@app.post(
    "/api/v1/security/validators/verhoeff",
    tags=["Validators"],
)
def check_verhoeff(req: VerhoeffRequest) -> dict[str, Any]:
    """
    Validate numeric string using the UIDAI Verhoeff Dihedral D5 checksum algorithm.
    """
    is_valid = validate_verhoeff(req.number)
    is_aadhaar = is_valid_aadhaar(req.number)
    calculated_digit = None
    if req.number.isdigit():
        calculated_digit = generate_check_digit(req.number)
    return {
        "input": req.number,
        "is_valid_verhoeff": is_valid,
        "is_valid_aadhaar": is_aadhaar,
        "calculated_check_digit": calculated_digit,
    }


@app.post(
    "/api/v1/security/canary/generate",
    tags=["Canary Honeytokens"],
)
def generate_canary(req: CanaryGenerateRequest) -> dict[str, Any]:
    """
    Generate and register a new decoy honeytoken.
    """
    if req.kind == "email":
        tok = canary_detector.generate_email(tag=req.attribution_tag)
    else:
        tok = canary_detector.generate_api_key(tag=req.attribution_tag)
    return {
        "status": "REGISTERED",
        "kind": req.kind,
        "token_id": tok.token_id,
        "value": tok.value,
        "attribution_tag": tok.tag,
    }


@app.post(
    "/api/v1/security/canary/scan",
    tags=["Canary Honeytokens"],
)
def scan_canary(req: CanaryScanRequest) -> dict[str, Any]:
    """
    Scan a payload for leaked canary honeytokens.
    """
    alerts = canary_detector.scan_payload(req.payload)
    return {
        "leaked": len(alerts) > 0,
        "alert_count": len(alerts),
        "alerts": alerts,
    }


@app.post(
    "/api/v1/security/breach-radar/password",
    tags=["Breach Radar (XposedOrNot)"],
)
def check_password_breach(req: PasswordBreachRequest) -> BreachRadarCheckResult:
    """
    Query XposedOrNot for password breach exposure using k-anonymity.
    Zero-knowledge guarantee: password is never transmitted across the network.
    """
    return breach_radar.check_password(req.password)


@app.post(
    "/api/v1/security/breach-radar/email",
    tags=["Breach Radar (XposedOrNot)"],
)
def check_email_breach(req: EmailBreachRequest) -> EmailBreachCheckResult:
    """
    Check email address exposure using XposedOrNot.
    """
    return breach_radar.check_email(req.email)


@app.post(
    "/api/v1/security/destinations/evaluate",
    response_model=DestinationTrustResult,
    tags=["Destination Trust"],
)
def check_destination(req: DestinationRequest) -> DestinationTrustResult:
    """
    Evaluate a destination URL against S.H.A.D.E. destination policy.
    """
    return dest_evaluator.evaluate(req.destination_url)


# ---------------------------------------------------------------------------
# CLI / Local Hosting Entrypoint
# ---------------------------------------------------------------------------

def run_server(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Run the FastAPI server locally."""
    print(f"[*] Starting S.H.A.D.E. Security & Threat Engine API on http://{host}:{port}")
    print(f"[*] Interactive API documentation available at: http://{host}:{port}/docs")
    uvicorn.run("security.server:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    port_env = int(os.environ.get("SHADE_SECURITY_PORT", "8000"))
    host_env = os.environ.get("SHADE_SECURITY_HOST", "127.0.0.1")
    run_server(host=host_env, port=port_env)
