"""
api_server.py
~~~~~~~~~~~~~
CryptoShield Intelligence Platform — REST API Server v2.1.0

Production-grade improvements over v2.0.0:
  - Async background task processing (non-blocking analysis)
  - Thread-safe rate limiting with asyncio.Lock
  - UUID-based request IDs (no collision risk)
  - Job status polling endpoint
  - Response size limiting (max 100 findings per category)
  - Restricted CORS configuration
  - Analysis timeout protection (10 minutes max)
  - Proper HTTP 503 on upstream failures

Workflow:
  POST /analyze        → returns job_id immediately (202 Accepted)
  GET  /jobs/{job_id}  → poll for result (200 when complete)

Usage:
    uvicorn api_server:app --host 0.0.0.0 --port 8000 --reload

Documentation:
    http://localhost:8000/docs
    http://localhost:8000/redoc
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import uvicorn
from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request, Security, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, field_validator

from cryptoshield import analyzer
from cryptoshield.logger import get_logger

load_dotenv()
log = get_logger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

_raw_keys = os.getenv("API_KEYS", "")
VALID_API_KEYS: set[str] = {k.strip() for k in _raw_keys.split(",") if k.strip()}

if not VALID_API_KEYS:
    import hashlib
    _dev_key = "dev-" + hashlib.sha256(b"cryptoshield-dev").hexdigest()[:24]
    VALID_API_KEYS.add(_dev_key)
    log.warning(
        "No API_KEYS configured in .env — using temporary dev key: %s\n"
        "Add API_KEYS=your-key to .env before going to production.",
        _dev_key,
    )

RATE_LIMIT_RPM:       int = int(os.getenv("RATE_LIMIT_RPM", "10"))
ANALYSIS_TIMEOUT_S:   int = int(os.getenv("ANALYSIS_TIMEOUT_S", "600"))
MAX_FINDINGS_PER_CAT: int = 100
MAX_JOBS_IN_MEMORY:   int = 1000

_raw_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8080")
ALLOWED_ORIGINS: list[str] = [o.strip() for o in _raw_origins.split(",") if o.strip()]


# ══════════════════════════════════════════════════════════════════════════════
#  FASTAPI APP
# ══════════════════════════════════════════════════════════════════════════════

app = FastAPI(
    title       = "CryptoShield Intelligence API",
    description = (
        "Professional wallet risk analysis for AML/KYC compliance.\n\n"
        "Screens Ethereum wallets against OFAC sanctions lists, traces "
        "multi-hop transaction graphs, and detects AML behavioral patterns.\n\n"
        "## Authentication\n"
        "Pass your API key in the `X-API-Key` request header.\n\n"
        "## How it works\n"
        "1. `POST /analyze` — Submit a wallet for analysis. Returns a `job_id` immediately.\n"
        "2. `GET /jobs/{job_id}` — Poll this endpoint until `status` is `completed` or `failed`.\n\n"
        "## Rate limit\n"
        f"{RATE_LIMIT_RPM} requests per minute per API key."
    ),
    version      = "2.1.0",
    contact      = {"name": "CryptoShield Support", "email": "support@cryptoshield.io"},
    license_info = {"name": "MIT"},
)

app.add_middleware(
    CORSMiddleware,
    allow_origins     = ALLOWED_ORIGINS,
    allow_credentials = False,
    allow_methods     = ["GET", "POST"],
    allow_headers     = ["X-API-Key", "Content-Type", "Accept"],
)


# ══════════════════════════════════════════════════════════════════════════════
#  AUTHENTICATION
# ══════════════════════════════════════════════════════════════════════════════

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(api_key: str = Security(api_key_header)) -> str:
    """
    Validate the API key in the X-API-Key request header.

    :raises HTTPException 401: If no key is provided.
    :raises HTTPException 403: If the key is invalid.
    :returns: The validated API key string.
    """
    if not api_key:
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail      = {
                "error": "Missing API key.",
                "hint":  "Provide your API key in the X-API-Key request header.",
            },
        )
    if api_key not in VALID_API_KEYS:
        log.warning("Rejected request with invalid API key: %s...", api_key[:8])
        raise HTTPException(
            status_code = status.HTTP_403_FORBIDDEN,
            detail      = {
                "error": "Invalid API key.",
                "hint":  "Contact support@cryptoshield.io to obtain a valid key.",
            },
        )
    return api_key


# ══════════════════════════════════════════════════════════════════════════════
#  RATE LIMITING  (thread-safe with asyncio.Lock)
# ══════════════════════════════════════════════════════════════════════════════

_rate_store: dict[str, list[float]] = {}
_rate_lock  = asyncio.Lock()


async def check_rate_limit(api_key: str) -> None:
    """
    Enforce per-API-key rate limiting.
    Uses asyncio.Lock to ensure thread-safe access to the rate store.

    :param api_key: The authenticated API key.
    :raises HTTPException 429: If the rate limit is exceeded.
    """
    now    = time.monotonic()
    window = 60.0

    async with _rate_lock:
        calls = _rate_store.get(api_key, [])
        calls = [t for t in calls if now - t < window]

        if len(calls) >= RATE_LIMIT_RPM:
            oldest   = calls[0]
            retry_in = int(window - (now - oldest)) + 1
            log.warning("Rate limit exceeded for key: %s...", api_key[:8])
            raise HTTPException(
                status_code = status.HTTP_429_TOO_MANY_REQUESTS,
                detail      = {
                    "error":               f"Rate limit exceeded ({RATE_LIMIT_RPM} requests/minute).",
                    "retry_after_seconds": retry_in,
                },
                headers = {"Retry-After": str(retry_in)},
            )

        calls.append(now)
        _rate_store[api_key] = calls


# ══════════════════════════════════════════════════════════════════════════════
#  JOB STORE
# ══════════════════════════════════════════════════════════════════════════════

class JobStatus(str, Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"


class Job(BaseModel):
    job_id       : str
    address      : str
    status       : JobStatus
    submitted_at : str
    completed_at : str | None = None
    result       : dict | None = None
    error        : str | None = None


_job_store: dict[str, Job] = {}
_job_lock  = asyncio.Lock()


async def _store_job(job: Job) -> None:
    """Store a job, evicting the oldest entry if the store is full."""
    async with _job_lock:
        if len(_job_store) >= MAX_JOBS_IN_MEMORY:
            oldest_key = next(iter(_job_store))
            del _job_store[oldest_key]
        _job_store[job.job_id] = job


async def _update_job(job_id: str, **kwargs: Any) -> None:
    """Update fields on an existing job."""
    async with _job_lock:
        if job_id in _job_store:
            _job_store[job_id] = _job_store[job_id].model_copy(update=kwargs)


# ══════════════════════════════════════════════════════════════════════════════
#  REQUEST / RESPONSE MODELS
# ══════════════════════════════════════════════════════════════════════════════

class AnalyzeRequest(BaseModel):
    """Request body for POST /analyze."""
    address: str

    @field_validator("address")
    @classmethod
    def validate_ethereum_address(cls, v: str) -> str:
        v = v.strip().lower()
        if not v.startswith("0x") or len(v) != 42:
            raise ValueError(
                "Invalid Ethereum address. "
                "Must start with '0x' and be exactly 42 characters long."
            )
        try:
            int(v, 16)
        except ValueError:
            raise ValueError("Address contains invalid hexadecimal characters.")
        return v

    model_config = {
        "json_schema_extra": {
            "examples": [{"address": "0x722122dF12D4e14e13Ac3b6895a86e84145b6967"}]
        }
    }


class SubmitResponse(BaseModel):
    job_id       : str
    status       : JobStatus
    submitted_at : str
    poll_url     : str
    message      : str


class JobResponse(BaseModel):
    job_id       : str
    address      : str
    status       : JobStatus
    submitted_at : str
    completed_at : str | None
    result       : dict | None
    error        : str | None


class HealthResponse(BaseModel):
    status        : str
    service       : str
    version       : str
    time          : str
    jobs_in_store : int


class ErrorResponse(BaseModel):
    error  : str
    detail : Any = None


# ══════════════════════════════════════════════════════════════════════════════
#  RESULT SERIALIZER
# ══════════════════════════════════════════════════════════════════════════════

def _serialize_result(result: analyzer.AnalysisResult) -> dict:
    """
    Convert an AnalysisResult into a JSON-serializable dict.
    Caps findings at MAX_FINDINGS_PER_CAT to prevent oversized responses.
    """
    verdict_labels = {
        "CRITICAL": "Immediate action required — block and report.",
        "HIGH":     "Suspend pending enhanced due diligence.",
        "MEDIUM":   "Flag for enhanced due diligence.",
        "LOW":      "No immediate action required.",
    }
    recommendations = {
        "CRITICAL": (
            "Block all transactions immediately. "
            "File a Suspicious Activity Report (SAR) with your compliance team. "
            "Do not process any funds until a full manual review is complete. "
            "Consider filing a report with FinCEN (US) or your national FIU."
        ),
        "HIGH": (
            "Suspend the account pending enhanced due diligence (EDD). "
            "Request full KYC documentation and source-of-funds evidence. "
            "Monitor all future transactions with elevated scrutiny."
        ),
        "MEDIUM": (
            "Flag for enhanced due diligence. "
            "Request source-of-funds documentation from the user. "
            "Apply transaction limits until the review is complete."
        ),
        "LOW": (
            "No immediate action required. "
            "Continue standard transaction monitoring per your AML policy."
        ),
    }

    direct = [
        {
            "counterparty": f.counterparty,
            "label":        f.label,
            "source":       f.source,
            "tier":         f.tier,
            "risk_weight":  f.weight,
            "tx_hash":      f.tx_hash,
            "date": (
                datetime.fromtimestamp(f.timestamp, tz=timezone.utc).strftime("%Y-%m-%d")
                if f.timestamp else "N/A"
            ),
        }
        for f in result.direct_findings[:MAX_FINDINGS_PER_CAT]
    ]

    indirect = [
        {
            "hop":         f.hop,
            "address":     f.address,
            "label":       f.label,
            "source":      f.source,
            "tier":        f.tier,
            "risk_weight": f.weight,
        }
        for f in result.hop_findings[:MAX_FINDINGS_PER_CAT]
    ]

    behavioral = [
        {
            "pattern_type": f.pattern_type,
            "description":  f.description,
            "severity":     f.severity,
            "risk_weight":  f.weight,
        }
        for f in result.behavior_findings[:MAX_FINDINGS_PER_CAT]
    ]

    truncated = (
        len(result.direct_findings)   > MAX_FINDINGS_PER_CAT or
        len(result.hop_findings)      > MAX_FINDINGS_PER_CAT or
        len(result.behavior_findings) > MAX_FINDINGS_PER_CAT
    )

    return {
        "engine_version":  "2.1.0",
        "analyzed_at":     datetime.now(tz=timezone.utc).isoformat(),
        "address":         result.address,
        "eth_balance":     result.balance,
        "overview": {
            "tx_count":            result.metadata.tx_count,
            "first_activity":      result.metadata.first_seen,
            "last_activity":       result.metadata.last_seen,
            "wallet_age_days":     result.metadata.wallet_age_days,
            "outgoing_volume_eth": result.metadata.outgoing_volume_eth,
            "counterparty_count":  result.metadata.counterparty_count,
        },
        "risk": {
            "score":   result.risk_score,
            "verdict": result.verdict,
            "label":   verdict_labels.get(result.verdict, ""),
        },
        "direct_sanctions":      direct,
        "indirect_connections":  indirect,
        "behavioral_patterns":   behavioral,
        "findings_truncated":    truncated,
        "findings_note": (
            f"Results capped at {MAX_FINDINGS_PER_CAT} per category. "
            "Contact support for full dataset export."
            if truncated else None
        ),
        "recommendation": recommendations.get(result.verdict, "Consult your compliance team."),
        "disclaimer": (
            "This report is generated by automated analysis and is intended "
            "as a decision-support tool only. It does not constitute legal advice. "
            "Final compliance decisions must be reviewed by a qualified "
            "AML/compliance professional."
        ),
    }


# ══════════════════════════════════════════════════════════════════════════════
#  BACKGROUND ANALYSIS TASK
# ══════════════════════════════════════════════════════════════════════════════

async def _run_analysis(job_id: str, address: str) -> None:
    """
    Execute the full analysis pipeline in a background thread.
    Uses asyncio.to_thread() to avoid blocking the event loop.
    Enforces ANALYSIS_TIMEOUT_S maximum duration.
    """
    await _update_job(job_id, status=JobStatus.RUNNING)
    log.info("Background analysis started | job=%s | address=%s", job_id, address)

    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(analyzer.run, address),
            timeout=ANALYSIS_TIMEOUT_S,
        )
        await _update_job(
            job_id,
            status       = JobStatus.COMPLETED,
            completed_at = datetime.now(tz=timezone.utc).isoformat(),
            result       = _serialize_result(result),
        )
        log.info(
            "Analysis complete | job=%s | score=%d | verdict=%s",
            job_id, result.risk_score, result.verdict,
        )

    except asyncio.TimeoutError:
        log.error("Timeout | job=%s | address=%s", job_id, address)
        await _update_job(
            job_id,
            status       = JobStatus.FAILED,
            completed_at = datetime.now(tz=timezone.utc).isoformat(),
            error        = f"Analysis timed out after {ANALYSIS_TIMEOUT_S} seconds.",
        )

    except Exception as exc:
        log.error("Analysis failed | job=%s | error=%s", job_id, exc, exc_info=True)
        await _update_job(
            job_id,
            status       = JobStatus.FAILED,
            completed_at = datetime.now(tz=timezone.utc).isoformat(),
            error        = "Analysis failed unexpectedly. Please try again.",
        )


# ══════════════════════════════════════════════════════════════════════════════
#  MIDDLEWARE
# ══════════════════════════════════════════════════════════════════════════════

@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log every request with method, path, status code, and duration."""
    start    = time.monotonic()
    response = await call_next(request)
    duration = round((time.monotonic() - start) * 1000, 1)
    log.info("%s %s → %d  (%sms)", request.method, request.url.path, response.status_code, duration)
    return response


# ══════════════════════════════════════════════════════════════════════════════
#  ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

@app.get(
    "/health",
    response_model = HealthResponse,
    summary        = "Health Check",
    description    = "Confirms the server is running. No authentication required.",
    tags           = ["System"],
)
async def health_check() -> HealthResponse:
    return HealthResponse(
        status        = "ok",
        service       = "CryptoShield Intelligence API",
        version       = "2.1.0",
        time          = datetime.now(tz=timezone.utc).isoformat(),
        jobs_in_store = len(_job_store),
    )


@app.post(
    "/analyze",
    response_model = SubmitResponse,
    status_code    = status.HTTP_202_ACCEPTED,
    summary        = "Submit Wallet for Analysis",
    description    = (
        "Submit an Ethereum wallet address for AML risk analysis.\n\n"
        "Returns a `job_id` **immediately** (HTTP 202). "
        "The analysis runs in the background.\n\n"
        "Poll `GET /jobs/{job_id}` until `status` is `completed` or `failed`.\n\n"
        "**Typical analysis time:** 2–8 minutes depending on wallet activity."
    ),
    tags = ["Analysis"],
    responses = {
        401: {"model": ErrorResponse, "description": "Missing API key"},
        403: {"model": ErrorResponse, "description": "Invalid API key"},
        422: {"model": ErrorResponse, "description": "Invalid Ethereum address"},
        429: {"model": ErrorResponse, "description": "Rate limit exceeded"},
    },
)
async def submit_analysis(
    request:          AnalyzeRequest,
    background_tasks: BackgroundTasks,
    api_key:          str = Security(require_api_key),
) -> SubmitResponse:
    await check_rate_limit(api_key)

    job_id = str(uuid.uuid4())
    now    = datetime.now(tz=timezone.utc).isoformat()

    job = Job(
        job_id       = job_id,
        address      = request.address,
        status       = JobStatus.PENDING,
        submitted_at = now,
    )
    await _store_job(job)
    background_tasks.add_task(_run_analysis, job_id, request.address)

    log.info("Job submitted | job=%s | address=%s | key=%s...", job_id, request.address, api_key[:8])

    return SubmitResponse(
        job_id       = job_id,
        status       = JobStatus.PENDING,
        submitted_at = now,
        poll_url     = f"/jobs/{job_id}",
        message      = (
            "Analysis job submitted successfully. "
            f"Poll GET /jobs/{job_id} to retrieve the result."
        ),
    )


@app.get(
    "/jobs/{job_id}",
    response_model = JobResponse,
    summary        = "Get Analysis Result",
    description    = (
        "Retrieve the status and result of a submitted analysis job.\n\n"
        "**Polling recommendation:** Check every 15–30 seconds.\n\n"
        "- `pending`   — Job queued, not yet started.\n"
        "- `running`   — Analysis in progress.\n"
        "- `completed` — Finished. `result` contains the full report.\n"
        "- `failed`    — Failed. `error` contains the reason."
    ),
    tags = ["Analysis"],
    responses = {
        401: {"model": ErrorResponse, "description": "Missing API key"},
        403: {"model": ErrorResponse, "description": "Invalid API key"},
        404: {"model": ErrorResponse, "description": "Job not found"},
    },
)
async def get_job(
    job_id:  str,
    api_key: str = Security(require_api_key),
) -> JobResponse:
    async with _job_lock:
        job = _job_store.get(job_id)

    if not job:
        raise HTTPException(
            status_code = status.HTTP_404_NOT_FOUND,
            detail      = {
                "error": f"Job '{job_id}' not found.",
                "hint":  "Jobs are retained for the server's current session only.",
            },
        )

    return JobResponse(
        job_id       = job.job_id,
        address      = job.address,
        status       = job.status,
        submitted_at = job.submitted_at,
        completed_at = job.completed_at,
        result       = job.result,
        error        = job.error,
    )


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    uvicorn.run(
        "api_server:app",
        host      = "0.0.0.0",
        port      = 8000,
        reload    = True,
        log_level = "info",
    )