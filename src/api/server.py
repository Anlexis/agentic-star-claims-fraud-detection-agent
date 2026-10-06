"""AgentCore Platform v1.0"""

# Standalone HTTP entry point.
#
# An adapter only: it authenticates the caller, bounds the request, and hands
# it to the graph. No screening logic lives here — the entry gate node owns the
# claim contract, and duplicating any part of it here would give the two copies
# somewhere to diverge.
#
# Three things this adapter has to do that a bare pass-through does not:
#
#   * establish the caller's trust level. Nothing upstream sets it in a
#     standalone deployment, so without the bearer check below every request
#     arrives anonymous and the entry gate — which requires a verified external
#     caller — refuses it before any node runs. The deployment answers health
#     checks and refuses every real invoke.
#   * load `config/config.yaml` and construct the graph with it. Constructing
#     it bare leaves `self.config` empty, so every declared runtime value —
#     the retry bound, the tuned detection thresholds — silently reverts to a
#     built-in default while the file that declares them looks authoritative.
#   * bound the request body before anything downstream reads it.
#
# The request carries no side channel: `input` is the whole contract. The
# platform's structured context channel is deliberately not accepted, because a
# value on it is returned verbatim by the framework's first node and then scanned
# by the output gate — so an ordinary document containing a token-shaped string
# fails the request at node one, with an error the caller cannot act on. An
# agent that does not open that channel cannot be broken through it.

import os
import secrets
from pathlib import Path
from typing import Any, Dict
from uuid import uuid4

import yaml
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel
from framework.secrets.context import bound_secrets
from shared.secrets import factory as secrets_factory

from src.graph.graph import Graph
from src.services.security import MAX_INPUT_CHARS

_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "config.yaml"


def _load_config() -> Dict[str, Any]:
    """Return the runtime configuration the graph is constructed with.

    A missing file is not silently tolerated into an empty dict at this level:
    the file is part of the deployment, and starting without it would mean
    running on defaults that no one chose.
    """
    with _CONFIG_PATH.open(encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle)
    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise TypeError(f"{_CONFIG_PATH.name} must contain a mapping")
    return loaded


app = FastAPI(title="Agent")

agent = Graph(config=_load_config())
agent.compile()
agent.provision_secrets(
    secrets_factory(namespace="ins", agent_name="InsuranceClaimsFraudDetectionInvestigatorAlertAgent")
)


class InvokeRequest(BaseModel):
    input: str
    session_id: str = ""


@app.post("/invoke")
async def invoke(req: InvokeRequest, request: Request) -> Any:
    if len(req.input) > MAX_INPUT_CHARS:
        raise HTTPException(status_code=400, detail=f"input exceeds {MAX_INPUT_CHARS} characters.")

    trust = getattr(request.state, "trust_level", TrustLevel.ANONYMOUS)
    # Standalone caller authentication. Where middleware has already vouched
    # for the caller, that decision stands and is never demoted. Where it has
    # not, and the deployment set INVOKE_AUTH_TOKEN, the caller must present it
    # to reach the verified-external level the entry gate requires.
    #
    # This is a deployment credential rather than an agent secret: it is
    # checked before any invocation context exists, so the secrets provider is
    # not the right home for it.
    expected = os.environ.get("INVOKE_AUTH_TOKEN")
    if expected and trust is TrustLevel.ANONYMOUS:
        supplied = request.headers.get("authorization", "")
        # Compared as bytes: constant-time comparison raises on non-ASCII text,
        # which would turn a malformed header into a 500 instead of a 401.
        if not secrets.compare_digest(supplied.encode(), f"Bearer {expected}".encode()):
            # Deliberately uniform: absent, malformed and wrong all read alike.
            raise HTTPException(status_code=401, detail="Token is invalid or expired.")
        trust = TrustLevel.VERIFIED_EXTERNAL

    with bound_secrets(agent._secrets_provider):
        ctx = InvocationContext(
            session_id=req.session_id or str(uuid4()),
            caller_trust_level=trust,
            caller_id=getattr(request.state, "caller_id", ""),
        )
        return agent.invoke(req.input, ctx=ctx)


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "agent": "InsuranceClaimsFraudDetectionInvestigatorAlertAgent"}
