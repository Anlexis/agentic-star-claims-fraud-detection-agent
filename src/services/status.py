"""AgentCore Platform v1.0"""

# Status helpers.
#
# `AgentStatus` is a `str` Enum whose ERROR member compares equal to "error",
# not to "ERROR". Every downstream node in this pipeline used to short-circuit
# on `state.get("status") == "ERROR"`, a comparison nothing in the system can
# satisfy — so an upstream failure was never seen. The node after it then
# returned SUCCESS with a zero score, and the pipeline reported "no fraud
# indicators detected" for a claim it had failed to assess: a fail-OPEN on the
# one decision the agent exists to make.
#
# Reading the status through this helper is what keeps the comparison honest,
# whether the value in state is the enum member or its string value.

from __future__ import annotations

from typing import Any, Dict

from framework.schemas.agent_status import AgentStatus


def is_error_state(state: Dict[str, Any]) -> bool:
    """True when an upstream node has already failed."""
    status = state.get("status")
    if status is None:
        return False
    if isinstance(status, AgentStatus):
        return status is AgentStatus.ERROR
    if isinstance(status, str):
        return bool(status.strip().lower() == AgentStatus.ERROR.value)
    return False
