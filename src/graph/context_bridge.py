"""AgentCore Platform v1.0"""

# Outer-to-inner state bridge for the two-layer graph.
#
# The subgraph node hands the inner graph a single string and nothing else:
# ``GraphNode.execute()`` calls ``subgraph.invoke(extract_input(state), ...)``,
# and the inner graph then builds a FRESH initial state. Every other outer field
# - the validated claim, the scope decision, the operator's tuned pattern set -
# is simply not there when the first inner node runs.
#
# Two consequences were live in this template before the bridge existed:
#
#   * the scope decision did not travel, so a claim the entry gate had already
#     marked out of scope was scored anyway, and the outer flag was then
#     overwritten by the inner graph's default of False - the entire
#     out-of-scope response was unreachable;
#   * each inner node re-parsed the claim out of ``user_input`` on its own,
#     which meant the detection rules read the RAW request rather than the
#     validated one.
#
# A ContextVar carries the outer hand-off across that boundary: the subgraph
# node stashes it inside ``extract_input()`` (which runs on the outer thread,
# immediately before ``invoke()``), and the inner graph seeds it into its
# initial state through ``_extra_initial_state()``. The variable is set and
# cleared around a single invocation, so concurrent requests never observe each
# other's hand-off.

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Dict, Iterator

_HANDOFF: ContextVar[Dict[str, Any]] = ContextVar("ins_c2_054_handoff", default={})


@contextmanager
def stash(handoff: Dict[str, Any]) -> Iterator[None]:
    """Publish *handoff* to the inner graph for the duration of the block."""
    token = _HANDOFF.set(dict(handoff))
    try:
        yield
    finally:
        _HANDOFF.reset(token)


def set_handoff(handoff: Dict[str, Any]) -> None:
    """Publish *handoff* without a scope guard.

    ``extract_input()`` and ``invoke()`` are separate calls inside
    ``GraphNode.execute()``, so the subgraph node cannot wrap the invocation in
    a context manager. It sets the hand-off here and the inner graph consumes it
    on the next ``_extra_initial_state()`` call, on the same thread.
    """
    _HANDOFF.set(dict(handoff))


def take_handoff() -> Dict[str, Any]:
    """Return the pending hand-off and clear it.

    Clearing on read means a second inner graph built without a fresh stash
    starts from an empty state rather than silently inheriting the previous
    request's claim.
    """
    handoff = _HANDOFF.get()
    _HANDOFF.set({})
    return dict(handoff)
