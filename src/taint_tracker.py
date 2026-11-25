"""Session-scoped, per-agent taint (information-flow) tracking."""
from collections import defaultdict
from typing import Dict, List, Set, Tuple


class TaintTracker:
    """Tracks trust/sensitivity labels for each (session, agent) pair."""

    def __init__(self) -> None:
        self._taints: Dict[Tuple[str, str], Set[str]] = defaultdict(set)

    def add_taint(self, session_id: str, agent_id: str, label: str) -> None:
        self._taints[(session_id, agent_id)].add(label)

    def get_taints(self, session_id: str, agent_id: str) -> List[str]:
        return sorted(self._taints.get((session_id, agent_id), ()))

    def propagate_taint(
        self, session_id: str, source_agent_id: str, target_agent_id: str
    ) -> None:
        """Copy every active label from the delegating agent to the receiver.

        Labels are never removed by delegation, so tainted data cannot be
        "laundered" through a chain of agents.
        """
        labels = self._taints.get((session_id, source_agent_id))
        if labels:
            self._taints[(session_id, target_agent_id)].update(labels)

    def clear_session(self, session_id: str) -> None:
        for key in [k for k in self._taints if k[0] == session_id]:
            del self._taints[key]
