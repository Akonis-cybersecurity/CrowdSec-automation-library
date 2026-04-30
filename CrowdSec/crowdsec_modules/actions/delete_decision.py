from typing import Any, Dict

from crowdsec_modules.actions.base import CrowdSecAction
from crowdsec_modules.models import DeleteDecisionArguments


class DeleteDecision(CrowdSecAction):
    """Delete a single decision by its ID from CrowdSec LAPI (Watcher auth)."""

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        args = DeleteDecisionArguments(**arguments)
        result = self.watcher_client.delete_decision_by_id(args.decision_id)
        return {"result": result}
