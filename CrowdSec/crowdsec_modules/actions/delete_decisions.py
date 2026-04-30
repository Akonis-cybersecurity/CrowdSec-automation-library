from typing import Any, Dict

from crowdsec_modules.actions.base import CrowdSecAction
from crowdsec_modules.models import DeleteDecisionsArguments


class DeleteDecisions(CrowdSecAction):
    """Delete decisions matching the given filters from CrowdSec LAPI (Watcher auth)."""

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        args = DeleteDecisionsArguments(**arguments)
        params = args.dict(exclude_none=True)
        result = self.watcher_client.delete_decisions(**params)
        return {"result": result}
