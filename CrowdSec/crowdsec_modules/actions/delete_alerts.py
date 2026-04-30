from typing import Any, Dict

from crowdsec_modules.actions.base import CrowdSecAction
from crowdsec_modules.models import DeleteAlertsArguments


class DeleteAlerts(CrowdSecAction):
    """Delete alerts matching the given filters from CrowdSec LAPI (Watcher auth)."""

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        args = DeleteAlertsArguments(**arguments)
        params = args.dict(exclude_none=True)
        result = self.watcher_client.delete_alerts(**params)
        return {"result": result}
