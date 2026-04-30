from typing import Any, Dict

from crowdsec_modules.actions.base import CrowdSecAction
from crowdsec_modules.models import DeleteAlertByIdArguments


class DeleteAlertById(CrowdSecAction):
    """Delete a single alert by its ID from CrowdSec LAPI (Watcher auth)."""

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        args = DeleteAlertByIdArguments(**arguments)
        result = self.watcher_client.delete_alert_by_id(args.alert_id)
        return {"result": result}
