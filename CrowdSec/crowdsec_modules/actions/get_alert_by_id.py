from typing import Any, Dict

from crowdsec_modules.actions.base import CrowdSecAction
from crowdsec_modules.models import GetAlertByIdArguments


class GetAlertById(CrowdSecAction):
    """Retrieve a single alert by its ID from CrowdSec LAPI (Watcher auth)."""

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        args = GetAlertByIdArguments(**arguments)
        alert = self.watcher_client.get_alert_by_id(args.alert_id)
        return {"alert": alert}
