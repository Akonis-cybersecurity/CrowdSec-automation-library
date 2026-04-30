from typing import Any, Dict, List

from crowdsec_modules.actions.base import CrowdSecAction
from crowdsec_modules.models import GetAlertsArguments


class GetAlerts(CrowdSecAction):
    """Search alerts in CrowdSec LAPI (Watcher auth)."""

    def run(self, arguments: Dict[str, Any]) -> Dict[str, List[Any]]:
        args = GetAlertsArguments(**arguments)
        params = args.dict(exclude_none=True)
        alerts = self.watcher_client.search_alerts(**params)
        return {"alerts": alerts}
