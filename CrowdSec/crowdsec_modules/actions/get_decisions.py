from typing import Any, Dict, List

from crowdsec_modules.actions.base import CrowdSecAction
from crowdsec_modules.models import GetDecisionsArguments


class GetDecisions(CrowdSecAction):
    """Retrieve active decisions from CrowdSec LAPI (Bouncer auth)."""

    def run(self, arguments: Dict[str, Any]) -> Dict[str, List[Any]]:
        args = GetDecisionsArguments(**arguments)
        params = args.dict(exclude_none=True)
        decisions = self.bouncer_client.get_decisions(**params)
        return {"decisions": decisions}
