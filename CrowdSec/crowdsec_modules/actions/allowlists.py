from typing import Any, Dict, List

from crowdsec_modules.actions.base import CrowdSecAction
from crowdsec_modules.models import BulkCheckAllowlistArguments, CheckAllowlistArguments, GetAllowlistArguments


class GetAllowlists(CrowdSecAction):
    """List all allowlists configured in CrowdSec LAPI (Watcher auth)."""

    def run(self, arguments: Dict[str, Any]) -> Dict[str, List[Any]]:
        allowlists = self.watcher_client.get_allowlists()
        return {"allowlists": allowlists}


class GetAllowlist(CrowdSecAction):
    """Retrieve a specific allowlist by name from CrowdSec LAPI (Watcher auth)."""

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        args = GetAllowlistArguments(**arguments)
        allowlist = self.watcher_client.get_allowlist(args.name, args.with_content)
        return {"allowlist": allowlist}


class CheckAllowlist(CrowdSecAction):
    """Check whether an IP or CIDR range is present in any CrowdSec allowlist (Watcher auth)."""

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        args = CheckAllowlistArguments(**arguments)
        result = self.watcher_client.check_allowlist(args.ip_or_range)
        return {"result": result}


class BulkCheckAllowlist(CrowdSecAction):
    """Check multiple IPs or CIDR ranges against all CrowdSec allowlists (Watcher auth)."""

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        args = BulkCheckAllowlistArguments(**arguments)
        result = self.watcher_client.bulk_check_allowlist(args.targets)
        return {"result": result}
