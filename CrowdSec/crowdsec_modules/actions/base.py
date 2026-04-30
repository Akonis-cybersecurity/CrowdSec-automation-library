from functools import cached_property

from sekoia_automation.action import Action

from crowdsec_modules import CrowdsecModule
from crowdsec_modules.client import CrowdSecClient, _secret


class CrowdSecAction(Action):
    """Base class for all CrowdSec actions."""

    module: CrowdsecModule

    @cached_property
    def bouncer_client(self) -> CrowdSecClient:
        cfg = self.module.configuration
        return CrowdSecClient(
            base_url=cfg.base_url,
            api_key=_secret(cfg.api_key),
        )

    @cached_property
    def watcher_client(self) -> CrowdSecClient:
        cfg = self.module.configuration
        return CrowdSecClient(
            base_url=cfg.base_url,
            machine_id=cfg.machine_id,
            password=_secret(cfg.password),
        )
