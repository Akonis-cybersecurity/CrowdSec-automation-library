from sekoia_automation.module import Module

from crowdsec_modules.models import CrowdSecModuleConfiguration


class CrowdsecModule(Module):
    configuration: CrowdSecModuleConfiguration
