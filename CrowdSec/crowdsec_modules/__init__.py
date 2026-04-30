from sekoia_automation.module import Module
from crowdsec_modules.models import CrowdsecModuleConfiguration


class CrowdsecModule(Module):
    configuration: CrowdsecModuleConfiguration
