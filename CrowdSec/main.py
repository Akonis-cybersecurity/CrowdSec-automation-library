from crowdsec_modules import CrowdsecModule
from crowdsec_modules.actions.allowlists import BulkCheckAllowlist, CheckAllowlist, GetAllowlist, GetAllowlists
from crowdsec_modules.actions.delete_alert_by_id import DeleteAlertById
from crowdsec_modules.actions.delete_alerts import DeleteAlerts
from crowdsec_modules.actions.delete_decision import DeleteDecision
from crowdsec_modules.actions.delete_decisions import DeleteDecisions
from crowdsec_modules.actions.get_alert_by_id import GetAlertById
from crowdsec_modules.actions.get_alerts import GetAlerts
from crowdsec_modules.actions.get_decisions import GetDecisions
from crowdsec_modules.triggers.alert_trigger import CrowdSecAlertTrigger
from crowdsec_modules.triggers.decision_trigger import CrowdSecDecisionTrigger

if __name__ == "__main__":
    module = CrowdsecModule()

    module.register(CrowdSecAlertTrigger, "crowdsec_alert_trigger")
    module.register(CrowdSecDecisionTrigger, "crowdsec_decision_trigger")

    module.register(GetDecisions, "crowdsec_get_decisions")
    module.register(GetAlerts, "crowdsec_get_alerts")
    module.register(GetAlertById, "crowdsec_get_alert_by_id")
    module.register(DeleteDecision, "crowdsec_delete_decision")
    module.register(DeleteDecisions, "crowdsec_delete_decisions")
    module.register(DeleteAlerts, "crowdsec_delete_alerts")
    module.register(DeleteAlertById, "crowdsec_delete_alert_by_id")
    module.register(GetAllowlists, "crowdsec_get_allowlists")
    module.register(GetAllowlist, "crowdsec_get_allowlist")
    module.register(CheckAllowlist, "crowdsec_check_allowlist")
    module.register(BulkCheckAllowlist, "crowdsec_bulk_check_allowlist")

    module.run()
