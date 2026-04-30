from typing import List, Optional

from pydantic.v1 import BaseModel, Field, SecretStr
from sekoia_automation.connector import DefaultConnectorConfiguration


class CrowdSecModuleConfiguration(BaseModel):
    base_url: str = Field(..., description="CrowdSec LAPI base URL (e.g. http://127.0.0.1:8080)")
    api_key: Optional[SecretStr] = Field(None, description="Bouncer API key (required for decision trigger)")
    machine_id: Optional[str] = Field(None, description="Watcher machine ID (required for alert trigger)")
    password: Optional[SecretStr] = Field(None, description="Watcher password (required for alert trigger)")


class CrowdSecAlertTriggerConfiguration(DefaultConnectorConfiguration):
    frequency: int = Field(60, description="Polling frequency in seconds")
    scenario: Optional[str] = Field(None, description="Filter alerts by scenario name")
    ip: Optional[str] = Field(None, description="Filter alerts by source IP")
    has_active_decision: Optional[bool] = Field(None, description="Filter alerts that have an active decision")
    origin: Optional[str] = Field(None, description="Filter alerts by origin")
    limit: int = Field(100, description="Maximum number of alerts per request")


class CrowdSecDecisionTriggerConfiguration(DefaultConnectorConfiguration):
    frequency: int = Field(60, description="Polling frequency in seconds")
    scopes: Optional[str] = Field(None, description="Comma-separated list of decision scopes")
    origins: Optional[str] = Field(None, description="Comma-separated list of decision origins")
    scenarios_containing: Optional[str] = Field(None, description="Filter decisions by scenario containing string")
    scenarios_not_containing: Optional[str] = Field(
        None, description="Filter decisions by scenario not containing string"
    )


class GetDecisionsArguments(BaseModel):
    scope: Optional[str] = Field(None, description="Filter by scope (ip, range, username…)")
    value: Optional[str] = Field(None, description="Filter by value")
    type: Optional[str] = Field(None, description="Filter by decision type (ban, captcha…)")
    ip: Optional[str] = Field(None, description="Filter decisions for a given IP")
    range: Optional[str] = Field(None, description="Filter decisions for a given IP range (CIDR)")
    contains: Optional[bool] = Field(None, description="Filter decisions containing the given IP/range")
    origins: Optional[str] = Field(None, description="Comma-separated list of origins")
    scenarios_containing: Optional[str] = Field(None, description="Filter by scenario containing string")
    scenarios_not_containing: Optional[str] = Field(None, description="Filter by scenario not containing string")


class GetAlertsArguments(BaseModel):
    scope: Optional[str] = Field(None, description="Filter by scope")
    value: Optional[str] = Field(None, description="Filter by value")
    scenario: Optional[str] = Field(None, description="Filter by scenario name")
    ip: Optional[str] = Field(None, description="Filter by source IP")
    range: Optional[str] = Field(None, description="Filter by IP range (CIDR)")
    since: Optional[str] = Field(None, description="Return alerts created after this timestamp (RFC3339)")
    until: Optional[str] = Field(None, description="Return alerts created before this timestamp (RFC3339)")
    origin: Optional[str] = Field(None, description="Filter by alert origin")
    has_active_decision: Optional[bool] = Field(None, description="Filter alerts with an active decision")
    decision_type: Optional[str] = Field(None, description="Filter alerts by their decision type")
    limit: Optional[int] = Field(None, description="Maximum number of alerts to return")


class GetAlertByIdArguments(BaseModel):
    alert_id: int = Field(..., description="Alert ID")


class DeleteDecisionArguments(BaseModel):
    decision_id: int = Field(..., description="Decision ID to delete")


class DeleteDecisionsArguments(BaseModel):
    scope: Optional[str] = Field(None, description="Filter by scope")
    value: Optional[str] = Field(None, description="Filter by value")
    type: Optional[str] = Field(None, description="Filter by decision type")
    ip: Optional[str] = Field(None, description="Filter by IP address")
    range: Optional[str] = Field(None, description="Filter by IP range (CIDR)")
    scenario: Optional[str] = Field(None, description="Filter by scenario name")
    origin: Optional[str] = Field(None, description="Filter by origin")


class DeleteAlertsArguments(BaseModel):
    scope: Optional[str] = Field(None, description="Filter by scope")
    value: Optional[str] = Field(None, description="Filter by value")
    scenario: Optional[str] = Field(None, description="Filter by scenario name")
    ip: Optional[str] = Field(None, description="Filter by IP address")
    range: Optional[str] = Field(None, description="Filter by IP range (CIDR)")
    since: Optional[str] = Field(None, description="Delete alerts created after this timestamp")
    until: Optional[str] = Field(None, description="Delete alerts created before this timestamp")
    origin: Optional[str] = Field(None, description="Filter by origin")
    has_active_decision: Optional[bool] = Field(None, description="Filter by has_active_decision")


class DeleteAlertByIdArguments(BaseModel):
    alert_id: int = Field(..., description="Alert ID to delete")


class GetAllowlistArguments(BaseModel):
    name: str = Field(..., description="Allowlist name")
    with_content: bool = Field(False, description="Include allowlist items in the response")


class CheckAllowlistArguments(BaseModel):
    ip_or_range: str = Field(..., description="IP address or CIDR range to check against all allowlists")


class BulkCheckAllowlistArguments(BaseModel):
    targets: List[str] = Field(..., description="List of IPs or CIDR ranges to check against all allowlists")
