import pytest
from pydantic.v1 import ValidationError

from crowdsec_modules.models import (
    BulkCheckAllowlistArguments,
    CheckAllowlistArguments,
    CrowdSecAlertTriggerConfiguration,
    CrowdSecDecisionTriggerConfiguration,
    CrowdSecModuleConfiguration,
    DeleteAlertByIdArguments,
    DeleteAlertsArguments,
    DeleteDecisionArguments,
    DeleteDecisionsArguments,
    GetAlertByIdArguments,
    GetAlertsArguments,
    GetAllowlistArguments,
    GetDecisionsArguments,
)


class TestCrowdSecModuleConfiguration:
    def test_required_base_url(self):
        cfg = CrowdSecModuleConfiguration(base_url="http://127.0.0.1:8080")
        assert cfg.base_url == "http://127.0.0.1:8080"
        assert cfg.api_key is None
        assert cfg.machine_id is None
        assert cfg.password is None

    def test_all_fields(self):
        cfg = CrowdSecModuleConfiguration(
            base_url="http://localhost:8080",
            api_key="bouncer-key",
            machine_id="my-machine",
            password="s3cr3t",
        )
        assert cfg.api_key.get_secret_value() == "bouncer-key"
        assert cfg.machine_id == "my-machine"
        assert cfg.password.get_secret_value() == "s3cr3t"

    def test_missing_base_url_raises(self):
        with pytest.raises(ValidationError):
            CrowdSecModuleConfiguration()


class TestAlertTriggerConfiguration:
    def test_defaults(self):
        cfg = CrowdSecAlertTriggerConfiguration(intake_key="ik-test")
        assert cfg.frequency == 60
        assert cfg.limit == 100
        assert cfg.scenario is None

    def test_custom_values(self):
        cfg = CrowdSecAlertTriggerConfiguration(
            intake_key="ik-test",
            frequency=30,
            scenario="ssh_brute-force",
            ip="1.2.3.4",
            has_active_decision=True,
            limit=50,
        )
        assert cfg.frequency == 30
        assert cfg.scenario == "ssh_brute-force"
        assert cfg.has_active_decision is True


class TestDecisionTriggerConfiguration:
    def test_defaults(self):
        cfg = CrowdSecDecisionTriggerConfiguration(intake_key="ik-test")
        assert cfg.frequency == 60
        assert cfg.scopes is None
        assert cfg.origins is None

    def test_custom_values(self):
        cfg = CrowdSecDecisionTriggerConfiguration(
            intake_key="ik-test",
            frequency=120,
            scopes="ip,range",
            origins="crowdsec",
        )
        assert cfg.scopes == "ip,range"
        assert cfg.origins == "crowdsec"


class TestGetDecisionsArguments:
    def test_all_optional(self):
        args = GetDecisionsArguments()
        assert args.dict(exclude_none=True) == {}

    def test_with_filters(self):
        args = GetDecisionsArguments(scope="ip", type="ban", ip="1.2.3.4")
        d = args.dict(exclude_none=True)
        assert d["scope"] == "ip"
        assert d["type"] == "ban"
        assert d["ip"] == "1.2.3.4"


class TestGetAlertsArguments:
    def test_all_optional(self):
        args = GetAlertsArguments()
        assert args.dict(exclude_none=True) == {}

    def test_with_since(self):
        args = GetAlertsArguments(since="2026-01-01T00:00:00Z", limit=50)
        d = args.dict(exclude_none=True)
        assert d["since"] == "2026-01-01T00:00:00Z"
        assert d["limit"] == 50


class TestGetAlertByIdArguments:
    def test_required_id(self):
        args = GetAlertByIdArguments(alert_id=42)
        assert args.alert_id == 42

    def test_missing_id_raises(self):
        with pytest.raises(ValidationError):
            GetAlertByIdArguments()


class TestDeleteDecisionArguments:
    def test_required_id(self):
        args = DeleteDecisionArguments(decision_id=99)
        assert args.decision_id == 99

    def test_missing_id_raises(self):
        with pytest.raises(ValidationError):
            DeleteDecisionArguments()


class TestDeleteDecisionsArguments:
    def test_all_optional(self):
        args = DeleteDecisionsArguments()
        assert args.dict(exclude_none=True) == {}


class TestDeleteAlertsArguments:
    def test_all_optional(self):
        args = DeleteAlertsArguments()
        assert args.dict(exclude_none=True) == {}


class TestDeleteAlertByIdArguments:
    def test_required_id(self):
        args = DeleteAlertByIdArguments(alert_id=7)
        assert args.alert_id == 7


class TestGetAllowlistArguments:
    def test_defaults(self):
        args = GetAllowlistArguments(name="my-list")
        assert args.name == "my-list"
        assert args.with_content is False

    def test_with_content(self):
        args = GetAllowlistArguments(name="my-list", with_content=True)
        assert args.with_content is True


class TestCheckAllowlistArguments:
    def test_required_field(self):
        args = CheckAllowlistArguments(ip_or_range="1.2.3.4")
        assert args.ip_or_range == "1.2.3.4"

    def test_missing_raises(self):
        with pytest.raises(ValidationError):
            CheckAllowlistArguments()


class TestBulkCheckAllowlistArguments:
    def test_targets(self):
        args = BulkCheckAllowlistArguments(targets=["1.2.3.4", "10.0.0.0/8"])
        assert len(args.targets) == 2

    def test_missing_raises(self):
        with pytest.raises(ValidationError):
            BulkCheckAllowlistArguments()
