from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from crowdsec_modules import CrowdsecModule
from crowdsec_modules.actions.allowlists import BulkCheckAllowlist, CheckAllowlist, GetAllowlist, GetAllowlists
from crowdsec_modules.actions.delete_alert_by_id import DeleteAlertById
from crowdsec_modules.actions.delete_alerts import DeleteAlerts
from crowdsec_modules.actions.delete_decision import DeleteDecision
from crowdsec_modules.actions.delete_decisions import DeleteDecisions
from crowdsec_modules.actions.get_alert_by_id import GetAlertById
from crowdsec_modules.actions.get_alerts import GetAlerts
from crowdsec_modules.actions.get_decisions import GetDecisions
from crowdsec_modules.client import CrowdSecClient
from crowdsec_modules.models import CrowdSecModuleConfiguration


def _make_module(base_url="http://localhost:8080", api_key="k", machine_id="m", password="p"):
    module = CrowdsecModule()
    module.configuration = CrowdSecModuleConfiguration(
        base_url=base_url,
        api_key=api_key,
        machine_id=machine_id,
        password=password,
    )
    return module


def _make_action(cls, module=None):
    action = cls.__new__(cls)
    action.module = module or _make_module()
    return action


def _make_jwt_client(base_url="http://localhost:8080", **kwargs) -> CrowdSecClient:
    client = CrowdSecClient(base_url=base_url, **kwargs)
    client._jwt_token = "test-token"
    client._jwt_expiry = datetime.now(tz=timezone.utc) + timedelta(hours=1)
    return client


class TestGetDecisionsAction:
    def test_run(self):
        action = _make_action(GetDecisions)
        mock_client = MagicMock()
        mock_client.get_decisions.return_value = [{"id": 1, "type": "ban"}]

        with patch.object(type(action), "bouncer_client", new_callable=lambda: property(lambda self: mock_client)):
            result = action.run({})

        assert result["decisions"][0]["type"] == "ban"
        mock_client.get_decisions.assert_called_once()

    def test_run_with_filters(self):
        action = _make_action(GetDecisions)
        mock_client = MagicMock()
        mock_client.get_decisions.return_value = []

        with patch.object(type(action), "bouncer_client", new_callable=lambda: property(lambda self: mock_client)):
            result = action.run({"type": "ban", "ip": "1.2.3.4"})

        assert result["decisions"] == []
        call_kwargs = mock_client.get_decisions.call_args[1]
        assert call_kwargs.get("type") == "ban"
        assert call_kwargs.get("ip") == "1.2.3.4"


class TestGetAlertsAction:
    def test_run(self):
        action = _make_action(GetAlerts)
        mock_client = MagicMock()
        mock_client.search_alerts.return_value = [{"id": 10, "scenario": "brute-force"}]

        with patch.object(type(action), "watcher_client", new_callable=lambda: property(lambda self: mock_client)):
            result = action.run({"scenario": "brute-force"})

        assert result["alerts"][0]["id"] == 10


class TestGetAlertByIdAction:
    def test_run(self):
        action = _make_action(GetAlertById)
        mock_client = MagicMock()
        mock_client.get_alert_by_id.return_value = {"id": 42}

        with patch.object(type(action), "watcher_client", new_callable=lambda: property(lambda self: mock_client)):
            result = action.run({"alert_id": 42})

        assert result["alert"]["id"] == 42
        mock_client.get_alert_by_id.assert_called_once_with(42)


class TestDeleteDecisionAction:
    def test_run(self):
        action = _make_action(DeleteDecision)
        mock_client = MagicMock()
        mock_client.delete_decision_by_id.return_value = {"nbDeleted": "1"}

        with patch.object(type(action), "watcher_client", new_callable=lambda: property(lambda self: mock_client)):
            result = action.run({"decision_id": 99})

        assert result["result"]["nbDeleted"] == "1"
        mock_client.delete_decision_by_id.assert_called_once_with(99)


class TestDeleteDecisionsAction:
    def test_run(self):
        action = _make_action(DeleteDecisions)
        mock_client = MagicMock()
        mock_client.delete_decisions.return_value = {"nbDeleted": "5"}

        with patch.object(type(action), "watcher_client", new_callable=lambda: property(lambda self: mock_client)):
            result = action.run({"ip": "1.2.3.4"})

        assert result["result"]["nbDeleted"] == "5"


class TestDeleteAlertsAction:
    def test_run(self):
        action = _make_action(DeleteAlerts)
        mock_client = MagicMock()
        mock_client.delete_alerts.return_value = {"nbDeleted": "3"}

        with patch.object(type(action), "watcher_client", new_callable=lambda: property(lambda self: mock_client)):
            result = action.run({"scenario": "ssh_brute-force"})

        assert result["result"]["nbDeleted"] == "3"


class TestDeleteAlertByIdAction:
    def test_run(self):
        action = _make_action(DeleteAlertById)
        mock_client = MagicMock()
        mock_client.delete_alert_by_id.return_value = {"nbDeleted": "1"}

        with patch.object(type(action), "watcher_client", new_callable=lambda: property(lambda self: mock_client)):
            result = action.run({"alert_id": 7})

        assert result["result"]["nbDeleted"] == "1"
        mock_client.delete_alert_by_id.assert_called_once_with(7)


class TestGetAllowlistsAction:
    def test_run(self):
        action = _make_action(GetAllowlists)
        mock_client = MagicMock()
        mock_client.get_allowlists.return_value = [{"name": "safe-ips"}]

        with patch.object(type(action), "watcher_client", new_callable=lambda: property(lambda self: mock_client)):
            result = action.run({})

        assert result["allowlists"][0]["name"] == "safe-ips"


class TestGetAllowlistAction:
    def test_run(self):
        action = _make_action(GetAllowlist)
        mock_client = MagicMock()
        mock_client.get_allowlist.return_value = {"name": "safe-ips", "items": []}

        with patch.object(type(action), "watcher_client", new_callable=lambda: property(lambda self: mock_client)):
            result = action.run({"name": "safe-ips", "with_content": True})

        assert result["allowlist"]["name"] == "safe-ips"
        mock_client.get_allowlist.assert_called_once_with("safe-ips", True)


class TestCheckAllowlistAction:
    def test_run(self):
        action = _make_action(CheckAllowlist)
        mock_client = MagicMock()
        mock_client.check_allowlist.return_value = {"results": []}

        with patch.object(type(action), "watcher_client", new_callable=lambda: property(lambda self: mock_client)):
            result = action.run({"ip_or_range": "10.0.0.1"})

        assert "result" in result
        mock_client.check_allowlist.assert_called_once_with("10.0.0.1")


class TestBulkCheckAllowlistAction:
    def test_run(self):
        action = _make_action(BulkCheckAllowlist)
        mock_client = MagicMock()
        mock_client.bulk_check_allowlist.return_value = {"results": []}

        with patch.object(type(action), "watcher_client", new_callable=lambda: property(lambda self: mock_client)):
            result = action.run({"targets": ["1.2.3.4", "5.6.7.8"]})

        assert "result" in result
        mock_client.bulk_check_allowlist.assert_called_once_with(["1.2.3.4", "5.6.7.8"])
