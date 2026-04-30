import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, call, patch

import pytest

from crowdsec_modules import CrowdsecModule
from crowdsec_modules.client import CrowdSecApiError
from crowdsec_modules.models import CrowdSecAlertTriggerConfiguration, CrowdSecDecisionTriggerConfiguration, CrowdSecModuleConfiguration
from crowdsec_modules.triggers.alert_trigger import CrowdSecAlertTrigger
from crowdsec_modules.triggers.decision_trigger import CrowdSecDecisionTrigger


def _make_module():
    module = CrowdsecModule()
    module.configuration = CrowdSecModuleConfiguration(
        base_url="http://localhost:8080",
        api_key="bouncer-key",
        machine_id="my-machine",
        password="my-password",
    )
    return module


def _make_alert_trigger(data_storage):
    trigger = CrowdSecAlertTrigger.__new__(CrowdSecAlertTrigger)
    trigger.module = _make_module()
    trigger.configuration = CrowdSecAlertTriggerConfiguration(intake_key="ik-test", frequency=60)
    trigger._data_path = data_storage
    trigger.__dict__.pop("client", None)
    return trigger


def _make_decision_trigger(data_storage):
    trigger = CrowdSecDecisionTrigger.__new__(CrowdSecDecisionTrigger)
    trigger.module = _make_module()
    trigger.configuration = CrowdSecDecisionTriggerConfiguration(intake_key="ik-test", frequency=60)
    trigger._data_path = data_storage
    trigger.__dict__.pop("client", None)
    return trigger


class TestAlertTriggerNormalize:
    def test_normalize_alert(self, data_storage):
        trigger = _make_alert_trigger(data_storage)
        raw = {
            "id": 1,
            "uuid": "abc-123",
            "created_at": "2026-01-01T00:00:00Z",
            "scenario": "ssh_brute-force",
            "message": "Brute force",
            "events_count": 5,
            "start_at": "2026-01-01T00:00:00Z",
            "stop_at": "2026-01-01T00:01:00Z",
            "simulated": False,
            "remediation": True,
            "alert_type": "ban",
            "source": {"ip": "1.2.3.4"},
            "decisions": [{"type": "ban"}],
            "events": [],
            "meta": [],
            "labels": None,
            "machine_id": "my-machine",
        }
        normalized = trigger._normalize_alert(raw)
        assert normalized["type"] == "crowdsec_alert"
        assert normalized["id"] == 1
        assert normalized["scenario"] == "ssh_brute-force"
        assert normalized["kind"] == "ban"
        assert normalized["machine_id"] == "my-machine"


class TestAlertTriggerFetchAndPush:
    def test_fetch_no_alerts(self, data_storage):
        trigger = _make_alert_trigger(data_storage)
        mock_client = MagicMock()
        mock_client.search_alerts.return_value = []

        with patch.object(type(trigger), "client", new_callable=lambda: property(lambda self: mock_client)):
            trigger.context = MagicMock()
            trigger.context.__enter__ = lambda s: {}
            trigger.context.__exit__ = MagicMock(return_value=False)
            trigger.push_events_to_intakes = MagicMock()
            trigger.log = MagicMock()
            trigger.fetch_and_push()

        trigger.push_events_to_intakes.assert_not_called()

    def test_fetch_with_alerts_pushes_json_strings(self, data_storage):
        trigger = _make_alert_trigger(data_storage)
        mock_client = MagicMock()
        mock_client.search_alerts.return_value = [
            {"id": 1, "created_at": "2026-01-01T00:00:01Z", "scenario": "ssh_brute-force"},
            {"id": 2, "created_at": "2026-01-01T00:00:02Z", "scenario": "http_scan"},
        ]

        with patch.object(type(trigger), "client", new_callable=lambda: property(lambda self: mock_client)):
            trigger.push_events_to_intakes = MagicMock()
            trigger.log = MagicMock()

            # Minimal PersistentJSON mock
            cache_store = {}
            cm = MagicMock()
            cm.__enter__ = lambda s: cache_store
            cm.__exit__ = MagicMock(return_value=False)
            trigger.context = cm

            trigger.fetch_and_push()

        trigger.push_events_to_intakes.assert_called_once()
        events = trigger.push_events_to_intakes.call_args[1]["events"]
        assert len(events) == 2
        # Each event must be a valid JSON string
        for e in events:
            parsed = json.loads(e)
            assert parsed["type"] == "crowdsec_alert"

    def test_fetch_api_error_logs_and_returns(self, data_storage):
        trigger = _make_alert_trigger(data_storage)
        mock_client = MagicMock()
        mock_client.search_alerts.side_effect = CrowdSecApiError(500, "Internal error")

        with patch.object(type(trigger), "client", new_callable=lambda: property(lambda self: mock_client)):
            trigger.push_events_to_intakes = MagicMock()
            trigger.log = MagicMock()

            cache_store = {}
            cm = MagicMock()
            cm.__enter__ = lambda s: cache_store
            cm.__exit__ = MagicMock(return_value=False)
            trigger.context = cm

            trigger.fetch_and_push()

        trigger.push_events_to_intakes.assert_not_called()
        trigger.log.assert_called()


class TestDecisionTriggerNormalize:
    def test_normalize_new_decision(self, data_storage):
        trigger = _make_decision_trigger(data_storage)
        raw = {
            "id": 5,
            "uuid": "dec-uuid",
            "origin": "crowdsec",
            "type": "ban",
            "scope": "ip",
            "value": "1.2.3.4",
            "duration": "4h",
            "scenario": "ssh_brute-force",
            "simulated": False,
        }
        normalized = trigger._normalize_decision(raw, "new")
        assert normalized["type"] == "crowdsec_decision"
        assert normalized["action"] == "new"
        assert normalized["decision_type"] == "ban"
        assert normalized["value"] == "1.2.3.4"

    def test_normalize_deleted_decision(self, data_storage):
        trigger = _make_decision_trigger(data_storage)
        normalized = trigger._normalize_decision({"id": 1}, "deleted")
        assert normalized["action"] == "deleted"


class TestDecisionTriggerFetchAndPush:
    def test_first_run_sends_startup_true(self, data_storage):
        trigger = _make_decision_trigger(data_storage)
        mock_client = MagicMock()
        mock_client.get_decisions_stream.return_value = {"new": [], "deleted": []}

        with patch.object(type(trigger), "client", new_callable=lambda: property(lambda self: mock_client)):
            trigger.push_events_to_intakes = MagicMock()
            trigger.log = MagicMock()

            cache_store = {"decision_first_run": True}
            cm = MagicMock()
            cm.__enter__ = lambda s: cache_store
            cm.__exit__ = MagicMock(return_value=False)
            trigger.context = cm

            trigger.fetch_and_push()

        mock_client.get_decisions_stream.assert_called_once_with(startup=True)

    def test_second_run_sends_startup_false(self, data_storage):
        trigger = _make_decision_trigger(data_storage)
        mock_client = MagicMock()
        mock_client.get_decisions_stream.return_value = {"new": [], "deleted": []}

        with patch.object(type(trigger), "client", new_callable=lambda: property(lambda self: mock_client)):
            trigger.push_events_to_intakes = MagicMock()
            trigger.log = MagicMock()

            cache_store = {"decision_first_run": False}
            cm = MagicMock()
            cm.__enter__ = lambda s: cache_store
            cm.__exit__ = MagicMock(return_value=False)
            trigger.context = cm

            trigger.fetch_and_push()

        mock_client.get_decisions_stream.assert_called_once_with(startup=False)

    def test_pushes_new_and_deleted(self, data_storage):
        trigger = _make_decision_trigger(data_storage)
        mock_client = MagicMock()
        mock_client.get_decisions_stream.return_value = {
            "new": [{"id": 1, "type": "ban", "value": "1.2.3.4"}],
            "deleted": [{"id": 2, "type": "ban", "value": "5.6.7.8"}],
        }

        with patch.object(type(trigger), "client", new_callable=lambda: property(lambda self: mock_client)):
            trigger.push_events_to_intakes = MagicMock()
            trigger.log = MagicMock()

            cache_store = {"decision_first_run": False}
            cm = MagicMock()
            cm.__enter__ = lambda s: cache_store
            cm.__exit__ = MagicMock(return_value=False)
            trigger.context = cm

            trigger.fetch_and_push()

        events = trigger.push_events_to_intakes.call_args[1]["events"]
        assert len(events) == 2
        actions = [json.loads(e)["action"] for e in events]
        assert "new" in actions
        assert "deleted" in actions

    def test_api_error_logs_and_returns(self, data_storage):
        trigger = _make_decision_trigger(data_storage)
        mock_client = MagicMock()
        mock_client.get_decisions_stream.side_effect = CrowdSecApiError(503, "Service Unavailable")

        with patch.object(type(trigger), "client", new_callable=lambda: property(lambda self: mock_client)):
            trigger.push_events_to_intakes = MagicMock()
            trigger.log = MagicMock()

            cache_store = {"decision_first_run": False}
            cm = MagicMock()
            cm.__enter__ = lambda s: cache_store
            cm.__exit__ = MagicMock(return_value=False)
            trigger.context = cm

            trigger.fetch_and_push()

        trigger.push_events_to_intakes.assert_not_called()
