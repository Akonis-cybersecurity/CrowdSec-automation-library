import json
import time
from functools import cached_property
from typing import Any, Dict, List, Optional

from sekoia_automation.connector import Connector
from sekoia_automation.storage import PersistentJSON

from crowdsec_modules import CrowdsecModule
from crowdsec_modules.client import CrowdSecApiError, CrowdSecClient, _secret
from crowdsec_modules.models import CrowdSecAlertTriggerConfiguration


class CrowdSecAlertTrigger(Connector):
    """
    Polls CrowdSec LAPI GET /v1/alerts and forwards new alerts to Sekoia intake.

    Authentication: Watcher (JWT) via machine_id + password.
    Cursor: ISO timestamp of the most recently seen alert (stored in context.json).
    """

    module: CrowdsecModule
    configuration: CrowdSecAlertTriggerConfiguration

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.context = PersistentJSON("crowdsec_alert_context.json", self._data_path)

    @cached_property
    def client(self) -> CrowdSecClient:
        cfg = self.module.configuration
        return CrowdSecClient(
            base_url=cfg.base_url,
            machine_id=cfg.machine_id,
            password=_secret(cfg.password),
        )

    @property
    def cursor(self) -> Optional[str]:
        with self.context as cache:
            return cache.get("alert_cursor")

    @cursor.setter
    def cursor(self, value: str) -> None:
        with self.context as cache:
            cache["alert_cursor"] = value

    def _normalize_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "type": "crowdsec_alert",
            "id": alert.get("id"),
            "uuid": alert.get("uuid"),
            "created_at": alert.get("created_at"),
            "scenario": alert.get("scenario"),
            "message": alert.get("message"),
            "events_count": alert.get("events_count"),
            "start_at": alert.get("start_at"),
            "stop_at": alert.get("stop_at"),
            "simulated": alert.get("simulated"),
            "remediation": alert.get("remediation"),
            "kind": alert.get("alert_type"),
            "source": alert.get("source"),
            "decisions": alert.get("decisions"),
            "events": alert.get("events"),
            "meta": alert.get("meta"),
            "labels": alert.get("labels"),
            "machine_id": alert.get("machine_id"),
        }

    def fetch_and_push(self) -> None:
        cfg = self.configuration
        params: Dict[str, Any] = {"limit": cfg.limit}

        since = self.cursor
        if since:
            params["since"] = since

        if cfg.scenario:
            params["scenario"] = cfg.scenario
        if cfg.ip:
            params["ip"] = cfg.ip
        if cfg.has_active_decision is not None:
            params["has_active_decision"] = cfg.has_active_decision
        if cfg.origin:
            params["origin"] = cfg.origin

        try:
            alerts: List[Dict[str, Any]] = self.client.search_alerts(**params)
        except CrowdSecApiError as exc:
            self.log(message=f"Failed to fetch alerts: {exc}", level="error")
            return

        if not alerts:
            self.log(message="No new alerts to forward", level="info")
            return

        batch = [json.dumps(self._normalize_alert(a)) for a in alerts]
        self.push_events_to_intakes(events=batch)
        self.log(message=f"Pushed {len(batch)} alert events to intake", level="info")

        most_recent = max(alerts, key=lambda a: a.get("created_at") or "")
        if most_recent.get("created_at"):
            self.cursor = most_recent["created_at"]

    def run(self) -> None:
        self.log(message="CrowdSec Alert Trigger started", level="info")

        while self.running:
            start = time.time()

            try:
                self.fetch_and_push()
            except Exception as exc:
                self.log_exception(exc, message="Unexpected error in CrowdSec Alert Trigger")

            elapsed = time.time() - start
            sleep_time = max(0.0, self.configuration.frequency - elapsed)
            if sleep_time > 0:
                time.sleep(sleep_time)

        self.log(message="CrowdSec Alert Trigger stopped", level="info")
