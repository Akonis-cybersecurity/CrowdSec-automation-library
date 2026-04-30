import json
import time
from functools import cached_property
from typing import Any, Dict, List

from sekoia_automation.connector import Connector
from sekoia_automation.storage import PersistentJSON

from crowdsec_modules import CrowdsecModule
from crowdsec_modules.client import CrowdSecApiError, CrowdSecClient, _secret
from crowdsec_modules.models import CrowdSecDecisionTriggerConfiguration


class CrowdSecDecisionTrigger(Connector):
    """
    Streams CrowdSec decisions via GET /v1/decisions/stream and forwards them to Sekoia intake.

    Authentication: Bouncer (X-Api-Key).
    First call uses startup=true (full snapshot); subsequent calls use startup=false (delta).
    Both "new" and "deleted" decisions are forwarded as separate events.
    """

    module: CrowdsecModule
    configuration: CrowdSecDecisionTriggerConfiguration

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.context = PersistentJSON("crowdsec_decision_context.json", self._data_path)

    @cached_property
    def client(self) -> CrowdSecClient:
        cfg = self.module.configuration
        return CrowdSecClient(
            base_url=cfg.base_url,
            api_key=_secret(cfg.api_key),
        )

    @property
    def is_first_run(self) -> bool:
        with self.context as cache:
            return cache.get("decision_first_run", True)

    @is_first_run.setter
    def is_first_run(self, value: bool) -> None:
        with self.context as cache:
            cache["decision_first_run"] = value

    def _normalize_decision(self, decision: Dict[str, Any], action: str) -> Dict[str, Any]:
        return {
            "type": "crowdsec_decision",
            "action": action,
            "id": decision.get("id"),
            "uuid": decision.get("uuid"),
            "origin": decision.get("origin"),
            "decision_type": decision.get("type"),
            "scope": decision.get("scope"),
            "value": decision.get("value"),
            "duration": decision.get("duration"),
            "scenario": decision.get("scenario"),
            "simulated": decision.get("simulated"),
        }

    def fetch_and_push(self) -> None:
        cfg = self.configuration
        startup = self.is_first_run

        params: Dict[str, Any] = {}
        if cfg.scopes:
            params["scopes"] = cfg.scopes
        if cfg.origins:
            params["origins"] = cfg.origins
        if cfg.scenarios_containing:
            params["scenarios_containing"] = cfg.scenarios_containing
        if cfg.scenarios_not_containing:
            params["scenarios_not_containing"] = cfg.scenarios_not_containing

        try:
            stream = self.client.get_decisions_stream(startup=startup, **params)
        except CrowdSecApiError as exc:
            self.log(message=f"Failed to fetch decision stream: {exc}", level="error")
            return

        events: List[str] = []
        for decision in stream.get("new") or []:
            events.append(json.dumps(self._normalize_decision(decision, "new")))
        for decision in stream.get("deleted") or []:
            events.append(json.dumps(self._normalize_decision(decision, "deleted")))

        if events:
            self.push_events_to_intakes(events=events)
            self.log(message=f"Pushed {len(events)} decision events to intake", level="info")
        else:
            self.log(message="No decision updates to forward", level="info")

        if startup:
            self.is_first_run = False

    def run(self) -> None:
        self.log(message="CrowdSec Decision Trigger started", level="info")

        while self.running:
            start = time.time()

            try:
                self.fetch_and_push()
            except Exception as exc:
                self.log_exception(exc, message="Unexpected error in CrowdSec Decision Trigger")

            elapsed = time.time() - start
            sleep_time = max(0.0, self.configuration.frequency - elapsed)
            if sleep_time > 0:
                time.sleep(sleep_time)

        self.log(message="CrowdSec Decision Trigger stopped", level="info")
