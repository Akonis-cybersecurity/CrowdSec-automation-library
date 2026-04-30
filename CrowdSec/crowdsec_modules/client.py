import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)


def _secret(val: Any) -> Optional[str]:
    """Extract the secret value whether the field is SecretStr or a plain str injected by the SDK."""
    if val is None:
        return None
    return val.get_secret_value() if hasattr(val, "get_secret_value") else str(val)


class CrowdSecApiError(Exception):
    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        self.message = message
        super().__init__(f"CrowdSec API error {status_code}: {message}")


class CrowdSecClient:
    """
    HTTP client for the CrowdSec Local API.

    Supports two authentication modes:
    - Bouncer (api_key → X-Api-Key header): read-only decisions
    - Watcher (machine_id + password → JWT): full access
    """

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        machine_id: Optional[str] = None,
        password: Optional[str] = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._machine_id = machine_id
        self._password = password
        self._jwt_token: Optional[str] = None
        self._jwt_expiry: Optional[datetime] = None
        self._session = requests.Session()

    # ------------------------------------------------------------------
    # Auth helpers
    # ------------------------------------------------------------------

    def _bouncer_headers(self) -> Dict[str, str]:
        if not self._api_key:
            raise CrowdSecApiError(401, "Bouncer API key not configured")
        return {"X-Api-Key": self._api_key}

    def _watcher_headers(self) -> Dict[str, str]:
        self._ensure_jwt()
        return {"Authorization": f"Bearer {self._jwt_token}"}

    def _ensure_jwt(self) -> None:
        now = datetime.now(tz=timezone.utc)
        if self._jwt_token and self._jwt_expiry and (self._jwt_expiry - now).total_seconds() > 60:
            return
        self._login()

    def _login(self) -> None:
        if not self._machine_id or not self._password:
            raise CrowdSecApiError(401, "Watcher credentials (machine_id, password) not configured")

        url = f"{self._base_url}/v1/watchers/login"
        payload = {"machine_id": self._machine_id, "password": self._password}

        try:
            resp = self._session.post(url, json=payload, timeout=30)
        except requests.RequestException as exc:
            raise CrowdSecApiError(0, f"Connection error during login: {exc}") from exc

        if not resp.ok:
            raise CrowdSecApiError(resp.status_code, "Watcher authentication failed")

        data = resp.json()
        self._jwt_token = data.get("token")
        expire_str = data.get("expire")
        if expire_str:
            try:
                self._jwt_expiry = datetime.fromisoformat(expire_str.replace("Z", "+00:00"))
            except ValueError:
                self._jwt_expiry = datetime.now(tz=timezone.utc) + timedelta(hours=1)
        else:
            self._jwt_expiry = datetime.now(tz=timezone.utc) + timedelta(hours=1)

    # ------------------------------------------------------------------
    # Low-level HTTP helpers
    # ------------------------------------------------------------------

    def _get(
        self,
        path: str,
        headers: Dict[str, str],
        params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        url = f"{self._base_url}{path}"
        try:
            resp = self._session.get(url, headers=headers, params=params, timeout=30)
        except requests.RequestException as exc:
            raise CrowdSecApiError(0, f"Connection error on GET {path}: {exc}") from exc
        if not resp.ok:
            raise CrowdSecApiError(resp.status_code, resp.text[:200])
        if not resp.content:
            return None
        return resp.json()

    def _post(
        self,
        path: str,
        headers: Dict[str, str],
        json: Any = None,
    ) -> Any:
        url = f"{self._base_url}{path}"
        try:
            resp = self._session.post(url, headers=headers, json=json, timeout=30)
        except requests.RequestException as exc:
            raise CrowdSecApiError(0, f"Connection error on POST {path}: {exc}") from exc
        if not resp.ok:
            raise CrowdSecApiError(resp.status_code, resp.text[:200])
        if not resp.content:
            return None
        return resp.json()

    def _delete(
        self,
        path: str,
        headers: Dict[str, str],
        params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        url = f"{self._base_url}{path}"
        try:
            resp = self._session.delete(url, headers=headers, params=params, timeout=30)
        except requests.RequestException as exc:
            raise CrowdSecApiError(0, f"Connection error on DELETE {path}: {exc}") from exc
        if not resp.ok:
            raise CrowdSecApiError(resp.status_code, resp.text[:200])
        if not resp.content:
            return {}
        return resp.json()

    # ------------------------------------------------------------------
    # Bouncer endpoints (X-Api-Key)
    # ------------------------------------------------------------------

    def get_decisions(self, **params: Any) -> List[Any]:
        filtered = {k: v for k, v in params.items() if v is not None}
        return self._get("/v1/decisions", self._bouncer_headers(), filtered) or []

    def get_decisions_stream(self, startup: bool = False, **params: Any) -> Dict[str, Any]:
        filtered = {k: v for k, v in params.items() if v is not None}
        filtered["startup"] = str(startup).lower()
        return self._get("/v1/decisions/stream", self._bouncer_headers(), filtered) or {}

    # ------------------------------------------------------------------
    # Watcher endpoints (JWT)
    # ------------------------------------------------------------------

    def search_alerts(self, **params: Any) -> List[Any]:
        filtered = {k: v for k, v in params.items() if v is not None}
        return self._get("/v1/alerts", self._watcher_headers(), filtered) or []

    def get_alert_by_id(self, alert_id: int) -> Dict[str, Any]:
        return self._get(f"/v1/alerts/{alert_id}", self._watcher_headers()) or {}

    def push_alerts(self, alerts: List[Any]) -> List[Any]:
        return self._post("/v1/alerts", self._watcher_headers(), alerts) or []

    def delete_decision_by_id(self, decision_id: int) -> Dict[str, Any]:
        return self._delete(f"/v1/decisions/{decision_id}", self._watcher_headers()) or {}

    def delete_decisions(self, **params: Any) -> Dict[str, Any]:
        filtered = {k: v for k, v in params.items() if v is not None}
        return self._delete("/v1/decisions", self._watcher_headers(), filtered) or {}

    def delete_alerts(self, **params: Any) -> Dict[str, Any]:
        filtered = {k: v for k, v in params.items() if v is not None}
        return self._delete("/v1/alerts", self._watcher_headers(), filtered) or {}

    def delete_alert_by_id(self, alert_id: int) -> Dict[str, Any]:
        return self._delete(f"/v1/alerts/{alert_id}", self._watcher_headers()) or {}

    def get_allowlists(self) -> List[Any]:
        return self._get("/v1/allowlists", self._watcher_headers()) or []

    def get_allowlist(self, name: str, with_content: bool = False) -> Dict[str, Any]:
        params = {"with_content": str(with_content).lower()}
        return self._get(f"/v1/allowlists/{name}", self._watcher_headers(), params) or {}

    def check_allowlist(self, ip_or_range: str) -> Dict[str, Any]:
        return self._get(f"/v1/allowlists/check/{ip_or_range}", self._watcher_headers()) or {}

    def bulk_check_allowlist(self, targets: List[str]) -> Dict[str, Any]:
        return self._post("/v1/allowlists/check", self._watcher_headers(), targets) or {}
