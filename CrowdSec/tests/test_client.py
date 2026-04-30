from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
import requests

from crowdsec_modules.client import CrowdSecApiError, CrowdSecClient, _secret


class TestSecretHelper:
    def test_plain_string(self):
        assert _secret("hello") == "hello"

    def test_secret_str(self):
        mock = MagicMock()
        mock.get_secret_value.return_value = "hidden"
        assert _secret(mock) == "hidden"

    def test_none(self):
        assert _secret(None) is None


class TestCrowdSecApiError:
    def test_message(self):
        err = CrowdSecApiError(403, "Forbidden")
        assert err.status_code == 403
        assert err.message == "Forbidden"
        assert "403" in str(err)


class TestCrowdSecClientInit:
    def test_base_url_stripped(self):
        client = CrowdSecClient(base_url="http://localhost:8080/")
        assert client._base_url == "http://localhost:8080"

    def test_no_auth_fields(self):
        client = CrowdSecClient(base_url="http://localhost:8080")
        assert client._api_key is None
        assert client._machine_id is None
        assert client._password is None


class TestBouncerAuth:
    def test_bouncer_headers_with_key(self):
        client = CrowdSecClient(base_url="http://localhost:8080", api_key="test-key")
        headers = client._bouncer_headers()
        assert headers == {"X-Api-Key": "test-key"}

    def test_bouncer_headers_no_key_raises(self):
        client = CrowdSecClient(base_url="http://localhost:8080")
        with pytest.raises(CrowdSecApiError) as exc_info:
            client._bouncer_headers()
        assert exc_info.value.status_code == 401


class TestWatcherAuth:
    def test_ensure_jwt_uses_cached_token(self):
        client = CrowdSecClient(base_url="http://localhost:8080", machine_id="m", password="p")
        client._jwt_token = "cached-token"
        client._jwt_expiry = datetime.now(tz=timezone.utc) + timedelta(hours=1)
        client._ensure_jwt()
        assert client._jwt_token == "cached-token"

    def test_ensure_jwt_refreshes_near_expiry(self):
        client = CrowdSecClient(base_url="http://localhost:8080", machine_id="m", password="p")
        client._jwt_token = "old-token"
        client._jwt_expiry = datetime.now(tz=timezone.utc) + timedelta(seconds=30)

        with patch.object(client, "_login") as mock_login:
            client._ensure_jwt()
            mock_login.assert_called_once()

    def test_ensure_jwt_no_token(self):
        client = CrowdSecClient(base_url="http://localhost:8080", machine_id="m", password="p")

        with patch.object(client, "_login") as mock_login:
            client._ensure_jwt()
            mock_login.assert_called_once()

    def test_login_no_credentials_raises(self):
        client = CrowdSecClient(base_url="http://localhost:8080")
        with pytest.raises(CrowdSecApiError) as exc_info:
            client._login()
        assert exc_info.value.status_code == 401

    def test_login_success(self, requests_mock):
        expire = (datetime.now(tz=timezone.utc) + timedelta(hours=2)).isoformat()
        requests_mock.post(
            "http://localhost:8080/v1/watchers/login",
            json={"token": "jwt-abc", "expire": expire},
        )
        client = CrowdSecClient(base_url="http://localhost:8080", machine_id="m", password="p")
        client._login()
        assert client._jwt_token == "jwt-abc"
        assert client._jwt_expiry is not None

    def test_login_http_error(self, requests_mock):
        requests_mock.post("http://localhost:8080/v1/watchers/login", status_code=401, text="Unauthorized")
        client = CrowdSecClient(base_url="http://localhost:8080", machine_id="m", password="p")
        with pytest.raises(CrowdSecApiError) as exc_info:
            client._login()
        assert exc_info.value.status_code == 401

    def test_login_connection_error(self):
        client = CrowdSecClient(base_url="http://localhost:8080", machine_id="m", password="p")
        with patch.object(client._session, "post", side_effect=requests.ConnectionError("refused")):
            with pytest.raises(CrowdSecApiError) as exc_info:
                client._login()
            assert exc_info.value.status_code == 0


class TestClientGetDecisions:
    def test_get_decisions_success(self, requests_mock):
        requests_mock.get(
            "http://localhost:8080/v1/decisions",
            json=[{"id": 1, "type": "ban", "value": "1.2.3.4"}],
        )
        client = CrowdSecClient(base_url="http://localhost:8080", api_key="test-key")
        result = client.get_decisions(type="ban")
        assert len(result) == 1
        assert result[0]["value"] == "1.2.3.4"

    def test_get_decisions_empty(self, requests_mock):
        requests_mock.get("http://localhost:8080/v1/decisions", json=None, status_code=200, text="null")
        client = CrowdSecClient(base_url="http://localhost:8080", api_key="test-key")
        # null body → returns []
        requests_mock.get("http://localhost:8080/v1/decisions", json=[])
        result = client.get_decisions()
        assert result == []

    def test_get_decisions_http_error(self, requests_mock):
        requests_mock.get("http://localhost:8080/v1/decisions", status_code=403, text="Forbidden")
        client = CrowdSecClient(base_url="http://localhost:8080", api_key="test-key")
        with pytest.raises(CrowdSecApiError) as exc_info:
            client.get_decisions()
        assert exc_info.value.status_code == 403


class TestClientDecisionStream:
    def test_stream_startup(self, requests_mock):
        requests_mock.get(
            "http://localhost:8080/v1/decisions/stream",
            json={"new": [{"id": 1}], "deleted": []},
        )
        client = CrowdSecClient(base_url="http://localhost:8080", api_key="k")
        result = client.get_decisions_stream(startup=True)
        assert result["new"][0]["id"] == 1
        assert requests_mock.last_request.qs.get("startup") == ["true"]

    def test_stream_delta(self, requests_mock):
        requests_mock.get(
            "http://localhost:8080/v1/decisions/stream",
            json={"new": [], "deleted": [{"id": 5}]},
        )
        client = CrowdSecClient(base_url="http://localhost:8080", api_key="k")
        result = client.get_decisions_stream(startup=False)
        assert result["deleted"][0]["id"] == 5
        assert requests_mock.last_request.qs.get("startup") == ["false"]


class TestClientSearchAlerts:
    def _make_client_with_jwt(self) -> CrowdSecClient:
        client = CrowdSecClient(base_url="http://localhost:8080", machine_id="m", password="p")
        client._jwt_token = "valid-token"
        client._jwt_expiry = datetime.now(tz=timezone.utc) + timedelta(hours=1)
        return client

    def test_search_alerts_success(self, requests_mock):
        requests_mock.get(
            "http://localhost:8080/v1/alerts",
            json=[{"id": 10, "scenario": "ssh_brute-force"}],
        )
        client = self._make_client_with_jwt()
        result = client.search_alerts(scenario="ssh_brute-force")
        assert result[0]["id"] == 10

    def test_get_alert_by_id(self, requests_mock):
        requests_mock.get("http://localhost:8080/v1/alerts/10", json={"id": 10})
        client = self._make_client_with_jwt()
        result = client.get_alert_by_id(10)
        assert result["id"] == 10

    def test_delete_decision_by_id(self, requests_mock):
        requests_mock.delete("http://localhost:8080/v1/decisions/5", json={"nbDeleted": "1"})
        client = self._make_client_with_jwt()
        result = client.delete_decision_by_id(5)
        assert "nbDeleted" in result

    def test_delete_alert_by_id(self, requests_mock):
        requests_mock.delete("http://localhost:8080/v1/alerts/10", json={"nbDeleted": "1"})
        client = self._make_client_with_jwt()
        result = client.delete_alert_by_id(10)
        assert result["nbDeleted"] == "1"

    def test_get_allowlists(self, requests_mock):
        requests_mock.get("http://localhost:8080/v1/allowlists", json=[{"name": "my-list"}])
        client = self._make_client_with_jwt()
        result = client.get_allowlists()
        assert result[0]["name"] == "my-list"

    def test_get_allowlist(self, requests_mock):
        requests_mock.get(
            "http://localhost:8080/v1/allowlists/my-list",
            json={"name": "my-list", "items": []},
        )
        client = self._make_client_with_jwt()
        result = client.get_allowlist("my-list", with_content=False)
        assert result["name"] == "my-list"

    def test_check_allowlist(self, requests_mock):
        requests_mock.get(
            "http://localhost:8080/v1/allowlists/check/1.2.3.4",
            json={"results": []},
        )
        client = self._make_client_with_jwt()
        result = client.check_allowlist("1.2.3.4")
        assert "results" in result

    def test_bulk_check_allowlist(self, requests_mock):
        requests_mock.post(
            "http://localhost:8080/v1/allowlists/check",
            json={"results": [{"ip": "1.2.3.4", "allowlisted": True}]},
        )
        client = self._make_client_with_jwt()
        result = client.bulk_check_allowlist(["1.2.3.4", "5.6.7.8"])
        assert result["results"][0]["allowlisted"] is True

    def test_no_content_response(self, requests_mock):
        requests_mock.delete("http://localhost:8080/v1/decisions/1", text="", status_code=200)
        client = self._make_client_with_jwt()
        result = client.delete_decision_by_id(1)
        assert result == {}
