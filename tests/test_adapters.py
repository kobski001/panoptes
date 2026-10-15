
import pytest

from panoptes.providers.shodan import ShodanInternetDBProvider
from panoptes.models import ProviderResult
from panoptes.providers.base import BaseProvider


def test_base_provider_cannot_be_instantiated():
    with pytest.raises(TypeError):
        BaseProvider()


def test_concrete_provider_must_implement_required_methods():
    class IncompleteProvider(BaseProvider):
        name = "shodan_host"

        def lookup(self, ip_address: str) -> ProviderResult:
            raise NotImplementedError

    with pytest.raises(TypeError):
        IncompleteProvider()


from unittest.mock import Mock, patch

import requests

from panoptes.providers.http import HttpClient, map_http_status


def test_http_status_mapping():
    assert map_http_status(200) == "success"
    assert map_http_status(401) == "auth_error"
    assert map_http_status(403) == "permission_error"
    assert map_http_status(404) == "no_data"
    assert map_http_status(429) == "rate_limited"
    assert map_http_status(500) == "error"


@patch("panoptes.providers.http.requests.Session.get")
def test_http_client_returns_json_on_success(mock_get):
    response = Mock()
    response.status_code = 200
    response.json.return_value = {"ip": "8.8.8.8"}
    mock_get.return_value = response

    client = HttpClient()
    status, payload, error = client.get_json("https://example.test/ip")

    assert status == "success"
    assert payload == {"ip": "8.8.8.8"}
    assert error is None


@patch("panoptes.providers.http.requests.Session.get")
def test_http_client_handles_timeout(mock_get):
    mock_get.side_effect = requests.Timeout()

    client = HttpClient()
    status, payload, error = client.get_json("https://example.test/ip")

    assert status == "timeout"
    assert payload == {}
    assert error is not None


@patch("panoptes.providers.http.requests.Session.get")
def test_http_client_handles_rate_limit(mock_get):
    response = Mock()
    response.status_code = 429
    mock_get.return_value = response

    client = HttpClient()
    status, payload, error = client.get_json("https://example.test/ip")

    assert status == "rate_limited"
    assert payload == {}
    assert error is not None



from unittest.mock import Mock

from panoptes.providers.ipinfo import IPInfoProvider


def test_ipinfo_normalizes_lite_fields():
    provider = IPInfoProvider(token="test-token")

    normalized = provider.normalize(
        {
            "ip": "8.8.8.8",
            "asn": "AS15169",
            "as_name": "Google LLC",
            "as_domain": "google.com",
            "country_code": "US",
            "country": "United States",
            "continent_code": "NA",
            "continent": "North America",
        }
    )

    assert normalized["ip_address"] == "8.8.8.8"
    assert normalized["asn"] == "AS15169"
    assert normalized["organization"] == "Google LLC"
    assert normalized["country_code"] == "US"
    assert "latitude" not in normalized


def test_ipinfo_lookup_success():
    client = Mock()
    client.get_json.return_value = (
        "success",
        {
            "ip": "8.8.8.8",
            "asn": "AS15169",
            "as_name": "Google LLC",
            "country_code": "US",
            "country": "United States",
        },
        None,
    )

    provider = IPInfoProvider(token="test-token", client=client)
    result = provider.lookup("8.8.8.8")

    assert result.status == "success"
    assert result.provider == "ipinfo_lite"
    assert result.normalized_data["ip_address"] == "8.8.8.8"
    assert result.expires_at is not None
    assert result.cached is False


def test_ipinfo_missing_token_returns_auth_error():
    client = Mock()
    provider = IPInfoProvider(token="", client=client)

    result = provider.lookup("8.8.8.8")

    assert result.status == "auth_error"
    assert result.error_code == "missing_api_token"
    client.get_json.assert_not_called()


def test_ipinfo_rate_limit_is_preserved():
    client = Mock()
    client.get_json.return_value = (
        "rate_limited",
        {},
        "Provider returned HTTP 429.",
    )

    provider = IPInfoProvider(token="test-token", client=client)
    result = provider.lookup("8.8.8.8")

    assert result.status == "rate_limited"
    assert result.normalized_data == {}
    assert result.raw_data == {}


def test_ipinfo_rejects_unexpected_payload():
    client = Mock()
    client.get_json.return_value = ("success", {"country": "US"}, None)

    provider = IPInfoProvider(token="test-token", client=client)
    result = provider.lookup("8.8.8.8")

    assert result.status == "error"
    assert result.error_code == "unexpected_payload"


def test_shodan_internetdb_normalizes_fields():
    provider = ShodanInternetDBProvider()

    normalized = provider.normalize({
        "ip": "8.8.8.8",
        "hostnames": ["dns.google"],
        "ports": [53, 443],
        "tags": ["cloud"],
        "cpes": ["cpe:/a:example:service"],
        "vulns": ["CVE-2024-12345"],
    })

    assert normalized["ip_address"] == "8.8.8.8"
    assert normalized["hostnames"] == ["dns.google"]
    assert normalized["ports"] == [53, 443]
    assert normalized["tags"] == ["cloud"]
    assert normalized["cpe_identifiers"] == ["cpe:/a:example:service"]
    assert normalized["vulnerability_identifiers"] == ["CVE-2024-12345"]


def test_shodan_internetdb_lookup_success():
    client = Mock()
    client.get_json.return_value = (
        "success",
        {
            "ip": "8.8.8.8",
            "hostnames": ["dns.google"],
            "ports": [53, 443],
            "tags": [],
            "cpes": [],
            "vulns": [],
        },
        None,
    )

    provider = ShodanInternetDBProvider(client=client)
    result = provider.lookup("8.8.8.8")

    assert result.status == "success"
    assert result.provider == "shodan_internetdb"
    assert result.normalized_data["ip_address"] == "8.8.8.8"
    assert result.expires_at is not None
    assert result.cached is False
    client.get_json.assert_called_once()


def test_shodan_internetdb_no_data():
    client = Mock()
    client.get_json.return_value = (
        "no_data",
        {},
        "Provider returned HTTP 404.",
    )

    provider = ShodanInternetDBProvider(client=client)
    result = provider.lookup("203.0.113.10")

    assert result.status == "no_data"
    assert result.error_code is None
    assert result.error_message is None
    assert result.normalized_data == {}
    assert result.raw_data == {}


def test_shodan_internetdb_rate_limit_is_preserved():
    client = Mock()
    client.get_json.return_value = (
        "rate_limited",
        {},
        "Provider returned HTTP 429.",
    )

    provider = ShodanInternetDBProvider(client=client)
    result = provider.lookup("8.8.8.8")

    assert result.status == "rate_limited"
    assert result.normalized_data == {}
    assert result.raw_data == {}
    assert result.error_code == "rate_limited"


def test_shodan_internetdb_rejects_unexpected_payload():
    client = Mock()
    client.get_json.return_value = (
        "success",
        {"hostnames": ["dns.google"]},
        None,
    )

    provider = ShodanInternetDBProvider(client=client)
    result = provider.lookup("8.8.8.8")

    assert result.status == "error"
    assert result.error_code == "unexpected_payload"
    assert result.normalized_data == {}

from panoptes.providers.shodan import ShodanHostProvider


SHODAN_HOST_PAYLOAD = {
    "ip_str": "8.8.8.8",
    "asn": "AS15169",
    "org": "Google LLC",
    "isp": "Google LLC",
    "country_code": "US",
    "country_name": "United States",
    "city": "Mountain View",
    "hostnames": ["dns.google"],
    "domains": ["dns.google"],
    "ports": [443, 53],
    "tags": [],
    "last_update": "2026-10-10T14:08:21.210242",
    "data": [
        {
            "port": 53,
            "transport": "udp",
            "product": "Google DNS",
            "timestamp": "2026-10-10T14:08:21.210242",
            "_shodan": {"module": "dns-udp"},
        },
        {
            "port": 443,
            "transport": "tcp",
            "timestamp": "2026-10-09T08:00:00.000000",
        },
        "not-a-banner",
    ],
}


def test_shodan_host_normalizes_fields():
    provider = ShodanHostProvider(api_key="test-key")

    normalized = provider.normalize(SHODAN_HOST_PAYLOAD)

    assert normalized["ip_address"] == "8.8.8.8"
    assert normalized["asn"] == "AS15169"
    assert normalized["organization"] == "Google LLC"
    assert normalized["country_code"] == "US"
    assert normalized["hostnames"] == ["dns.google"]
    assert normalized["domains"] == ["dns.google"]
    assert normalized["ports"] == [53, 443]
    assert len(normalized["services"]) == 2
    assert normalized["services"][0] == {
        "port": 53,
        "transport": "udp",
        "product": "Google DNS",
        "version": None,
        "module": "dns-udp",
        "observed_at": "2026-10-10T14:08:21.210242",
    }
    assert normalized["services"][1]["product"] is None
    assert normalized["services"][1]["module"] is None


def test_shodan_host_normalize_tolerates_missing_and_malformed_fields():
    provider = ShodanHostProvider(api_key="test-key")

    normalized = provider.normalize({
        "ip_str": "8.8.8.8",
        "hostnames": None,
        "data": {"unexpected": "shape"},
        "vulns": {"CVE-2024-12345": {"cvss": 7.5}},
    })

    assert normalized["hostnames"] == []
    assert normalized["services"] == []
    assert normalized["ports"] == []
    assert normalized["organization"] is None
    assert normalized["vulnerability_identifiers"] == ["CVE-2024-12345"]


def test_shodan_host_derives_ports_from_banners_when_missing():
    provider = ShodanHostProvider(api_key="test-key")

    normalized = provider.normalize({
        "ip_str": "8.8.8.8",
        "data": [{"port": 22}, {"port": 80}, {"port": 22}],
    })

    assert normalized["ports"] == [22, 80]


def test_shodan_host_lookup_success():
    client = Mock()
    client.get_json.return_value = ("success", SHODAN_HOST_PAYLOAD, None)

    provider = ShodanHostProvider(api_key="test-key", client=client)
    result = provider.lookup("8.8.8.8")

    assert result.status == "success"
    assert result.provider == "shodan_host"
    assert result.normalized_data["ip_address"] == "8.8.8.8"
    assert result.raw_data == SHODAN_HOST_PAYLOAD
    assert result.expires_at is not None
    assert result.cached is False

    url = client.get_json.call_args.args[0]
    assert url == "https://api.shodan.io/shodan/host/8.8.8.8"
    assert client.get_json.call_args.kwargs["params"] == {"key": "test-key"}


def test_shodan_host_missing_api_key_returns_auth_error(monkeypatch):
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    client = Mock()

    provider = ShodanHostProvider(client=client)
    result = provider.lookup("8.8.8.8")

    assert result.status == "auth_error"
    assert result.error_code == "missing_api_key"
    client.get_json.assert_not_called()


def test_shodan_host_reads_api_key_from_environment(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "env-key")

    provider = ShodanHostProvider(client=Mock())

    assert provider.api_key == "env-key"


def test_shodan_host_rate_limit_is_preserved():
    client = Mock()
    client.get_json.return_value = (
        "rate_limited",
        {},
        "Provider returned HTTP 429.",
    )

    provider = ShodanHostProvider(api_key="secret-key", client=client)
    result = provider.lookup("8.8.8.8")

    assert result.status == "rate_limited"
    assert result.error_code == "rate_limited"
    assert result.normalized_data == {}
    assert result.raw_data == {}
    assert "secret-key" not in (result.error_message or "")


def test_shodan_host_no_data():
    client = Mock()
    client.get_json.return_value = (
        "no_data",
        {},
        "Provider returned HTTP 404.",
    )

    provider = ShodanHostProvider(api_key="test-key", client=client)
    result = provider.lookup("203.0.113.10")

    assert result.status == "no_data"
    assert result.error_code is None
    assert result.error_message is None
    assert result.normalized_data == {}


def test_shodan_host_rejects_unexpected_payload():
    client = Mock()
    client.get_json.return_value = ("success", {"org": "Google LLC"}, None)

    provider = ShodanHostProvider(api_key="test-key", client=client)
    result = provider.lookup("8.8.8.8")

    assert result.status == "error"
    assert result.error_code == "unexpected_payload"
    assert result.normalized_data == {}
