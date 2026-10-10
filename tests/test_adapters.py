
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