
from datetime import datetime, timezone

from panoptes.models import ProviderResult, ScanResult


def make_result(status: str, provider: str) -> ProviderResult:
    return ProviderResult(
        provider=provider,
        status=status,
        retrieved_at=datetime.now(timezone.utc),
    )


def test_all_provider_results_usable_means_success():
    scan = ScanResult(
        scan_id="test-1",
        ip_address="8.8.8.8",
        started_at=datetime.now(timezone.utc),
        provider_results=[
            make_result("success", "shodan_host"),
            make_result("no_data", "ipinfo_lite"),
        ],
    )
    assert scan.calculate_status() == "success"


def test_mixed_usable_and_failed_results_means_partial():
    scan = ScanResult(
        scan_id="test-2",
        ip_address="8.8.8.8",
        started_at=datetime.now(timezone.utc),
        provider_results=[
            make_result("success", "virustotal"),
            make_result("timeout", "shodan_host"),
        ],
    )
    assert scan.calculate_status() == "partial"


def test_no_usable_results_means_failed():
    scan = ScanResult(
        scan_id="test-3",
        ip_address="8.8.8.8",
        started_at=datetime.now(timezone.utc),
        provider_results=[
            make_result("timeout", "shodan_host"),
            make_result("auth_error", "virustotal"),
        ],
    )
    assert scan.calculate_status() == "failed"


def test_empty_provider_list_means_failed():
    scan = ScanResult(
        scan_id="test-4",
        ip_address="8.8.8.8",
        started_at=datetime.now(timezone.utc),
    )
    assert scan.calculate_status() == "failed"
