
import pytest

from panoptes.indicators import normalize_ip


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("8.8.8.8", "8.8.8.8"),
        (" 8.8.8.8 ", "8.8.8.8"),
        ("2001:4860:4860::8888", "2001:4860:4860::8888"),
        ("2001:0db8:0000:0000:0000:0000:0000:0001",
         "2001:db8::1"),
    ],
)
def test_valid_ips_are_normalized(value, expected):
    assert normalize_ip(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "not-an-ip",
        "999.999.999.999",
        "example.com",
        "8.8.8.8:443",
    ],
)
def test_invalid_ips_are_rejected(value):
    with pytest.raises(ValueError):
        normalize_ip(value)


def test_non_string_input_is_rejected():
    with pytest.raises(ValueError):
        normalize_ip(None)
