
import ipaddress


def normalize_ip(value: str) -> str:
    """Validate an IPv4 or IPv6 address and return its canonical form."""
    if not isinstance(value, str):
        raise ValueError("IP address must be a string.")

    value = value.strip()

    if not value:
        raise ValueError("IP address cannot be empty.")

    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValueError("Enter a valid IPv4 or IPv6 address.") from exc
