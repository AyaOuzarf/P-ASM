import json

from normalizers.shodan_normalizer import normalize_host, parse_file


def test_normalize_host_accepts_shodan_scanner_match():
    normalized = normalize_host(
        {
            "ip": "203.0.113.10",
            "port": 443,
            "org": "Example Org",
            "hostnames": ["origin.example.com"],
            "location": {"country": "Exampleland", "city": "Example City"},
        }
    )

    assert normalized["ip"] == "203.0.113.10"
    assert normalized["open_ports"] == [443]
    assert normalized["country"] == "Exampleland"
    assert normalized["city"] == "Example City"


def test_parse_file_accepts_collector_matches_and_legacy_raw_hosts(tmp_path):
    filepath = tmp_path / "shodan_example.com.json"
    filepath.write_text(
        json.dumps(
            {
                "domain": "example.com",
                "matches": [{"ip": "203.0.113.10", "port": 443}],
            }
        ),
        encoding="utf-8",
    )

    domain, hosts = parse_file(str(filepath))

    assert domain == "example.com"
    assert hosts[0]["ip"] == "203.0.113.10"
    assert hosts[0]["open_ports"] == [443]

    filepath.write_text(
        json.dumps(
            {
                "domain": "example.com",
                "raw_hosts": [
                    {
                        "ip_str": "203.0.113.11",
                        "ports": [80, 443],
                        "country_name": "Exampleland",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    domain, hosts = parse_file(str(filepath))

    assert domain == "example.com"
    assert hosts[0]["ip"] == "203.0.113.11"
    assert hosts[0]["open_ports"] == [80, 443]
