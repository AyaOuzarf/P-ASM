from risk_engine import calculate_enterprise_risk


def test_enterprise_score_uses_verified_evidence():
    score = calculate_enterprise_risk(
        subdomain="vpn.example.com",
        asset_criticality=5,
        exposure=4,
        verified_cves=[
            {"cve_id": "CVE-2024-1234", "cvss_score": 9.8, "epss_score": 0.85, "source": ["nvd", "cisa_kev", "epss"]}
        ],
        takeover_risk=None,
        cert_active=True,
    )

    assert score["score"] >= 8
    assert score["priority"] in {"P1", "P2"}
    assert "CVE-2024-1234" in score["justification"]


def test_enterprise_score_keeps_low_risk_without_evidence():
    score = calculate_enterprise_risk(
        subdomain="www.example.com",
        asset_criticality=2,
        exposure=2,
        verified_cves=[],
        takeover_risk=None,
        cert_active=True,
    )

    assert score["score"] <= 5
    assert score["priority"] in {"P3", "P4"}


def test_cve_id_alone_does_not_add_known_exploit_bonus():
    score = calculate_enterprise_risk(
        subdomain="www.example.com",
        asset_criticality=2,
        exposure=2,
        verified_cves=[
            {"cve_id": "CVE-2024-1234", "cvss_score": 3.0, "source": ["nvd"]}
        ],
        takeover_risk=None,
        cert_active=True,
    )

    assert score["score"] == 2


def test_missing_certificate_data_is_not_treated_as_expired():
    score = calculate_enterprise_risk(
        subdomain="www.example.com",
        asset_criticality=2,
        exposure=2,
        cert_active=None,
    )

    assert score["score"] == 1
    assert "Certificate inactive/expired" not in score["justification"]


def test_explicitly_inactive_certificate_adds_evidence_and_score():
    score = calculate_enterprise_risk(
        subdomain="www.example.com",
        asset_criticality=2,
        exposure=2,
        cert_active=False,
    )

    assert score["score"] == 2
    assert "Certificate inactive/expired" in score["justification"]
