from risk_engine import calculate_enterprise_risk


def test_enterprise_score_uses_verified_evidence():
    score = calculate_enterprise_risk(
        subdomain="vpn.example.com",
        asset_criticality=5,
        exposure=4,
        verified_cves=[
            {"cve_id": "CVE-2024-1234", "cvss_score": 9.8, "epss_score": 0.85, "source": ["nvd", "kev", "epss"]}
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
