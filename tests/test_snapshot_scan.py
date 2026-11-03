import json

import app as dashboard
from normalizers import snapshot_scan


def test_dashboard_displays_synthetic_takeover_fixture(monkeypatch):
    monkeypatch.setattr(dashboard, "collect_verified_findings", lambda *_: [])
    asset = {
        "id": 1,
        "subdomain": "takeover.demo-fixture.example.com",
        "root_domain": "example.com",
        "category": "Other",
        "priority": "P4",
        "alive": None,
        "certificate": None,
        "score": 1,
        "risk_color": "success",
        "risk_label": "Low",
        "sources": ["amass"],
        "confidence": 25,
        "takeover_risk": {"confidence": "medium"},
        "is_shadow": False,
        "cve_findings": [],
        "verified_vulns": [],
    }
    monkeypatch.setattr(dashboard, "build_assets", lambda: [asset])
    monkeypatch.setattr(
        dashboard,
        "build_stats",
        lambda assets: {
            "total": len(assets),
            "alive": 0,
            "critical": 0,
            "high": 0,
            "takeover_risks": 1,
            "with_cve": 0,
        },
    )

    client = dashboard.app.test_client()
    response = client.get("/")

    assert response.status_code == 200
    assert b"takeover.demo-fixture.example.com" in response.data
    assert b"Takeover" in response.data
    assert b"sekera_logo" not in response.data
    assert b"Aya Ouzarf" in response.data
    assert b"theme-toggle" in response.data
    assert b'<html lang="en"' in response.data
    assert b"Filters" in response.data
    assert "Réinitialiser".encode() not in response.data

    filtered_response = client.get("/?search=takeover.demo-fixture.example.com")
    assert filtered_response.status_code == 200
    assert b"takeover.demo-fixture.example.com" in filtered_response.data


def test_brand_logo_and_short_methodology_pages():
    client = dashboard.app.test_client()

    logo = client.get("/brand/sekera.png")
    assert logo.status_code == 200
    assert logo.mimetype == "image/png"

    methodology = client.get("/methodology")
    assert methodology.status_code == 200
    assert b'<html lang="en"' in methodology.data
    assert b"Risk scale" in methodology.data
    assert b"Sources used" in methodology.data
    assert "Méthodologie".encode() not in methodology.data


def test_asset_detail_hides_ai_summary(monkeypatch):
    monkeypatch.setattr(
        dashboard,
        "build_assets",
        lambda: [
            {
                "id": 1,
                "subdomain": "www.example.com",
                "root_domain": "example.com",
                "risk_color": "success",
                "risk_label": "Low",
                "score": 1,
                "category": "Other",
                "alive": None,
                "ports": [],
                "notes": "No risk evidence",
                "sources": ["subfinder"],
                "certificate": None,
                "takeover_risk": None,
                "cve_findings": [],
                "verified_vulns": [],
                "confidence": 25,
            }
        ],
    )

    response = dashboard.app.test_client().get("/asset/1")

    assert response.status_code == 200
    assert b"AI summary" not in response.data
    assert b"Sources" in response.data


def test_take_snapshot_writes_assets_to_history(tmp_path, monkeypatch):
    monkeypatch.setattr(snapshot_scan, "HISTORY_DIR", str(tmp_path))
    monkeypatch.setattr(
        snapshot_scan,
        "build_assets",
        lambda with_liveness: [
            {
                "subdomain": "www.example.com",
                "root_domain": "example.com",
                "sources": ["subfinder"],
                "certificate": None,
                "takeover_risk": None,
            }
        ],
    )

    filepath = snapshot_scan.take_snapshot()

    with open(filepath, encoding="utf-8") as snapshot_file:
        snapshot = json.load(snapshot_file)

    assert snapshot["subdomains"]["www.example.com"] == {
        "domain": "example.com",
        "sources": ["subfinder"],
        "certificate": None,
        "takeover_risk": False,
    }


def test_dashboard_skips_live_vulnerability_lookups_by_default(monkeypatch):
    monkeypatch.setattr(dashboard, "ENABLE_LIVE_VULN_LOOKUPS", False)
    monkeypatch.setattr(
        dashboard,
        "load_all_records",
        lambda: [{"subdomain": "www.example.com", "domain": "example.com", "source": "subfinder"}],
    )
    monkeypatch.setattr(dashboard, "load_certs_data", lambda: {"by_subdomain": {}})
    monkeypatch.setattr(dashboard, "load_takeover_data", lambda: {})
    monkeypatch.setattr(dashboard, "load_cve_data", lambda: {})
    monkeypatch.setattr(dashboard, "load_ports_by_host", lambda: {})

    def unexpected_live_lookup(*_args):
        raise AssertionError("live vulnerability lookups should be disabled by default")

    monkeypatch.setattr(dashboard, "collect_verified_findings", unexpected_live_lookup)

    assets = dashboard.build_assets()

    assert len(assets) == 1
    assert assets[0]["verified_vulns"] == []
