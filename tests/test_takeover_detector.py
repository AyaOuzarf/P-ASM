import json

from normalizers import takeover_detector


def test_analyze_reports_known_service_and_unresolved_cname(tmp_path, monkeypatch):
    scans_dir = tmp_path / "scans"
    scans_dir.mkdir()
    (scans_dir / "amass_example.com.txt").write_text(
        "old.example.com (FQDN) --> cname_record --> abandoned.herokuapp.com (FQDN)\n",
        encoding="utf-8",
    )
    output_file = tmp_path / "takeover_findings.json"

    monkeypatch.setattr(takeover_detector, "SCANS_DIR", str(scans_dir))
    monkeypatch.setattr(takeover_detector, "OUTPUT_FILE", str(output_file))
    monkeypatch.setattr(takeover_detector, "target_resolves", lambda _: False)

    findings = takeover_detector.analyze()

    assert findings == [
        {
            "subdomain": "old.example.com",
            "domain": "example.com",
            "cname_target": "abandoned.herokuapp.com",
            "signals": ["known_vulnerable_service", "unresolved_target"],
            "confidence": "high",
            "service_hint": "Heroku",
        }
    ]
    assert json.loads(output_file.read_text(encoding="utf-8")) == findings
