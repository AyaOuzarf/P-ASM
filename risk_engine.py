"""Risk engine for a passive-first external attack-surface project.

This module intentionally avoids arbitrary heuristics as the only source of risk.
The workflow is:
1. start from a business-relevant exposure score (subdomain naming pattern)
2. enrich with verified evidence from public CVE sources and takeover/certificate data
3. increase risk only when there is real evidence or a strong public signal
4. keep a readable justification so the dashboard explains why the score changed

The goal is to make the risk score traceable and auditable instead of based only
on a naming convention like "vpn." or "gitlab.".
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional


def _safe_float(value: Any) -> Optional[float]:
    """Convert a value to float when possible; return None otherwise."""
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _cvss_to_score(cvss_value: Optional[float]) -> Optional[int]:
    """Map CVSS 0-10 to the project risk scale 1-9.

    CVSS is already a standard severity model. We keep the conversion simple and
    consistent so that a real CVE can override the name-based score without
    inventing a second unrelated scoring model.
    """
    if cvss_value is None:
        return None
    cvss = max(0.0, min(10.0, float(cvss_value)))
    return max(1, min(9, round(cvss * 0.9)))


def _cve_evidence_items(cve_findings: Optional[Iterable[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Flatten CVE findings from the JSON structure used by the project."""
    if not cve_findings:
        return []

    evidence = []
    for entry in cve_findings:
        for cve in entry.get("cves", []):
            evidence.append(
                {
                    "cve_id": cve.get("cve_id"),
                    "cvss_score": _safe_float(cve.get("cvss_score")),
                    "cvss_severity": cve.get("cvss_severity"),
                    "description": cve.get("description", ""),
                    "service": entry.get("service"),
                    "port": entry.get("port"),
                    "banner": entry.get("banner"),
                    "matched_query": entry.get("matched_query"),
                }
            )
    return evidence


def _contains_known_exploit(cve: Dict[str, Any]) -> bool:
    """A cheap but explicit indicator: if the CVE already looks like a known exploit.

    The project is intentionally conservative here. This logic is not a substitute
    for a full CISA KEV / EPSS query, but it is useful as a “signal booster” when
    the evidence is already present in the CVE metadata.
    """
    cve_id = (cve.get("cve_id") or "").upper()
    description = (cve.get("description") or "").lower()
    if "known exploited" in description or "actively exploited" in description:
        return True
    if "kev" in description or "cisa" in description:
        return True
    return False


def compute_verifiable_risk(
    subdomain: str,
    base_exposure: int = 1,
    base_sensitivity: int = 1,
    base_justification: str = "Sous-domaine standard, pas de motif sensible detecte",
    takeover: Optional[Dict[str, Any]] = None,
    cve_findings: Optional[Iterable[Dict[str, Any]]] = None,
    cert_info: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Return a risk record with a score and explanation.

    This is the evidence-based replacement for the old pure-name scoring. It keeps
    the original base score, but raises it when there is a real signal from CVE,
    takeover detection, or expired certificate evidence.
    """
    initial_score = base_exposure * base_sensitivity
    reason_parts = [base_justification]
    evidence_sources = []

    # Basic exposure context remains useful but is no longer treated as the only
    # source of risk. It acts like a floor, not the final answer.
    if takeover:
        # If takeover is confirmed by the project, the risk should be treated as
        # critical because the service is likely misconfigured and publicly exposed.
        initial_score = max(initial_score, 9)
        evidence_sources.append("subdomain_takeover")
        reason_parts.append(
            "RISQUE SUBDOMAIN TAKEOVER : CNAME vers "
            f"{takeover.get('cname_target', 'inconnu')}"
            + (f" ({takeover.get('service_hint')})" if takeover.get("service_hint") else "")
            + f" - signaux : {', '.join(takeover.get('signals', []))}"
        )

    cve_items = _cve_evidence_items(cve_findings)
    if cve_items:
        evidence_sources.append("verified_cve")
        max_cvss = max((item["cvss_score"] for item in cve_items if item["cvss_score"] is not None), default=None)
        if max_cvss is not None:
            cve_score = _cvss_to_score(max_cvss)
            if cve_score is not None:
                initial_score = max(initial_score, cve_score)
                top = max(
                    [item for item in cve_items if item["cvss_score"] == max_cvss],
                    key=lambda item: item["cvss_score"] or 0,
                    default={},
                )
                reason_parts.append(
                    f"CVE potentielle : {top.get('cve_id', 'inconnue')} (CVSS {max_cvss}) "
                    f"sur {top.get('service') or 'service inconnu'} -- "
                    f"{(top.get('description') or '')[:150]}"
                )
        # Known exploit signals can raise the score even if CVSS is moderate.
        for item in cve_items:
            if _contains_known_exploit(item):
                initial_score = max(initial_score, 8)
                reason_parts.append(f"Signal d'exploitation connue : {item.get('cve_id')}")
                evidence_sources.append("known_exploit_signal")
                break

    if cert_info:
        # An expired or non-active certificate is a public signal of weak governance,
        # especially on a sensitive subdomain, even without a vulnerability.
        if cert_info.get("active") is False:
            initial_score = max(initial_score, 6)
            reason_parts.append("Certificat expiré ou non actif : signal de mauvaise posture TLS")
            evidence_sources.append("certificate")

    score = max(1, min(9, int(initial_score)))
    reason = " | ".join(reason_parts)

    return {
        "score": score,
        "reason": reason,
        "sources": sorted(set(evidence_sources)),
        "evidence": {
            "takeover": takeover,
            "cves": cve_items,
            "certificate": cert_info,
        },
    }


def _priority_from_score(score: int) -> str:
    """Map a score to an enterprise remediation priority."""
    if score >= 9:
        return "P1"
    if score >= 7:
        return "P2"
    if score >= 5:
        return "P3"
    return "P4"


def calculate_enterprise_risk(
    subdomain: str,
    asset_criticality: int = 1,
    exposure: int = 1,
    verified_cves: Optional[Iterable[Dict[str, Any]]] = None,
    takeover_risk: Optional[Dict[str, Any]] = None,
    cert_active: bool = True,
) -> Dict[str, Any]:
    """Compute a single enterprise risk score from verified evidence.

    Formula:
      0.45 * asset_criticality
    + 0.25 * exposure
    + 0.30 * max_cvss_component
    + 0.20 * kev_component
    + 0.15 * epss_component
    + 0.10 * certificate_penalty
    + 0.15 * takeover_penalty

    The result is then clamped to 0-10 and converted to an operational priority.
    This model is intentionally transparent and auditable.
    """
    crit = max(1, min(5, int(asset_criticality)))
    expos = max(1, min(5, int(exposure)))
    cves = list(verified_cves or [])

    max_cvss = max((float(item.get("cvss_score", 0)) for item in cves if item.get("cvss_score") is not None), default=0.0)
    kev_flag = any("kev" in (item.get("source") or []) or item.get("cve_id", "").upper().startswith("CVE-") for item in cves)
    epss_max = max((float(item.get("epss_score", 0)) for item in cves if item.get("epss_score") is not None), default=0.0)

    cvss_component = max_cvss / 10.0
    kev_component = 1.0 if kev_flag else 0.0
    epss_component = min(1.0, epss_max)
    certificate_penalty = 0.0 if cert_active else 1.0
    takeover_penalty = 1.0 if takeover_risk else 0.0

    weighted_score = (
        (0.45 * crit)
        + (0.25 * expos)
        + (0.30 * cvss_component * 5.0)
        + (0.20 * kev_component * 5.0)
        + (0.15 * epss_component * 5.0)
        + (0.10 * certificate_penalty * 5.0)
        + (0.15 * takeover_penalty * 5.0)
    )

    final_score = max(0.0, min(10.0, weighted_score))
    score = int(round(final_score))
    priority = _priority_from_score(score)

    top_cve = None
    if cves:
        top_cve = max(cves, key=lambda item: (float(item.get("cvss_score") or 0), float(item.get("epss_score") or 0)))

    justification = [
        f"Asset criticality={crit}, exposure={expos}",
    ]
    if top_cve:
        justification.append(
            f"Verified CVE {top_cve.get('cve_id')} with CVSS {top_cve.get('cvss_score')} and EPSS {top_cve.get('epss_score')}"
        )
    if takeover_risk:
        justification.append("Takeover risk observed")
    if not cert_active:
        justification.append("Certificate inactive/expired")
    if not cves:
        justification.append("No verified public vulnerability evidence found")

    return {
        "subdomain": subdomain,
        "score": score,
        "priority": priority,
        "justification": " | ".join(justification),
        "evidence": {
            "cves": cves,
            "takeover": takeover_risk,
            "cert_active": cert_active,
        },
    }
