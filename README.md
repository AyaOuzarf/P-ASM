# P-ASM: Passive Attack-Surface Management

P-ASM is a small security inventory project. It collects public information about an organization's internet-facing hostnames, combines results from several sources, adds available security evidence, and presents the result in a web dashboard.

Use it only for domains you own or have permission to assess. Its purpose is **visibility and prioritization**: show what public assets are known, where each was found, what evidence is available, and what may deserve review first. It is not an exploit framework, and a score or public-source match is not proof that a system is vulnerable.

## The Project in Simple Steps

1. **Find hostnames:** Subfinder, Amass, and Assetfinder search public sources using different methods.
2. **Check certificate history:** crt.sh and Cert Spotter search public certificate records. Certificate names can reveal forgotten hostnames.
3. **Organize results:** normalizers clean the raw results and save them as JSON so different tools can be combined.
4. **Add security context:** takeover checks, certificate status, and public vulnerability information add evidence where available.
5. **Prioritize:** the risk engine turns the available information into a score, priority, and written explanation.
6. **Review:** the Flask dashboard displays assets, filters, details, and a JSON export.

```text
Discovery sources -> raw results -> normalizers -> JSON data
                                           |
                                           v
                 Flask app + risk engine + vulnerability lookups
                                           |
                                           v
                             dashboard and JSON export
```

## What Each Tool Does

The discovery tools are not interchangeable. Each has different coverage, so the project can compare their results and record which ones found each hostname.

| Tool | In simple words | Role in this project |
| --- | --- | --- |
| **Subfinder** | Passive subdomain discovery from public sources. It returns a list of names and does not actively scan the target. | `scanner/subfinder.py` runs it for the configured domains. Its normalizer prepares the output for the dashboard. |
| **Amass** | Passive domain enumeration that can show relationships, not only a list of names. | `scanner/amass.py` saves relationship output. The normalizer extracts hostnames; the takeover detector examines CNAME relationships. |
| **Assetfinder** | A lightweight, separate way to find public subdomain names. | `scanner/assetfinder.py` saves a hostname list under the root `scans/` folder. Its normalizer reads from the same folder and converts that list to dashboard records. |
| **crt.sh and Cert Spotter** | Public Certificate Transparency search services. They show names included in publicly logged TLS certificates. | `scanner/certs.py` queries both. This can reveal names missed by discovery tools, but a certificate does not prove a host is currently online. |
| **Shodan** | A search engine that indexes internet-visible systems and may show IPs, ports, and services. | In our workflow Shodan is mainly **used manually**: search in its web interface, inspect a result, and verify it belongs to the authorized organization. The project also has an optional API wrapper, but it is not part of the normal dashboard flow. API use requires a Shodan key and consumes search credits. |
| **Censys** | A public internet and certificate search service, similar in purpose to Shodan but with its own data and interface. | This project has a normalizer for records collected manually. It does not have an automatic Censys collector, and the dashboard does not currently load its output. |

### Why use several discovery sources?

One tool may find a name another misses. Certificate logs can reveal names that do not appear in a current DNS-focused result. When several tools report the same hostname, the dashboard records those sources together. This helps explain where an asset came from; it does not by itself prove the asset is risky.

## CVEs and Risk Score

A **CVE** is the public identifier for a known software vulnerability. **CVSS** is a severity rating for that vulnerability. Finding a CVE while searching a product or service name is a clue to investigate, not proof that the discovered host runs the affected product or version.

| Source | What it adds |
| --- | --- |
| **NVD** | Public CVE descriptions and CVSS information. |
| **CISA KEV** | Marks vulnerabilities that CISA lists as known to have been exploited. |
| **EPSS** | Estimates the likelihood that a CVE may be exploited; useful for prioritization, not certainty. |
| **OSV** | Public vulnerability records for open-source packages and ecosystems. |

`vulnerability_sources.py` makes best-effort lookups using names inferred from assets and service names. The application can also read `cve_findings.json` if supplied, but this repository does not include a script that creates that file. Verify product and version matches before treating a CVE as applicable.

Live public-source lookups are disabled by default so opening or refreshing the dashboard does not wait on external services. To enable NVD, CISA KEV, EPSS, and OSV enrichment during dashboard requests, set `ENABLE_LIVE_VULN_LOOKUPS=true` before starting the app. These network lookups can noticeably increase page load time; locally supplied `cve_findings.json` data continues to be used without this setting.

### How the risk engine works

`risk_engine.py` first gives an asset a basic score from business context, such as whether its hostname looks like a VPN or administrative service. This is only an initial signal. It then uses stronger evidence when available, including CVE severity, takeover findings, and inactive certificates. The enterprise calculation also considers exposure, criticality, and public vulnerability signals such as EPSS/KEV.

The final result includes a score from 1 to 10, a priority from `P1` to `P4`, supporting evidence, and an explanation. Higher priorities should be reviewed sooner. The score helps organize investigation; it is not a finding of exploitability.

### Takeover checks

A possible subdomain takeover can occur when a hostname points to a third-party service that is no longer configured for the organization. The takeover detector looks for CNAMEs to known services and DNS resolution signals. Its output is a **potential finding to verify**, not confirmation that someone can take over the hostname.

For a local demonstration, `scans/amass_demo-fixture.example.com.txt` and `scans/subfinder_demo-fixture.example.com.txt` provide a clearly synthetic asset under the reserved `example.com` domain. Its CNAME target uses the reserved `.invalid` suffix, so it exercises unresolved-target detection without querying a real service. The demo appears in normalized data and the dashboard; exclude or remove those fixture files before collecting/reporting real-scope results.

## AI Helper

`ai_helper.py` writes a short plain-language explanation from evidence already assembled by the application.

- **No API key:** a local summary is generated from the asset name, score, category, and risk notes. No asset data is sent to an AI provider.
- **Remote AI enabled:** a configured provider key is required. The helper sends asset information to an OpenAI-compatible API and asks it to summarize only the supplied evidence. Remote AI is optional; the dashboard and risk scoring do not require it.

The AI summary does not discover vulnerabilities or decide the score. Review a provider's data-handling terms before sending real asset data. If the remote request fails, the helper uses its local summary instead.

## Dashboard Pages

- `/` is the asset inventory, summary counts, and filters.
- `/asset/<id>` shows one asset's sources and supporting evidence.
- `/methodology` explains the project's approach and data sources.
- `/export.json` returns the current assets and statistics as JSON.

The dashboard interface and its built-in risk explanations are presented in English.

The app is passive-first. When passive-only mode is enabled, it does not check whether every hostname answers HTTP, so availability is unknown. Optional HTTP `HEAD` checks send requests to discovered hosts and should only be enabled for an authorized scope.

## What Is Connected?

The main dashboard uses normalized Subfinder, Amass, and Assetfinder records, plus certificate and takeover information when present. Shodan searches, manually collected Censys records, threat-intelligence results, and snapshots are separate optional pieces and are not all connected to the dashboard. The file guide below explains each one.

## Important Project Notes

- Scanner scripts have separate hard-coded domain lists rather than one shared scope setting.
- Raw samples and new scanner output are stored in the root `scans/` folder. All scanner wrappers and corresponding normalizers use this shared location.
- The merge normalizer expects a data shape different from the output of the dedicated normalizers; the Shodan normalizer accepts both the collector's `matches` output and the legacy `raw_hosts` format.
- Snapshots can be written, but the dashboard has no drift page at present.
- Threat-intelligence and Censys output are not currently loaded by the dashboard.
- The dashboard can read `cve_findings.json`, but the repository has no CVE-scanner script to create it.
- `tests/test_risk_engine.py` contains the risk-engine tests. Pytest is a test-only dependency, not an application feature.

## Known Limitations

- Domain scope is hard-coded separately in scanner scripts rather than loaded from one shared configuration.
- All scanner wrappers and normalizers use the root `scans/` folder; no scan-file copying or nested `scanner/scans/` directory is required.
- `merge_normalizer.py` expects `by_subdomain` objects from its Subfinder/Amass inputs, while the current dedicated normalizers produce lists. It is not part of the dashboard's required workflow.
- `shodan_normalizer.py` can normalize the Shodan collector's `matches` output, but Shodan data is not currently loaded by the dashboard.
- `snapshot_scan.py` stores snapshots, but the documented `/drift` route is not implemented in the current Flask routes.
- Threat-intelligence and Censys normalized data are not currently consumed by the dashboard; the dashboard also has no active port inventory source.
- Optional `cve_findings.json` is referenced by the app but no producer is included in this repository.
- The existing risk-engine tests require pytest, which is not included in the runtime requirements.

## File-by-File Guide

This catalog describes the project files currently present in the repository. Generated Python cache files and local virtual environments are not source files and are intentionally not listed.

### Root files

| File | What it contains / does |
| --- | --- |
| `.env.example` | Example environment-variable names and default settings. It is a reference only; the application does not automatically load this file. Never put real secrets in a committed example file. |
| `README.md` | This guide: project purpose, tool roles, data flow, risk scoring, AI helper, and file explanations. |
| `ai_helper.py` | Creates a local summary from an asset's existing evidence, or optionally calls a compatible remote AI endpoint when configured. |
| `app.py` | Flask application. Loads normalized data, joins records by hostname, computes asset details and statistics, renders pages, and serves JSON export. |
| `requirements.txt` | Python runtime packages required by the app and optional Shodan support: Flask, Shodan, and Certifi. Pytest is a separate development/test dependency. |
| `risk_engine.py` | Risk calculation functions. Raises a base exposure score when it sees evidence such as a takeover finding, CVE, or inactive certificate, and computes an enterprise score and priority. |
| `vulnerability_sources.py` | Best-effort clients and normalization for public NVD, CISA KEV, EPSS, and OSV data. It enriches assets; it does not probe target services. |

### `scanner/`: collection scripts

These Python scripts invoke an external command or public data source and write raw results. The Python file is the wrapper; it is not the Subfinder/Amass/Assetfinder tool itself.

| File | What it contains / does |
| --- | --- |
| `scanner/__init__.py` | Marks `scanner` as a Python package. |
| `scanner/subfinder.py` | Runs the Subfinder executable for the configured domains and saves one raw hostname list per domain. |
| `scanner/amass.py` | Runs Amass in passive enumeration mode and saves its relationship-graph text output per domain. |
| `scanner/assetfinder.py` | Runs the Assetfinder executable and saves discovered subdomains per domain. |
| `scanner/certs.py` | Queries crt.sh and Cert Spotter certificate-transparency data, validates hostnames, and writes raw per-domain JSON. |
| `scanner/shodan_scanner.py` | Searches Shodan by certificate subject for possible publicly indexed hosts. Requires a Shodan API key and consumes Shodan search credits. It is optional and not part of the dashboard's main input pipeline. |

### External tools and data sources

| Tool/source | Role in this project | Requirement / note |
| --- | --- | --- |
| Subfinder | Passive subdomain discovery. | The project wrapper is `scanner/subfinder.py`; the external executable performs the actual discovery. |
| Amass | Passive domain enumeration and relationship output, including CNAME relationships used by takeover analysis. | The project wrapper is `scanner/amass.py`; the external executable performs the actual discovery. |
| Assetfinder | Subdomain discovery from public sources. | The project wrapper is `scanner/assetfinder.py`; the external executable performs the actual discovery. |
| crt.sh | Public certificate-transparency search. | Queried by `scanner/certs.py`; no project API key is configured. |
| Cert Spotter | Additional public certificate-transparency source. | Queried by `scanner/certs.py` to complement crt.sh. |
| Shodan | Search engine for internet-connected hosts, queried here by TLS certificate name. | Optional API key and account search credits; not currently wired into dashboard asset construction. |
| NVD | Public CVE records and CVSS details. | Queried by `vulnerability_sources.py` when the dashboard enriches assets. |
| CISA KEV | Catalog of vulnerabilities known to be exploited. | Public catalog lookup; used as vulnerability context. |
| EPSS | Exploit prediction probability and percentile for CVEs. | Public API lookup; used to help prioritize findings. |
| OSV | Open-source package vulnerability records. | Public API lookup for inferred service/package names. |
| URLhaus, AlienVault OTX, AbuseIPDB | Threat-intelligence sources for host/domain indicators. | Accessed by the standalone `normalizers/threat_intel_scanner.py`; not currently displayed by the dashboard. |
| Censys | External asset/certificate search service. | This repository has a normalizer for manually collected results, not a Censys API collector. |
| Flask | Python web framework used to serve the dashboard. | Listed in `requirements.txt`. |
| Shodan Python package | Python client used by the optional Shodan wrapper. | Listed in `requirements.txt`; a Shodan account key is still needed for API searches. |
| Certifi | CA certificate bundle used by threat-intelligence HTTPS requests. | Listed in `requirements.txt`. |
| Bootstrap 5 | CSS framework used for the page layout and components. | Referenced from a CDN in `templates/layout.html`, so browsers need network access for its styling. |

### `normalizers/`: processing, detections, and saved JSON

Normalizers turn raw scanner output into simpler records. JSON files in this folder are data, not Python modules; some are checked-in sample/current results and may be replaced when their corresponding normalizer runs.

| File | What it contains / does |
| --- | --- |
| `normalizers/amass_normalizer.py` | Extracts in-scope hostnames from Amass relationship output or plain hostname lists and writes `amass_normalized.json`. |
| `normalizers/amass_normalized.json` | Saved normalized Amass hostname records, with domain, source, and discovery timestamp. |
| `normalizers/assetfinder_normalizer.py` | Validates and converts root-level `scans/assetfinder_*.txt` files into `assetfinder_normalized.json`. Its input directory currently differs from the scanner output directory. |
| `normalizers/assetfinder_normalized.json` | Saved Assetfinder hostname records used by the dashboard. |
| `normalizers/censys_normalizer.py` | Converts manually prepared `scans/censys_raw.json` records to normalized Censys records. It does not query Censys. |
| `normalizers/certs_normalizer.py` | Aggregates raw certificate results into per-domain and per-host certificate summaries and writes `certs_normalized.json`. |
| `normalizers/dns_enum_normalizer.py` | Produces an aggregate comparison of Subfinder and Amass discovery. It is an additional report and is not the dashboard's primary loader. |
| `normalizers/merge_normalizer.py` | Intended to combine certificate, Subfinder, and Amass normalized data into a unified report. Its expected input schema currently differs from the output of the dedicated normalizers; see Known Limitations. |
| `normalizers/shodan_normalizer.py` | Normalizes Shodan collector `matches` or legacy `raw_hosts` records into per-domain host details. Its output is not currently loaded by the dashboard. |
| `normalizers/snapshot_scan.py` | Saves timestamped snapshots of the current assets for later comparison. The app does not currently implement the `/drift` route mentioned in this script's comments. |
| `normalizers/subfinder_normalizer.py` | Reads Subfinder raw text files from `scans/` and writes `subfinder_normalized.json`. |
| `normalizers/subfinder_normalized.json` | Saved normalized Subfinder hostname records, with domain, source, and discovery timestamp. |
| `normalizers/takeover_detector.py` | Reads Amass CNAME relationships and checks for known third-party service patterns and unresolved DNS targets; writes takeover findings. A finding is a signal to verify, not proof of exploitability. |
| `normalizers/takeover_findings.json` | Saved takeover-detection findings consumed by the dashboard. |
| `normalizers/threat_intel_scanner.py` | Standalone best-effort lookups to URLhaus, OTX, and AbuseIPDB for discovered hosts; writes `threat_intel_findings.json`. The dashboard does not currently load that output. |

### `scans/`: checked-in raw sample results

These are per-domain text files already in the repository. They are examples/current raw inputs, not executable tools. The prefixes identify which collector produced a file; each contains results for the domain in its filename.

| File | Collector and contents |
| --- | --- |
| `scans/amass_sec-dojo.com.txt` | Amass raw relationship output for `sec-dojo.com`. |
| `scans/amass_secdojo.com.txt` | Amass raw relationship output for `secdojo.com`. |
| `scans/amass_sekera-group.com.txt` | Amass raw relationship output for `sekera-group.com`. |
| `scans/amass_vinci-logic.com.txt` | Amass raw relationship output for `vinci-logic.com`. |
| `scans/amass_vincilogic.com.txt` | Amass raw relationship output for `vincilogic.com`. |
| `scans/assetfinder_sec-dojo.com.txt` | Assetfinder raw hostname list for `sec-dojo.com`. |
| `scans/assetfinder_secdojo.com.txt` | Assetfinder raw hostname list for `secdojo.com`. |
| `scans/assetfinder_sekera-group.com.txt` | Assetfinder raw hostname list for `sekera-group.com`. |
| `scans/assetfinder_vinci-logic.com.txt` | Assetfinder raw hostname list for `vinci-logic.com`. |
| `scans/assetfinder_vincilogic.com.txt` | Assetfinder raw hostname list for `vincilogic.com`. |
| `scans/subfinder_sec-dojo.com.txt` | Subfinder raw hostname list for `sec-dojo.com`. |
| `scans/subfinder_secdojo.com.txt` | Subfinder raw hostname list for `secdojo.com`. |
| `scans/subfinder_vinci-logic.com.txt` | Subfinder raw hostname list for `vinci-logic.com`. |
| `scans/subfinder_vincilogic.com.txt` | Subfinder raw hostname list for `vincilogic.com`. |

The raw sample files and scanner outputs are all in the root `scans/` folder. Collectors and normalizers share this location, so no copying into a second scans folder is required.

### `templates/`: dashboard pages

| File | What it contains / does |
| --- | --- |
| `templates/layout.html` | Shared page shell, navigation, Bootstrap link, and base styling used by the other templates. |
| `templates/index.html` | Main inventory table, summary counters, and filters for search, category, priority, status, and root domain. |
| `templates/asset.html` | Detail view for one asset, including score explanation, sources, certificate, takeover, CVE, and summary fields. |
| `templates/methodology.html` | Explains the project's approach and lists the public sources shown on the methodology page. |

### `tests/`: automated checks

| File | What it checks |
| --- | --- |
| `tests/test_risk_engine.py` | Checks that strong vulnerability evidence raises enterprise risk and that an ordinary asset without such evidence remains lower priority. |

### Local/generated folders

`.venv/`, `venv/`, and `__pycache__/` are local virtual-environment or Python cache folders visible in some development setups. They are not project source, should not be documented as application modules, and should generally not be committed.