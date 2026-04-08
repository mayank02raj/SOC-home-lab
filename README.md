# SOC Home Lab v2

A production-shaped Security Operations Center on your laptop. Wazuh SIEM, Suricata NIDS, TheHive case management, Cortex enrichment, Grafana KPI dashboards, and three vulnerable targets on an isolated network. Detection content is treated as code with unit tests, CI, and a Sigma to Wazuh compiler. An eight-stage adversary emulation script walks the full MITRE ATT&CK kill chain so you can demonstrate end-to-end detection coverage.

## Architecture

```
┌──────────────────────── blue_net (SOC tooling) ───────────────────────┐
│                                                                        │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐           │
│   │ Wazuh        │    │ Wazuh        │    │ Wazuh        │           │
│   │ Manager      │◄──►│ Indexer      │◄──►│ Dashboard    │           │
│   │ (rules)      │    │ (OpenSearch) │    │ :443         │           │
│   └──────┬───────┘    └──────┬───────┘    └──────────────┘           │
│          │                   │                                        │
│          │                   ▼                                        │
│   ┌──────┴───────┐    ┌──────────────┐    ┌──────────────┐           │
│   │ Filebeat     │    │ Prometheus   │◄──►│ Grafana      │           │
│   │ (suricata)   │    │ :9090        │    │ :3000        │           │
│   └──────────────┘    └──────────────┘    └──────────────┘           │
│                                                                        │
│   ┌──────────────┐    ┌──────────────┐                                │
│   │ TheHive      │◄──►│ Cortex       │                                │
│   │ :9000        │    │ :9001        │                                │
│   └──────────────┘    └──────────────┘                                │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
                              │
                              │  Suricata (host network, sees all traffic)
                              ▼
┌──────────────────── red_net (isolated, no egress) ────────────────────┐
│                                                                        │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐           │
│   │ DVWA         │    │ Juice Shop   │    │ Metasploit-  │           │
│   │ :8080        │    │ :3001        │    │ able2        │           │
│   └──────────────┘    └──────────────┘    └──────────────┘           │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
                              ▲
                              │
                       attack_chain.py
                       (8-stage adversary emulation)
```

## What ships in this repo

| Component | Path | Purpose |
|---|---|---|
| Multi-network compose | `docker-compose.yml` | Isolated red/blue networks, 11 services |
| Sigma rules (9) | `sigma-rules/` | Win, Linux, web, DNS, SMB lateral movement |
| Suricata rules | `suricata/rules/local.rules` | Web attacks, recon, C2, lateral, brute force |
| Adversary emulation | `attack_chain.py` | 8-stage MITRE ATT&CK kill chain with timeline export |
| Sigma compiler | `sigma_to_wazuh.py` | Translates Sigma YAML to Wazuh local_rules.xml |
| Detection unit tests | `test_detections.py` | Mini Sigma evaluator + parametrized rule tests |
| CI workflow | `.github/workflows/detection-ci.yml` | Lint, validate, test, compile on every push |
| Threat hunting | `notebooks/threat_hunting.ipynb` | Four hypothesis-driven hunts against the indexer |
| Active response | `active-response/block_ip.sh` | Auto-blocks attacker IPs with safe-IP guard |
| Custom decoders | `custom-decoders/local_decoder.xml` | Parses Suricata EVE, DVWA access logs, AR audit |
| SOC dashboard | `grafana/dashboards/soc-overview.json` | KPIs: alerts, severities, MITRE coverage, top IPs |
| Filebeat shipper | `filebeat/filebeat.yml` | Suricata eve.json to Wazuh indexer |
| TheHive config | `thehive/application.conf` | Case mgmt + Cortex integration |

## Skills demonstrated

SIEM engineering, detection-as-code, MITRE ATT&CK alignment, Sigma rule authoring, network IDS deployment, log pipeline design, threat hunting methodology, adversary emulation, CI/CD for security content, container orchestration, multi-tier network segmentation, SOAR primitives (active response), KPI dashboarding.

## Quick start

```bash
git clone <this-repo>
cd soc-lab
cp .env.example .env

make up                # bring up the stack
sleep 90               # let Wazuh initialize
make rules             # compile Sigma rules and reload manager
make test              # run detection unit tests
make attack            # run the full 8-stage adversary emulation
```

Then open the dashboards:

| URL | Service | Default credentials |
|---|---|---|
| https://localhost:443 | Wazuh | admin / SecretPassword |
| http://localhost:3000 | Grafana | admin / admin |
| http://localhost:9000 | TheHive | admin@thehive.local / secret |
| http://localhost:9001 | Cortex | admin / (set on first login) |
| http://localhost:9090 | Prometheus | n/a |
| http://localhost:8080 | DVWA target | admin / password |
| http://localhost:3001 | Juice Shop target | n/a |

## Detection content lifecycle

```
   ┌────────────┐     ┌────────────┐     ┌────────────┐     ┌────────────┐
   │ Author     │────►│ Lint +     │────►│ Unit test  │────►│ Compile to │
   │ Sigma rule │     │ validate   │     │ (pytest)   │     │ Wazuh XML  │
   └────────────┘     └────────────┘     └────────────┘     └─────┬──────┘
                                                                  │
   ┌────────────┐     ┌────────────┐     ┌────────────┐           │
   │ Tune from  │◄────│ Triage in  │◄────│ Alert in   │◄──────────┘
   │ feedback   │     │ TheHive    │     │ dashboard  │
   └────────────┘     └────────────┘     └────────────┘
```

Every Sigma rule under `sigma-rules/` is:

1. Linted by GitHub Actions on push (YAML valid, required fields present, ATT&CK tag exists)
2. Unit-tested by `test_detections.py` against synthetic malicious AND benign events
3. Compiled by `sigma_to_wazuh.py` into native Wazuh format on demand
4. Loaded by the manager from a read-only volume mount

The tests use a small embedded Sigma evaluator so they run in any environment without needing a live SIEM. This is the same pattern Splunk's `attack_range`, Red Canary's `atomic-red-team`, and Elastic's `detection-rules` repos use.

## Adversary emulation

`attack_chain.py` walks an 8-stage kill chain mapped to ATT&CK techniques. Each stage logs to a JSON timeline so you can prove the SOC saw the full attack, not just isolated alerts.

```
Stage 1  Recon (T1595)              dir busting + scanner UA
Stage 2  Initial Access (T1190)     SQLi UNION + auth bypass
Stage 3  Execution (T1059.004)      command injection
Stage 4  Persistence (T1505.003)    web shell upload
Stage 5  Discovery (T1083)          LFI filesystem enum
Stage 6  Cred Access (T1003.008)    /etc/shadow read
Stage 7  Exfiltration (T1041)       data POST
Stage 8  Impact (T1499.002)         brute force DoS
```

Run individual stages with `--stage N` for tuning, or the full chain with no flag.

## Threat hunting

`notebooks/threat_hunting.ipynb` connects to the Wazuh indexer and runs four hypothesis-driven hunts:

1. **Rare process parent-child relationships** (T1059) — finds anomalies like `winword.exe` spawning `powershell.exe`
2. **First-seen external IPs by user** (T1078) — flags credential theft candidates
3. **Off-hours admin activity** (T1078.002) — sudo at 3 AM
4. **High-entropy DNS subdomains** (T1568.002) — DGAs and DNS tunneling

Extend it by writing more cells against the same OpenSearch client. Each hunt takes about ten lines.

## What to capture for the portfolio writeup

1. Architecture diagram (this README has the ASCII version, build a clean SVG for the resume site)
2. Screenshot of Grafana SOC dashboard during an attack run
3. Wazuh dashboard drilldown of a single triaged alert with full event metadata
4. The Sigma rule and the alert it produced, side by side
5. CI run showing detection tests passing on a rule edit
6. Attack timeline JSON paired with the alerts it generated, proving end-to-end coverage
7. Threat hunting notebook output with one anomaly you flagged

## Production hardening notes

The single-node Wazuh setup is appropriate for a lab. For anything production-ish:

- Generate proper certs with `wazuh-certs-tool.sh`, mount them into manager and indexer
- Move to the multi-node compose file from the Wazuh docs
- Run TheHive against Cassandra and Elasticsearch instead of the embedded BerkeleyDB
- Replace `verify_certs=false` everywhere with real CA validation
- Rotate the secrets in `.env` and never commit the file
- Put Grafana and the dashboard behind an authenticated reverse proxy
- Add `node-exporter` and proper alerting rules to Prometheus

## Why this matters for defense contractor roles

Every Tier 1 contractor running a SOC has the same checklist: detection coverage mapped to ATT&CK, content under version control with CI, hunt capability beyond out-of-the-box rules, automated triage with case management, and KPIs the customer can see. This lab demonstrates all five in one repo. When the interview question is "describe a time you built detection content from scratch," you have a working artifact to walk through, not a hypothetical.
