#!/usr/bin/env python3
"""
sigma_to_wazuh.py
Compile every Sigma rule in sigma-rules/ into a single Wazuh local rules XML
file using sigma-cli. Drop the result into custom-rules/ where the manager
container picks it up on restart.

Usage:
    pip install sigma-cli pysigma-backend-elasticsearch
    python sigma_to_wazuh.py
"""

import os
import subprocess
import sys
from pathlib import Path

SIGMA_DIR = Path("sigma-rules")
OUT_DIR = Path("custom-rules")
OUT_FILE = OUT_DIR / "local_rules.xml"

WAZUH_RULE_HEADER = """<!-- Auto-generated from Sigma. Do not edit by hand. -->
<group name="sigma,custom,">
"""
WAZUH_RULE_FOOTER = "</group>\n"


def have_sigma_cli() -> bool:
    try:
        subprocess.run(["sigma", "--help"],
                       capture_output=True, check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


def convert_one(yml_path: Path) -> str:
    """Use sigma-cli to translate one Sigma file to Wazuh XML."""
    try:
        result = subprocess.run(
            ["sigma", "convert", "-t", "wazuh", "-p", "wazuh", str(yml_path)],
            capture_output=True, text=True, check=True,
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"  ! failed to convert {yml_path.name}: {e.stderr.strip()}")
        return ""


def main():
    if not have_sigma_cli():
        print("ERROR: sigma-cli not found. Install with:")
        print("  pip install sigma-cli pysigma-backend-elasticsearch")
        sys.exit(1)

    if not SIGMA_DIR.exists():
        print(f"ERROR: {SIGMA_DIR} not found")
        sys.exit(1)

    OUT_DIR.mkdir(exist_ok=True)
    rules = sorted(SIGMA_DIR.rglob("*.yml"))
    if not rules:
        print(f"No Sigma rules found in {SIGMA_DIR}")
        sys.exit(1)

    print(f"[+] Converting {len(rules)} Sigma rules to Wazuh format")
    parts = [WAZUH_RULE_HEADER]
    converted = 0
    for r in rules:
        print(f"  - {r.name}")
        out = convert_one(r)
        if out:
            parts.append(out)
            converted += 1
    parts.append(WAZUH_RULE_FOOTER)

    OUT_FILE.write_text("\n".join(parts))
    print(f"\n[+] Wrote {converted}/{len(rules)} rules to {OUT_FILE}")
    print("\nNext steps:")
    print("  docker compose restart wazuh.manager")
    print("  Verify in dashboard under Management -> Rules")


if __name__ == "__main__":
    main()
