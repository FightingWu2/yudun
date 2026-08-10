import json
from collections import Counter, defaultdict
from pathlib import Path

from app.detection.rules import run_detection_rules
from app.pcap.manifest import scan_capture
from app.pcap.parser import normalize_capture


def main() -> None:
    root = Path("data/测评中心基线样本nta")
    samples = json.loads(Path("artifacts/verified_sample_set.json").read_text(encoding="utf-8"))[
        "samples"
    ]
    expected_by_label = {
        "SQL_INJECTION": "nta-sqli",
        "COMMAND_INJECTION": "nta-cmdi",
        "WEBSHELL_RCE": "nta-webshell",
        "DNSLOG": "nta-dnslog",
    }
    matches = Counter()
    misses: dict[str, list[str]] = defaultdict(list)
    for sample in samples:
        path = root / sample["display_name"]
        normalized = normalize_capture(scan_capture(root, path), path)
        matched_rules = {item.rule.rule_id for item in run_detection_rules(normalized)}
        expected = expected_by_label[sample["human_label"]]
        if expected in matched_rules:
            matches[expected] += 1
        else:
            misses[expected].append(sample["sample_id"])
    report = {
        "scope": "verified sample regression only; not whole-dataset accuracy",
        "sample_count": len(samples),
        "expected_matches": matches,
        "misses": misses,
        "limitations": [
            "The set is selected and singly reviewed, not competition ground truth.",
            "Encrypted, fragmented, and unsupported binary protocols may remain opaque.",
        ],
    }
    output = Path("artifacts/rule_regression_report.json")
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False))


if __name__ == "__main__":
    main()
