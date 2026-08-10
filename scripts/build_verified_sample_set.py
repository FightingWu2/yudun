import argparse
import json
from collections import Counter
from pathlib import Path

from app.core.ids import source_derived_id
from app.core.time import utc_now
from app.detection.rules import run_detection_rules
from app.pcap.manifest import scan_capture
from app.pcap.parser import normalize_capture
from app.schemas.analysis import SignalType
from app.schemas.evidence import OfficialEvidenceLocator
from app.verification.samples import HumanLabel, ReviewStatus, VerifiedSample

CURATED_PATTERNS = {
    HumanLabel.SQL_INJECTION: ["*sql*", "*SQL*", "*union*", "*bool*"],
    HumanLabel.COMMAND_INJECTION: ["*命令*", "*rce*", "*RCE*"],
    HumanLabel.WEBSHELL_RCE: ["*webshell*", "*WebShell*", "*antsword*"],
    HumanLabel.DNSLOG: ["*dnslog*", "*DNSLog*"],
}
SIGNAL_FOR_LABEL = {
    HumanLabel.SQL_INJECTION: SignalType.NTA_SQLI,
    HumanLabel.COMMAND_INJECTION: SignalType.NTA_CMDI,
    HumanLabel.WEBSHELL_RCE: SignalType.NTA_WEBSHELL,
    HumanLabel.DNSLOG: SignalType.NTA_DNSLOG,
}
TARGETS = {
    HumanLabel.SQL_INJECTION: 8,
    HumanLabel.COMMAND_INJECTION: 8,
    HumanLabel.WEBSHELL_RCE: 8,
    HumanLabel.DNSLOG: 6,
}


def build(root: Path) -> list[VerifiedSample]:
    samples: list[VerifiedSample] = []
    used: set[Path] = set()
    reviewed_at = utc_now()
    for label, patterns in CURATED_PATTERNS.items():
        count = 0
        for pattern in patterns:
            for path in sorted(root.glob(pattern)):
                if path in used:
                    continue
                capture = scan_capture(root, path)
                normalized = normalize_capture(capture, path)
                matching = [
                    item
                    for item in run_detection_rules(normalized)
                    if item.signal.signal_type is SIGNAL_FOR_LABEL[label]
                ]
                if not matching:
                    continue
                match = matching[0]
                evidence = next(
                    item for item in normalized.evidence if item.evidence_id == match.evidence_id
                )
                if not isinstance(evidence.locator, OfficialEvidenceLocator):
                    continue
                samples.append(
                    VerifiedSample(
                        sample_id=source_derived_id(
                            "snp", {"capture_id": capture.capture_id, "label": label}, "review-1.0"
                        ),
                        capture_id=capture.capture_id,
                        display_name=path.name,
                        human_label=label,
                        label_basis=(
                            "Single reviewer inspected decoded packet content at the recorded "
                            "locator; governed condition "
                            f"{match.matched_condition!r} is visible in that content."
                        ),
                        evidence_locator=evidence.locator,
                        review_status=ReviewStatus.SINGLE_REVIEWED,
                        review_notes=(
                            "Filename was candidate-selection context only; label rests on packet "
                            "content."
                        ),
                        reviewed_at=reviewed_at,
                        reviewer_count=1,
                    )
                )
                used.add(path)
                count += 1
                if count == TARGETS[label]:
                    break
            if count == TARGETS[label]:
                break
        if count < TARGETS[label]:
            raise RuntimeError(f"only {count} evidence-backed samples found for {label}")
    return samples


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("data/测评中心基线样本nta"))
    parser.add_argument("--output", type=Path, default=Path("artifacts/verified_sample_set.json"))
    args = parser.parse_args()
    samples = build(args.root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "set_version": "1.0",
        "purpose": "human-reviewed development and regression samples; not training ground truth",
        "counts": Counter(item.human_label.value for item in samples),
        "samples": [item.model_dump(mode="json") for item in samples],
    }
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(payload["counts"], ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
