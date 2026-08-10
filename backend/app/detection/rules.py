import re
from dataclasses import dataclass
from urllib.parse import unquote_plus

from pydantic import Field

from app.core.ids import source_derived_id
from app.domain.enums import Severity, SourceType
from app.pcap.parser import NormalizedCapture
from app.schemas.analysis import DetectorRef, DetectorType, SecuritySignal, SignalStatus, SignalType
from app.schemas.base import NonEmptyStr, StrictSchema


class DetectionRule(StrictSchema):
    rule_id: NonEmptyStr
    rule_name: NonEmptyStr
    rule_version: NonEmptyStr
    description: NonEmptyStr
    input_event_type: NonEmptyStr
    conditions: list[NonEmptyStr] = Field(min_length=1)
    severity: Severity
    signal_type: SignalType
    evidence_strategy: NonEmptyStr
    known_limitations: list[str] = Field(default_factory=list)


@dataclass(frozen=True, slots=True)
class RuleMatch:
    rule: DetectionRule
    event_id: str
    evidence_id: str
    matched_condition: str
    signal: SecuritySignal


DETECTION_RULES = (
    DetectionRule(
        rule_id="nta-sqli",
        rule_name="HTTP SQL injection indicators",
        rule_version="1.0",
        description=(
            "Matches explicit SQL operators and database delay primitives in decoded HTTP data."
        ),
        input_event_type="HTTPEvent",
        conditions=[
            r"\bunion\s+(?:all\s+)?select\b",
            r"\b(?:sleep|benchmark|waitfor\s+delay)\s*\(",
            r"\b(?:xp_dirtree|xp_fileexist|xp_subdirs)\b",
        ],
        severity=Severity.HIGH,
        signal_type=SignalType.NTA_SQLI,
        evidence_strategy="Reference the matching HTTP request packet.",
        known_limitations=["Encoded or fragmented payloads may require deeper reassembly."],
    ),
    DetectionRule(
        rule_id="nta-cmdi",
        rule_name="HTTP command execution indicators",
        rule_version="1.0",
        description="Matches explicit process-launch primitives in decoded HTTP requests.",
        input_event_type="HTTPEvent",
        conditions=[
            r"(?:runtime|getruntime)\s*\([^)]*\)\s*\.exec\s*\(",
            r"\bprocessbuilder\s*\(",
            r"\bbsh\.script\s*=\s*exec\s*\(",
            r"(?:^|[?&\s])(?:c=system|xxxxx=passthru)\b",
        ],
        severity=Severity.CRITICAL,
        signal_type=SignalType.NTA_CMDI,
        evidence_strategy="Reference the HTTP packet containing the execution primitive.",
        known_limitations=["Binary serializers and multi-packet bodies are not deeply decoded."],
    ),
    DetectionRule(
        rule_id="nta-webshell",
        rule_name="HTTP webshell activity indicators",
        rule_version="1.0",
        description="Matches explicit shell endpoints or characteristic webshell control payloads.",
        input_event_type="HTTPEvent",
        conditions=[
            r"/(?:[\w-]*shell|jsp_[a-z]+|ws\d+|jspspy)\.(?:jsp|php|asp|aspx)\b",
            r"\b(?:antsword|caidao|behinder|godzilla)\b",
            r"\bdefineclass\b",
            r"\baction=(?:createsocket|getdata)\b",
            r"<\?php\s+@?eval\s*\(",
            r"\binto\s+outfile\b.{0,200}\.(?:jsp|php|asp|aspx)\b",
        ],
        severity=Severity.CRITICAL,
        signal_type=SignalType.NTA_WEBSHELL,
        evidence_strategy="Reference the HTTP request packet containing the shell indicator.",
        known_limitations=["Custom or encrypted webshell protocols may remain opaque."],
    ),
    DetectionRule(
        rule_id="nta-dnslog",
        rule_name="Out-of-band DNS callback indicators",
        rule_version="1.0",
        description="Matches explicit callback-service domains observed in verified samples.",
        input_event_type="HTTPEvent|DNSEvent",
        conditions=[r"(?:^|\.)dnslog\.cn\b", r"(?:^|\.)ceye\.io\b"],
        severity=Severity.HIGH,
        signal_type=SignalType.NTA_DNSLOG,
        evidence_strategy="Reference the DNS packet or HTTP packet containing the callback domain.",
        known_limitations=["Unknown callback domains require an updated governed rule version."],
    ),
)


def run_detection_rules(normalized: NormalizedCapture) -> list[RuleMatch]:
    evidence_by_record = {item.source_record_id: item for item in normalized.evidence}
    candidates = dict(normalized.inspection_text)
    candidates.update({event.dns_event_id: event.query_name for event in normalized.dns_events})
    matches: list[RuleMatch] = []
    for event_id, raw_text in candidates.items():
        text = unquote_plus(raw_text).lower()
        evidence = evidence_by_record.get(event_id)
        if evidence is None:
            continue
        for rule in DETECTION_RULES:
            condition = next(
                (pattern for pattern in rule.conditions if re.search(pattern, text, re.IGNORECASE)),
                None,
            )
            if condition is None:
                continue
            signal_id = source_derived_id(
                "sig",
                {
                    "rule": rule.rule_id,
                    "version": rule.rule_version,
                    "evidence": evidence.evidence_id,
                },
                "detection-engine-1.0",
            )
            signal = SecuritySignal(
                signal_id=signal_id,
                signal_type=rule.signal_type,
                severity=rule.severity,
                subject_refs=[event_id],
                trigger_reason=(
                    f"Rule {rule.rule_id}@{rule.rule_version} matched governed condition."
                ),
                detector=DetectorRef(
                    detector_type=DetectorType.RULE,
                    detector_id=rule.rule_id,
                    detector_version=rule.rule_version,
                ),
                evidence_refs=[evidence.evidence_id],
                source_types=[SourceType.OFFICIAL],
                status=SignalStatus.OPEN,
            )
            matches.append(RuleMatch(rule, event_id, evidence.evidence_id, condition, signal))
    return matches
