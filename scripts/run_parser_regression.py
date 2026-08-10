import json
from collections import Counter
from pathlib import Path

from app.detection.rules import run_detection_rules
from app.pcap.manifest import scan_capture
from app.pcap.parser import normalize_capture
from app.schemas.data import ApplicationProtocol

REPRESENTATIVES = {
    "SQL_INJECTION_WITH_BACKGROUND": "sql注入.pcap",
    "COMMAND_RCE": "ThinkPHP_rce.pcap",
    "WEBSHELL": "shiro550_webshell_CommonsCollections2_10.100.4.101.pcap",
    "DNSLOG": "algo_mssql_oob_xp_fileexist_dnslog#ns(10.100.15.254),wd(10.100.13.25).pcap",
    "PCAP_NG": "jsp.pcap",
    "TLS_OPAQUE": "1.postgresql_dnslog_powershell_cs.pcap",
}


def main() -> None:
    root = Path("data/测评中心基线样本nta")
    records = []
    for category, name in REPRESENTATIVES.items():
        path = root / name
        capture = scan_capture(root, path)
        normalized = normalize_capture(capture, path)
        protocol_counts = Counter(flow.application_protocol.value for flow in normalized.flows)
        records.append(
            {
                "category": category,
                "display_name": name,
                "capture_id": capture.capture_id,
                "format": capture.format.value,
                "parse_status": normalized.parse_status.value,
                "packets": len(normalized.raw_events),
                "flows": len(normalized.flows),
                "http": len(normalized.http_events),
                "dns": len(normalized.dns_events),
                "tls_flows": protocol_counts[ApplicationProtocol.TLS.value],
                "evidence": len(normalized.evidence),
                "signals": len(run_detection_rules(normalized)),
                "errors": normalized.errors,
            }
        )
    output = Path("artifacts/parser_regression_report.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(records, ensure_ascii=False))


if __name__ == "__main__":
    main()
