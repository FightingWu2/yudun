import hashlib
import socket
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO
from urllib.parse import parse_qsl, quote, urlsplit

import dpkt

from app.core.canonical import canonical_json
from app.core.ids import source_derived_id
from app.core.redaction import is_sensitive_key, redact_text
from app.core.time import utc_now
from app.domain.enums import EvidenceSensitivity, SourceType
from app.schemas.data import (
    ApplicationProtocol,
    CaptureRecord,
    DNSEvent,
    DnsParseStatus,
    DnsQueryType,
    EventKind,
    EventParseStatus,
    FiveTuple,
    FlowDirection,
    FlowSourceLocation,
    GenericSourceLocation,
    HTTPEvent,
    HttpMethod,
    HttpParseStatus,
    NetworkFlow,
    PayloadReference,
    RawEvent,
    RedactionStatus,
    TcpSummary,
    TransportProtocol,
)
from app.schemas.evidence import EvidenceReference, EvidenceType, OfficialEvidenceLocator

NORMALIZER_VERSION = "pcap-normalizer-1.0"
_HTTP_METHODS = {method.value: method for method in HttpMethod if method is not HttpMethod.OTHER}
_HEADER_ALLOWLIST = {"host", "user-agent", "content-type", "accept", "server"}
_DB_PORTS = {
    1433: ApplicationProtocol.TDS,
    3306: ApplicationProtocol.MYSQL,
    1521: ApplicationProtocol.ORACLE,
}


@dataclass(slots=True)
class PacketObservation:
    index: int
    timestamp: datetime
    raw_bytes: bytes
    raw_event: RawEvent
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    transport: TransportProtocol | None = None
    payload: bytes = b""
    tcp_flags: int = 0


@dataclass(slots=True)
class FlowAccumulator:
    capture_id: str
    source_id: str
    base_key: tuple[str, int, str, int, TransportProtocol]
    ordinal: int
    initiator: tuple[str, int]
    responder: tuple[str, int]
    observations: list[PacketObservation] = field(default_factory=list)


@dataclass(slots=True)
class NormalizedCapture:
    capture_id: str
    parse_status: EventParseStatus
    raw_events: list[RawEvent] = field(default_factory=list)
    flows: list[NetworkFlow] = field(default_factory=list)
    http_events: list[HTTPEvent] = field(default_factory=list)
    dns_events: list[DNSEvent] = field(default_factory=list)
    evidence: list[EvidenceReference] = field(default_factory=list)
    inspection_text: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


def _reader(handle: BinaryIO, capture_format: str):  # type: ignore[no-untyped-def]
    if capture_format == "PCAP":
        return dpkt.pcap.Reader(handle)
    if capture_format == "PCAP_NG":
        return dpkt.pcapng.Reader(handle)
    raise ValueError(f"unsupported capture format: {capture_format}")


def _application_protocol(
    src_port: int | None, dst_port: int | None, payload: bytes
) -> ApplicationProtocol:
    ports = {port for port in (src_port, dst_port) if port is not None}
    upper = payload[:16].upper()
    request_prefixes = tuple(f"{method} ".encode() for method in _HTTP_METHODS)
    if upper.startswith(request_prefixes) or upper.startswith(b"HTTP/"):
        return ApplicationProtocol.HTTP
    if 53 in ports:
        return ApplicationProtocol.DNS
    if 443 in ports or (len(payload) >= 3 and payload[0] == 0x16 and payload[1] == 0x03):
        return ApplicationProtocol.TLS
    for port, protocol in _DB_PORTS.items():
        if port in ports:
            return protocol
    if ports & {80, 8000, 8080, 8081, 8888}:
        return ApplicationProtocol.HTTP
    return ApplicationProtocol.UNKNOWN


def _decode_packet(
    capture_id: str, source_id: str, packet_index: int, timestamp: datetime, raw_bytes: bytes
) -> PacketObservation:
    src_ip = dst_ip = None
    src_port = dst_port = None
    transport: TransportProtocol | None = None
    payload = b""
    tcp_flags = 0
    parse_status = EventParseStatus.OPAQUE
    app_protocol: ApplicationProtocol | None = None
    event_kind = EventKind.PACKET
    error: str | None = None
    try:
        ethernet = dpkt.ethernet.Ethernet(raw_bytes)
        if not isinstance(ethernet.data, dpkt.ip.IP):
            raise ValueError("non-IPv4 Ethernet payload")
        ip = ethernet.data
        src_ip = socket.inet_ntoa(ip.src)
        dst_ip = socket.inet_ntoa(ip.dst)
        event_kind = EventKind.NETWORK
        if isinstance(ip.data, dpkt.tcp.TCP):
            transport = TransportProtocol.TCP
            src_port, dst_port = ip.data.sport, ip.data.dport
            payload = bytes(ip.data.data)
            tcp_flags = int(ip.data.flags)
        elif isinstance(ip.data, dpkt.udp.UDP):
            transport = TransportProtocol.UDP
            src_port, dst_port = ip.data.sport, ip.data.dport
            payload = bytes(ip.data.data)
        elif isinstance(ip.data, dpkt.icmp.ICMP):
            transport = TransportProtocol.ICMP
            payload = bytes(ip.data.data)
        else:
            transport = TransportProtocol.OTHER
            payload = bytes(ip.data) if ip.data is not None else b""
        app_protocol = _application_protocol(src_port, dst_port, payload)
        parse_status = EventParseStatus.PARSED
    except (dpkt.dpkt.Error, ValueError, OSError) as exc:
        error = f"{type(exc).__name__}: {exc}"[:300]

    locator = {
        "capture_id": capture_id,
        "packet_index": packet_index,
    }
    raw_event = RawEvent(
        event_id=source_derived_id("raw", locator, NORMALIZER_VERSION),
        capture_id=capture_id,
        source_type=SourceType.OFFICIAL,
        source_id=f"{source_id}#packet-{packet_index}",
        source_location=GenericSourceLocation(
            dataset="official_nta", record_ref=f"{capture_id}:packet:{packet_index}"
        ),
        source_timestamp=timestamp,
        ingested_at=utc_now(),
        event_kind=event_kind,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        transport_protocol=transport,
        application_protocol=app_protocol,
        payload_reference=PayloadReference(
            object_ref=f"{capture_id}:packet:{packet_index}",
            byte_offset=0,
            byte_length=len(raw_bytes),
        ),
        payload_sha256=hashlib.sha256(raw_bytes).hexdigest(),
        parser_version=NORMALIZER_VERSION,
        parse_status=parse_status,
        redaction_status=RedactionStatus.RESTRICTED if payload else RedactionStatus.NOT_REQUIRED,
        attributes={"parse_error": error} if error else {},
    )
    return PacketObservation(
        index=packet_index,
        timestamp=timestamp,
        raw_bytes=raw_bytes,
        raw_event=raw_event,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        transport=transport,
        payload=payload,
        tcp_flags=tcp_flags,
    )


def _base_flow_key(observation: PacketObservation) -> tuple[str, int, str, int, TransportProtocol]:
    assert observation.src_ip is not None
    assert observation.dst_ip is not None
    assert observation.src_port is not None
    assert observation.dst_port is not None
    assert observation.transport is not None
    left = (observation.src_ip, observation.src_port)
    right = (observation.dst_ip, observation.dst_port)
    first, second = sorted((left, right))
    return first[0], first[1], second[0], second[1], observation.transport


def _build_flows(
    capture_id: str, source_id: str, observations: list[PacketObservation]
) -> list[FlowAccumulator]:
    active: dict[tuple[str, int, str, int, TransportProtocol], FlowAccumulator] = {}
    ordinals: dict[tuple[str, int, str, int, TransportProtocol], int] = {}
    completed: list[FlowAccumulator] = []
    for observation in observations:
        if (
            observation.transport not in {TransportProtocol.TCP, TransportProtocol.UDP}
            or observation.src_ip is None
            or observation.dst_ip is None
            or observation.src_port is None
            or observation.dst_port is None
        ):
            continue
        key = _base_flow_key(observation)
        new_tcp_stream = (
            observation.transport is TransportProtocol.TCP
            and bool(observation.tcp_flags & dpkt.tcp.TH_SYN)
            and not bool(observation.tcp_flags & dpkt.tcp.TH_ACK)
            and key in active
            and active[key].observations
        )
        if new_tcp_stream:
            completed.append(active.pop(key))
            ordinals[key] = ordinals.get(key, 0) + 1
        if key not in active:
            active[key] = FlowAccumulator(
                capture_id=capture_id,
                source_id=source_id,
                base_key=key,
                ordinal=ordinals.get(key, 0),
                initiator=(observation.src_ip, observation.src_port),
                responder=(observation.dst_ip, observation.dst_port),
            )
        active[key].observations.append(observation)
    completed.extend(active.values())
    return completed


def _flow_schema(accumulator: FlowAccumulator) -> NetworkFlow:
    observations = accumulator.observations
    first = observations[0]
    last = observations[-1]
    protocol = accumulator.base_key[-1]
    seen_forward = any(
        (item.src_ip, item.src_port) == accumulator.initiator for item in observations
    )
    seen_reverse = any(
        (item.src_ip, item.src_port) == accumulator.responder for item in observations
    )
    if seen_forward and seen_reverse:
        direction = FlowDirection.BIDIRECTIONAL
    elif seen_forward:
        direction = FlowDirection.INITIATOR_TO_RESPONDER
    else:
        direction = FlowDirection.RESPONDER_TO_INITIATOR
    application = max(
        (
            item.raw_event.application_protocol or ApplicationProtocol.UNKNOWN
            for item in observations
        ),
        key=lambda value: value is not ApplicationProtocol.UNKNOWN,
    )
    locator = {
        "capture_id": accumulator.capture_id,
        "five_tuple": accumulator.base_key,
        "first_packet_timestamp_ns": int(first.timestamp.timestamp() * 1_000_000_000),
        "stream_ordinal": accumulator.ordinal,
    }
    return NetworkFlow(
        flow_id=source_derived_id("flw", locator, NORMALIZER_VERSION),
        capture_id=accumulator.capture_id,
        source_type=SourceType.OFFICIAL,
        source_id=f"{accumulator.source_id}#flow-{first.index}",
        source_location=FlowSourceLocation(
            capture_id=accumulator.capture_id,
            first_packet_index=first.index,
            last_packet_index=last.index,
        ),
        source_timestamp=first.timestamp,
        five_tuple=FiveTuple(
            initiator_ip=accumulator.initiator[0],
            initiator_port=accumulator.initiator[1],
            responder_ip=accumulator.responder[0],
            responder_port=accumulator.responder[1],
            protocol=protocol,
        ),
        start_time=first.timestamp,
        end_time=last.timestamp,
        packet_count=len(observations),
        byte_count=sum(len(item.raw_bytes) for item in observations),
        direction=direction,
        application_protocol=application,
        raw_event_ids=[item.raw_event.event_id for item in observations],
        tcp_summary=TcpSummary(
            syn_seen=any(item.tcp_flags & dpkt.tcp.TH_SYN for item in observations),
            fin_seen=any(item.tcp_flags & dpkt.tcp.TH_FIN for item in observations),
            rst_seen=any(item.tcp_flags & dpkt.tcp.TH_RST for item in observations),
        )
        if protocol is TransportProtocol.TCP
        else None,
        parser_version=NORMALIZER_VERSION,
    )


def _sanitized_query(raw_query: str) -> tuple[list[str], str | None]:
    if not raw_query:
        return [], None
    pairs = parse_qsl(raw_query, keep_blank_values=True)
    keys = [key for key, _ in pairs]
    safe_pairs = [
        (key, "[REDACTED]" if is_sensitive_key(key) else redact_text(value)) for key, value in pairs
    ]
    encoded = "&".join(
        f"{quote(key, safe='')}={quote(value, safe='[]')}" for key, value in safe_pairs
    )
    return keys, encoded


def _headers(headers: dict[str, str]) -> tuple[dict[str, str], list[str]]:
    safe: dict[str, str] = {}
    sensitive_present: list[str] = []
    for key, value in headers.items():
        normalized = key.lower()
        if is_sensitive_key(normalized):
            sensitive_present.append(normalized)
        elif normalized in _HEADER_ALLOWLIST:
            safe[key] = redact_text(value)
    return safe, sorted(sensitive_present)


def _parse_http(
    capture_id: str, source_id: str, flow: NetworkFlow, accumulator: FlowAccumulator
) -> tuple[list[HTTPEvent], list[EvidenceReference], dict[str, str]]:
    events: list[HTTPEvent] = []
    evidence: list[EvidenceReference] = []
    inspection: dict[str, str] = {}
    pending_request: HTTPEvent | None = None
    for observation in accumulator.observations:
        if not observation.payload:
            continue
        payload = observation.payload
        try:
            request = dpkt.http.Request(payload)
            split = urlsplit(request.uri)
            query_keys, sanitized_query = _sanitized_query(split.query)
            headers, sensitive_present = _headers(dict(request.headers))
            event_id = source_derived_id(
                "raw",
                {
                    "capture_id": capture_id,
                    "packet_index": observation.index,
                    "kind": "http-request",
                },
                NORMALIZER_VERSION,
            )
            body = bytes(request.body)
            pending_request = HTTPEvent(
                http_event_id=event_id,
                flow_id=flow.flow_id,
                capture_id=capture_id,
                source_type=SourceType.OFFICIAL,
                source_id=f"{source_id}#http-{observation.index}",
                source_location=FlowSourceLocation(
                    capture_id=capture_id,
                    first_packet_index=observation.index,
                    last_packet_index=observation.index,
                ),
                source_timestamp=observation.timestamp,
                request_packet_range=(observation.index, observation.index),
                method=_HTTP_METHODS.get(request.method.upper(), HttpMethod.OTHER),
                scheme="http",
                host=request.headers.get("host"),
                uri_path=split.path or "/",
                query_keys=query_keys,
                sanitized_query=sanitized_query,
                headers_redacted=headers,
                body_reference=PayloadReference(
                    object_ref=f"{capture_id}:packet:{observation.index}:http-body",
                    byte_offset=max(0, len(payload) - len(body)),
                    byte_length=len(body),
                )
                if body
                else None,
                body_sha256=hashlib.sha256(body).hexdigest() if body else None,
                parse_status=HttpParseStatus.REQUEST_ONLY,
                parser_version=NORMALIZER_VERSION,
                metadata={"sensitive_headers_present": sensitive_present},
            )
            events.append(pending_request)
            inspection[event_id] = redact_text(
                " ".join(
                    item
                    for item in (
                        request.method,
                        split.path,
                        sanitized_query or "",
                        body.decode("utf-8", errors="replace")[:16_384],
                    )
                    if item
                )
            )
            evidence.append(
                _official_evidence(
                    capture_id,
                    event_id,
                    EvidenceType.HTTP_EVENT,
                    [observation.index],
                    flow.flow_id,
                    hashlib.sha256(payload).hexdigest(),
                    "Parsed HTTP request with packet locator",
                )
            )
            continue
        except (dpkt.dpkt.Error, UnicodeError, ValueError):
            pass
        try:
            response = dpkt.http.Response(payload)
        except (dpkt.dpkt.Error, UnicodeError, ValueError):
            continue
        if pending_request is not None:
            response_headers, _ = _headers(dict(response.headers))
            updated = pending_request.model_copy(
                update={
                    "response_packet_range": (observation.index, observation.index),
                    "status_code": int(response.status),
                    "response_headers_redacted": response_headers,
                    "response_reference": PayloadReference(
                        object_ref=f"{capture_id}:packet:{observation.index}:http-response",
                        byte_offset=0,
                        byte_length=len(payload),
                    ),
                    "parse_status": HttpParseStatus.COMPLETE,
                }
            )
            events[-1] = HTTPEvent.model_validate(updated.model_dump(mode="python"))
            pending_request = events[-1]
    return events, evidence, inspection


def _dns_query_type(value: int) -> DnsQueryType:
    mapping = {
        dpkt.dns.DNS_A: DnsQueryType.A,
        dpkt.dns.DNS_AAAA: DnsQueryType.AAAA,
        dpkt.dns.DNS_CNAME: DnsQueryType.CNAME,
        dpkt.dns.DNS_TXT: DnsQueryType.TXT,
        dpkt.dns.DNS_MX: DnsQueryType.MX,
        dpkt.dns.DNS_NS: DnsQueryType.NS,
        dpkt.dns.DNS_PTR: DnsQueryType.PTR,
    }
    return mapping.get(value, DnsQueryType.OTHER)


def _parse_dns(
    capture_id: str, source_id: str, flow: NetworkFlow, accumulator: FlowAccumulator
) -> tuple[list[DNSEvent], list[EvidenceReference]]:
    events: list[DNSEvent] = []
    evidence: list[EvidenceReference] = []
    for observation in accumulator.observations:
        if not observation.payload or 53 not in {observation.src_port, observation.dst_port}:
            continue
        try:
            dns = dpkt.dns.DNS(observation.payload)
        except (dpkt.dpkt.Error, ValueError):
            continue
        if not dns.qd:
            continue
        question = dns.qd[0]
        answers: list[str] = []
        for answer in dns.an:
            if hasattr(answer, "ip") and answer.ip:
                answers.append(socket.inet_ntoa(answer.ip))
            elif getattr(answer, "cname", None):
                answers.append(str(answer.cname))
            elif getattr(answer, "text", None):
                answers.append(redact_text(str(answer.text)))
        event_id = source_derived_id(
            "raw",
            {"capture_id": capture_id, "packet_index": observation.index, "kind": "dns"},
            NORMALIZER_VERSION,
        )
        event = DNSEvent(
            dns_event_id=event_id,
            flow_id=flow.flow_id,
            capture_id=capture_id,
            source_type=SourceType.OFFICIAL,
            source_id=f"{source_id}#dns-{observation.index}",
            source_location=FlowSourceLocation(
                capture_id=capture_id,
                first_packet_index=observation.index,
                last_packet_index=observation.index,
            ),
            source_timestamp=observation.timestamp,
            src_ip=observation.src_ip,
            src_port=observation.src_port,
            dns_server=observation.dst_ip,
            query_id=int(dns.id),
            query_name=str(question.name),
            query_type=_dns_query_type(int(question.type)),
            response_codes=[str(dns.rcode)] if dns.qr else [],
            answers_redacted=answers,
            packet_indexes=[observation.index],
            parse_status=DnsParseStatus.COMPLETE if dns.qr else DnsParseStatus.QUERY_ONLY,
            parser_version=NORMALIZER_VERSION,
        )
        events.append(event)
        evidence.append(
            _official_evidence(
                capture_id,
                event_id,
                EvidenceType.DNS_EVENT,
                [observation.index],
                flow.flow_id,
                hashlib.sha256(observation.payload).hexdigest(),
                "Parsed DNS event with packet locator",
            )
        )
    return events, evidence


def _official_evidence(
    capture_id: str,
    source_record_id: str,
    evidence_type: EvidenceType,
    packet_indexes: list[int],
    flow_id: str,
    content_sha256: str,
    summary: str,
) -> EvidenceReference:
    locator_data = {
        "capture_id": capture_id,
        "packet_indexes": packet_indexes,
        "flow_id": flow_id,
        "evidence_type": evidence_type.value,
    }
    return EvidenceReference(
        evidence_id=source_derived_id("evd", locator_data, NORMALIZER_VERSION),
        source_type=SourceType.OFFICIAL,
        source_dataset="official_nta",
        source_record_id=source_record_id,
        evidence_type=evidence_type,
        locator=OfficialEvidenceLocator(
            capture_id=capture_id, packet_indexes=packet_indexes, flow_id=flow_id
        ),
        content_sha256=content_sha256,
        summary=summary,
        sensitivity=EvidenceSensitivity.INTERNAL,
        allowed_agent_types=[
            "SILENT_MONITOR_AGENT",
            "INVESTIGATION_AGENT",
            "TRACE_AGENT",
        ],
        created_by="PCAP_NORMALIZER",
    )


def normalize_capture(capture_record: CaptureRecord, path: Path) -> NormalizedCapture:
    result = NormalizedCapture(
        capture_id=capture_record.capture_id,
        parse_status=EventParseStatus.PARSED,
    )
    observations: list[PacketObservation] = []
    try:
        with path.open("rb") as handle:
            for index, (timestamp, raw_bytes) in enumerate(
                _reader(handle, capture_record.format.value), start=1
            ):
                try:
                    observed_at = datetime.fromtimestamp(float(timestamp), tz=UTC)
                    observation = _decode_packet(
                        capture_record.capture_id,
                        capture_record.source_id,
                        index,
                        observed_at,
                        bytes(raw_bytes),
                    )
                    observations.append(observation)
                    result.raw_events.append(observation.raw_event)
                    if observation.raw_event.parse_status is EventParseStatus.OPAQUE:
                        result.parse_status = EventParseStatus.PARTIAL
                except Exception as exc:  # packet isolation; recorded and continued
                    result.errors.append(f"packet {index}: {type(exc).__name__}: {exc}"[:500])
                    result.parse_status = EventParseStatus.PARTIAL
    except (OSError, ValueError, dpkt.dpkt.Error) as exc:
        result.parse_status = EventParseStatus.FAILED
        result.errors.append(f"capture: {type(exc).__name__}: {exc}"[:500])
        return result

    for accumulator in _build_flows(
        capture_record.capture_id, capture_record.source_id, observations
    ):
        flow = _flow_schema(accumulator)
        result.flows.append(flow)
        if flow.application_protocol is ApplicationProtocol.HTTP:
            http_events, evidence, inspection = _parse_http(
                capture_record.capture_id, capture_record.source_id, flow, accumulator
            )
            result.http_events.extend(http_events)
            result.evidence.extend(evidence)
            result.inspection_text.update(inspection)
        if flow.application_protocol is ApplicationProtocol.DNS:
            dns_events, evidence = _parse_dns(
                capture_record.capture_id, capture_record.source_id, flow, accumulator
            )
            result.dns_events.extend(dns_events)
            result.evidence.extend(evidence)
    return result


def read_packet(path: Path, capture_format: str, packet_index: int) -> bytes:
    if packet_index < 1:
        raise ValueError("packet_index is 1-based")
    with path.open("rb") as handle:
        for current, (_timestamp, raw_bytes) in enumerate(_reader(handle, capture_format), start=1):
            if current == packet_index:
                return bytes(raw_bytes)
    raise IndexError(f"packet_index {packet_index} is outside capture")


def evidence_packet_bytes(
    evidence: EvidenceReference, path: Path, capture_format: str
) -> list[bytes]:
    if not isinstance(evidence.locator, OfficialEvidenceLocator):
        raise ValueError("only OFFICIAL evidence has packet locators")
    return [
        read_packet(path, capture_format, packet_index)
        for packet_index in evidence.locator.packet_indexes or []
    ]


def normalized_summary(result: NormalizedCapture) -> str:
    return canonical_json(
        {
            "capture_id": result.capture_id,
            "status": result.parse_status.value,
            "raw_events": len(result.raw_events),
            "flows": len(result.flows),
            "http_events": len(result.http_events),
            "dns_events": len(result.dns_events),
            "evidence": len(result.evidence),
            "errors": result.errors,
        }
    )
