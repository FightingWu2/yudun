from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field, IPvAnyAddress, StringConstraints, field_validator, model_validator

from app.domain.enums import SourceType
from app.schemas.base import (
    NonEmptyStr,
    Port,
    PositiveCount,
    SafeMetadata,
    Sha256,
    StrictSchema,
    TimestampedSchema,
    UtcDateTime,
    require_prefix,
)


class CaptureFormat(StrEnum):
    PCAP = "PCAP"
    PCAP_NG = "PCAP_NG"
    UNKNOWN = "UNKNOWN"
    BROKEN = "BROKEN"


class CaptureParseStatus(StrEnum):
    PENDING = "PENDING"
    PARSED = "PARSED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class DatasetLocation(StrictSchema):
    dataset: NonEmptyStr
    relative_path: NonEmptyStr

    @field_validator("relative_path")
    @classmethod
    def safe_relative_path(cls, value: str) -> str:
        if value.startswith(("/", "\\")) or ".." in value.replace("\\", "/").split("/"):
            raise ValueError("source path must be a safe relative path")
        return value


class CaptureRecord(TimestampedSchema):
    capture_id: str
    source_type: Literal[SourceType.OFFICIAL]
    source_id: NonEmptyStr
    safe_display_name: NonEmptyStr
    source_location: DatasetLocation
    source_timestamp: UtcDateTime | None = None
    file_sha256: Sha256
    format: CaptureFormat
    file_size: PositiveCount
    packet_count: PositiveCount | None = None
    first_packet_at: UtcDateTime | None = None
    last_packet_at: UtcDateTime | None = None
    parser_version: NonEmptyStr
    parse_status: CaptureParseStatus
    parse_error: str | None = None

    @field_validator("capture_id")
    @classmethod
    def validate_capture_id(cls, value: str) -> str:
        return require_prefix(value, "cap")

    @model_validator(mode="after")
    def validate_packet_window(self) -> "CaptureRecord":
        if (
            self.first_packet_at
            and self.last_packet_at
            and self.first_packet_at > self.last_packet_at
        ):
            raise ValueError("first_packet_at must not be after last_packet_at")
        if self.parse_status is CaptureParseStatus.FAILED and not self.parse_error:
            raise ValueError("failed capture requires parse_error")
        return self


class EventKind(StrEnum):
    PACKET = "PACKET"
    NETWORK = "NETWORK"
    HTTP = "HTTP"
    DNS = "DNS"
    CI = "CI"
    SECRET_ACCESS = "SECRET_ACCESS"
    CREDENTIAL_EXPOSURE = "CREDENTIAL_EXPOSURE"
    CLOUD_API = "CLOUD_API"
    RESOURCE_ACCESS = "RESOURCE_ACCESS"
    RESOURCE_OPERATION = "RESOURCE_OPERATION"
    MOCK_STATE = "MOCK_STATE"


class TransportProtocol(StrEnum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    OTHER = "OTHER"


class ApplicationProtocol(StrEnum):
    HTTP = "HTTP"
    DNS = "DNS"
    TLS = "TLS"
    TDS = "TDS"
    MYSQL = "MYSQL"
    ORACLE = "ORACLE"
    UNKNOWN = "UNKNOWN"


class EventParseStatus(StrEnum):
    PARSED = "PARSED"
    PARTIAL = "PARTIAL"
    OPAQUE = "OPAQUE"
    FAILED = "FAILED"


class RedactionStatus(StrEnum):
    NOT_REQUIRED = "NOT_REQUIRED"
    REDACTED = "REDACTED"
    RESTRICTED = "RESTRICTED"


class GenericSourceLocation(StrictSchema):
    dataset: NonEmptyStr
    record_ref: NonEmptyStr
    field_path: str | None = None


class PayloadReference(StrictSchema):
    object_ref: NonEmptyStr
    byte_offset: PositiveCount | None = None
    byte_length: PositiveCount | None = None


class RawEvent(TimestampedSchema):
    event_id: str
    capture_id: str | None = None
    source_type: Literal[SourceType.OFFICIAL, SourceType.SYNTHETIC, SourceType.MOCK]
    source_id: NonEmptyStr
    source_location: GenericSourceLocation
    source_timestamp: UtcDateTime
    ingested_at: UtcDateTime
    event_kind: EventKind
    src_ip: IPvAnyAddress | None = None
    dst_ip: IPvAnyAddress | None = None
    src_port: Port | None = None
    dst_port: Port | None = None
    transport_protocol: TransportProtocol | None = None
    application_protocol: ApplicationProtocol | None = None
    payload_reference: PayloadReference | None = None
    payload_sha256: Sha256 | None = None
    parser_version: NonEmptyStr
    parse_status: EventParseStatus
    redaction_status: RedactionStatus
    attributes: SafeMetadata = Field(default_factory=dict)
    supersedes_event_id: str | None = None

    @field_validator("event_id")
    @classmethod
    def validate_event_id(cls, value: str) -> str:
        return require_prefix(value, "raw")

    @model_validator(mode="after")
    def validate_capture_source(self) -> "RawEvent":
        if self.source_type is SourceType.OFFICIAL and self.capture_id is None:
            raise ValueError("OFFICIAL RawEvent requires capture_id")
        if self.capture_id is not None:
            require_prefix(self.capture_id, "cap")
        return self


class FlowSourceLocation(StrictSchema):
    capture_id: str
    first_packet_index: Annotated[int, Field(ge=1)]
    last_packet_index: Annotated[int, Field(ge=1)]

    @model_validator(mode="after")
    def validate_range(self) -> "FlowSourceLocation":
        require_prefix(self.capture_id, "cap")
        if self.first_packet_index > self.last_packet_index:
            raise ValueError("invalid packet index range")
        return self


class FiveTuple(StrictSchema):
    initiator_ip: IPvAnyAddress
    initiator_port: Port
    responder_ip: IPvAnyAddress
    responder_port: Port
    protocol: Literal[TransportProtocol.TCP, TransportProtocol.UDP]


class FlowDirection(StrEnum):
    INITIATOR_TO_RESPONDER = "INITIATOR_TO_RESPONDER"
    RESPONDER_TO_INITIATOR = "RESPONDER_TO_INITIATOR"
    BIDIRECTIONAL = "BIDIRECTIONAL"


class TcpSummary(StrictSchema):
    syn_seen: bool = False
    fin_seen: bool = False
    rst_seen: bool = False


class NetworkFlow(TimestampedSchema):
    flow_id: str
    capture_id: str
    source_type: Literal[SourceType.OFFICIAL]
    source_id: NonEmptyStr
    source_location: FlowSourceLocation
    source_timestamp: UtcDateTime
    five_tuple: FiveTuple
    start_time: UtcDateTime
    end_time: UtcDateTime
    packet_count: PositiveCount
    byte_count: PositiveCount
    direction: FlowDirection
    application_protocol: ApplicationProtocol
    raw_event_ids: list[str] = Field(min_length=1)
    tcp_summary: TcpSummary | None = None
    parser_version: NonEmptyStr

    @model_validator(mode="after")
    def validate_flow(self) -> "NetworkFlow":
        require_prefix(self.flow_id, "flw")
        require_prefix(self.capture_id, "cap")
        if self.source_location.capture_id != self.capture_id:
            raise ValueError("source_location capture_id mismatch")
        if self.start_time > self.end_time:
            raise ValueError("flow start_time must not be after end_time")
        for event_id in self.raw_event_ids:
            require_prefix(event_id, "raw")
        return self


PacketRange = Annotated[tuple[int, int], Field(min_length=2, max_length=2)]


class HttpMethod(StrEnum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    OTHER = "OTHER"


class HttpParseStatus(StrEnum):
    COMPLETE = "COMPLETE"
    REQUEST_ONLY = "REQUEST_ONLY"
    PARTIAL = "PARTIAL"
    OPAQUE = "OPAQUE"


class HTTPEvent(TimestampedSchema):
    http_event_id: str
    flow_id: str
    capture_id: str
    source_type: Literal[SourceType.OFFICIAL]
    source_id: NonEmptyStr
    source_location: FlowSourceLocation
    source_timestamp: UtcDateTime
    request_packet_range: PacketRange
    response_packet_range: PacketRange | None = None
    method: HttpMethod
    scheme: Literal["http", "unknown"]
    host: str | None = None
    uri_path: NonEmptyStr
    query_keys: list[str] = Field(default_factory=list)
    sanitized_query: str | None = None
    headers_redacted: SafeMetadata = Field(default_factory=dict)
    body_reference: PayloadReference | None = None
    body_sha256: Sha256 | None = None
    status_code: Annotated[int, Field(ge=100, le=599)] | None = None
    response_headers_redacted: SafeMetadata = Field(default_factory=dict)
    response_reference: PayloadReference | None = None
    parse_status: HttpParseStatus
    parser_version: NonEmptyStr

    @model_validator(mode="after")
    def validate_http_event(self) -> "HTTPEvent":
        require_prefix(self.http_event_id, "raw")
        require_prefix(self.flow_id, "flw")
        require_prefix(self.capture_id, "cap")
        for packet_range in (self.request_packet_range, self.response_packet_range):
            if packet_range is not None and (
                packet_range[0] < 1 or packet_range[0] > packet_range[1]
            ):
                raise ValueError("invalid HTTP packet range")
        return self


class DnsQueryType(StrEnum):
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    TXT = "TXT"
    MX = "MX"
    NS = "NS"
    PTR = "PTR"
    OTHER = "OTHER"


class DnsParseStatus(StrEnum):
    QUERY_ONLY = "QUERY_ONLY"
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"


class DNSEvent(TimestampedSchema):
    dns_event_id: str
    flow_id: str
    capture_id: str
    source_type: Literal[SourceType.OFFICIAL]
    source_id: NonEmptyStr
    source_location: FlowSourceLocation
    source_timestamp: UtcDateTime
    src_ip: IPvAnyAddress
    src_port: Port
    dns_server: IPvAnyAddress
    query_id: Annotated[int, Field(ge=0, le=65535)]
    query_name: Annotated[
        str, StringConstraints(strip_whitespace=True, min_length=1, max_length=253)
    ]
    query_type: DnsQueryType
    response_codes: list[str] = Field(default_factory=list)
    answers_redacted: list[str] = Field(default_factory=list)
    packet_indexes: list[Annotated[int, Field(ge=1)]] = Field(min_length=1)
    parse_status: DnsParseStatus
    parser_version: NonEmptyStr

    @model_validator(mode="after")
    def validate_dns_event(self) -> "DNSEvent":
        require_prefix(self.dns_event_id, "raw")
        require_prefix(self.flow_id, "flw")
        require_prefix(self.capture_id, "cap")
        return self
