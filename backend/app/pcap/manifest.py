import hashlib
import re
from datetime import UTC, datetime
from pathlib import Path

import dpkt
from pydantic import Field

from app.core.ids import source_derived_id
from app.core.time import utc_now
from app.domain.enums import SourceType
from app.schemas.base import StrictSchema, UtcDateTime
from app.schemas.data import (
    CaptureFormat,
    CaptureParseStatus,
    CaptureRecord,
    DatasetLocation,
)

MANIFEST_VERSION = "1.0"
MANIFEST_PARSER_VERSION = "manifest-1.0"
_PCAP_MAGICS = {
    bytes.fromhex("d4c3b2a1"),
    bytes.fromhex("a1b2c3d4"),
    bytes.fromhex("4d3cb2a1"),
    bytes.fromhex("a1b23c4d"),
}
_PCAPNG_MAGIC = bytes.fromhex("0a0d0d0a")
_OPAQUE_NAME = re.compile(r"^(?:[0-9a-f]{32}|\d+)\.json\.pcap$", re.IGNORECASE)
_UNSAFE_DISPLAY = re.compile(r"[\x00-\x1f\x7f/\\]")


class ManifestSummary(StrictSchema):
    total_files: int = Field(ge=0)
    pcap_files: int = Field(ge=0)
    pcapng_files: int = Field(ge=0)
    unknown_files: int = Field(ge=0)
    broken_files: int = Field(ge=0)
    total_bytes: int = Field(ge=0)
    total_packets: int = Field(ge=0)


class OfficialDatasetManifest(StrictSchema):
    manifest_version: str = MANIFEST_VERSION
    dataset_alias: str = "official_nta"
    generated_at: UtcDateTime = Field(default_factory=utc_now)
    parser_version: str = MANIFEST_PARSER_VERSION
    entries: list[CaptureRecord]
    summary: ManifestSummary


def detect_capture_format(path: Path) -> CaptureFormat:
    try:
        with path.open("rb") as handle:
            magic = handle.read(4)
    except OSError:
        return CaptureFormat.BROKEN
    if len(magic) < 4:
        return CaptureFormat.BROKEN
    if magic in _PCAP_MAGICS:
        return CaptureFormat.PCAP
    if magic == _PCAPNG_MAGIC:
        return CaptureFormat.PCAP_NG
    return CaptureFormat.UNKNOWN


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_path(dataset_root: Path, candidate: Path) -> tuple[Path, str]:
    root = dataset_root.resolve(strict=True)
    resolved = candidate.resolve(strict=True)
    try:
        relative = resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("capture path is outside the official dataset root") from exc
    if not resolved.is_file():
        raise ValueError("capture path must be a file")
    return resolved, relative.as_posix()


def _packet_metadata(
    path: Path, capture_format: CaptureFormat
) -> tuple[int, datetime | None, datetime | None]:
    reader_type = dpkt.pcap.Reader if capture_format is CaptureFormat.PCAP else dpkt.pcapng.Reader
    packet_count = 0
    first: datetime | None = None
    last: datetime | None = None
    with path.open("rb") as handle:
        reader = reader_type(handle)
        for timestamp, _packet in reader:
            observed = datetime.fromtimestamp(float(timestamp), tz=UTC)
            first = observed if first is None else first
            last = observed
            packet_count += 1
    return packet_count, first, last


def scan_capture(dataset_root: Path, candidate: Path) -> CaptureRecord:
    path, relative_path = _safe_path(dataset_root, candidate)
    file_hash = sha256_file(path)
    capture_format = detect_capture_format(path)
    parse_status = CaptureParseStatus.PENDING
    parse_error: str | None = None
    packet_count: int | None = None
    first_packet_at: datetime | None = None
    last_packet_at: datetime | None = None
    if capture_format in {CaptureFormat.PCAP, CaptureFormat.PCAP_NG}:
        try:
            packet_count, first_packet_at, last_packet_at = _packet_metadata(path, capture_format)
        except (ValueError, dpkt.dpkt.Error, OSError) as exc:
            capture_format = CaptureFormat.BROKEN
            parse_status = CaptureParseStatus.FAILED
            parse_error = f"{type(exc).__name__}: {exc}"[:500]
    else:
        parse_status = CaptureParseStatus.FAILED
        parse_error = "unsupported or truncated capture magic"

    weak_hint = None if _OPAQUE_NAME.fullmatch(path.name) else path.name
    return CaptureRecord(
        capture_id=source_derived_id("cap", {"file_sha256": file_hash}, MANIFEST_PARSER_VERSION),
        source_type=SourceType.OFFICIAL,
        source_id=path.name,
        safe_display_name=_UNSAFE_DISPLAY.sub("_", path.name),
        source_location=DatasetLocation(dataset="official_nta", relative_path=relative_path),
        file_sha256=file_hash,
        format=capture_format,
        file_size=path.stat().st_size,
        packet_count=packet_count,
        first_packet_at=first_packet_at,
        last_packet_at=last_packet_at,
        parser_version=MANIFEST_PARSER_VERSION,
        parse_status=parse_status,
        parse_error=parse_error,
        metadata={"weak_label_hint": weak_hint} if weak_hint else {},
    )


def build_manifest(dataset_root: Path) -> OfficialDatasetManifest:
    root = dataset_root.resolve(strict=True)
    entries = [scan_capture(root, path) for path in sorted(root.rglob("*")) if path.is_file()]
    summary = ManifestSummary(
        total_files=len(entries),
        pcap_files=sum(entry.format is CaptureFormat.PCAP for entry in entries),
        pcapng_files=sum(entry.format is CaptureFormat.PCAP_NG for entry in entries),
        unknown_files=sum(entry.format is CaptureFormat.UNKNOWN for entry in entries),
        broken_files=sum(entry.format is CaptureFormat.BROKEN for entry in entries),
        total_bytes=sum(entry.file_size for entry in entries),
        total_packets=sum(entry.packet_count or 0 for entry in entries),
    )
    return OfficialDatasetManifest(entries=entries, summary=summary)
