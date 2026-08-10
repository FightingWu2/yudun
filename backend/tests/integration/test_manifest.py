from pathlib import Path

import dpkt
import pytest
from app.pcap.manifest import build_manifest, detect_capture_format, scan_capture, sha256_file
from app.schemas.data import CaptureFormat


def ethernet_packet() -> bytes:
    tcp = dpkt.tcp.TCP(sport=12345, dport=80, seq=1, flags=dpkt.tcp.TH_ACK)
    tcp.data = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"
    ip = dpkt.ip.IP(src=b"\xc0\x00\x02\x01", dst=b"\xc6\x33\x64\x01", p=dpkt.ip.IP_PROTO_TCP)
    ip.data = tcp
    ip.len = len(ip)
    ethernet = dpkt.ethernet.Ethernet(
        src=b"\x00\x01\x02\x03\x04\x05",
        dst=b"\x06\x07\x08\x09\x0a\x0b",
        type=dpkt.ethernet.ETH_TYPE_IP,
        data=ip,
    )
    return bytes(ethernet)


def write_capture(path: Path, *, pcapng: bool = False) -> None:
    writer_type = dpkt.pcapng.Writer if pcapng else dpkt.pcap.Writer
    with path.open("wb") as handle:
        writer = writer_type(handle)
        writer.writepkt(ethernet_packet(), ts=1_700_000_000.0)
        writer.close()


def test_magic_detection_ignores_extension(tmp_path: Path) -> None:
    disguised = tmp_path / "sample.json.pcap"
    write_capture(disguised)
    pcapng = tmp_path / "sample.pcap"
    write_capture(pcapng, pcapng=True)
    unknown = tmp_path / "unknown.pcap"
    unknown.write_bytes(b"NOT_A_CAPTURE")
    broken = tmp_path / "broken.pcap"
    broken.write_bytes(b"\x00\x01")

    assert detect_capture_format(disguised) is CaptureFormat.PCAP
    assert detect_capture_format(pcapng) is CaptureFormat.PCAP_NG
    assert detect_capture_format(unknown) is CaptureFormat.UNKNOWN
    assert detect_capture_format(broken) is CaptureFormat.BROKEN


def test_scan_is_reproducible_and_filename_is_only_weak_hint(tmp_path: Path) -> None:
    capture_path = tmp_path / "SQL注入.json.pcap"
    write_capture(capture_path)
    first = scan_capture(tmp_path, capture_path)
    second = scan_capture(tmp_path, capture_path)

    assert first.capture_id == second.capture_id
    assert first.file_sha256 == second.file_sha256 == sha256_file(capture_path)
    assert first.packet_count == 1
    assert first.metadata == {"weak_label_hint": "SQL注入.json.pcap"}
    assert "ground_truth" not in first.model_dump()
    assert "fact" not in first.model_dump()


def test_manifest_summary_counts_formats_and_packets(tmp_path: Path) -> None:
    write_capture(tmp_path / "classic.pcap")
    write_capture(tmp_path / "nextgen.pcap", pcapng=True)
    (tmp_path / "unknown.bin").write_bytes(b"UNKNOWN_DATA")
    (tmp_path / "broken.bin").write_bytes(b"\x00")

    manifest = build_manifest(tmp_path)
    assert manifest.summary.total_files == 4
    assert manifest.summary.pcap_files == 1
    assert manifest.summary.pcapng_files == 1
    assert manifest.summary.unknown_files == 1
    assert manifest.summary.broken_files == 1
    assert manifest.summary.total_packets == 2


def test_path_outside_dataset_is_rejected(tmp_path: Path) -> None:
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    outside = tmp_path / "outside.pcap"
    write_capture(outside)
    with pytest.raises(ValueError, match="outside"):
        scan_capture(dataset, outside)


def test_real_official_pcapng_and_json_pcap_are_detected() -> None:
    root = Path("data/测评中心基线样本nta")
    assert detect_capture_format(root / "jsp.pcap") is CaptureFormat.PCAP_NG
    json_named = next(root.glob("*.json.pcap"))
    assert detect_capture_format(json_named) is CaptureFormat.PCAP
