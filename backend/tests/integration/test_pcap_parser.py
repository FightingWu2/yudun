from pathlib import Path

import dpkt
from app.pcap.manifest import scan_capture
from app.pcap.parser import evidence_packet_bytes, normalize_capture
from app.schemas.data import ApplicationProtocol, CaptureFormat


def _ethernet(payload: object, *, protocol: int) -> bytes:
    ip = dpkt.ip.IP(
        src=b"\xc0\x00\x02\x01",
        dst=b"\xc6\x33\x64\x01",
        p=protocol,
        data=payload,
    )
    ip.len = len(ip)
    return bytes(
        dpkt.ethernet.Ethernet(
            src=b"\x00\x01\x02\x03\x04\x05",
            dst=b"\x06\x07\x08\x09\x0a\x0b",
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip,
        )
    )


def _write_fixture(path: Path, *, pcapng: bool = False) -> None:
    request = dpkt.tcp.TCP(
        sport=34567,
        dport=80,
        seq=1,
        flags=dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK,
        data=(
            b"GET /search?q=test&api_key=never-store-this HTTP/1.1\r\n"
            b"Host: example.test\r\nAuthorization: Bearer never-store-this\r\n\r\n"
        ),
    )
    dns = dpkt.dns.DNS(
        id=7,
        qd=[dpkt.dns.DNS.Q(name="probe.example.test", type=dpkt.dns.DNS_A)],
    )
    udp = dpkt.udp.UDP(sport=45678, dport=53, data=bytes(dns))
    udp.ulen = len(udp)
    writer_type = dpkt.pcapng.Writer if pcapng else dpkt.pcap.Writer
    with path.open("wb") as handle:
        writer = writer_type(handle)
        writer.writepkt(_ethernet(request, protocol=dpkt.ip.IP_PROTO_TCP), ts=1_700_000_000)
        writer.writepkt(_ethernet(udp, protocol=dpkt.ip.IP_PROTO_UDP), ts=1_700_000_001)
        writer.close()


def test_normalize_http_dns_flow_evidence_and_redaction(tmp_path: Path) -> None:
    path = tmp_path / "fixture.pcap"
    _write_fixture(path)
    capture = scan_capture(tmp_path, path)
    result = normalize_capture(capture, path)

    assert len(result.raw_events) == 2
    assert {flow.application_protocol for flow in result.flows} == {
        ApplicationProtocol.HTTP,
        ApplicationProtocol.DNS,
    }
    assert len(result.http_events) == 1
    assert len(result.dns_events) == 1
    http = result.http_events[0]
    assert "never-store-this" not in http.model_dump_json()
    assert "api_key=[REDACTED]" in (http.sanitized_query or "")
    assert result.dns_events[0].query_name == "probe.example.test"
    packet_bytes = evidence_packet_bytes(result.evidence[0], path, capture.format.value)
    assert packet_bytes and packet_bytes[0]
    assert result.evidence[0].locator.capture_id == capture.capture_id


def test_pcapng_normalization_uses_magic_not_suffix(tmp_path: Path) -> None:
    path = tmp_path / "misleading.pcap"
    _write_fixture(path, pcapng=True)
    capture = scan_capture(tmp_path, path)
    result = normalize_capture(capture, path)
    assert capture.format is CaptureFormat.PCAP_NG
    assert result.http_events and result.dns_events


def test_flow_id_is_capture_scoped(tmp_path: Path) -> None:
    first = tmp_path / "first.pcap"
    second = tmp_path / "second.pcap"
    _write_fixture(first)
    _write_fixture(second)
    # Make content identity different while preserving the same five-tuple and valid framing.
    second.write_bytes(second.read_bytes().replace(b"example.test", b"examplf.test"))
    one = normalize_capture(scan_capture(tmp_path, first), first)
    two = normalize_capture(scan_capture(tmp_path, second), second)
    assert {flow.flow_id for flow in one.flows}.isdisjoint(flow.flow_id for flow in two.flows)


def test_real_official_representatives_are_traceable() -> None:
    root = Path("data/测评中心基线样本nta")
    for name in ("sql注入.pcap", "jsp.pcap"):
        path = root / name
        capture = scan_capture(root, path)
        result = normalize_capture(capture, path)
        assert result.raw_events
        assert result.flows
        assert result.http_events
        assert all(item.locator.capture_id == capture.capture_id for item in result.evidence)
        assert all(
            evidence_packet_bytes(item, path, capture.format.value) for item in result.evidence
        )
