#!/usr/bin/env python3
"""Contest-machine reality check with a secret-free JSON report."""

import importlib.metadata
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def command_output(command: list[str], *, timeout: int = 30) -> tuple[bool, str, float]:
    started = time.perf_counter()
    try:
        result = subprocess.run(
            command, check=False, capture_output=True, text=True, timeout=timeout
        )
        output = (result.stdout or result.stderr).strip()
        return result.returncode == 0, output, round((time.perf_counter() - started) * 1000, 2)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, type(exc).__name__, round((time.perf_counter() - started) * 1000, 2)


def port_available(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def writable(directory: Path) -> bool:
    directory.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.NamedTemporaryFile(prefix="contest-preflight-", dir=directory):
            return True
    except OSError:
        return False


def network_status() -> dict[str, object]:
    result: dict[str, object] = {"internet_required_for_demo": False}
    try:
        socket.getaddrinfo("api.deepseek.com", 443)
        result["dns"] = "AVAILABLE"
    except OSError:
        result["dns"] = "UNAVAILABLE"
    try:
        with socket.create_connection(("1.1.1.1", 443), timeout=2):
            result["outbound_tcp_443"] = "AVAILABLE"
    except OSError:
        result["outbound_tcp_443"] = "UNAVAILABLE"
    result["offline_fallback"] = "DETERMINISTIC_TEST + OFFICIAL + SYNTHETIC + MOCK"
    return result


def main() -> int:
    started = time.perf_counter()
    root = Path(__file__).resolve().parents[1]
    artifacts = root / "artifacts"
    runtime = root / ".runtime"
    manifest_path = artifacts / "official_dataset_manifest.json"
    verified_path = artifacts / "verified_sample_set.json"
    manifest = (
        json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    )
    verified_document = (
        json.loads(verified_path.read_text(encoding="utf-8")) if verified_path.exists() else []
    )
    verified_samples = (
        verified_document.get("samples", [])
        if isinstance(verified_document, dict)
        else verified_document
    )
    screen_ok, screen_text, _ = command_output(["system_profiler", "SPDisplaysDataType"])
    resolutions = [
        line.split("Resolution:", 1)[1].strip()
        for line in screen_text.splitlines()
        if "Resolution:" in line
    ]
    node_ok, node_version, _ = command_output(["node", "--version"])
    npm_ok, npm_version, _ = command_output(["npm", "--version"])
    backend_ok, _, backend_import_ms = command_output(
        [sys.executable, "-c", "import app.main"], timeout=60
    )
    secret_ok, secret_message, secret_ms = command_output(
        [sys.executable, str(root / "scripts" / "secret_scan.py")], timeout=60
    )
    disk = shutil.disk_usage(root)
    browser_cache = Path.home() / "Library" / "Caches" / "ms-playwright"
    browsers = list(browser_cache.glob("chromium-*/chrome-mac*/Google Chrome for Testing.app"))
    model_config = {
        provider: {
            name: bool(os.getenv(name))
            for name in (f"{provider}_API_KEY", f"{provider}_BASE_URL", f"{provider}_MODEL")
        }
        for provider in ("DEEPSEEK", "QWEN")
    }
    port_8000 = port_available(8000)
    port_5173 = port_available(5173)
    db_writable = writable(runtime)
    checks: dict[str, dict[str, object]] = {
        "python": {
            "pass": sys.version_info[:2] == (3, 11),
            "version": platform.python_version(),
        },
        "node": {"pass": node_ok, "version": node_version.strip()},
        "npm": {"pass": npm_ok, "version": npm_version.strip()},
        "dependencies": {
            "pass": backend_ok,
            "fastapi": importlib.metadata.version("fastapi"),
            "pydantic": importlib.metadata.version("pydantic"),
            "sqlalchemy": importlib.metadata.version("sqlalchemy"),
            "langgraph": importlib.metadata.version("langgraph"),
        },
        "ports": {"pass": port_8000 and port_5173, "8000": port_8000, "5173": port_5173},
        "database_paths": {
            "pass": db_writable,
            "business_db_writable": db_writable,
            "checkpoints_db_writable": db_writable,
        },
        "official_manifest": {
            "pass": manifest_path.exists(),
            "path": str(manifest_path),
            "captures": manifest.get("summary", {}).get("total_files"),
        },
        "verified_sample_set": {
            "pass": verified_path.exists() and len(verified_samples) >= 30,
            "path": str(verified_path),
            "samples": len(verified_samples),
        },
        "frontend_build": {
            "pass": (root / "frontend" / "dist" / "index.html").exists(),
            "path": str(root / "frontend" / "dist"),
        },
        "browser": {
            "pass": bool(browsers),
            "engine": "Playwright Chromium",
            "installations": len(browsers),
        },
        "screen": {
            "pass": screen_ok and bool(resolutions),
            "detected_resolutions": resolutions,
            "browser_viewports_to_validate": ["1280x720", "1440x900"],
        },
        "model_config": {
            "pass": any(all(values.values()) for values in model_config.values()),
            "providers": model_config,
            "fallback": "DETERMINISTIC_TEST",
        },
        "network": {"pass": True, **network_status()},
        "disk": {
            "pass": disk.free >= 2 * 1024**3,
            "free_gib": round(disk.free / 1024**3, 2),
            "warning": "LOW" if disk.free < 8 * 1024**3 else None,
        },
        "secret_scan": {
            "pass": secret_ok,
            "result": secret_message.splitlines()[-1] if secret_message else "",
            "duration_ms": secret_ms,
        },
    }
    hard_requirements = [
        "python",
        "node",
        "npm",
        "dependencies",
        "ports",
        "database_paths",
        "official_manifest",
        "verified_sample_set",
        "frontend_build",
        "browser",
        "screen",
        "network",
        "disk",
        "secret_scan",
    ]
    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": "PASS" if all(checks[name]["pass"] for name in hard_requirements) else "FAIL",
        "checks": checks,
        "timings_ms": {
            "backend_cold_import": backend_import_ms,
            "preflight_total": round((time.perf_counter() - started) * 1000, 2),
        },
        "truthful_limitations": [
            "Real-model checks remain BLOCKED_CONFIG when provider variables are absent.",
            "Sangfor integration remains PENDING EXTERNAL INTERFACE.",
            "Network availability is informational; deterministic demo is offline-capable.",
        ],
    }
    output = artifacts / "contest_preflight_report.json"
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
