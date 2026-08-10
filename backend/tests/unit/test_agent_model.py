import json

import httpx
import pytest
from app.agents.contracts import InvestigationModelOutput
from app.agents.model import DeterministicTestModel, OpenAICompatibleModelAdapter
from app.core.errors import DomainError, ErrorCode


def _output() -> dict[str, object]:
    return {
        "statement": "Evidence-backed fixture finding.",
        "evidence_refs": ["evd_fixture"],
        "confidence_level": "HIGH",
        "limitations": [],
        "unresolved_questions": [],
        "proposed_fact_types": [],
    }


def test_deterministic_model_returns_schema_validated_output() -> None:
    model = DeterministicTestModel({"investigation-v1": _output()})
    output, metadata = model.structured(
        prompt_version="investigation-v1",
        system_instruction="fixture",
        input_payload={},
        output_type=InvestigationModelOutput,
    )
    assert output.statement == "Evidence-backed fixture finding."
    assert metadata.provider == "DETERMINISTIC_TEST"


def test_openai_compatible_adapter_validates_structured_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_post(*args: object, **kwargs: object) -> httpx.Response:
        captured.update(kwargs)
        request = httpx.Request("POST", str(args[0]))
        return httpx.Response(
            200,
            request=request,
            json={"choices": [{"message": {"content": json.dumps(_output())}}]},
        )

    monkeypatch.setattr(httpx, "post", fake_post)
    adapter = OpenAICompatibleModelAdapter(
        provider="DEEPSEEK",
        base_url="https://model.invalid",
        api_key="fixture-runtime-only-key",
        model_id="fixture-model",
    )
    output, metadata = adapter.structured(
        prompt_version="investigation-v1",
        system_instruction="fixture",
        input_payload={"incident_id": "inc_fixture"},
        output_type=InvestigationModelOutput,
    )
    assert output.confidence_level.value == "HIGH"
    assert metadata.status == "SUCCEEDED"
    request_json = captured["json"]
    assert "fixture-runtime-only-key" not in json.dumps(request_json)


def test_openai_compatible_adapter_rejects_invalid_model_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_post(*args: object, **kwargs: object) -> httpx.Response:
        del kwargs
        request = httpx.Request("POST", str(args[0]))
        return httpx.Response(
            200,
            request=request,
            json={"choices": [{"message": {"content": "not-json"}}]},
        )

    monkeypatch.setattr(httpx, "post", fake_post)
    adapter = OpenAICompatibleModelAdapter(
        provider="QWEN",
        base_url="https://model.invalid",
        api_key="fixture-runtime-only-key",
        model_id="fixture-model",
    )
    with pytest.raises(DomainError) as captured:
        adapter.structured(
            prompt_version="investigation-v1",
            system_instruction="fixture",
            input_payload={},
            output_type=InvestigationModelOutput,
        )
    assert captured.value.code is ErrorCode.SCHEMA_INVALID
