import json
import os
import time
from dataclasses import dataclass
from typing import Protocol, TypeVar

import httpx
from pydantic import BaseModel, ValidationError

from app.core.errors import DomainError, ErrorCode

OutputT = TypeVar("OutputT", bound=BaseModel)


@dataclass(frozen=True, slots=True)
class ModelCallMetadata:
    provider: str
    model_id: str
    latency_ms: float
    status: str
    error_type: str | None = None


class ModelAdapter(Protocol):
    provider: str
    model_id: str

    def structured(
        self,
        *,
        prompt_version: str,
        system_instruction: str,
        input_payload: dict[str, object],
        output_type: type[OutputT],
    ) -> tuple[OutputT, ModelCallMetadata]: ...


class DeterministicTestModel:
    provider = "DETERMINISTIC_TEST"
    model_id = "fixture-structured-v1"

    def __init__(self, responses: dict[str, dict[str, object]], *, fail: str | None = None) -> None:
        self._responses = responses
        self._fail = fail

    def structured(
        self,
        *,
        prompt_version: str,
        system_instruction: str,
        input_payload: dict[str, object],
        output_type: type[OutputT],
    ) -> tuple[OutputT, ModelCallMetadata]:
        del system_instruction, input_payload
        started = time.perf_counter()
        if self._fail == "TIMEOUT":
            raise DomainError(ErrorCode.TIMEOUT, "deterministic model timeout")
        raw = self._responses.get(prompt_version)
        if raw is None:
            raise DomainError(ErrorCode.SCHEMA_INVALID, "no deterministic response configured")
        try:
            output = output_type.model_validate(raw)
        except ValidationError as exc:
            raise DomainError(ErrorCode.SCHEMA_INVALID, "model output failed schema") from exc
        return output, ModelCallMetadata(
            provider=self.provider,
            model_id=self.model_id,
            latency_ms=(time.perf_counter() - started) * 1000,
            status="SUCCEEDED",
        )


class OpenAICompatibleModelAdapter:
    """Minimal DeepSeek/Qwen-compatible adapter; credentials never enter payload or logs."""

    def __init__(self, *, provider: str, base_url: str, api_key: str, model_id: str) -> None:
        if not api_key:
            raise ValueError("api_key is required")
        self.provider = provider
        self.model_id = model_id
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key

    @classmethod
    def from_environment(cls, provider: str) -> "OpenAICompatibleModelAdapter | None":
        prefix = provider.upper()
        key = os.getenv(f"{prefix}_API_KEY")
        base_url = os.getenv(f"{prefix}_BASE_URL")
        model = os.getenv(f"{prefix}_MODEL")
        if not all((key, base_url, model)):
            return None
        return cls(provider=prefix, base_url=base_url, api_key=key, model_id=model)  # type: ignore[arg-type]

    def structured(
        self,
        *,
        prompt_version: str,
        system_instruction: str,
        input_payload: dict[str, object],
        output_type: type[OutputT],
    ) -> tuple[OutputT, ModelCallMetadata]:
        started = time.perf_counter()
        schema = output_type.model_json_schema()
        request = {
            "model": self.model_id,
            "messages": [
                {"role": "system", "content": system_instruction},
                {
                    "role": "user",
                    "content": json.dumps(
                        {"prompt_version": prompt_version, "input": input_payload},
                        ensure_ascii=False,
                    ),
                },
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": output_type.__name__, "schema": schema},
            },
        }
        try:
            response = httpx.post(
                f"{self._base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self._api_key}"},
                json=request,
                timeout=30,
            )
            response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"]
            output = output_type.model_validate_json(content)
        except httpx.TimeoutException as exc:
            raise DomainError(ErrorCode.TIMEOUT, "model endpoint timeout") from exc
        except (httpx.HTTPError, KeyError, TypeError, ValidationError, ValueError) as exc:
            raise DomainError(
                ErrorCode.SCHEMA_INVALID, "model response unavailable or invalid"
            ) from exc
        return output, ModelCallMetadata(
            provider=self.provider,
            model_id=self.model_id,
            latency_ms=(time.perf_counter() - started) * 1000,
            status="SUCCEEDED",
        )
