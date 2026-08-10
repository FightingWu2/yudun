from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import router
from app.api.schemas import ApiError
from app.application.demo import DemoRuntime
from app.core.errors import DomainError, ErrorCode


def create_app(runtime: DemoRuntime | None = None) -> FastAPI:
    application = FastAPI(title="御盾智核", version="0.2.0")
    application.state.demo_runtime = runtime or DemoRuntime(Path.cwd())
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "X-Demo-Role"],
    )

    @application.exception_handler(DomainError)
    async def domain_error(_request: Request, exc: DomainError) -> JSONResponse:
        status = {
            ErrorCode.PERMISSION_DENIED: 403,
            ErrorCode.NOT_FOUND: 404,
            ErrorCode.CONFLICT: 409,
            ErrorCode.SCHEMA_INVALID: 422,
            ErrorCode.SOURCE_UNAVAILABLE: 422,
            ErrorCode.TIMEOUT: 504,
            ErrorCode.EVIDENCE_REQUIRED: 422,
            ErrorCode.INVALID_STATE_TRANSITION: 409,
        }[exc.code]
        payload = ApiError(
            code=exc.code.value,
            message=exc.message,
            retryable=exc.retryable,
        )
        return JSONResponse(status_code=status, content=payload.model_dump(mode="json"))

    @application.exception_handler(RequestValidationError)
    async def request_validation_error(
        _request: Request, _exc: RequestValidationError
    ) -> JSONResponse:
        payload = ApiError(
            code=ErrorCode.SCHEMA_INVALID.value,
            message="request schema validation failed",
        )
        return JSONResponse(status_code=422, content=payload.model_dump(mode="json"))

    @application.get("/health", tags=["system"])
    def health() -> dict[str, str]:
        return {"status": "ok"}

    application.include_router(router)
    return application


app = create_app()
