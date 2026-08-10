import asyncio

from app.main import app
from httpx import ASGITransport, AsyncClient


async def request_health() -> tuple[int, dict[str, str]]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")
    return response.status_code, response.json()


def test_health() -> None:
    status_code, payload = asyncio.run(request_health())
    assert status_code == 200
    assert payload == {"status": "ok"}
