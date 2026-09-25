"""
Rate-limiting behaviour (429 + Retry-After header).

The production API mounts UserRateThrottle on vault routes; to keep this test
fast and hermetic we probe a dedicated endpoint with a 5-per-minute ceiling
so the 429 triggers after exactly six requests. The Django cache is cleared
up-front so throttle history from earlier tests cannot leak in.
"""

import logging

from django.core.cache import cache
from ninja import NinjaAPI, Router
from ninja.testing import TestClient
from ninja.throttling import AnonRateThrottle

logger = logging.getLogger(__name__)


def test_throttle_returns_429_with_retry_after():
    """The 6th request inside the window must yield 429 + Retry-After."""

    probe = Router()

    @probe.get("/probe", auth=None, throttle=AnonRateThrottle("5/m"))
    def _probe(request):
        return {"ok": True}

    api = NinjaAPI(urls_namespace=f"throttle-probe-{id(probe)}")
    api.add_router("probe", probe)
    client = TestClient(api)

    cache.clear()  # isolate this test from any prior throttle history

    for _ in range(5):
        assert client.get("/probe/probe").status_code == 200

    blocked = client.get("/probe/probe")
    assert blocked.status_code == 429
    assert "Too many requests" in blocked.content.decode()
    retry_after = blocked.headers.get("Retry-After")
    assert retry_after is not None and int(retry_after) > 0
