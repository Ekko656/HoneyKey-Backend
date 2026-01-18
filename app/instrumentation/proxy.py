"""
API Proxy Layer for transparent request forwarding with instrumentation.

This module provides the core proxy functionality that:
1. Accepts incoming requests
2. Captures telemetry
3. Forwards to the real API unchanged
4. Returns responses verbatim
5. Classifies behavior
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Optional
from urllib.parse import urljoin

import httpx

from .classifier import (
    Classification,
    ClassificationResult,
    RequestContext,
    classify_request,
)
from .telemetry import (
    TelemetryRecord,
    capture_request,
    capture_response,
    create_telemetry_record,
    generate_request_id,
)


@dataclass
class ProxyConfig:
    """
    Configuration for an API proxy instance.

    Attributes:
        name: Identifier for this proxy (e.g., "stripe", "openai")
        target_base_url: Base URL of the target API
        timeout_seconds: Request timeout in seconds
        max_retries: Maximum retry attempts for failed requests
        verify_ssl: Whether to verify SSL certificates
    """
    name: str
    target_base_url: str
    timeout_seconds: float = 30.0
    max_retries: int = 0
    verify_ssl: bool = True


@dataclass
class ProxyResponse:
    """
    Response from the proxy layer.

    Contains both the actual API response and instrumentation data.
    """
    status_code: int
    headers: dict[str, str]
    body: bytes
    telemetry: TelemetryRecord
    classification: ClassificationResult

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary (excludes body for logging)."""
        return {
            "status_code": self.status_code,
            "headers": dict(self.headers),
            "body_size": len(self.body),
            "telemetry": self.telemetry.to_dict(),
            "classification": self.classification.to_dict(),
        }


# Type alias for telemetry callback
TelemetryCallback = Callable[[TelemetryRecord, ClassificationResult], None]


class APIProxy:
    """
    Transparent API proxy with instrumentation.

    This class wraps a target API and:
    - Forwards all requests unchanged
    - Captures comprehensive telemetry
    - Classifies request behavior
    - Optionally calls a callback with telemetry data

    Example:
        proxy = APIProxy(ProxyConfig(
            name="stripe",
            target_base_url="https://api.stripe.com",
        ))

        response = await proxy.forward(
            method="GET",
            path="/v1/charges",
            headers={"Authorization": "Bearer sk_test_..."},
            source_ip="192.168.1.1",
        )
    """

    def __init__(
        self,
        config: ProxyConfig,
        telemetry_callback: Optional[TelemetryCallback] = None,
        context_provider: Optional[Callable[[str], RequestContext]] = None,
    ):
        """
        Initialize the API proxy.

        Args:
            config: Proxy configuration
            telemetry_callback: Optional callback invoked with telemetry after each request
            context_provider: Optional function to get RequestContext for a source IP
        """
        self.config = config
        self.telemetry_callback = telemetry_callback
        self.context_provider = context_provider

        # Configure httpx client
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(config.timeout_seconds),
            verify=config.verify_ssl,
            follow_redirects=False,  # Let caller handle redirects
        )

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()

    async def __aenter__(self) -> "APIProxy":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    def _build_target_url(self, path: str) -> str:
        """Construct the full target URL."""
        # Ensure path starts with /
        if not path.startswith("/"):
            path = "/" + path
        return urljoin(self.config.target_base_url, path)

    def _prepare_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """
        Prepare headers for forwarding.

        Removes hop-by-hop headers that shouldn't be forwarded.
        """
        hop_by_hop = {
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailers",
            "transfer-encoding",
            "upgrade",
            "host",  # Will be set by httpx
        }

        return {
            k: v for k, v in headers.items()
            if k.lower() not in hop_by_hop
        }

    async def forward(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        source_ip: str,
        query_params: Optional[dict[str, str]] = None,
        body: Optional[bytes] = None,
    ) -> ProxyResponse:
        """
        Forward a request to the target API.

        This method:
        1. Captures request telemetry
        2. Forwards the request unchanged to the target
        3. Captures response telemetry
        4. Classifies the behavior
        5. Invokes telemetry callback if configured
        6. Returns both the response and instrumentation data

        Args:
            method: HTTP method (GET, POST, etc.)
            path: Request path (e.g., /v1/charges)
            headers: Request headers (forwarded as-is)
            source_ip: Client's IP address
            query_params: URL query parameters
            body: Request body

        Returns:
            ProxyResponse containing response data and instrumentation
        """
        request_id = generate_request_id()

        # Capture request telemetry
        request_telemetry = capture_request(
            request_id=request_id,
            source_ip=source_ip,
            method=method,
            path=path,
            headers=headers,
            query_params=query_params,
            body=body,
        )

        # Build target URL
        target_url = self._build_target_url(path)

        # Prepare headers for forwarding
        forward_headers = self._prepare_headers(headers)

        # Forward the request
        start_time = time.perf_counter()
        try:
            response = await self._client.request(
                method=method,
                url=target_url,
                headers=forward_headers,
                params=query_params,
                content=body,
            )
            response_body = response.content
            status_code = response.status_code
            response_headers = dict(response.headers)

        except httpx.TimeoutException:
            # Timeout - return 504
            latency_ms = (time.perf_counter() - start_time) * 1000
            response_body = b'{"error": {"message": "Gateway timeout"}}'
            status_code = 504
            response_headers = {"content-type": "application/json"}

        except httpx.RequestError as e:
            # Connection error - return 502
            latency_ms = (time.perf_counter() - start_time) * 1000
            response_body = f'{{"error": {{"message": "Bad gateway: {str(e)}"}}}}'.encode()
            status_code = 502
            response_headers = {"content-type": "application/json"}

        else:
            latency_ms = (time.perf_counter() - start_time) * 1000

        # Capture response telemetry
        response_telemetry = capture_response(
            request_id=request_id,
            status_code=status_code,
            latency_ms=latency_ms,
            body=response_body,
        )

        # Create complete telemetry record
        telemetry = create_telemetry_record(
            request=request_telemetry,
            response=response_telemetry,
            target_api=self.config.name,
        )

        # Get context for classification (if provider configured)
        context = None
        if self.context_provider:
            context = self.context_provider(source_ip)

        # Classify behavior
        classification = classify_request(telemetry, context)

        # Invoke callback if configured
        if self.telemetry_callback:
            try:
                self.telemetry_callback(telemetry, classification)
            except Exception:
                pass  # Don't let callback errors affect response

        return ProxyResponse(
            status_code=status_code,
            headers=response_headers,
            body=response_body,
            telemetry=telemetry,
            classification=classification,
        )


class SyncAPIProxy:
    """
    Synchronous version of APIProxy for non-async contexts.

    Example:
        proxy = SyncAPIProxy(ProxyConfig(
            name="stripe",
            target_base_url="https://api.stripe.com",
        ))

        response = proxy.forward(
            method="GET",
            path="/v1/charges",
            headers={"Authorization": "Bearer sk_test_..."},
            source_ip="192.168.1.1",
        )
    """

    def __init__(
        self,
        config: ProxyConfig,
        telemetry_callback: Optional[TelemetryCallback] = None,
        context_provider: Optional[Callable[[str], RequestContext]] = None,
    ):
        """Initialize the synchronous API proxy."""
        self.config = config
        self.telemetry_callback = telemetry_callback
        self.context_provider = context_provider

        self._client = httpx.Client(
            timeout=httpx.Timeout(config.timeout_seconds),
            verify=config.verify_ssl,
            follow_redirects=False,
        )

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()

    def __enter__(self) -> "SyncAPIProxy":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def _build_target_url(self, path: str) -> str:
        """Construct the full target URL."""
        if not path.startswith("/"):
            path = "/" + path
        return urljoin(self.config.target_base_url, path)

    def _prepare_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Prepare headers for forwarding."""
        hop_by_hop = {
            "connection", "keep-alive", "proxy-authenticate",
            "proxy-authorization", "te", "trailers",
            "transfer-encoding", "upgrade", "host",
        }
        return {k: v for k, v in headers.items() if k.lower() not in hop_by_hop}

    def forward(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        source_ip: str,
        query_params: Optional[dict[str, str]] = None,
        body: Optional[bytes] = None,
    ) -> ProxyResponse:
        """
        Forward a request to the target API (synchronous).

        See APIProxy.forward for detailed documentation.
        """
        request_id = generate_request_id()

        request_telemetry = capture_request(
            request_id=request_id,
            source_ip=source_ip,
            method=method,
            path=path,
            headers=headers,
            query_params=query_params,
            body=body,
        )

        target_url = self._build_target_url(path)
        forward_headers = self._prepare_headers(headers)

        start_time = time.perf_counter()
        try:
            response = self._client.request(
                method=method,
                url=target_url,
                headers=forward_headers,
                params=query_params,
                content=body,
            )
            response_body = response.content
            status_code = response.status_code
            response_headers = dict(response.headers)

        except httpx.TimeoutException:
            latency_ms = (time.perf_counter() - start_time) * 1000
            response_body = b'{"error": {"message": "Gateway timeout"}}'
            status_code = 504
            response_headers = {"content-type": "application/json"}

        except httpx.RequestError as e:
            latency_ms = (time.perf_counter() - start_time) * 1000
            response_body = f'{{"error": {{"message": "Bad gateway: {str(e)}"}}}}'.encode()
            status_code = 502
            response_headers = {"content-type": "application/json"}

        else:
            latency_ms = (time.perf_counter() - start_time) * 1000

        response_telemetry = capture_response(
            request_id=request_id,
            status_code=status_code,
            latency_ms=latency_ms,
            body=response_body,
        )

        telemetry = create_telemetry_record(
            request=request_telemetry,
            response=response_telemetry,
            target_api=self.config.name,
        )

        context = None
        if self.context_provider:
            context = self.context_provider(source_ip)

        classification = classify_request(telemetry, context)

        if self.telemetry_callback:
            try:
                self.telemetry_callback(telemetry, classification)
            except Exception:
                pass

        return ProxyResponse(
            status_code=status_code,
            headers=response_headers,
            body=response_body,
            telemetry=telemetry,
            classification=classification,
        )


# =============================================================================
# PRE-CONFIGURED PROXY FACTORIES
# =============================================================================

def create_stripe_proxy(
    telemetry_callback: Optional[TelemetryCallback] = None,
) -> APIProxy:
    """Create a proxy configured for the Stripe API."""
    return APIProxy(
        config=ProxyConfig(
            name="stripe",
            target_base_url="https://api.stripe.com",
            timeout_seconds=30.0,
        ),
        telemetry_callback=telemetry_callback,
    )


def create_openai_proxy(
    telemetry_callback: Optional[TelemetryCallback] = None,
) -> APIProxy:
    """Create a proxy configured for the OpenAI API."""
    return APIProxy(
        config=ProxyConfig(
            name="openai",
            target_base_url="https://api.openai.com",
            timeout_seconds=120.0,  # Longer timeout for LLM requests
        ),
        telemetry_callback=telemetry_callback,
    )


def create_github_proxy(
    telemetry_callback: Optional[TelemetryCallback] = None,
) -> APIProxy:
    """Create a proxy configured for the GitHub API."""
    return APIProxy(
        config=ProxyConfig(
            name="github",
            target_base_url="https://api.github.com",
            timeout_seconds=30.0,
        ),
        telemetry_callback=telemetry_callback,
    )
