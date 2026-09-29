"""OpenAPI and Swagger specification parser for API surface cataloging."""

from typing import Any

from isihlangu.core.errors import TargetIntrospectionError


class APIEndpoint:
    def __init__(
        self,
        path: str,
        method: str,
        summary: str = "",
        parameters: list[dict[str, Any]] = None,
        request_body: dict[str, Any] = None,
        security: list[dict[str, Any]] = None,
    ) -> None:
        self.path = path
        self.method = method.upper()
        self.summary = summary
        self.parameters = parameters or []
        self.request_body = request_body or {}
        self.security = security or []


class APIParser:
    """Parses OpenAPI 3.0+ and Swagger documents into actionable endpoints."""

    def parse_openapi_spec(self, spec: dict[str, Any]) -> list[APIEndpoint]:
        endpoints = []
        paths = spec.get("paths", {})

        if not paths:
            raise TargetIntrospectionError("OpenAPI spec contains no valid 'paths'")

        for path, path_item in paths.items():
            for method in ["get", "post", "put", "delete", "patch"]:
                if method in path_item:
                    op = path_item[method]
                    endpoints.append(
                        APIEndpoint(
                            path=path,
                            method=method,
                            summary=op.get("summary", ""),
                            parameters=op.get("parameters", []),
                            request_body=op.get("requestBody", {}),
                            security=op.get("security", spec.get("security", [])),
                        )
                    )

        return endpoints
