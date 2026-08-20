# Build stage
FROM python:3.12-slim AS builder
WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
RUN pip install --no-cache-dir build && python -m build --wheel

# Production stage
FROM python:3.12-slim AS production

LABEL org.opencontainers.image.source="https://github.com/poojakira/aws-agent-identity-guard"
LABEL org.opencontainers.image.description="AWS Agent Identity Guard - Production Security Platform"
LABEL org.opencontainers.image.licenses="MIT"

RUN groupadd -r guard && useradd -r -g guard -d /app -s /sbin/nologin guard
WORKDIR /app

COPY --from=builder /build/dist/*.whl ./
RUN pip install --no-cache-dir *.whl && rm *.whl

COPY policies/ ./policies/

USER guard
EXPOSE 8080 9090

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/v1/health')"

ENTRYPOINT ["python", "-m", "aws_agent_identity_guard.api"]
CMD ["--host", "0.0.0.0", "--port", "8080"]
