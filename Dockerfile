FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir .

RUN useradd --create-home --uid 10001 iamguard \
    && mkdir -p /workspace \
    && chown -R iamguard:iamguard /workspace /app
USER iamguard
WORKDIR /workspace

ENTRYPOINT ["aws-agent-identity-guard"]
