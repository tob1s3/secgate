# syntax=docker/dockerfile:1
# Двухэтапная сборка: в итоговом образе нет pip-кэша, исходников и инструментов сборки.
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim
LABEL org.opencontainers.image.title="secgate" \
      org.opencontainers.image.description="Security gate for CI: Trivy, Bandit, Semgrep, pip-audit" \
      org.opencontainers.image.source="https://github.com/tob1s3/secgate" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /install /usr/local
RUN useradd --system --uid 10001 --no-create-home secgate
USER 10001
WORKDIR /reports
# Это CLI, а не сервис: проверять «здоровье» нечего.
HEALTHCHECK NONE
ENTRYPOINT ["secgate"]
CMD ["--help"]
