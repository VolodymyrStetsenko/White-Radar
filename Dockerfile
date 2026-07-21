FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN groupadd --system --gid 10001 radar \
    && useradd --system --uid 10001 --gid radar --home-dir /nonexistent --shell /usr/sbin/nologin radar

COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN python -m pip install --upgrade pip \
    && python -m pip install .

RUN mkdir -p /app/data \
    && chown -R radar:radar /app/data

USER 10001:10001

ENTRYPOINT ["white-radar", "--config", "/app/config.toml"]
CMD ["daemon"]
