FROM python:3.12-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpcap-dev git make \
    && git clone --depth=1 https://github.com/robertdavidgraham/masscan /masscan \
    && cd /masscan && make -j4 \
    && rm -rf /var/lib/apt/lists/*

FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /masscan/bin/masscan /usr/local/bin/masscan
WORKDIR /app
COPY pyproject.toml .
RUN pip install --no-cache-dir -e .
COPY app/ ./app/
EXPOSE 8007
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8007"]
