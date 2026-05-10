FROM python:3.11-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY datasets ./datasets

RUN pip install --no-cache-dir -e .

CMD ["dual-llm-security", "run-dataset", "--dataset", "datasets", "--mode", "dual", "--output", "/tmp/dual-traces.jsonl"]
