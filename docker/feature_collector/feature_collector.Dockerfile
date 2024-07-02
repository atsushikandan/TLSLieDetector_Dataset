ARG VERSION=3.11-slim-bookworm
FROM python:${VERSION}
RUN pip install --no-cache-dir scipy numpy
ENTRYPOINT ["python3"]
