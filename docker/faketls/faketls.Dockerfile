ARG BUILD_BASE=tls_docker/alpine-build-base:3.18
ARG VERSION=3.11-alpine3.18
FROM $BUILD_BASE as faketls-build
RUN pip install --no-cache-dir cryptography

FROM python:$VERSION
COPY --from=faketls-build /usr/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
RUN apk --update --no-cache add bash
ENTRYPOINT ["python3"]
