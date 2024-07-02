ARG VERSION=latest
FROM alpine:$VERSION
RUN apk --update --no-cache add \
      bash \
      openssl

WORKDIR /ca