ARG VERSION=latest
FROM alpine:$VERSION
RUN apk --update --no-cache add \
      alpine-sdk \
      autoconf \
      automake \
      bash \
      bison \
      build-base \
      bsd-compat-headers \
      cmake \
      coreutils \
      gettext-dev \
      git \
      gmp-dev \
      gperf \
      libffi-dev \
      libtool \
      linux-headers \
      musl-utils \
      py-cffi \
      py3-pip \
      python3-dev \
      strace \
      unzip \
      util-linux \
      wget \
      zlib-dev
RUN pip install --no-cache-dir \
      jsonschema \
      jinja2

WORKDIR /src/
