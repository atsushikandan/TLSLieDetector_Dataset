ARG BUILD_BASE=tls_docker/alpine-build-base:3.18
ARG ENTRY_BASE=tls_docker/alpine-entry-base:3.18
FROM $BUILD_BASE as wolfssl-build
ARG VERSION
RUN git clone --depth=1 --branch=v${VERSION}-stable https://github.com/wolfSSL/wolfssl
WORKDIR /src/wolfssl
RUN ./autogen.sh
RUN ./configure --prefix=/build/ --enable-dtls13 --enable-tls12 --enable-all
RUN make && make install

FROM wolfssl-build as wolfssl-py
RUN USE_LOCAL_WOLFSSL=/build pip install --no-cache-dir --use-pep517 wolfssl

FROM $ENTRY_BASE
ARG VERSION
RUN apk --update --no-cache add python3~=3.11
COPY --from=wolfssl-build /build/lib/libwolfssl.so.* /lib/
COPY --from=wolfssl-py /usr/lib/python3.11/site-packages /usr/lib/python3.11/site-packages
LABEL "tls_library"="wolfssl"
LABEL "tls_library_version"="${VERSION}"
ENTRYPOINT ["bash"]
