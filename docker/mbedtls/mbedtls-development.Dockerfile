ARG BUILD_BASE=tls_docker/alpine-build-base:3.18
ARG ENTRY_BASE=tls_docker/alpine-entry-base:3.18
FROM $BUILD_BASE as mbedtls-build
RUN git clone --depth 1 --branch development https://github.com/Mbed-TLS/mbedtls mbedtls
COPY programs/ssl_client2_custom.c mbedtls/programs/ssl/ssl_client2_custom.c
COPY programs/ssl_server2_custom.c mbedtls/programs/ssl/ssl_server2_custom.c
RUN sed -i -e "s|//#define MBEDTLS_SSL_PROTO_TLS1_3|#define MBEDTLS_SSL_PROTO_TLS1_3|g" mbedtls/include/mbedtls/mbedtls_config.h && \
    sed -i -e "s|//#define MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE|#define MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE|g" mbedtls/include/mbedtls/mbedtls_config.h &&\
    sed -i -e "/^    ssl_client2/a    ssl_client2_custom" mbedtls/programs/ssl/CMakeLists.txt &&\
    sed -i -e "/^    ssl_server2/a    ssl_server2_custom" mbedtls/programs/ssl/CMakeLists.txt &&\
    sed -i -e "s/^    if(exe STREQUAL \"ssl_client2\" OR exe STREQUAL \"ssl_server2\")/     if(exe STREQUAL \"ssl_client2\" OR exe STREQUAL \"ssl_server2\" OR exe STREQUAL \"ssl_client2_custom\" OR exe STREQUAL \"ssl_server2_custom\")/g" mbedtls/programs/ssl/CMakeLists.txt
WORKDIR /src/mbedtls
RUN git submodule update --init
WORKDIR /build/
RUN cmake -DCMAKE_BUILD_TYPE=Release /src/mbedtls && make

FROM $ENTRY_BASE
COPY --from=mbedtls-build /lib/ld-musl-aarch64.so.* /lib/
COPY --from=mbedtls-build /build/programs/ssl/ssl_client2_custom /bin/
COPY --from=mbedtls-build /build/programs/ssl/ssl_server2_custom /bin/
LABEL "tls_library"="mbedtls"
LABEL "tls_library_version"="development"
ENTRYPOINT ["bash"]
