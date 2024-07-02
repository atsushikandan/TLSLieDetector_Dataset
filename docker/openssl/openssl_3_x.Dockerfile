ARG BUILD_BASE=tls_docker/alpine-build-base:3.18
ARG ENTRY_BASE=tls_docker/alpine-entry-base:3.18
FROM $BUILD_BASE as openssl-build
ARG VERSION
RUN wget -O openssl.tar.gz https://github.com/openssl/openssl/releases/download/openssl-3.${VERSION}/openssl-3.${VERSION}.tar.gz
RUN mkdir openssl
RUN tar -xzf openssl.tar.gz -C openssl --strip-components 1
WORKDIR /src/openssl
RUN ./config --prefix=/build/ --openssldir=/build/ no-async 
RUN make && make install
RUN mkdir /libdeps
RUN cp $(LD_LIBRARY_PATH="/build/lib/" ldd /build/bin/openssl | awk '$3=="" {print $1}; $3!="" {print $3}') /libdeps/

FROM $ENTRY_BASE
ARG VERSION
COPY --from=openssl-build /libdeps/* /lib/
COPY --from=openssl-build /build/bin/openssl /bin/
LABEL "tls_library"="openssl"
LABEL "tls_library_version"="3.${VERSION}"
ENTRYPOINT ["bash"]