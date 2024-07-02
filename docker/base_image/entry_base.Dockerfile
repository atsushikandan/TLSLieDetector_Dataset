ARG VERSION=latest
FROM alpine:$VERSION
RUN apk --update --no-cache add \
      bash \
      tcpdump \
      tshark

WORKDIR /
ENTRYPOINT ["bash"]