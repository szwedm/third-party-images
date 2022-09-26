FROM golang:1.19 as build

ARG LOKI_VERSION

WORKDIR /src/loki
ADD https://github.com/grafana/loki/archive/refs/tags/v${LOKI_VERSION}.tar.gz /loki.tar.gz
RUN tar -xz --strip-components=1 --directory=/src/loki --file=/loki.tar.gz

# fix compatibility issue with golang 1.19
RUN go get github.com/json-iterator/go@v1.1.12
RUN go mod vendor

RUN make NETGO_CHECK='' clean && make BUILD_IN_CONTAINER=false NETGO_CHECK='' loki

FROM alpine:3.16

RUN apk add --no-cache ca-certificates libcap

COPY --from=build /src/loki/cmd/loki/loki /usr/bin/loki
COPY --from=build /src/loki/cmd/loki/loki-docker-config.yaml /etc/loki/local-config.yaml

RUN addgroup -g 10001 -S loki && \
    adduser -u 10001 -S loki -G loki
RUN mkdir -p /loki/rules && \
    mkdir -p /loki/tmprules && \
    chown -R loki:loki /etc/loki /loki

# See https://github.com/grafana/loki/issues/1928
RUN [ ! -e /etc/nsswitch.conf ] && echo 'hosts: files dns' > /etc/nsswitch.conf

USER loki
EXPOSE 3100
ENTRYPOINT [ "/usr/bin/loki" ]
CMD ["-config.file=/etc/loki/local-config.yaml"]