ARG LOKI_VERSION

FROM grafana/loki:${LOKI_VERSION} as builder

FROM alpine:3.15.0

RUN apk --no-cache upgrade && \
    apk add --no-cache ca-certificates libcap

COPY --from=builder /usr/bin/loki /usr/bin/loki
COPY --from=builder /etc/loki/local-config.yaml /etc/loki/local-config.yaml

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

