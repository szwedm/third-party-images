FROM alpine:3.14.2 as builder

ENV exporter_version 1.1.2

RUN apk update && apk upgrade && \
    apk add --no-cache bash curl

RUN curl -LO https://github.com/prometheus/node_exporter/releases/download/v${exporter_version}/node_exporter-${exporter_version}.linux-amd64.tar.gz \
    && tar -xvzf node_exporter-${exporter_version}.linux-amd64.tar.gz  \
    && cp node_exporter-${exporter_version}.linux-amd64/node_exporter /tmp/

FROM scratch

COPY --from=builder /tmp/node_exporter /usr/local/bin/
COPY --from=builder /etc/passwd /etc/passwd

EXPOSE 9100

USER nobody

LABEL source=git@github.com:kyma-project/kyma.git

ENTRYPOINT ["node_exporter"]
