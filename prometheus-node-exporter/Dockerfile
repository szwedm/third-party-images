FROM alpine:3.16 as builder

ARG NODE_EXPORTER_VERSION

RUN apk update && apk upgrade && \
    apk add --no-cache bash curl

RUN curl -LO https://github.com/prometheus/node_exporter/releases/download/v${NODE_EXPORTER_VERSION}/node_exporter-${NODE_EXPORTER_VERSION}.linux-amd64.tar.gz \
    && tar -xvzf node_exporter-${NODE_EXPORTER_VERSION}.linux-amd64.tar.gz  \
    && cp node_exporter-${NODE_EXPORTER_VERSION}.linux-amd64/node_exporter /tmp/

FROM scratch

COPY --from=builder /tmp/node_exporter /usr/local/bin/
COPY --from=builder /etc/passwd /etc/passwd

EXPOSE 9100

USER nobody

LABEL source=git@github.com:kyma-project/kyma.git

ENTRYPOINT ["node_exporter"]

