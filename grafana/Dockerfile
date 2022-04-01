ARG GRAFANA_VERSION

FROM grafana/grafana:${GRAFANA_VERSION} as grafana-builder

FROM alpine:3.15.3 as grafana

ARG GF_UID="472"
ARG GF_GID="0"

ENV PATH=/usr/share/grafana/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    GF_PATHS_CONFIG="/etc/grafana/grafana.ini" \
    GF_PATHS_DATA="/var/lib/grafana" \
    GF_PATHS_HOME="/usr/share/grafana" \
    GF_PATHS_LOGS="/var/log/grafana" \
    GF_PATHS_PLUGINS="/var/lib/grafana/plugins" \
    GF_PATHS_PROVISIONING="/etc/grafana/provisioning"

WORKDIR $GF_PATHS_HOME

RUN apk --no-cache upgrade && \
    apk add --no-cache ca-certificates bash tzdata && \
    apk add --no-cache openssl musl-utils

COPY --from=grafana-builder "$GF_PATHS_HOME" "$GF_PATHS_HOME"

RUN if [ ! $(getent group "$GF_GID") ]; then \
      addgroup -S -g $GF_GID grafana; \
    fi

RUN export GF_GID_NAME=$(getent group $GF_GID | cut -d':' -f1) && \
    mkdir -p "$GF_PATHS_HOME/.aws" && \
    adduser -S -u $GF_UID -G "$GF_GID_NAME" grafana && \
    mkdir -p "$GF_PATHS_PROVISIONING/datasources" \
             "$GF_PATHS_PROVISIONING/dashboards" \
             "$GF_PATHS_PROVISIONING/notifiers" \
             "$GF_PATHS_PROVISIONING/plugins" \
             "$GF_PATHS_LOGS" \
             "$GF_PATHS_PLUGINS" \
             "$GF_PATHS_DATA" && \
    cp "$GF_PATHS_HOME/conf/sample.ini" "$GF_PATHS_CONFIG" && \
    cp "$GF_PATHS_HOME/conf/ldap.toml" /etc/grafana/ldap.toml && \
    chown -R "grafana:$GF_GID_NAME" "$GF_PATHS_DATA" "$GF_PATHS_HOME/.aws" "$GF_PATHS_LOGS" "$GF_PATHS_PLUGINS" "$GF_PATHS_PROVISIONING" && \
    chmod -R 777 "$GF_PATHS_DATA" "$GF_PATHS_HOME/.aws" "$GF_PATHS_LOGS" "$GF_PATHS_PLUGINS" "$GF_PATHS_PROVISIONING"

EXPOSE 3000

COPY ./run.sh /run.sh

USER "$GF_UID"
ENTRYPOINT [ "/run.sh" ]

FROM golang:1.18 as go-builder

ENV GO111MODULE=on

WORKDIR /workspace

COPY go.mod go.mod
COPY go.sum go.sum

RUN go mod download

COPY main_test.go main_test.go
COPY main.go main.go

RUN go mod verify
RUN go test ./...

RUN rm main_test.go

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o grafanawatcher main.go

FROM grafana

WORKDIR /
COPY --from=go-builder /workspace/grafanawatcher .
USER 65532:65532

ENTRYPOINT ["/grafanawatcher"]
