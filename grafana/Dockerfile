ARG ALPINE_VERSION=3.16
ARG GOLANG_VERSION=1.19.2
ARG NODE_VERSION=14.20

# Fetch the sources
FROM alpine:${ALPINE_VERSION} as fetcher
ARG GRAFANA_VERSION
WORKDIR /build
ADD https://github.com/grafana/grafana/archive/refs/tags/v${GRAFANA_VERSION}.tar.gz /grafana.tar.bz2
RUN tar -xf /grafana.tar.bz2 -C /build --strip-components 1

# Build UI components
FROM node:${NODE_VERSION}-alpine${ALPINE_VERSION} as js-builder

WORKDIR /usr/src/app/

COPY --from=fetcher /build/package.json ./
COPY --from=fetcher /build/yarn.lock ./
COPY --from=fetcher /build/patches patches

COPY --from=fetcher /build/packages packages

RUN apk --no-cache upgrade && \
    apk add --no-cache git

RUN yarn install --pure-lockfile --no-progress

COPY --from=fetcher /build/tsconfig.json ./
COPY --from=fetcher /build/.eslintrc ./
COPY --from=fetcher /build/.editorconfig ./
COPY --from=fetcher /build/.browserslistrc ./
COPY --from=fetcher /build/.prettierrc.js ./

COPY --from=fetcher /build/public public
COPY --from=fetcher /build/tools tools
COPY --from=fetcher /build/scripts scripts
COPY --from=fetcher /build/emails emails

ENV NODE_ENV production
RUN yarn build

# Build go components
FROM golang:${GOLANG_VERSION}-alpine${ALPINE_VERSION} as go-builder

RUN apk add --no-cache gcc g++

WORKDIR $GOPATH/src/github.com/grafana/grafana

COPY --from=fetcher /build/go.mod ./
COPY --from=fetcher /build/go.sum ./
COPY --from=fetcher /build/pkg pkg

RUN go mod verify

COPY --from=fetcher /build/build.go /build/package.json ./

RUN go run build.go build


# Final stage
FROM alpine:${ALPINE_VERSION} as grafana

ARG GF_UID="472"
ARG GF_GID="0"

ENV PATH="/usr/share/grafana/bin:$PATH" \
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

COPY --from=fetcher /build/conf conf

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

COPY --from=go-builder /go/src/github.com/grafana/grafana/bin/linux-amd64/grafana-server bin/

COPY --from=js-builder /usr/src/app/public public
COPY --from=js-builder /usr/src/app/tools tools

EXPOSE 3000

COPY --from=fetcher /build/packaging/docker/run.sh /run.sh

USER grafana
ENTRYPOINT [ "/run.sh" ]

FROM golang:${GOLANG_VERSION}-alpine${ALPINE_VERSION}  as gw-builder

RUN apk add --no-cache gcc g++

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
COPY --from=gw-builder /workspace/grafanawatcher .
USER 65532:65532

ENTRYPOINT ["/grafanawatcher"]
