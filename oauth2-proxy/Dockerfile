ARG ALPINE_VERSION=3.16.2
ARG GOLANG_VERSION=1.19.2

FROM golang:${GOLANG_VERSION}-buster as builder

ARG OAUTH2_PROXY_VERSION

WORKDIR /src/oauth2
ADD https://github.com/oauth2-proxy/oauth2-proxy/archive/refs/tags/v${OAUTH2_PROXY_VERSION}.tar.gz /oauth2.tar.gz
RUN tar -xz --strip-components=1 --directory=/src/oauth2 --file=/oauth2.tar.gz

RUN go mod download

RUN GOARCH=amd64 VERSION=${OAUTH2_PROXY_VERSION} make build && touch jwt_signing_key.pem
 
FROM alpine:${ALPINE_VERSION}

RUN apk --no-cache upgrade

COPY --from=builder /etc/nsswitch.conf /etc/nsswitch.conf
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /src/oauth2/oauth2-proxy /bin/oauth2-proxy
COPY --from=builder /src/oauth2/jwt_signing_key.pem /etc/ssl/private/jwt_signing_key.pem

USER 65532:65532

ENTRYPOINT ["/bin/oauth2-proxy"]
