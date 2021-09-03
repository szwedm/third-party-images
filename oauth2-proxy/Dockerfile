ARG OAUTH2_PROXY_VERSION

FROM quay.io/oauth2-proxy/oauth2-proxy:v${OAUTH2_PROXY_VERSION} as builder
 
FROM alpine:3.14.2

COPY --from=builder /etc/nsswitch.conf /etc/nsswitch.conf
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /bin/oauth2-proxy /bin/oauth2-proxy
COPY --from=builder /etc/ssl/private/jwt_signing_key.pem /etc/ssl/private/jwt_signing_key.pem

USER 2000:2000

ENTRYPOINT ["/bin/oauth2-proxy"]
