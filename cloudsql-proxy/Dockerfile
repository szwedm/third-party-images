FROM gcr.io/cloudsql-docker/gce-proxy:1.31.0 as builder

FROM alpine:latest as user

# Add a non-root user matching the nonroot user from the main container
# Set the uid as an integer for compatibility with runAsNonRoot in Kubernetes
RUN addgroup -S nonroot
RUN adduser -s /sbin/nologin -S -D -H nonroot -u 65532 -G nonroot

FROM scratch

LABEL source=git@github.com:kyma-project/kyma.git

COPY --from=builder /etc /etc
COPY --from=user /etc/passwd /etc/passwd
COPY --from=user /etc/group /etc/group
COPY --from=builder --chown=nonroot:nonroot /cloud_sql_proxy /cloud_sql_proxy
