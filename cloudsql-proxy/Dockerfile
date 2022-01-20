FROM gcr.io/cloudsql-docker/gce-proxy:1.28.0-alpine as builder

FROM alpine:3.14.3

LABEL source=git@github.com:kyma-project/kyma.git

RUN apk --no-cache upgrade && \
    apk --no-cache add \ 
    ca-certificates \
    libc6-compat

# Add a non-root user matching the nonroot user from the main container
RUN addgroup -g 65532 -S nonroot && adduser -u 65532 -S nonroot -G nonroot
# Set the uid as an integer for compatibility with runAsNonRoot in Kubernetes
USER 65532

COPY --from=builder --chown=nonroot /cloud_sql_proxy /cloud_sql_proxy
