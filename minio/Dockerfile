FROM minio/minio:RELEASE.2020-09-21T22-31-59Z as builder

FROM alpine:3.14.2

LABEL source=git@github.com:kyma-project/kyma.git

ENV MINIO_UPDATE off
ENV MINIO_ACCESS_KEY_FILE=access_key \
    MINIO_SECRET_KEY_FILE=secret_key \
    MINIO_SSE_MASTER_KEY_FILE=sse_master_key

EXPOSE 9000

COPY --from=builder /usr/bin/minio /usr/bin/minio
COPY --from=builder /usr/bin/docker-entrypoint.sh /usr/bin/docker-entrypoint.sh

RUN  \
    apk update && apk upgrade && \
    apk add --no-cache ca-certificates curl 'su-exec>=0.2' && \
    echo 'hosts: files mdns4_minimal [NOTFOUND=return] dns mdns4' >> /etc/nsswitch.conf

ENTRYPOINT ["/usr/bin/docker-entrypoint.sh"]

VOLUME ["/data"]

CMD ["minio"]
