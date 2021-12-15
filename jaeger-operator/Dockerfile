FROM jaegertracing/jaeger-operator:1.29.0 as builder

FROM scratch

ENV OPERATOR=/jaeger-operator \
    USER_UID=1001 \
    USER_NAME=jaeger-operator

COPY --from=builder ${OPERATOR} ${OPERATOR}
COPY --from=builder /scripts/ /scripts/

LABEL source=git@github.com:kyma-project/kyma.git

ENTRYPOINT ["/jaeger-operator"]

USER ${USER_UID}