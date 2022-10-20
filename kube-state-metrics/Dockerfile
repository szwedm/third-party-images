ARG GOLANG_VERSION=1.19.2

FROM golang:${GOLANG_VERSION} as builder

ARG KSM_VERSION

WORKDIR /src/ksm
ADD https://github.com/kubernetes/kube-state-metrics/archive/refs/tags/v${KSM_VERSION}.tar.gz /ksm.tar.gz
RUN tar -xz --strip-components=1 --directory=/src/ksm --file=/ksm.tar.gz

RUN make build-local

FROM scratch
COPY --from=builder /src/ksm/kube-state-metrics /

USER nobody

ENTRYPOINT ["/kube-state-metrics", "--port=8080", "--telemetry-port=8081"]

EXPOSE 8080 8081