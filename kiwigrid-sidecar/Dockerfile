ARG KIWIGRID_SIDECAR_VERSION
ARG PYTHON_VERSION=3.10.8
ARG ALPINE_VERSION=3.16

FROM kiwigrid/k8s-sidecar:${KIWIGRID_SIDECAR_VERSION} as builder

FROM python:${PYTHON_VERSION}-alpine${ALPINE_VERSION}

ARG KIWIGRID_SIDECAR_VERSION

ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN wget https://raw.githubusercontent.com/kiwigrid/k8s-sidecar/${KIWIGRID_SIDECAR_VERSION}/src/requirements.txt

COPY --from=builder /app/* /app/
RUN apk --no-cache upgrade && \
    apk --no-cache add gcc && \
    pip install -r requirements.txt && \
    apk del -r gcc && \
    rm -rf /var/cache/apk/* requirements.txt

USER 65534:65534

LABEL source=git@github.com:kyma-project/kyma.git

CMD [ "python", "-u", "/app/sidecar.py" ]
