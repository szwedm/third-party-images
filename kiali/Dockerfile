ARG KIALI_VERSION
ARG ALPINE_VERSION=3.16.2

FROM quay.io/kiali/kiali:v${KIALI_VERSION} as builder

FROM alpine:${ALPINE_VERSION}

ENV KIALI_HOME=/opt/kiali \
    PATH=$KIALI_HOME:$PATH

WORKDIR $KIALI_HOME

COPY --from=builder $KIALI_HOME/ $KIALI_HOME/
COPY --from=builder $KIALI_HOME/console/ $KIALI_HOME/console/

RUN apk --no-cache upgrade \
 && apk add --no-cache bash

RUN adduser -D -u 1000 kiali && \
    chown -R kiali:kiali $KIALI_HOME/console && \
    chmod -R g=u $KIALI_HOME/console

LABEL source=git@github.com:kyma-project/kyma.git

USER 1000 

ENTRYPOINT ["/opt/kiali/kiali"]
