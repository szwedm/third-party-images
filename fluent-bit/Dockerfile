ARG FLB_VERSION
FROM fluent/fluent-bit:${FLB_VERSION} as fluentbit

# build sequential_http plugin
FROM debian:bullseye-slim as plugin-builder
ARG FLB_VERSION
ARG FLB_TARBALL=https://github.com/fluent/fluent-bit/archive/v$FLB_VERSION.tar.gz
ENV FLB_SOURCE $FLB_TARBALL
RUN mkdir -p /fluent-bit/bin /fluent-bit/etc /fluent-bit/log /tmp/fluent-bit-master/

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && \
    apt-get -y dist-upgrade && \
    apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    ca-certificates \
    cmake \
    make \
    tar \
    libssl-dev \
    libsasl2-dev \
    pkg-config \
    libsystemd-dev \
    zlib1g-dev \
    libpq-dev \
    postgresql-server-dev-all \
    flex \
    bison \
    libyaml-dev \
    libjemalloc-dev \
    libc-ares-dev \ 
    && curl -L -o "/tmp/fluent-bit.tar.gz" ${FLB_SOURCE} \
    && cd tmp/ && mkdir fluent-bit \
    && tar zxfv fluent-bit.tar.gz -C ./fluent-bit --strip-components=1 \
    && cd fluent-bit/build/ \
    && rm -rf /tmp/fluent-bit/build/*

WORKDIR /tmp/fluent-bit/build/

RUN cmake -DFLB_RELEASE=On \
          -DFLB_TRACE=Off \
          -DFLB_JEMALLOC=On \
          -DFLB_TLS=On \
          -DFLB_SHARED_LIB=Off \
          -DFLB_EXAMPLES=Off \
          -DFLB_HTTP_SERVER=On \
          -DFLB_IN_SYSTEMD=On \
          -DFLB_OUT_KAFKA=On \
          -DFLB_OUT_PGSQL=On ..

RUN make -j $(getconf _NPROCESSORS_ONLN)
RUN install bin/fluent-bit /fluent-bit/bin/

RUN rm -rf /plugins
COPY plugins /plugins
RUN mkdir -p /plugins/build/
WORKDIR /plugins/build/
RUN cmake -DFLB_SOURCE=/tmp/fluent-bit \
          -DPLUGIN_NAME=out_sequentialhttp  ../
RUN make -j $(getconf _NPROCESSORS_ONLN)

# build loki plugin
FROM golang:1.17 as loki-builder
ARG LOKI_VERSION

RUN mkdir -p /tmp/src /loki
RUN curl -L https://github.com/grafana/loki/archive/v${LOKI_VERSION}.tar.gz | \
    tar zx --strip=1 -C /tmp/src/
WORKDIR /tmp/src
RUN make clean && make BUILD_IN_CONTAINER=false fluent-bit-plugin 
RUN cp /tmp/src/cmd/fluent-bit/out_grafana_loki.so /loki

# Take upstream image and copy over our plugins
FROM fluentbit

COPY --from=plugin-builder /plugins/build/flb-out_sequentialhttp.so /fluent-bit/lib/flb-out_sequentialhttp.so
COPY --from=loki-builder /loki/out_grafana_loki.so /fluent-bit/lib/out_grafana_loki.so

LABEL source=git@github.com:kyma-project/kyma.git
CMD ["/fluent-bit/bin/fluent-bit", "-e", "/fluent-bit/lib/flb-out_sequentialhttp.so", "-e", "/fluent-bit/lib/out_grafana_loki.so", "-c", "/fluent-bit/etc/fluent-bit.conf"]

