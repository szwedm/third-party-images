FROM debian:testing-20211011-slim as builder

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

# Add sequentialhttp
RUN rm -rf /plugins
COPY plugins /plugins
RUN mkdir -p /plugins/build/
WORKDIR /plugins/build/
RUN cmake -DFLB_SOURCE=/tmp/fluent-bit \
          -DPLUGIN_NAME=out_sequentialhttp  ../
RUN make -j $(getconf _NPROCESSORS_ONLN)
# End sequentialhttp

# Configuration files
WORKDIR /tmp/fluent-bit/
RUN mkdir /fluent-bit/lib
RUN cp conf/fluent-bit.conf \
     conf/parsers.conf \
     conf/parsers_ambassador.conf \
     conf/parsers_java.conf \
     conf/parsers_extra.conf \
     conf/parsers_openstack.conf \
     conf/parsers_cinder.conf \
     conf/plugins.conf \
     /fluent-bit/etc/

FROM golang:1.15 as lokibuilder

# 2.2.x is the last version on Apache 2.0 license, please verify the license before upgrading further
ENV LOKI_VERSION 2.2.1 

RUN mkdir -p /tmp/src /loki
RUN curl -L https://github.com/grafana/loki/archive/v${LOKI_VERSION}.tar.gz | \
    tar zx --strip=1 -C /tmp/src/
WORKDIR /tmp/src
RUN make clean && make BUILD_IN_CONTAINER=false fluent-bit-plugin 
RUN cp /tmp/src/cmd/fluent-bit/out_grafana_loki.so /loki

FROM debian:testing-20211011-slim

RUN apt-get update && \
    apt-get -y dist-upgrade && \
    apt-get install -y --no-install-recommends \
    libsasl2-2 \
    libssl1.1 \
    ca-certificates && \
    rm -rf /var/lib/apt/lists

COPY --from=builder /usr/lib/x86_64-linux-gnu/libpq.so* /usr/lib/x86_64-linux-gnu/
COPY --from=builder /usr/lib/x86_64-linux-gnu/libldap* /usr/lib/x86_64-linux-gnu/
COPY --from=builder /usr/lib/x86_64-linux-gnu/liblber* /usr/lib/x86_64-linux-gnu/

COPY --from=builder /fluent-bit /fluent-bit
COPY --from=builder /plugins/build/flb-out_sequentialhttp.so /fluent-bit/lib
COPY --from=lokibuilder /loki/out_grafana_loki.so /fluent-bit/lib

EXPOSE 2020

LABEL source=git@github.com:kyma-project/kyma.git
CMD ["/fluent-bit/bin/fluent-bit", "-e", "/fluent-bit/lib/flb-out_sequentialhttp.so", "-e", "/fluent-bit/lib/out_grafana_loki.so", "-c", "/fluent-bit/etc/fluent-bit.conf"]
