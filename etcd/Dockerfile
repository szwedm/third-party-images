FROM eu.gcr.io/kyma-project/external/quay.io/coreos/etcd:v3.3.25 as builder

# builder relies on https://github.com/etcd-io/etcd/blob/v3.3.25/Dockerfile-release

FROM alpine:3.15.0

LABEL source=git@github.com:kyma-project/kyma.git

RUN apk --no-cache add --update openssl openssl-dev --repository=https://dl-cdn.alpinelinux.org/alpine/edge/main
RUN mkdir -p /var/etcd/
RUN mkdir -p /var/lib/etcd/

# Alpine Linux doesn't use pam, which means that there is no /etc/nsswitch.conf,
# but Golang relies on /etc/nsswitch.conf to check the order of DNS resolving
# (see https://github.com/golang/go/commit/9dee7771f561cf6aee081c0af6658cc81fac3918)
# To fix this we just create /etc/nsswitch.conf and add the following line:
RUN echo 'hosts: files mdns4_minimal [NOTFOUND=return] dns mdns4' >> /etc/nsswitch.conf

EXPOSE 2379 2380

COPY --from=builder /usr/local/bin/ /usr/local/bin/

CMD ["/usr/local/bin/etcd"]
