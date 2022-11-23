FROM alpine:3.17.0

# Commit details

ARG commit
ENV IMAGE_COMMIT=$commit
LABEL io.kyma-project.third-party-images.commit=$commit

LABEL source=git@github.com:kyma-project/third-party-images.git

ENV KUBECTL_VERSION="v1.24.7"

RUN apk --no-cache upgrade &&\
apk add --no-cache curl=7.86.0-r1  --repository=http://dl-cdn.alpinelinux.org/alpine/edge/main &&\
    apk --no-cache add wget openssl coreutils curl bash jq grep inotify-tools &&\
    wget https://storage.googleapis.com/kubernetes-release/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl -O /usr/local/bin/kubectl &&\
    chmod +x /usr/local/bin/kubectl

ENTRYPOINT ["/bin/bash"]
