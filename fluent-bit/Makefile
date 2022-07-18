APP_NAME ?= fluent-bit
FLUENTBIT_VERSION = 1.9.6
# 2.2.x is the last version on Apache 2.0 license, please verify the license before upgrading further
LOKI_VERSION = 2.2.1
TAG = $(FLUENTBIT_VERSION)-$(DOCKER_TAG)
IMG = $(DOCKER_PUSH_REPOSITORY)$(DOCKER_PUSH_DIRECTORY)/$(APP_NAME):$(TAG)
IMG_DOCKER_TAG = $(DOCKER_PUSH_REPOSITORY)$(DOCKER_PUSH_DIRECTORY)/$(APP_NAME):$(DOCKER_TAG)

# Use generic makefile
COMMON_DIR = $(realpath $(shell pwd)/../)/common
include $(COMMON_DIR)/generic_makefile.mk

# override docker-build
docker-build:
	docker build . -t ${IMG} --build-arg FLB_VERSION=$(FLUENTBIT_VERSION) --build-arg LOKI_VERSION=$(LOKI_VERSION)

