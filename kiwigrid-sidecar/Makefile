APP_NAME ?= k8s-sidecar
KIWIGRID_SIDECAR_VERSION = 1.15.7
TAG = $(KIWIGRID_SIDECAR_VERSION)-$(DOCKER_TAG)
IMG = $(DOCKER_PUSH_REPOSITORY)$(DOCKER_PUSH_DIRECTORY)/$(APP_NAME):$(TAG)
IMG_DOCKER_TAG = $(DOCKER_PUSH_REPOSITORY)$(DOCKER_PUSH_DIRECTORY)/$(APP_NAME):$(DOCKER_TAG)

# Use generic makefile
COMMON_DIR = $(realpath $(shell pwd)/../)/common
include $(COMMON_DIR)/generic_makefile.mk

# override docker-build
docker-build:
	docker build . -t ${IMG} --build-arg KIWIGRID_SIDECAR_VERSION=$(KIWIGRID_SIDECAR_VERSION)
