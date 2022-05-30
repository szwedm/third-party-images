APP_NAME ?= oauth2-proxy
OAUTH2_PROXY_VERSION = 7.3.0
TAG = $(OAUTH2_PROXY_VERSION)-$(DOCKER_TAG)
IMG = $(DOCKER_PUSH_REPOSITORY)$(DOCKER_PUSH_DIRECTORY)/$(APP_NAME):$(TAG)
IMG_DOCKER_TAG = $(DOCKER_PUSH_REPOSITORY)$(DOCKER_PUSH_DIRECTORY)/$(APP_NAME):$(DOCKER_TAG)

# Use generic makefile
COMMON_DIR = $(realpath $(shell pwd)/../)/common
include $(COMMON_DIR)/generic_makefile.mk

# override docker-build
docker-build:
	docker build . -t ${IMG} --build-arg OAUTH2_PROXY_VERSION=$(OAUTH2_PROXY_VERSION)
