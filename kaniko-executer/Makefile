APP_NAME ?= kaniko-executor
VERSION = 1.6.0
TAG = $(VERSION)-$(DOCKER_TAG)
IMG = $(DOCKER_PUSH_REPOSITORY)$(DOCKER_PUSH_DIRECTORY)/$(APP_NAME):$(TAG)
IMG_DOCKER_TAG = $(DOCKER_PUSH_REPOSITORY)$(DOCKER_PUSH_DIRECTORY)/$(APP_NAME):$(DOCKER_TAG)

# Use generic makefile
COMMON_DIR = $(realpath $(shell pwd)/../)/common
include $(COMMON_DIR)/generic_makefile.mk



# override docker-build
docker-build:
	echo $(TAG)
	docker build . -t ${IMG} --build-arg  KANIKO_VERSION=$(VERSION)