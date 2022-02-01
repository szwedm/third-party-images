# The RELEASE.2021-04-22T15-44-28Z is the last version before the RELEASE.2021-05-11T23-27-41Z where Minio changed the license 
# https://github.com/minio/minio/commit/069432566fcfac1f1053677cc925ddafd750730a
MINIO_VERSION = RELEASE.2021-04-22T15-44-28Z
APP_NAME ?= minio/minio
TAG = $(MINIO_VERSION)-$(DOCKER_TAG)
IMG = $(DOCKER_PUSH_REPOSITORY)$(DOCKER_PUSH_DIRECTORY)/$(APP_NAME):$(TAG)
IMG_DOCKER_TAG = $(DOCKER_PUSH_REPOSITORY)$(DOCKER_PUSH_DIRECTORY)/$(APP_NAME):$(DOCKER_TAG)

# Use generic makefile
COMMON_DIR = $(realpath $(shell pwd)/../)/common
include $(COMMON_DIR)/generic_makefile.mk

.PHONY: docker-build
docker-build:
	docker build . -t ${IMG} --build-arg MINIO_VERSION=$(MINIO_VERSION)
