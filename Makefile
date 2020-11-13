# Copyright 2020 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# Set by cloudbuild (see cloudbuild.yaml)
# TAG will contain a tag of the form vYYYYMMDD-hash, vYYYYMMDD-tag, or vYYYYMMDD-tag-n-ghash,
# depending on the git tags on your repo. The test-infra docs recommend using $_GIT_TAG
# to tag our images.
# PULL_BASE_REF will contain the base ref that was pushed to - for instance, master or
# release-0.2 for a PR merge, or v0.2 for a tag.

SOURCES := $(shell find . -name '*.go')
GOOS ?= $(shell go env GOOS)
GIT_VERSION := $(shell git describe --match=$(git rev-parse --short=8 HEAD) --always --dirty --abbrev=8)
LDFLAGS := "-w -s -X 'main.version=$(GIT_VERSION)'"
ifneq ($(GOPROXY),)
	GOPROXYFLAG := --build-arg GOPROXY=$(GOPROXY)
endif

# Registry and image name
STAGING_REGISTRY := gcr.io/k8s-staging-provider-aws
REGISTRY ?= $(STAGING_REGISTRY)
IMAGE_NAME ?= cloud-controller-manager

# tags
ifneq ($(TAG),)
	DEV_TAG = $(TAG)
else
	DEV_TAG = $(GIT_VERSION)
endif
IMAGE ?= $(REGISTRY)/$(IMAGE_NAME):$(DEV_TAG)

RELEASE_TAG := $(shell git describe --abbrev=0 2>/dev/null)
RELEASE_IMAGE ?= $(REGISTRY)/$(IMAGE_NAME):$(RELEASE_TAG)

aws-cloud-controller-manager: $(SOURCES)
	 CGO111MODULE=on GO_ENABLED=0 GOOS=$(GOOS) go build \
		-ldflags $(LDFLAGS) \
		-o aws-cloud-controller-manager \
		cmd/aws-cloud-controller-manager/main.go

.PHONY: docker-build
docker-build:
	docker build --build-arg LDFLAGS=$(LDFLAGS) $(GOPROXYFLAG) -t $(IMAGE) .

.PHONY: docker-push
docker-push:
	docker push $(IMAGE)

.PHONY: release-tag
release-tag:
	gcloud container images add-tag -q $(IMAGE) $(RELEASE_IMAGE)

.PHONY: release-staging
release-staging:
	$(MAKE) docker-build docker-push release-tag

.PHONY: check
check: verify-fmt verify-lint vet

.PHONY: test
test:
	go test -count=1 -race -v $(shell go list ./...)

.PHONY: verify-fmt
verify-fmt:
	./hack/verify-gofmt.sh

.PHONY: verify-lint
verify-lint:
	which golint 2>&1 >/dev/null || go get golang.org/x/lint/golint
	golint -set_exit_status $(shell go list ./...)

.PHONY: verify-codegen
verify-codegen: 
	./hack/verify-codegen.sh

.PHONY: vet
vet:
	go vet ./...

.PHONY: update-fmt
update-fmt:
	./hack/update-gofmt.sh
