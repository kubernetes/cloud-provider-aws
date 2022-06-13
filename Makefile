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


SHELL := /bin/bash
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
GOPROXY ?= $(shell go env GOPROXY)
GIT_VERSION := $(shell git describe --dirty --tags --match='v*')
VERSION ?= $(GIT_VERSION)
IMAGE_REPOSITORY ?= amazon/cloud-controller-manager
IMAGE ?= $(IMAGE_REPOSITORY):$(VERSION)
OUTPUT ?= $(shell pwd)/_output
INSTALL_PATH ?= $(OUTPUT)/bin
LDFLAGS ?= -w -s -X k8s.io/component-base/version.gitVersion=$(VERSION)

.PHONY: aws-cloud-controller-manager
aws-cloud-controller-manager:
	 GO111MODULE=on CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) GOPROXY=$(GOPROXY) go build \
		-trimpath \
		-ldflags="$(LDFLAGS)" \
		-o=aws-cloud-controller-manager \
		cmd/aws-cloud-controller-manager/main.go

.PHONY: ecr-credential-provider
ecr-credential-provider:
	 GO111MODULE=on CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) GOPROXY=$(GOPROXY) go build \
		-trimpath \
		-ldflags="$(LDFLAGS)" \
		-o=ecr-credential-provider \
		cmd/ecr-credential-provider/*.go

.PHONY: ecr-credential-provider.exe
ecr-credential-provider.exe:
	 GO111MODULE=on CGO_ENABLED=0 GOOS=windows GOPROXY=$(GOPROXY) go build \
		-trimpath \
		-ldflags="$(LDFLAGS)" \
		-o=ecr-credential-provider.exe \
		cmd/ecr-credential-provider/*.go

.PHONY: docker-build-amd64
docker-build-amd64:
	docker buildx build --output=type=docker \
		--build-arg VERSION=$(VERSION) \
		--build-arg GOPROXY=$(GOPROXY) \
		--platform linux/amd64 \
		--tag $(IMAGE) .

.PHONY: docker-build-arm64
docker-build-arm64:
	docker buildx build --output=type=docker \
		--build-arg VERSION=$(VERSION) \
		--build-arg GOPROXY=$(GOPROXY) \
		--platform linux/arm64 \
		--tag $(IMAGE) .

.PHONY: docker-build
docker-build:
	docker buildx build --output=type=registry \
		--build-arg LDFLAGS="$(LDFLAGS)" \
		--build-arg GOPROXY=$(GOPROXY) \
		--platform linux/amd64,linux/arm64 \
		--tag $(IMAGE) .

.PHONY: e2e.test
e2e.test:
	pushd tests/e2e > /dev/null && \
		go test -c && popd
	mv tests/e2e/e2e.test e2e.test

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
	which golint 2>&1 >/dev/null || go install golang.org/x/lint/golint@latest
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

.PHONY: docs
docs:
	./hack/build-gitbooks.sh

.PHONY: publish-docs
publish-docs:
	./hack/publish-docs.sh

.PHONY: kops-example
kops-example:
	./hack/kops-example.sh

.PHONY: test-e2e
test-e2e: e2e.test docker-build-amd64 install-e2e-tools
	AWS_REGION=us-west-2 \
	TEST_PATH=./tests/e2e/... \
	BUILD_IMAGE=$(IMAGE) \
	BUILD_VERSION=$(VERSION) \
	INSTALL_PATH=$(INSTALL_PATH) \
	GINKGO_FOCUS="\[cloud-provider-aws-e2e\]" \
	./hack/e2e/run.sh

# Use `make install-e2e-tools KOPS_ROOT=<local-kops-installation>`
# to skip the kops download, test local changes to the kubetest2-kops
# deployer, etc.
.PHONY: install-e2e-tools
install-e2e-tools:
	mkdir -p $(INSTALL_PATH)
	INSTALL_PATH=$(INSTALL_PATH) \
	./hack/install-e2e-tools.sh

.PHONY: print-image-tag
print-image-tag:
	@echo $(IMAGE)
