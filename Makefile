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

SOURCES := $(shell find . -name '*.go')
GOOS ?= $(shell go env GOOS)
GOPROXY ?= $(shell go env GOPROXY)
GIT_VERSION := $(shell git describe --dirty --tags --match='v*')
VERSION ?= $(GIT_VERSION)
IMAGE := amazon/cloud-controller-manager:$(VERSION)
OUTPUT ?= $(shell pwd)/_output
INSTALL_PATH ?= $(OUTPUT)/bin
LDFLAGS ?= -w -s -X k8s.io/component-base/version.gitVersion=$(VERSION)

aws-cloud-controller-manager: $(SOURCES)
	 GO111MODULE=on CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) GOPROXY=$(GOPROXY) go build \
		-trimpath \
		-ldflags="$(LDFLAGS)" \
		-o=aws-cloud-controller-manager \
		cmd/aws-cloud-controller-manager/main.go

ecr-credential-provider: $(shell find ./cmd/ecr-credential-provider -name '*.go')
	 GO111MODULE=on CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) GOPROXY=$(GOPROXY) go build \
		-trimpath \
		-ldflags="$(LDFLAGS)" \
		-o=ecr-credential-provider \
		cmd/ecr-credential-provider/*.go

ecr-credential-provider.exe: $(wildcard ./cmd/ecr-credential-provider/*.go)
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
		--build-arg LDFLAGS=$(LDFLAGS) \
		--build-arg GOPROXY=$(GOPROXY) \
		--tag $(IMAGE) .

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

.PHONY: docs
docs:
	./hack/build-gitbooks.sh

.PHONY: publish-docs
publish-docs:
	./hack/publish-docs.sh
