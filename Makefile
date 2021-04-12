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
GIT_VERSION := $(shell git describe --match=$(git rev-parse --short=8 HEAD) --always --dirty --abbrev=8)
VERSION ?= $(GIT_VERSION)
IMAGE := amazon/cloud-controller-manager:$(VERSION)

aws-cloud-controller-manager: $(SOURCES)
	 GO111MODULE=on CGO_ENABLED=0 GOOS=$(GOOS) GOPROXY=$(GOPROXY) go build \
		-ldflags="-w -s -X 'main.version=$(VERSION)'" \
		-o=aws-cloud-controller-manager \
		cmd/aws-cloud-controller-manager/main.go

ecr-credential-provider:  $(shell find ./cmd/ecr-credential-provider -name '*.go')
	 GO111MODULE=on CGO_ENABLED=0 GOOS=$(GOOS) GOPROXY=$(GOPROXY) go build \
		-ldflags="-w -s -X 'main.version=$(VERSION)'" \
		-o=ecr-credential-provider \
		cmd/ecr-credential-provider/*.go

.PHONY: docker-build
docker-build:
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg GOOS=$(GOOS) \
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

.PHONY: test-e2e
test-e2e:
	AWS_REGION=us-west-2 \
	TEST_PATH=./tests/e2e/... \
	GINKGO_FOCUS="\[cloud-provider-aws-e2e\]" \
	./hack/e2e/run.sh
