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

ROOT ?= $(shell pwd)
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

# flags for ecr-credential-provider artifact promotion
UPLOAD ?= $(OUTPUT)/upload
GCS_LOCATION ?= gs://test-ecr-build
GCS_URL = $(GCS_LOCATION:gs://%=https://storage.googleapis.com/%)
LATEST_FILE ?= latest-ci.txt
BUILD=$(ROOT)/.build
DIST=$(BUILD)/dist
GCFLAGS?=
BUILDFLAGS="-trimpath"
EXTRA_BUILDFLAGS=-installsuffix cgo
EXTRA_LDFLAGS=-s -w
GITSHA := $(shell cd ${ROOT}; git describe --always)

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

.PHONY: ko
ko:
	hack/install-ko.sh

.PHONY: ko-build
ko-build: ko
	KO_DOCKER_REPO="$(IMAGE_REPOSITORY)" GOFLAGS="-ldflags=-X=k8s.io/component-base/version.gitVersion=$(VERSION)" ko build --tags ${VERSION}  --platform=linux/amd64,linux/arm64 --bare ./cmd/aws-cloud-controller-manager/

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

.PHONY: gsutil
gsutil:
	/Users/prasita/Downloads/google-cloud-sdk/bin/gcloud info
	/Users/prasita/Downloads/google-cloud-sdk/bin/gcloud config list
	/Users/prasita/Downloads/google-cloud-sdk/bin/gcloud auth list
# update to below cmd before commit and remove above 3 lines
# hack/install-gsutil.sh

.PHONY: ecr-credential-provider-linux-amd64 ecr-credential-provider-linux-arm64
ecr-credential-provider-linux-amd64 ecr-credential-provider-linux-arm64: ecr-credential-provider
    mkdir -p ${DIST}/linux/$*
    GOOS=linux GOARCH=$* go build ${GCFLAGS} ${BUILDFLAGS} ${EXTRA_BUILDFLAGS} -o ${DIST}/linux/$*/ecr-credential-provider ${LDFLAGS}“${EXTRA_LDFLAGS} -X k8s.io/ecr-credential-provider.Version=${VERSION} -X k8s.io/ecr-credential-provider.GitVersion=${GITSHA}" k8s.io/cloud-provider-aws/cmd/ecr-credential-provider/*.go

.PHONY: crossbuild-ecr-credential-provider
crossbuild-ecr-credential-provider: ecr-credential-provider-linux-amd64 ecr-credential-provider-linux-arm64 ecr-credential-provider.exe 

.PHONY: copy-bins-for-upload
copy-bins-for-upload: crossbuild-ecr-credential-provider
	mkdir -p ${UPLOAD}/provider-aws/${VERSION}/linux/amd64/
	mkdir -p ${UPLOAD}/provider-aws/${VERSION}/linux/arm64/
	mkdir -p ${UPLOAD}/provider-aws/windows
	cp ${DIST}/linux/amd64/ecr-credential-provider ${UPLOAD}/provider-aws/${VERSION}/linux/amd64/ecr-credential-provider
	hack/sha256 ${UPLOAD}/provider-aws/${VERSION}/linux/amd64/ecr-credential-provider ${UPLOAD}/provider-aws/${VERSION}/linux/amd64/ecr-credential-provider.sha256
	cp ${DIST}/linux/arm64/ecr-credential-provider ${UPLOAD}/provider-aws/${VERSION}/linux/arm64/ecr-credential-provider
	hack/sha256 ${UPLOAD}/provider-aws/${VERSION}/linux/arm64/ecr-credential-provider ${UPLOAD}/provider-aws/${VERSION}/linux/arm64/ecr-credential-provider.sha256
	cp ecr-credential-provider.exe $(UPLOAD)/provider-aws/windows
	hack/sha256 ${UPLOAD}/provider-aws/windows/ecr-credential-provider.exe ${UPLOAD}/provider-aws/windows/ecr-credential-provider.exe.sha256

# gcs-upload builds provider-aws and uploads to GCS
.PHONY: gcs-upload
gcs-upload: gsutil copy-bins-for-upload
	@echo "== Uploading provider-aws =="
	/Users/prasita/Downloads/google-cloud-sdk/bin/gsutil -h "Cache-Control:private, max-age=0, no-transform" -m cp -n -r ${UPLOAD}/* ${GCS_LOCATION}

# gcs-upload-tag runs gcs-upload to upload, then uploads a version-marker to LATEST_FILE
.PHONY: gcs-upload-and-tag
gcs-upload-and-tag: gsutil gcs-upload
	echo "${GCS_URL}-${VERSION}" > ${UPLOAD}/latest.txt
	/Users/prasita/Downloads/google-cloud-sdk/bin/gsutil -h "Cache-Control:private, max-age=0, no-transform" cp ${UPLOAD}/latest.txt ${GCS_LOCATION}/${LATEST_FILE}

# CloudBuild artifacts
# We hash some artifacts, so that we have can know that they were not modified after being built.
.PHONY: cloudbuild-artifacts
cloudbuild-artifacts: gcs-upload-and-tag
	mkdir -p ${ROOT}/cloudbuild/
	cd ${UPLOAD}/provider-aws/; find . -type f | sort | xargs sha256sum > ${ROOT}/cloudbuild/files.sha256
	cd ${ROOT}/cloudbuild/; find . -type f | sort | xargs sha256sum > ${OUTPUT}/cloudbuild_output