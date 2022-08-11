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
ROOT ?= $(shell pwd)
UPLOAD ?= $(OUTPUT)/upload
GCS_LOCATION ?= gs://must-override
GCS_URL = $(GCS_LOCATION:gs://%=https://storage.googleapis.com/%)
LATEST_FILE ?= latest-ci.txt
BUILD=$(ROOT)/.build
DIST=$(BUILD)/dist
GCFLAGS?=
OSARCH=$(shell go env GOOS)/$(shell go env GOARCH)
GITSHA := $(shell cd ${ROOT}; git describe --always)
GOPATH_1ST:=$(shell go env | grep GOPATH | cut -f 2 -d '"' | sed 's/ /\\ /g')
BUILDFLAGS="-trimpath"

ifdef STATIC_BUILD
  CGO_ENABLED=0
  export CGO_ENABLED
  EXTRA_BUILDFLAGS=-installsuffix cgo
  EXTRA_LDFLAGS=-s -w
endif

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
	hack/install-gsutil.sh

.PHONY: crossbuild-provider-aws-linux-amd64 crossbuild-provider-aws-linux-arm64
crossbuild-provider-aws-linux-amd64 crossbuild-provider-aws-linux-arm64: crossbuild-provider-aws-linux-%:
	mkdir -p ${DIST}/linux/$*
	GOOS=linux GOARCH=$* go build ${GCFLAGS} ${BUILDFLAGS} ${EXTRA_BUILDFLAGS} -o ${DIST}/linux/$*/provider-aws ${LDFLAGS}"${EXTRA_LDFLAGS} -X k8s.io/provider-aws.Version=${VERSION} -X k8s.io/provider-aws.GitVersion=${GITSHA}" k8s.io/provider-aws/cmd/provider-aws

.PHONY: crossbuild-provider-aws-darwin-amd64 crossbuild-provider-aws-darwin-arm64
crossbuild-provider-aws-darwin-amd64 crossbuild-provider-aws-darwin-arm64: crossbuild-provider-aws-darwin-%:
	mkdir -p ${DIST}/darwin/$*
	GOOS=darwin GOARCH=$* go build ${GCFLAGS} ${BUILDFLAGS} ${EXTRA_BUILDFLAGS} -o ${DIST}/darwin/$*/provider-aws ${LDFLAGS}"${EXTRA_LDFLAGS} -X k8s.io/provider-aws.Version=${VERSION} -X k8s.io/provider-aws.GitVersion=${GITSHA}" k8s.io/provider/cmd/provider

.PHONY: crossbuild-provider-aws-windows-amd64
crossbuild-provider-aws-windows-amd64:
	mkdir -p ${DIST}/windows/amd64
	GOOS=windows GOARCH=amd64 go build ${GCFLAGS} ${BUILDFLAGS} ${EXTRA_BUILDFLAGS} -o ${DIST}/windows/amd64/provider-aws.exe ${LDFLAGS}"${EXTRA_LDFLAGS} -X k8s.io/provider-aws.Version=${VERSION} -X k8s.io/provider-aws.GitVersion=${GITSHA}" k8s.io/provider-aws/cmd/provider-aws

.PHONY: crossbuild
crossbuild: crossbuild-provider-aws

.PHONY: crossbuild-provider-aws
crossbuild: crossbuild-provider-aws-linux-amd64 crossbuild-provider-aws-linux-arm64 crossbuild-provider-aws-darwin-amd64 crossbuild-provider-aws-darwin-arm64 crossbuild-provider-aws-windows-amd64

.PHONY: nodeup-amd64 nodeup-arm64
nodeup-amd64 nodeup-arm64: nodeup-%:
	mkdir -p ${DIST}/linux/$*
	GOOS=linux GOARCH=$* go build ${GCFLAGS} ${BUILDFLAGS} ${EXTRA_BUILDFLAGS} -o ${DIST}/linux/$*/nodeup ${LDFLAGS}"${EXTRA_LDFLAGS} -X k8s.io/provider-aws.Version=${VERSION} -X k8s.io/provider-aws.GitVersion=${GITSHA}" k8s.io/provider-aws/cmd/nodeup

.PHONY: nodeup
nodeup: nodeup-amd64

.phony: nodeup-install # install channels to local $gopath/bin
nodeup-install: nodeup
	cp ${DIST}/${OSARCH}/channels ${GOPATH_1ST}/bin

# dev-upload-nodeup uploads nodeup
.PHONY: version-dist-nodeup version-dist-nodeup-amd64 version-dist-nodeup-arm64
version-dist-nodeup: version-dist-nodeup-amd64 version-dist-nodeup-arm64

version-dist-nodeup-amd64 version-dist-nodeup-arm64: version-dist-nodeup-%: nodeup-%
	mkdir -p ${UPLOAD}/provider-aws/${VERSION}/linux/$*/
	cp -fp ${DIST}/linux/$*/nodeup ${UPLOAD}/provider-aws/${VERSION}/linux/$*/nodeup
	tools/sha256 ${UPLOAD}/provider-aws/${VERSION}/linux/$*/nodeup ${UPLOAD}/provider-aws/${VERSION}/linux/$*/nodeup.sha256


# dev-upload-linux-amd64 does a faster build and uploads to GCS / S3
.PHONY: dev-version-dist dev-version-dist-amd64 dev-version-dist-arm64
dev-version-dist: dev-version-dist-amd64 dev-version-dist-arm64

dev-version-dist-amd64 dev-version-dist-arm64: dev-version-dist-%: version-dist-nodeup-% version-dist-channels-% version-dist-protokube-% version-dist-kops-controller-% version-dist-kube-apiserver-healthcheck-% version-dist-dns-controller-%


.PHONY: version-dist
version-dist: dev-version-dist-amd64 dev-version-dist-arm64 crossbuild
	mkdir -p ${UPLOAD}/provider-aws/${VERSION}/linux/amd64/
	mkdir -p ${UPLOAD}/provider-aws/${VERSION}/linux/arm64/
	mkdir -p ${UPLOAD}/provider-aws/${VERSION}/darwin/amd64/
	mkdir -p ${UPLOAD}/provider-aws/${VERSION}/darwin/arm64/
	mkdir -p ${UPLOAD}/provider-aws/${VERSION}/windows/amd64/
	cp ${DIST}/linux/amd64/provider-aws ${UPLOAD}/provider-aws/${VERSION}/linux/amd64/provider-aws
	tools/sha256 ${UPLOAD}/provider-aws/${VERSION}/linux/amd64/provider-aws ${UPLOAD}/provider-aws/${VERSION}/linux/amd64/provider-aws.sha256
	cp ${DIST}/linux/arm64/provider-aws ${UPLOAD}/provider-aws/${VERSION}/linux/arm64/provider-aws
	tools/sha256 ${UPLOAD}/provider-aws/${VERSION}/linux/arm64/provider-aws ${UPLOAD}/provider-aws/${VERSION}/linux/arm64/provider-aws.sha256
	cp ${DIST}/darwin/amd64/provider-aws ${UPLOAD}/provider-aws/${VERSION}/darwin/amd64/provider-aws
	tools/sha256 ${UPLOAD}/provider-aws/${VERSION}/darwin/amd64/provider-aws ${UPLOAD}/provider-aws/${VERSION}/darwin/amd64/provider-aws.sha256
	cp ${DIST}/darwin/arm64/provider-aws ${UPLOAD}/provider-aws/${VERSION}/darwin/arm64/provider-aws
	tools/sha256 ${UPLOAD}/provider-aws/${VERSION}/darwin/arm64/provider-aws ${UPLOAD}/provider-aws/${VERSION}/darwin/arm64/provider-aws.sha256
	cp ${DIST}/windows/amd64/provider-aws.exe ${UPLOAD}/provider-aws/${VERSION}/windows/amd64/provider-aws.exe
	tools/sha256 ${UPLOAD}/provider-aws/${VERSION}/windows/amd64/provider-aws.exe ${UPLOAD}/provider-aws/${VERSION}/windows/amd64/provider-aws.exe.sha256


# gcs-upload builds provider-aws and uploads to GCS
.PHONY: gcs-upload
gcs-upload: gsutil version-dist
	@echo "== Uploading provider-aws =="
	gsutil -h "Cache-Control:private, max-age=0, no-transform" -m cp -n -r ${UPLOAD}/provider-aws/* ${GCS_LOCATION}

# gcs-upload-tag runs gcs-upload to upload, then uploads a version-marker to LATEST_FILE
.PHONY: gcs-upload-and-tag
gcs-upload-and-tag: gsutil gcs-upload
	echo "${GCS_URL}${VERSION}" > ${UPLOAD}/latest.txt
	gsutil -h "Cache-Control:private, max-age=0, no-transform" cp ${UPLOAD}/latest.txt ${GCS_LOCATION}${LATEST_FILE}

.PHONY: copy-bins-for-upload
copy-bins-for-upload:
	cp ecr-credential-provider $(UPLOAD)

# CloudBuild artifacts
# We hash some artifacts, so that we have can know that they were not modified after being built.
.PHONY: cloudbuild-artifacts
cloudbuild-artifacts: copy-bins-for-upload
	mkdir -p ${ROOT}/cloudbuild/
	cd ${UPLOAD}/provider-aws/; find . -type f | sort | xargs sha256sum > ${ROOT}/cloudbuild/files.sha256
	cd ${ROOT}/cloudbuild/; find -type f | sort | xargs sha256sum > ${BUILDER_OUTPUT}/output
