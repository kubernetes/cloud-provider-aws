# Copyright 2018 The Kubernetes Authors.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

################################################################################
##                               BUILD ARGS                                   ##
################################################################################
# This build arg allows the specification of a custom Golang image.
ARG GOLANG_IMAGE=golang:1.17.4

# The distroless image on which the CPI manager image is built.
#
# Please do not use "latest". Explicit tags should be used to provide
# deterministic builds. This image doesn't have semantic version tags, but
# the fully-qualified image can be obtained by entering
# "gcr.io/distroless/static:latest" in a browser and then copying the
# fully-qualified image from the web page.
ARG DISTROLESS_IMAGE=gcr.io/distroless/static@sha256:1cc74da80bbf80d89c94e0c7fe22830aa617f47643f2db73f66c8bd5bf510b25

################################################################################
##                              BUILD STAGE                                   ##
################################################################################
# Build the manager as a statically compiled binary so it has no dependencies
# libc, muscl, etc.
FROM --platform=linux/amd64 ${GOLANG_IMAGE} as builder

ARG VERSION
ARG GOPROXY=https://goproxy.io,direct
ARG TARGETOS
ARG TARGETARCH

WORKDIR /build
COPY go.mod go.sum ./
COPY cmd/ cmd/
COPY pkg/ pkg/
RUN GO111MODULE=on CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} GOPROXY=${GOPROXY} \
		go build \
		-trimpath \
		-ldflags="-w -s -X 'main.version=${VERSION}'" \
		-o=aws-cloud-controller-manager \
		cmd/aws-cloud-controller-manager/main.go

################################################################################
##                               MAIN STAGE                                   ##
################################################################################
# Copy the manager into the distroless image.
FROM --platform=${TARGETPLATFORM} ${DISTROLESS_IMAGE}
COPY --from=builder /build/aws-cloud-controller-manager /bin/aws-cloud-controller-manager
ENTRYPOINT [ "/bin/aws-cloud-controller-manager" ]
