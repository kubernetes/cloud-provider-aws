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
ARG GOLANG_IMAGE=golang:1.15.3

# The distroless image on which the CPI manager image is built.
#
# Please do not use "latest". Explicit tags should be used to provide
# deterministic builds. This image doesn't have semantic version tags, but
# the fully-qualified image can be obtained by entering
# "gcr.io/distroless/static:latest" in a browser and then copying the
# fully-qualified image from the web page.
ARG DISTROLESS_IMAGE=gcr.io/distroless/static@sha256:c6d5981545ce1406d33e61434c61e9452dad93ecd8397c41e89036ef977a88f4

################################################################################
##                              BUILD STAGE                                   ##
################################################################################
# Build the manager as a statically compiled binary so it has no dependencies
# libc, muscl, etc.
FROM ${GOLANG_IMAGE} as builder

# This build arg is the version to embed in the CPI binary
ARG VERSION=unknown

# This build arg controls the GOPROXY setting
ARG GOPROXY

WORKDIR /build
COPY go.mod go.sum ./
COPY cmd/ cmd/
COPY pkg/ pkg/
COPY Makefile ./Makefile
ENV CGO_ENABLED=0
ENV GOPROXY ${GOPROXY:-https://proxy.golang.org}
RUN make aws-cloud-controller-manager

################################################################################
##                               MAIN STAGE                                   ##
################################################################################
# Copy the manager into the distroless image.
FROM ${DISTROLESS_IMAGE}
COPY --from=builder /build/aws-cloud-controller-manager /bin/aws-cloud-controller-manager
ENTRYPOINT [ "/bin/aws-cloud-controller-manager" ]
