# Copyright 2022 OWASP Core Rule Set Project
# SPDX-License-Identifier: Apache-2.0

FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
ARG TARGETPLATFORM

RUN apk add --no-cache ca-certificates

ENTRYPOINT ["/crs-toolchain"]
COPY ${TARGETPLATFORM}/crs-toolchain /
