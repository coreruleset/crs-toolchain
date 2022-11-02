# Copyright 2022 OWASP Core Rule Set Project
# SPDX-License-Identifier: Apache-2.0

FROM alpine:3

RUN apk add --no-cache ca-certificates

ENTRYPOINT ["/crs-toolchain"]
COPY crs-toolchain /
