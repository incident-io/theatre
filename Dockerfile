# Build Go binary without cgo dependencies
FROM golang:1.27.4-trixie@sha256:b54b2639de8c1bfe538ec5ffc45f29b1932235ac5f6d63c059853646677112d9 AS builder
WORKDIR /go/src/github.com/gocardless/theatre

# Install dependencies
COPY go.mod go.sum /go/src/github.com/gocardless/theatre/
RUN go mod download

COPY . /go/src/github.com/gocardless/theatre
ARG git_revision=unset
RUN echo $git_revision > REVISION
RUN set -x \
  && make VERSION="$(cat VERSION)" GIT_REVISION="$(cat REVISION)" build

# The binaries are static, so they need only CA certificates, which distroless includes.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329 AS base

COPY --from=builder /go/src/github.com/gocardless/theatre/bin/* /usr/local/bin/
COPY --from=builder /go/src/github.com/gocardless/theatre/REVISION /REVISION
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/workloads-manager"]

# The vault acceptance tests run shell commands in this image. Only cmd/acceptance builds
# this stage; runtime stays last so a plain build never ships a shell.
FROM base AS acceptance
COPY --from=busybox:1.37.0-musl@sha256:f6a95d611e0a8780fabdb2aec43e31275b2720dfefa3e41b16835bfc42454478 /bin/ /bin/

FROM base AS runtime
