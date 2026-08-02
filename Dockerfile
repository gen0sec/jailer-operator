# Build the manager against the same Go version go.mod asks for.
FROM golang:1.24 AS build
WORKDIR /src

# Dependencies first, so source edits do not refetch the module graph.
COPY go.mod go.sum ./
RUN go mod download

COPY api/ api/
COPY cmd/ cmd/
COPY internal/ internal/

# Static, so the runtime image needs no libc. The manager talks to the API
# server and nothing else, so there is nothing to link against.
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/manager ./cmd/manager

# The manager holds no host privileges and reads no files, so it gets a
# runtime with no shell, no package manager and a non-root uid.
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=build /out/manager /manager
USER 65532:65532
ENTRYPOINT ["/manager"]
