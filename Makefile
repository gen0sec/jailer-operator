CONTROLLER_GEN ?= $(shell go env GOPATH)/bin/controller-gen
CONTROLLER_TOOLS_VERSION ?= v0.17.2

.PHONY: all
all: generate manifests fmt vet test

.PHONY: controller-gen
controller-gen:
	@test -x $(CONTROLLER_GEN) || \
		GOFLAGS=-mod=mod go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)

.PHONY: generate
generate: controller-gen ## deepcopy methods
	$(CONTROLLER_GEN) object:headerFile="" paths="./api/..."

.PHONY: manifests
manifests: controller-gen ## CRD yaml
	$(CONTROLLER_GEN) crd paths="./api/..." output:crd:artifacts:config=config/crd/bases

.PHONY: fmt
fmt:
	gofmt -w .

.PHONY: vet
vet:
	go vet ./...

.PHONY: test
test:
	go test -race ./...

.PHONY: verify
verify: generate manifests ## fail if generated files are stale
	@git diff --exit-code -- api config || \
		{ echo; echo "generated files are out of date -- run 'make generate manifests'"; exit 1; }
