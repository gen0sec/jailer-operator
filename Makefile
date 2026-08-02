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
	@./hack/check-go-version.sh
	@git diff --exit-code -- api config || \
		{ echo; echo "generated files are out of date -- run 'make generate manifests'"; exit 1; }

IMG ?= jailer-operator:latest

.PHONY: docker-build
docker-build: ## build the manager image
	docker build -t $(IMG) .

.PHONY: docker-save
docker-save: docker-build ## export the image for side-loading into a cluster
	docker save $(IMG) -o jailer-operator.tar

.PHONY: install
install: manifests ## install the CRDs
	kubectl apply -f config/crd/bases

.PHONY: deploy
deploy: install ## install RBAC and the manager
	kubectl apply -f config/manager/manager.yaml
	kubectl apply -f config/rbac/role.yaml
	kubectl apply -f config/rbac/leader_election_role.yaml

.PHONY: undeploy
undeploy:
	-kubectl delete -f config/manager/manager.yaml
	-kubectl delete -f config/rbac/role.yaml
