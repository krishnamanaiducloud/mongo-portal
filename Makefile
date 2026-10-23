VERSION ?= 0.0.1
COMMIT  ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
IMAGE   ?= docker.io/mohankrishna999/mongo-portal
PLATFORMS ?= linux/amd64,linux/arm64

.PHONY: test test-go test-web integration images smoke scan render push

test: test-go test-web

test-go:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go test -race -count=1 ./internal/...

test-web:
	cd web && npm ci --ignore-scripts && npm run lint && npm run typecheck && npm test && npm run build

integration:
	bash test/integration/run.sh

images:
	docker buildx build --load --target production --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) -t mongo-portal:production .
	docker buildx build --load --target debug      --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) -t mongo-portal:debug .

smoke:
	bash test/container/smoke.sh mongo-portal:production mongo-portal:debug

scan:
	bash scripts/security-scan.sh mongo-portal:production mongo-portal:debug

render:
	for env in dev test prod; do kubectl kustomize examples/kustomize/overlays/$$env > /dev/null && echo "$$env ok"; done

# Publishing is normally done by the CI release job. Manual use requires an
# explicit decision and `docker login`; existing tags are never overwritten.
push:
	@if docker buildx imagetools inspect $(IMAGE):$(VERSION) >/dev/null 2>&1; then echo "$(IMAGE):$(VERSION) exists"; exit 1; fi
	docker buildx build --platform $(PLATFORMS) --target production --sbom=true --provenance=mode=max \
	  --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) -t $(IMAGE):$(VERSION) --push .
	docker buildx build --platform $(PLATFORMS) --target debug --sbom=true --provenance=mode=max \
	  --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) -t $(IMAGE):$(VERSION)-debug --push .
