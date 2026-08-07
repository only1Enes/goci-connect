.PHONY: fmt fmt-check vet test test-race lint vuln check

GOLANGCI_LINT ?= golangci-lint
GOVULNCHECK ?= govulncheck

fmt:
	gofmt -w .

fmt-check:
	@files="$$(gofmt -l .)"; \
	if [ -n "$$files" ]; then \
		printf 'The following files need formatting:\n%s\n' "$$files"; \
		exit 1; \
	fi

vet:
	go vet ./...

test:
	go test ./...

test-race:
	go test -race ./...

lint:
	$(GOLANGCI_LINT) run ./...

vuln:
	$(GOVULNCHECK) ./...

check: fmt-check vet test lint
