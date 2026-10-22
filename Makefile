.PHONY: build vet test fmt-check check

build:
	go build ./...

vet:
	go vet ./...

test:
	go test ./...

fmt-check:
	@out="$$(gofmt -l .)"; \
	if [ -n "$$out" ]; then \
		echo "gofmt required for:"; \
		echo "$$out"; \
		exit 1; \
	fi

check: build vet test fmt-check
