.PHONY: check test coverage vulncheck trivy verify clean

check:
	@test -z "$$(gofmt -s -l .)" || (echo "Unformatted files found. Run 'gofmt -s -w .' to fix them." && false)
	golangci-lint run ./modules/...
	go build ./...

test:
	go test -v -race ./...

coverage:
	go test -v -race -coverprofile=coverage.out ./modules/...
	go tool cover -func=coverage.out

vulncheck:
	govulncheck ./...

trivy:
	trivy fs --severity CRITICAL,HIGH .

verify: check test vulncheck trivy

clean:
	rm -rf coverage *.out .gocache
