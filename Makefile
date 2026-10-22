.PHONY: check test coverage vulncheck trivy secrets-scan verify clean

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

secrets-scan:
	gitleaks detect --source . --no-git --no-color -v --redact

verify: check test vulncheck trivy secrets-scan

clean:
	rm -rf coverage *.out .gocache *.log
