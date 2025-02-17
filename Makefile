run: test
	go run *.go

build: test
	go build -o socks5 *.go

test:
	go test -v .

.PHONY: run