all: build docker

build:
	go build ./tools/http_server

docker:
	bash ./script/build.sh

fixstyle:
	@gofmt -w .
	@go mod tidy

.PHONY: docker
