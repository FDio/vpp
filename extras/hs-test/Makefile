all: build docker

install-dep:
	apt update -y && apt install -y golang docker-ce apache2-utils wrk

build:
	go build ./tools/http_server

docker:
	bash ./script/build.sh

fixstyle:
	@gofmt -w .
	@go mod tidy

.PHONY: docker
