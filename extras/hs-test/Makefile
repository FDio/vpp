all: build docker

build:
	go build ./tools/http_server
	go build .

docker:
	bash ./script/build.sh

.PHONY: docker
