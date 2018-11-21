# VPP interface stats client

This is a source code and a binary of a 'thin client' to collect, 
aggregate and expose VPP interface stats through VPP stats socket API. 
It also provides some information about the installed VPP version.

This can be used by monitoring systems that needs to grab those details 
through a simple executable client with no dependencies.

example use case: where VPP runs in a container that can't expose the socket API to the host level


## Prerequisites (for building)

**GoVPP** library (compatible with VPP 18.10)
vpp, vpp-api, vpp-lib

## Building

```bash
go get git.fd.io/govpp.git
go build
``` 

## Using (pre-built linux 64bit binary included)

```bash
./bin/vpp_if_stats_linux_amd64
```

## Output examples

[JSON schema](./response_schema.json)
[Example](./response_example.json)

