# VPP interface stats client {#if_stats_client_doc}

This is a source code and a binary of a REST server to collect, 
aggregate and expose VPP interface stats through VPP API and stats sockets. 
It also provides some information about the installed VPP distribution.

This can be used by monitoring systems that needs to grab those details 
through a simple executable client with no dependencies.

Example use case: where VPP runs in a container 
that can't expose the socket API to host level


## Prerequisites (for building)

- go 1.12
- VPP shared libraries (matching target VPP version)

## How to build

```bash
GOOS=linux GOARCH=amd64 go build
``` 

## How to run

Help page
```bash
$ ./vpp_if_stats -h

  -api_socket_path string
    	Path to VPP API socket (default "/run/vpp/api.sock")
  -log_level string
    	Log level: (DEBUG, INFO, WARN or ERROR) (default "INFO")
  -no_retry_limit
    	If specified, will try to connect to VPP indefinitely
  -port int
    	Port to listen on (default 7670)
  -shm_prefix string
    	Shared memory prefix (advanced)
  -stats_socket_path string
    	Path to VPP stats socket (default "/run/vpp/stats.sock")
  -v	Prints vppifstats version

```

Server start example
```bash
$ ./vpp_if_stats -port=7670 -api_socket_path=/run/vpp-api.sock
2019-06-18T12:33:59.476Z|INFO|Connecting to VPP using API socket (/run/vpp-api.sock)
2019-06-18T12:33:59.479Z|INFO|Creating VPP API channel
2019-06-18T12:33:59.479Z|INFO|Connecting to stats socket (path: /run/vpp/stats.sock)
2019-06-18T12:33:59.479Z|INFO|Connection to VPP successful
2019-06-18T12:33:59.479Z|INFO|Listening on localhost:7670
```

## Usage
```bash
$ curl http://localhost:7670/
// See response_example.json
```

## Output examples

[JSON schema](./response_schema.json)

[Response example](./response_example.json)

