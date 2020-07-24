Govpp Routing Table Download Example
====================================

Make sure that $GOPATH, $GOROOT, and $PATH are set. If you cloned the
govpp repo manually, you'll probably regret it.

Instead:

```
    go get git.fd.io/govpp.git
```

### Build and install the govpp binary api generator

```
    $ cd $GOPATH/src/git.fd.io/govpp.git/cmd/binapi-generator
    $ go install
    $ binapi-generator -version
    govpp v0.4.0-dev  # or some such
```
### Build and install VPP

Since this example depends on an as-yet-unmerged change to
.../src/vnet/ip/ip.api, you'll need to build and install vpp
release Debian packages:

```
   $ cd <vpp-workspace>
   $ make pkg-deb
   ...
   $ cd build-root
   $ sudo dpkg -i *.deb
```
### Generate Go bindings

Generating Go bindings for VPP binary API from the JSON files
installed with the vpp binary artifacts.

```
    $ cd $GOPATH/src/git.fd.io/govpp.git
    $ binapi-generator --output-dir=binapi
    INFO[0000] resolved import path prefix: git.fd.io/govpp.git/binapi
    INFO[0000] Generating 207 files
```

The golang binding files land here: $GOPATH/src/git.fd.io/govpp.git/binapi

### /etc/vpp/startup.conf parameter changes

You'll need to increase the ip heap size, and the statseg size to
load the (800K) prefixes in extras/govpp_route_download/internet-prefixes:

```
   ip {heap-size 1g} statseg { size 1G }
```

### Copy testvpp.go to $GOPATH/src and build the application

```
    $ cd $GOPATH/src
    $ mkdir govpp # or some such
    $ cd govpp
    $ cp <vpp-workspace>/extras/govpp_route_download/* .
    $ go build
```

### Run the test
```
    $ bunzip2 internet-prefixes.bz2
    $ sudo ./govpp file internet-prefixes
    Add routes from file...
    Done in 1.765144s, 817368 routes, 463060.15 routes/sec
    Delete 817368 routes...
    Done in 1.213310s, 673667.87 routes/sec
```
