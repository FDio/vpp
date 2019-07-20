SRv6 Mobile User Plane Plugin for VPP
========================

## Introduction

This fork of VPP implements stateless mobile user plane protocols translation between GTP-U and SRv6.
The functions of the translation take advantage of SRv6 network programmability. 
[SRv6 Mobile User Plane](https://tools.ietf.org/html/draft-ietf-dmm-srv6-mobile-uplane-05) defines the user plane protocol using SRv6
including following stateless translations:

- T.M.GTP4.D:
 - GTP-U over UDP/IPv4 -> SRv6

- End.M.GTP4.E:
 -  SRv6 -> GTP-U over UDP/IPv4
- End.M.GTP6.D: 
 - GTP-U over UDP/IPv6 -> SRv6
- End.M.GTP6.E: 
 - SRv6 -> GTP-U over UDP/IPv6

These functions benefit both user plane(overlay) to be able to utilize data plane(underlay) networks properly. And also it benefits
data plane to be able to handle user plane in routing paradigm.

## Getting started
To play with SRv6 Mobile User Plane on VPP, you need to install following packages:

	docker
	python3

	Python packages (use pip):
	docker
	scapy
	jinja2


### Quick-start

1. Build up the docker container image as following:

```
$ git clone https://github.com/filvarga/srv6-mobile.git
$ cd ./srv6-mobile/extras/ietf105
$ ./runner.py infra build

```

### Test Scenarios
#### SRv6 Drop-in for GTP-U/UDP/IPv4

IPv4 payload over GTP-U:

```
./runner.py test tmap
```

IPv6 payload over GTP-U:
```
./runner.py test tmap_ipv6
```

#### SRv6 Drop-in for GTP-U/UDP/IPv6

IPv4 payload over GTP-U:

```
./runner.py test gtp6_drop_in
```

IPv6 payload over GTP-U:
```
./runner.py test gtp6_drop_in_ipv6
```


#### SRv6 from GTP-U/UDP/IPv6

IPv4 payload over GTP-U:

```
./runner.py test gtp6
```

IPv6 payload over GTP-U:
```
./runner.py test gtp6_ipv6
```

## More information
TBD

## Test Framework
TBD
