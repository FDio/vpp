SRv6 Mobile User Plane Plugin for VPP
========================

## Introduction

[SRv6 Mobile User Plane](https://tools.ietf.org/html/draft-ietf-dmm-srv6-mobile-uplane-05).


## Getting started
To play with SRv6 Mobile User Plane on VPP, you need to install following packages:

	docker
	python3

	Python packages (use pip):
	docker
	scapy
	jinja2


### Quick-start: On an existing Linux host

```
git clone https://github.com/filvarga/srv6-mobile.git
cd ./srv6-mobile/extras/ietf105
./runner.py infra build

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
