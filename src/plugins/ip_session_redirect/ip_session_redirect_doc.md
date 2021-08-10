# IP session redirect {#ip_session_redirect_doc}

This plugin allows to steer packet via different paths based on the
classifier.
It leverages the VPP classifier acl infrastructure (classifier, in_out_acl
etc), extending its capabilities so we can redirect traffic without having to
resort on additional VRFs.
It also allows to steer punted packets using the same mechanisms.

## Maturity level
Under development: it should work, but has not been thoroughly tested.

## Features
 - steer regular or/and punt traffic using the classifier
 - API

## Known limitations

### in-ACL and punt incompatibility
Enabling both classifier-based input ACLs and punt steering at the same time
on the same interface is not supported.

### Punt traffic originating from an interface not configured for steering will crash
Steering via input ACLs is enabled per interface whereas punt is enabled
globally. Because of that, if you enable punt steering on an interface and not
on others and punt traffic is received on an interface not configured for
steering, the input ACL node will crash.
Either enable punt steering on all intefaces or make sure you cannot punt
traffic originating not-configured interfaces.

## Quickstart
1. configure punting
```
~# vppctl set punt ipv4 udp all
```
2. create the classifier table and enable punt steering
```
~# vppctl classify table miss-next drop mask l3 ip4 src l4 udp src_port
buckets 100000
~# vppctl ip session redirect punt add pg0 table 0
```
3. add session to steer punted packets
```
~# vppctl ip session redirect table 0 match l3 ip4 src 10.10.10.10 l4 src_port 1234 via 10.10.0.10 pg1
```
