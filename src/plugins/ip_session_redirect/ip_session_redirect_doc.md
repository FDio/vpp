# IP session redirect {#ip_session_redirect_doc}

This plugin allows to steer packet via different paths based on the
classifier.
It leverages the VPP classifier ACL infrastructure (classifier, in_out_acl
etc), extending its capabilities to redirect traffic without having to
resort on additional VRFs.
It also allows to steer punted packets using the same mechanism.

## Maturity level
Under development: it should work, but has not been thoroughly tested.

## Features
 - steer regular or/and punt traffic using the classifier
 - API

## Quickstart
1. configure punting
```
~# vppctl set punt ipv4 udp all
```
2. create the classifier table and uses it for punt ACL
```
~# vppctl classify table miss-next drop mask l3 ip4 src l4 udp src_port buckets 100000
~# vppctl set interface input acl intfc local0 ip4-punt-table 0
```
3. add session to steer punted packets
```
~# vppctl ip session redirect table 0 match l3 ip4 src 10.10.10.10 l4 src_port 1234 via 10.10.0.10 pg1
```
