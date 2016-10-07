Per-packet IPFIX flow record plugin    {#flowperpkt_plugin_doc}
===================================

## Introduction

This plugin generates one ipfix record entry per packet transmitted
on interfaces which have the feature enabled

## Sample configuration

set ipfix exporter collector 192.168.6.2 src 192.168.6.1 template-interval 20 port 4739 path-mtu 1500

flowperpkt feature add-del GigabitEthernet2/3/0
