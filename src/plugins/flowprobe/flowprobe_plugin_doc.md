IPFIX flow record plugin    {#flowprobe_plugin_doc}
========================

## Introduction

This plugin generates ipfix flow records on interfaces which have the feature enabled

## Sample configuration

set ipfix exporter collector 192.168.6.2 src 192.168.6.1 template-interval 20 port 4739 path-mtu 1500

flowprobe params record l3 active 20 passive 120
flowprobe feature add-del GigabitEthernet2/3/0 l2