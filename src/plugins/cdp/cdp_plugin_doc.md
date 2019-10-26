Cisco Discovery Protocol (CDP) plugin    {#cdp_plugin_doc}
========================

## Introduction

This plugin sends/receives CDP messages on enabled interfaces.

## Sample configuration
```console
vpp# show cdp  
CDP is not enabled...

comment { enable cdp globally }
vpp# cdp enable

vpp# show cdp
         Our Port                Peer System                Peer Port         Last Heard
   GigabitEthernet5/0/0             Switch             GigabitEthernet0/45      3747.2  
```
