# Sample SRv6 LocalSID documentation    {#srv6_plugin_doc}

## Introduction

This plugin is an example of how an user can create a new SRv6 LocalSID behavior by using VPP plugins with the appropiate API calls to the existing SR code.

This **example** plugin registers a new localsid behavior, with cli keyword 'new_srv6_localsid' which only takes one parameter, a fib-table. Upon recival of a packet, this plugin will enforce the next IP6 lookup in the specific fib-table specified by the user. (Indeed it will do the lookup in the fib_table n+1 (since for the shake of the example we increment the fib-table.)

Notice that the plugin only 'defines' a new SRv6 LocalSID behavior, but the existing SR code in VNET is the one actually instantiating new LocalSIDs. Notice that there are callback functions such that when you create or remove a LocalSID you can actually setup specific parameters through the functions in this plugin.

## Variables to watch for

* srv6_localsid_name: This variable is the name (used as a unique key) identifying this SR LocalSID plugin.
* keyword_str: This is the CLI keyword to be used for the plugin. In this example 'new_srv6_localsid'. (i.e. sr localsid address cafe::1 behavior new_srv6_localsid <parameters>)
* def_str: This is a definition of this SR behavior. This is printed when you do 'show sr localsid behaviors'.
* params_str: This is a definition of the parameters of this localsid. This is printed when you do 'show sr localsid behaviors'.

## Functions to watch for

* srv6_localsid_creation_fn: This function will be called every time a new SR LocalSID is instantiated with the behavior defined in this plugin. 
* srv6_localsid_removal_fn: This function will be called every time a new SR LocalSID is removed with the behavior defined in this plugin. This function tends to be used for freeing up all the memory created in the previous function.
* format_srv6_localsid_sample: This function prints nicely the parameters of every SR LocalSID using this behavior.
* unformat_srv6_localsid_sample: This function parses the CLI command when initialising a new SR LocalSID using this behavior. It parses all the parameters and ensures that the parameters are correct.
* format_srv6_localsid_sample_dpo: This function formats the 'show ip6 fib' message for the SR LocalSIDs created with this plugin behavior.

## Graph node

The current graph node uses the function 'end_srh_processing' to do the Segment Routing Endpoint behavior. Notice that it does not allow the cleanup of a Segment Routing header (as per the SRv6 behavior specs).
This function is identical to the one found in /src/vnet/srv6/sr_localsid.c
In case that by some other reason you want to do decapsulation, or SRH clean_up you can use the functions 'end_decaps_srh_processing' or 'end_psp_srh_processing' respectively.
