# Release Notes    {#release_notes}

* @subpage release_notes_2101
* @subpage release_notes_2009
* @subpage release_notes_20051
* @subpage release_notes_2005
* @subpage release_notes_2001
* @subpage release_notes_19083
* @subpage release_notes_19082
* @subpage release_notes_19081
* @subpage release_notes_1908
* @subpage release_notes_19043
* @subpage release_notes_19042
* @subpage release_notes_19041
* @subpage release_notes_1904
* @subpage release_notes_19013
* @subpage release_notes_19012
* @subpage release_notes_19011
* @subpage release_notes_1901
* @subpage release_notes_1810
* @subpage release_notes_1807
* @subpage release_notes_1804
* @subpage release_notes_18012
* @subpage release_notes_18011
* @subpage release_notes_1801
* @subpage release_notes_1710
* @subpage release_notes_1707
* @subpage release_notes_1704
* @subpage release_notes_17011
* @subpage release_notes_1701
* @subpage release_notes_1609
* @subpage release_notes_1606

@page release_notes_2101 Release notes for VPP 21.01

More than 562 commits since the previous release, including 274 fixes.

## Features

- Binary API Libraries
  - Vat2 and JSON autogeneration for API messages ([df87f8092](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=df87f8092))
- Plugins
  - AF\_XDP driver
    - Add option to claim all available RX queues ([d4e109138](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=d4e109138))
  - CNat
    - Disable default scanner process ([d63f73b83](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=d63f73b83))
    - IP ICMP error support ([ece39214b](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=ece39214b))
    - Add support for SNat ICMP ([613b2c3c7](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=613b2c3c7))
    - Introduce parametric source policy ([ce25b60de](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=ce25b60de))
    - Add DHCP support ([af897c5e3](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=af897c5e3))
  - Crypto - ipsecmb
    - Bump to intel-ipsec-mb version 0.55 ([b5df85e24](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b5df85e24))
  - DPDK
    - Call the meson-based build instead of Makefiles ([4c4633cad](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=4c4633cad))
    - Telemetry thread is off by default. ([83f37fc3b](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=83f37fc3b))
    - Bump to DPDK 20.11 ([f0419a0c8](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f0419a0c8))
  - Internet Key Exchange (IKEv2) Protocol
    - Support IPv6 traffic selectors & overlay ([84962d19b](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=84962d19b))
    - CLI for disabling dead peer detection ([af4a414eb](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=af4a414eb))
    - Add option to disable NAT traversal ([d7fc12f07](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=d7fc12f07))
  - RDMA (ibverb) driver
    - Add RSS support for IPv6 and TCP ([91603958d](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=91603958d))
  - VRRP
    - Asynchronous events on VR state change ([78f487e11](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=78f487e11))
  - Wireguard
    - Return public key in API ([de22111b5](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=de22111b5))
  - Flowprobe
    - Add show commands for params and list of interfaces for recording ([d1146f6dd](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=d1146f6dd))
- Python binding for the VPP API
  -  add support for enumflag part 1 of 2 ([3825d93af](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=3825d93af))
- SVM Library
  - Support for multi-segment enqueues ([c95cfa218](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c95cfa218))
- Statistics Segment
  - Counters data model ([148c7b768](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=148c7b768))
- VNET
  - FIB
    - Source Address Selection ([e2fe09742](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e2fe09742))
    - Adjacency flag for midchain to perfom flow hash (on inner packet) ([5c544c8c3](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=5c544c8c3))
  - Feature Arcs
    - Add packet trace API ([c0b195450](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c0b195450))
  - IPSec
    - Support for multipoint on IPSec interfaces ([6ba4e41d3](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=6ba4e41d3))
    - Tunnel SA DSCP behaviour ([041add7d1](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=041add7d1))
  - Native Virtio Drivers
    - Add packet buffering on transmit path ([e347acbc3](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e347acbc3))
    - Virtio: implement packed queues from virtio 1.1 ([b977d3f7c](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b977d3f7c))
  - Segment Routing (IPv6 and MPLS)
    - Show IPv6 address used as SRv6 Encaps source ([448bc81d3](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=448bc81d3))
    - Show the hop-limit value used for SRv6 encapsulation ([80f0b88fc](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=80f0b88fc))
  - Session Layer
    - Add Unix socket API for app attachment ([61ae056bd](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=61ae056bd))
    - Per worker state for ct sessions ([2d0e3de14](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=2d0e3de14))
  - TAP Drivers
    - Allow change of carrier state on host ([bd50ed18d](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=bd50ed18d))
    - Add function to set speed ([a6c34a19d](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=a6c34a19d))
- VPP Comms Library
  - Add support for app socket API ([935ce75cb](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=935ce75cb))
  - Provide apps access to fifo chunks ([d68faf855](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=d68faf855))
- VPP Executable
  - Use VPP heap for libc ([ec4749a20](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=ec4749a20))
- Vector Library - Buffer Management
  - Add page-size config ([61559029d](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=61559029d))

## Known issues

For the full list of issues please refer to fd.io [JIRA](https://jira.fd.io).

## Fixed issues

For the full list of fixed issues please refer to:
- fd.io [JIRA](https://jira.fd.io)
- git [commit log](https://git.fd.io/vpp/log/?h=master)


## API changes

Description of results:

* _Definition changed_: indicates that the API file was modified between releases.
* _Only in image_: indicates the API is new for this release.
* _Only in file_: indicates the API has been removed in this release.

Message Name                                                 | Result
-------------------------------------------------------------|------------------
classify_pcap_get_tables                                     | only in image
classify_pcap_get_tables_reply                               | only in image
classify_pcap_lookup_table                                   | only in image
classify_pcap_lookup_table_reply                             | only in image
classify_pcap_set_table                                      | only in image
classify_pcap_set_table_reply                                | only in image
classify_trace_get_tables                                    | only in image
classify_trace_get_tables_reply                              | only in image
classify_trace_lookup_table                                  | only in image
classify_trace_lookup_table_reply                            | only in image
classify_trace_set_table                                     | only in image
classify_trace_set_table_reply                               | only in image
cnat_get_snat_addresses                                      | only in image
cnat_get_snat_addresses_reply                                | only in image
cnat_session_details                                         | definition changed
cnat_set_snat_addresses                                      | definition changed
cnat_translation_details                                     | definition changed
cnat_translation_update                                      | definition changed
det44_plugin_enable_disable                                  | definition changed
graph_node_details                                           | only in image
graph_node_get                                               | only in image
graph_node_get_reply                                         | only in image
ikev2_profile_details                                        | definition changed
ikev2_profile_disable_natt                                   | only in image
ikev2_profile_disable_natt_reply                             | only in image
ikev2_profile_set_ts                                         | definition changed
ikev2_sa_details                                             | definition changed
ikev2_set_responder                                          | definition changed
ikev2_traffic_selector_details                               | definition changed
ip_mroute_add_del                                            | definition changed
ip_mroute_details                                            | definition changed
ip_neighbor_event_v2                                         | only in image
ipsec_sa_v2_details                                          | only in image
ipsec_sa_v2_dump                                             | only in image
ipsec_sad_entry_add_del_v2                                   | only in image
ipsec_sad_entry_add_del_v2_reply                             | only in image
nat44_plugin_enable_disable                                  | only in image
nat44_plugin_enable_disable_reply                            | only in image
nat44_show_running_config                                    | only in image
nat44_show_running_config_reply                              | only in image
nat64_get_timeouts                                           | only in image
nat64_get_timeouts_reply                                     | only in image
nat64_plugin_enable_disable                                  | only in image
nat64_plugin_enable_disable_reply                            | only in image
nat64_set_timeouts                                           | only in image
nat64_set_timeouts_reply                                     | only in image
pppoe_add_del_cp                                             | only in image
pppoe_add_del_cp_reply                                       | only in image
rdma_create_v2                                               | only in image
rdma_create_v2_reply                                         | only in image
sw_vmxnet3_interface_details                                 | only in image
sw_vmxnet3_interface_dump                                    | only in image
trace_capture_packets                                        | only in image
trace_capture_packets_reply                                  | only in image
trace_clear_capture                                          | only in image
trace_clear_capture_reply                                    | only in image
trace_details                                                | definition changed
trace_set_filters                                            | only in image
trace_set_filters_reply                                      | only in image
vrrp_vr_event                                                | only in image
want_ip_neighbor_events_v2                                   | only in image
want_ip_neighbor_events_v2_reply                             | only in image
want_vrrp_vr_events                                          | only in image
want_vrrp_vr_events_reply                                    | only in image
wireguard_interface_create                                   | definition changed
wireguard_interface_details                                  | definition changed

Found 66 api message signature differences


### Newly deprecated API messages

These messages are still there in the API, but can and probably
will disappear in the next release.

- geneve_add_del_tunnel
- ip_neighbor_event
- nat44_forwarding_enable_disable
- nat44_forwarding_enable_disable_reply
- nat44_forwarding_is_enabled
- nat44_forwarding_is_enabled_reply
- nat44_session_cleanup
- nat44_session_cleanup_reply
- nat_control_ping
- nat_control_ping_reply
- nat_get_timeouts
- nat_get_timeouts_reply
- nat_ipfix_enable_disable
- nat_ipfix_enable_disable_reply
- nat_set_log_level
- nat_set_log_level_reply
- nat_set_timeouts
- nat_set_timeouts_reply
- nat_show_config
- nat_show_config_2
- nat_show_config_2_reply
- nat_show_config_reply
- rdma_create
- vmxnet3_dump
- want_ip_neighbor_events
- want_ip_neighbor_events_reply

### In-progress API messages

These messages are provided for testing and experimentation only.
They are *not* subject to any compatibility process,
and therefore can arbitrarily change or disappear at *any* moment.
Also they may have less than satisfactory testing, making
them unsuitable for other use than the technology preview.
If you are intending to use these messages in production projects,
please collaborate with the feature maintainer on their productization.

- abf_itf_attach_add_del
- abf_itf_attach_add_del_reply
- abf_itf_attach_details
- abf_itf_attach_dump
- abf_plugin_get_version
- abf_plugin_get_version_reply
- abf_policy_add_del
- abf_policy_add_del_reply
- abf_policy_details
- abf_policy_dump
- adl_allowlist_enable_disable
- adl_allowlist_enable_disable_reply
- adl_interface_enable_disable
- adl_interface_enable_disable_reply
- af_xdp_create
- af_xdp_create_reply
- af_xdp_delete
- af_xdp_delete_reply
- cnat_add_del_snat_prefix
- cnat_add_del_snat_prefix_reply
- cnat_get_snat_addresses
- cnat_get_snat_addresses_reply
- cnat_session_details
- cnat_session_dump
- cnat_session_purge
- cnat_session_purge_reply
- cnat_set_snat_addresses
- cnat_set_snat_addresses_reply
- cnat_translation_del
- cnat_translation_del_reply
- cnat_translation_details
- cnat_translation_dump
- cnat_translation_update
- cnat_translation_update_reply
- crypto_sw_scheduler_set_worker
- crypto_sw_scheduler_set_worker_reply
- det44_get_timeouts_reply
- det44_interface_add_del_feature
- det44_interface_add_del_feature_reply
- det44_interface_details
- det44_interface_dump
- det44_plugin_enable_disable
- det44_plugin_enable_disable_reply
- det44_set_timeouts
- det44_set_timeouts_reply
- flow_add
- flow_add_reply
- flow_del
- flow_del_reply
- flow_disable
- flow_disable_reply
- flow_enable
- flow_enable_reply
- gbp_bridge_domain_add
- gbp_bridge_domain_add_reply
- gbp_bridge_domain_del
- gbp_bridge_domain_del_reply
- gbp_bridge_domain_details
- gbp_bridge_domain_dump
- gbp_bridge_domain_dump_reply
- gbp_contract_add_del
- gbp_contract_add_del_reply
- gbp_contract_details
- gbp_contract_dump
- gbp_endpoint_add
- gbp_endpoint_add_reply
- gbp_endpoint_del
- gbp_endpoint_del_reply
- gbp_endpoint_details
- gbp_endpoint_dump
- gbp_endpoint_group_add
- gbp_endpoint_group_add_reply
- gbp_endpoint_group_del
- gbp_endpoint_group_del_reply
- gbp_endpoint_group_details
- gbp_endpoint_group_dump
- gbp_ext_itf_add_del
- gbp_ext_itf_add_del_reply
- gbp_ext_itf_details
- gbp_ext_itf_dump
- gbp_recirc_add_del
- gbp_recirc_add_del_reply
- gbp_recirc_details
- gbp_recirc_dump
- gbp_route_domain_add
- gbp_route_domain_add_reply
- gbp_route_domain_del
- gbp_route_domain_del_reply
- gbp_route_domain_details
- gbp_route_domain_dump
- gbp_route_domain_dump_reply
- gbp_subnet_add_del
- gbp_subnet_add_del_reply
- gbp_subnet_details
- gbp_subnet_dump
- gbp_vxlan_tunnel_add
- gbp_vxlan_tunnel_add_reply
- gbp_vxlan_tunnel_del
- gbp_vxlan_tunnel_del_reply
- gbp_vxlan_tunnel_details
- gbp_vxlan_tunnel_dump
- ikev2_child_sa_details
- ikev2_child_sa_dump
- ikev2_initiate_del_child_sa
- ikev2_initiate_del_child_sa_reply
- ikev2_initiate_del_ike_sa
- ikev2_initiate_del_ike_sa_reply
- ikev2_initiate_rekey_child_sa
- ikev2_initiate_rekey_child_sa_reply
- ikev2_initiate_sa_init
- ikev2_initiate_sa_init_reply
- ikev2_nonce_get
- ikev2_nonce_get_reply
- ikev2_profile_add_del
- ikev2_profile_add_del_reply
- ikev2_profile_details
- ikev2_profile_disable_natt
- ikev2_profile_disable_natt_reply
- ikev2_profile_dump
- ikev2_profile_set_auth
- ikev2_profile_set_auth_reply
- ikev2_profile_set_id
- ikev2_profile_set_id_reply
- ikev2_profile_set_ipsec_udp_port
- ikev2_profile_set_ipsec_udp_port_reply
- ikev2_profile_set_liveness
- ikev2_profile_set_liveness_reply
- ikev2_profile_set_ts
- ikev2_profile_set_ts_reply
- ikev2_profile_set_udp_encap
- ikev2_profile_set_udp_encap_reply
- ikev2_sa_details
- ikev2_sa_dump
- ikev2_set_esp_transforms
- ikev2_set_esp_transforms_reply
- ikev2_set_ike_transforms
- ikev2_set_ike_transforms_reply
- ikev2_set_local_key
- ikev2_set_local_key_reply
- ikev2_set_responder
- ikev2_set_responder_reply
- ikev2_set_sa_lifetime
- ikev2_set_sa_lifetime_reply
- ikev2_set_tunnel_interface
- ikev2_set_tunnel_interface_reply
- ikev2_traffic_selector_details
- ikev2_traffic_selector_dump
- l2_emulation
- l2_emulation_reply
- mdata_enable_disable
- mdata_enable_disable_reply
- nat44_add_del_static_mapping_v2
- nat44_add_del_static_mapping_v2_reply
- nat44_show_running_config
- nat44_show_running_config_reply
- nat64_plugin_enable_disable
- nat64_plugin_enable_disable_reply
- oddbuf_enable_disable
- oddbuf_enable_disable_reply
- pg_interface_enable_disable_coalesce
- pg_interface_enable_disable_coalesce_reply
- sample_macswap_enable_disable
- sample_macswap_enable_disable_reply
- sr_policies_with_sl_index_details
- sr_policies_with_sl_index_dump
- sw_interface_set_vxlan_gbp_bypass
- sw_interface_set_vxlan_gbp_bypass_reply
- test_enum
- test_enum_reply
- test_prefix
- test_prefix_reply
- trace_capture_packets
- trace_capture_packets_reply
- trace_clear_capture
- trace_clear_capture_reply
- trace_details
- trace_dump
- trace_dump_reply
- trace_set_filters
- trace_set_filters_reply
- vxlan_gbp_tunnel_add_del
- vxlan_gbp_tunnel_add_del_reply
- vxlan_gbp_tunnel_details
- vxlan_gbp_tunnel_dump
- wireguard_interface_create
- wireguard_interface_create_reply
- wireguard_interface_delete
- wireguard_interface_delete_reply
- wireguard_interface_details
- wireguard_interface_dump
- wireguard_peer_add
- wireguard_peer_add_reply
- wireguard_peer_remove
- wireguard_peer_remove_reply
- wireguard_peers_details
- wireguard_peers_dump

### Patches that changed API definitions

| @c src/vpp/api/vpe_types.api ||
| ------- | ------- |
| [dc01471be](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=dc01471be) | api: add missing version info |

| @c src/vat2/test/vat2_test.api ||
| ------- | ------- |
| [58a6e7725](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=58a6e7725) | api: crchcecker ignore version < 1.0.0 and outside of src directory |
| [510aaa891](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=510aaa891) | api: crchcecker ignore version < 1.0.0 and outside of src directory |
| [793be4632](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=793be4632) | api: fromjson/tojson enum flag support |

| @c src/vnet/mpls/mpls.api ||
| ------- | ------- |
| [df87f8092](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=df87f8092) | api: vat2 and json autogeneration for api messages |

| @c src/vnet/ipip/ipip.api ||
| ------- | ------- |
| [33c45f56a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=33c45f56a) | fib: supporting inner flow hash on tunnels |

| @c src/vnet/vxlan-gbp/vxlan_gbp.api ||
| ------- | ------- |
| [b468773aa](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b468773aa) | vxlan-gbp: Mark APIs as in-progress |

| @c src/vnet/ipsec/ipsec.api ||
| ------- | ------- |
| [041add7d1](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=041add7d1) | ipsec: Tunnel SA DSCP behaviour |
| [f916414b3](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f916414b3) | api: clean up use of deprecated flag |

| @c src/vnet/ipsec/ipsec_types.api ||
| ------- | ------- |
| [041add7d1](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=041add7d1) | ipsec: Tunnel SA DSCP behaviour |

| @c src/vnet/tunnel/tunnel_types.api ||
| ------- | ------- |
| [dc01471be](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=dc01471be) | api: add missing version info |
| [33c45f56a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=33c45f56a) | fib: supporting inner flow hash on tunnels |

| @c src/vnet/classify/classify.api ||
| ------- | ------- |
| [5c1e48c01](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=5c1e48c01) | classify: add pcap/trace classfier mgmt API calls |

| @c src/vnet/ipfix-export/ipfix_export.api ||
| ------- | ------- |
| [f6cf57ceb](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f6cf57ceb) | misc: fix api in ipfix_classify_table_add/details |

| @c src/vnet/mfib/mfib_types.api ||
| ------- | ------- |
| [dc01471be](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=dc01471be) | api: add missing version info |
| [990f69450](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=990f69450) | ip: convert u32 entry_flags to vl_api_mfib_entry_flags_t on mroute API |

| @c src/vnet/gre/gre.api ||
| ------- | ------- |
| [33c45f56a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=33c45f56a) | fib: supporting inner flow hash on tunnels |

| @c src/vnet/ip/ip_types.api ||
| ------- | ------- |
| [6dc0c8d14](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=6dc0c8d14) | ip: Sub Address Family types. Feature enable for each SAFI |

| @c src/vnet/ip/ip.api ||
| ------- | ------- |
| [df87f8092](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=df87f8092) | api: vat2 and json autogeneration for api messages |
| [990f69450](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=990f69450) | ip: convert u32 entry_flags to vl_api_mfib_entry_flags_t on mroute API |

| @c src/vnet/ethernet/ethernet_types.api ||
| ------- | ------- |
| [dc01471be](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=dc01471be) | api: add missing version info |

| @c src/vnet/l2/l2.api ||
| ------- | ------- |
| [df87f8092](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=df87f8092) | api: vat2 and json autogeneration for api messages |

| @c src/vnet/cop/cop.api ||
| ------- | ------- |
| [6c8cdf78b](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=6c8cdf78b) | misc: cop - clean up stray doxygen block |
| [f916414b3](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f916414b3) | api: clean up use of deprecated flag |

| @c src/vnet/crypto/crypto.api ||
| ------- | ------- |
| [8c91b2ae2](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=8c91b2ae2) | crypto: Crypto set handler API to support set all as CLI |

| @c src/vnet/devices/virtio/virtio.api ||
| ------- | ------- |
| [e347acbc3](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e347acbc3) | virtio: add packet buffering on transmit path |
| [f916414b3](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f916414b3) | api: clean up use of deprecated flag |

| @c src/vnet/interface_types.api ||
| ------- | ------- |
| [dc01471be](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=dc01471be) | api: add missing version info |

| @c src/vnet/ip-neighbor/ip_neighbor.api ||
| ------- | ------- |
| [4ac36bcb1](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=4ac36bcb1) | ip-neighbor: Send API event when neighbor is removed |

| @c src/vnet/policer/policer_types.api ||
| ------- | ------- |
| [dc01471be](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=dc01471be) | api: add missing version info |

| @c src/vnet/srv6/sr_types.api ||
| ------- | ------- |
| [dc01471be](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=dc01471be) | api: add missing version info |

| @c src/plugins/map/map.api ||
| ------- | ------- |
| [148c7b768](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=148c7b768) | stats: counters data model |
| [f916414b3](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f916414b3) | api: clean up use of deprecated flag |

| @c src/plugins/nat/nat64/nat64.api ||
| ------- | ------- |
| [1f36023d2](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=1f36023d2) | nat: move nat64 to a subfeature |

| @c src/plugins/nat/det44/det44.api ||
| ------- | ------- |
| [d1762e614](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=d1762e614) | nat: det44 plugin fix style and api cleanup |
| [f916414b3](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f916414b3) | api: clean up use of deprecated flag |

| @c src/plugins/nat/nat44.api ||
| ------- | ------- |
| [df87f8092](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=df87f8092) | api: vat2 and json autogeneration for api messages |
| [25fd8ad03](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=25fd8ad03) | nat: cleanup & reorganization |
| [b227aa699](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b227aa699) | nat: api,cli and test update & cleanup |

| @c src/plugins/nat/nat_types.api ||
| ------- | ------- |
| [25fd8ad03](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=25fd8ad03) | nat: cleanup & reorganization |

| @c src/plugins/lisp/lisp-cp/one.api ||
| ------- | ------- |
| [2b202bc4b](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=2b202bc4b) | lisp: Move to plugin |

| @c src/plugins/lisp/lisp-cp/lisp.api ||
| ------- | ------- |
| [068ad25c1](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=068ad25c1) | lisp: .api dont set defaults in reply messages |
| [2b202bc4b](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=2b202bc4b) | lisp: Move to plugin |

| @c src/plugins/lisp/lisp-cp/lisp_types.api ||
| ------- | ------- |
| [2b202bc4b](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=2b202bc4b) | lisp: Move to plugin |

| @c src/plugins/lisp/lisp-gpe/lisp_gpe.api ||
| ------- | ------- |
| [2b202bc4b](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=2b202bc4b) | lisp: Move to plugin |

| @c src/plugins/nsim/nsim.api ||
| ------- | ------- |
| [f916414b3](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f916414b3) | api: clean up use of deprecated flag |

| @c src/plugins/lb/lb_types.api ||
| ------- | ------- |
| [dc01471be](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=dc01471be) | api: add missing version info |

| @c src/plugins/lb/lb.api ||
| ------- | ------- |
| [df87f8092](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=df87f8092) | api: vat2 and json autogeneration for api messages |

| @c src/plugins/pppoe/pppoe.api ||
| ------- | ------- |
| [340b10a38](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=340b10a38) | pppoe: make pppoe plugin work with dot1q subinterfaces |

| @c src/plugins/geneve/geneve.api ||
| ------- | ------- |
| [3a6adc52f](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=3a6adc52f) | geneve: Move to plugin |

| @c src/plugins/vmxnet3/vmxnet3.api ||
| ------- | ------- |
| [490e077fb](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=490e077fb) | vmxnet3: add sw_if_index filter to vmxnet3 interface dump |

| @c src/plugins/wireguard/wireguard.api ||
| ------- | ------- |
| [de22111b5](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=de22111b5) | wireguard: return public key in api |

| @c src/plugins/l2tp/l2tp.api ||
| ------- | ------- |
| [6810a77da](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=6810a77da) | misc: Move l2tp to plugin |

| @c src/plugins/acl/acl.api ||
| ------- | ------- |
| [df87f8092](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=df87f8092) | api: vat2 and json autogeneration for api messages |

| @c src/plugins/acl/acl_types.api ||
| ------- | ------- |
| [dc01471be](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=dc01471be) | api: add missing version info |

| @c src/plugins/rdma/rdma.api ||
| ------- | ------- |
| [798267aaa](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=798267aaa) | rdma: implement multiseg rx without striding rq |

| @c src/plugins/ikev2/ikev2.api ||
| ------- | ------- |
| [d7fc12f07](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=d7fc12f07) | ikev2: add option to disable NAT traversal |
| [84962d19b](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=84962d19b) | ikev2: support ipv6 traffic selectors & overlay |

| @c src/plugins/ikev2/ikev2_types.api ||
| ------- | ------- |
| [dc01471be](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=dc01471be) | api: add missing version info |
| [d7fc12f07](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=d7fc12f07) | ikev2: add option to disable NAT traversal |
| [84962d19b](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=84962d19b) | ikev2: support ipv6 traffic selectors & overlay |

| @c src/plugins/cnat/cnat.api ||
| ------- | ------- |
| [2082835fe](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=2082835fe) | cnat: allow max_u16 translation backends |
| [af897c5e3](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=af897c5e3) | cnat: Add DHCP support |

| @c src/plugins/tracedump/tracedump.api ||
| ------- | ------- |
| [c0b195450](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c0b195450) | feature: Add packet trace API |

| @c src/plugins/tracedump/graph.api ||
| ------- | ------- |
| [c0b195450](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c0b195450) | feature: Add packet trace API |

| @c src/plugins/vrrp/vrrp.api ||
| ------- | ------- |
| [78f487e11](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=78f487e11) | vrrp: asynchronous events on VR state change |

| @c src/plugins/flowprobe/flowprobe.api ||
| ------- | ------- |
| [df87f8092](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=df87f8092) | api: vat2 and json autogeneration for api messages |

| @c src/plugins/lldp/lldp.api ||
| ------- | ------- |
| [3f9fdd984](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=3f9fdd984) | lldp: Move to plugin |

| @c src/plugins/memif/memif.api ||
| ------- | ------- |
| [6223766f9](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=6223766f9) | libmemif: clean up typos |

| @c src/plugins/dns/dns.api ||
| ------- | ------- |
| [df87f8092](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=df87f8092) | api: vat2 and json autogeneration for api messages |

| @c src/plugins/stn/stn.api ||
| ------- | ------- |
| [df87f8092](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=df87f8092) | api: vat2 and json autogeneration for api messages |

| @c src/plugins/af_xdp/af_xdp.api ||
| ------- | ------- |
| [d4e109138](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=d4e109138) | af_xdp: add option to claim all available rx queues |

| @c src/plugins/gbp/gbp.api ||
| ------- | ------- |
| [df87f8092](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=df87f8092) | api: vat2 and json autogeneration for api messages |


@page release_notes_2009 Release notes for VPP 20.09

More than 458 commits since the previous release, including 266 fixes.

## Release Highlights

The FD.io VPP 20.09 release added a number of notable new features. In plugins,
the I/O layer added support for the Linux AF\_XDP interface with the AF\_XDP
plugin. New plugins where added supporting both the Wireguard security protocol
and CNAT destination based address translation, and the existing IKEv2 plugin
added support for NAT-T. In the cryptography layer, support was added for
synchronous software crypto engines, enabling users to allocate dedicated crypto
worker threads. The flow layer added support for steering IPSEC ESP/AH flows to
worker threads. GRO support was added to the packet coalescing library.

This release introduces the new FD.io VPP API change policy to ensure
backwards-compatibility. The policy will ensure seamless upgrades to new
versions of FD.io VPP in future, provided no "in-progress" or deprecated APIs
are in use. Enabling the FD.io community to enjoy the benefits of new releases,
while minimizing the work involved in staying current.

If you dive into the implementation, you will note that policy in action. A
number of modified API messages have had their original versions maintained to
ensure compatibility.

Reflecting the new policy we added two new sections to the release notes
describing:
- Newly deprecated API messages: please note that if you are using a deprecated
message, they will soon be removed in a subsequent release. Collaborate with
the feature maintainer on the best approach to mitigate.
- In-progress API messages: They are work-in-progress, and are *not* subject to
the policy, and may change or even be removed at any time. Please collaborate
with the feature maintainer on plans to productize the message before using in
any product. In-progress APIs must eventually become stable or be removed.

## Features

- VNET
  - Crypto Infra
    - Add chacha20-poly1305 algo (61f49aa38)
    - Asynchronous crypto engines (2284817ea)
    - Add asynchronous crypto APIs (0c936b147)
    - Added support for optimized cryptodev API (ef80ad6bf)
  - FLOW
    - Added ability to steer IPSec ESP/AH flows to worker threads (d4c3666b9)
    - Added the vnet/flow API (d0236f725)
  - GENEVE
    - Support geneve interface acting as a bvi (7fc88cf3a)
  - GSO
    - Added software GRO support (f382b06fe)
  - IPSec
    - Dedicated IPSec interface type (dd4ccf262)
    - Deprecate old interface API (e6df80de4)
  - Interface Common
    - Support configuring RSS steering queues (c4665093c)
  - Native Virtio Drivers
    - Add vhost sw\_if\_index filter for sw\_interface\_vhost\_user\_dump (a0e8d9669)
    - Add modern device support (379aac395)
    - Add virtio 1.1 api flags (518251bc8)
  - TAP Drivers
    - Add gro support (9e2a78564)
    - Add virtio 1.1 API flag (50bd16559)
  - TCP
    - Track reorder with selective acknowledgments (cc4d6d022)
- Plugins
  - AF\_XDP driver
    - New plugin for Linux AF\_XDP input (4a76d6f6d)
  - CNat
    - New plugin for destination based NAT (29f3c7d2e)
  - Wireguard
    - New plugin, initial implementation of wireguard protocol (edca1325c)
  - Crypto - OpenSSL
    - Add chacha20-poly1305 support to crypto-openssl (1b6ed022e)
  - DPDK
    - Device\_id sorted order for cryptodev (5a849e3b3)
    - Call the meson-based build instead of Makefiles (73903d7e8)
  - Internet Key Exchange (IKEv2) Protocol
    - Add support for NAT traversal (NAT-T) (4362baa33)
    - Add profile dump API (6a9bd8188)
    - Add support for AES-GCM cipher in IKE (a7b963df2)
    - Add SA dump API (a340fe1ac)
  - Network Delay Simulator
    - Basic reorder support (e6c3e8f0e)
- VPP Comms Library
  - Nest vcl\_mq\_epfd to support epoll\_wait without high CPU usage (4266d4d5f)
  - Support connected udp listens (1e96617d9)
  - Support inter worker rpc (40c07ce7a)
  - Support multi-threads with session migration (a3a489691)
- Vector Library
  - Add recursive macro expander to debug cli (961e3c842)
- Binary API Libraries
  - Add new stream message convention (f5db3711b)
  - Make VPP api handlers endian independent (e796a1873)
- Infrastructure Library
  - Multiarch support for OCTEONTX2 SoC (e2f5236dc)

## Known issues

For the full list of issues please refer to fd.io [JIRA](https://jira.fd.io).

## Fixed issues

For the full list of fixed issues please refer to:
- fd.io [JIRA](https://jira.fd.io)
- git [commit log](https://git.fd.io/vpp/log/?h=stable/2009)


## API changes

Description of results:

* _Definition changed_: indicates that the API file was modified between releases.
* _Only in image_: indicates the API is new for this release.
* _Only in file_: indicates the API has been removed in this release.

Message Name                                                 | Result
-------------------------------------------------------------|------------------
adl_allowlist_enable_disable                                 | only in image
adl_allowlist_enable_disable_reply                           | only in image
adl_interface_enable_disable                                 | only in image
adl_interface_enable_disable_reply                           | only in image
bond_add_member                                              | only in image
bond_add_member_reply                                        | only in image
bond_create2                                                 | only in image
bond_create2_reply                                           | only in image
bond_detach_member                                           | only in image
bond_detach_member_reply                                     | only in image
cnat_add_del_snat_prefix                                     | only in image
cnat_add_del_snat_prefix_reply                               | only in image
cnat_session_details                                         | only in image
cnat_session_dump                                            | only in image
cnat_session_purge                                           | only in image
cnat_session_purge_reply                                     | only in image
cnat_set_snat_addresses                                      | only in image
cnat_set_snat_addresses_reply                                | only in image
cnat_translation_del                                         | only in image
cnat_translation_del_reply                                   | only in image
cnat_translation_details                                     | only in image
cnat_translation_dump                                        | only in image
cnat_translation_update                                      | only in image
cnat_translation_update_reply                                | only in image
crypto_set_async_dispatch                                    | only in image
crypto_set_async_dispatch_reply                              | only in image
crypto_set_handler                                           | only in image
crypto_set_handler_reply                                     | only in image
crypto_sw_scheduler_set_worker                               | only in image
crypto_sw_scheduler_set_worker_reply                         | only in image
det44_add_del_map                                            | only in image
det44_add_del_map_reply                                      | only in image
det44_close_session_in                                       | only in image
det44_close_session_in_reply                                 | only in image
det44_close_session_out                                      | only in image
det44_close_session_out_reply                                | only in image
det44_forward                                                | only in image
det44_forward_reply                                          | only in image
det44_get_timeouts                                           | only in image
det44_get_timeouts_reply                                     | only in image
det44_interface_add_del_feature                              | only in image
det44_interface_add_del_feature_reply                        | only in image
det44_interface_details                                      | only in image
det44_interface_dump                                         | only in image
det44_map_details                                            | only in image
det44_map_dump                                               | only in image
det44_plugin_enable_disable                                  | only in image
det44_plugin_enable_disable_reply                            | only in image
det44_reverse                                                | only in image
det44_reverse_reply                                          | only in image
det44_session_details                                        | only in image
det44_session_dump                                           | only in image
det44_set_timeouts                                           | only in image
det44_set_timeouts_reply                                     | only in image
flow_add                                                     | only in image
flow_add_reply                                               | only in image
flow_del                                                     | only in image
flow_del_reply                                               | only in image
flow_disable                                                 | only in image
flow_disable_reply                                           | only in image
flow_enable                                                  | only in image
flow_enable_reply                                            | only in image
geneve_add_del_tunnel2                                       | only in image
geneve_add_del_tunnel2_reply                                 | only in image
gtpu_add_del_tunnel                                          | definition changed
gtpu_tunnel_details                                          | definition changed
gtpu_tunnel_update_tteid                                     | only in image
gtpu_tunnel_update_tteid_reply                               | only in image
ikev2_child_sa_details                                       | only in image
ikev2_child_sa_dump                                          | only in image
ikev2_nonce_get                                              | only in image
ikev2_nonce_get_reply                                        | only in image
ikev2_profile_details                                        | only in image
ikev2_profile_dump                                           | only in image
ikev2_profile_set_ts                                         | definition changed
ikev2_sa_details                                             | only in image
ikev2_sa_dump                                                | only in image
ikev2_set_esp_transforms                                     | definition changed
ikev2_set_ike_transforms                                     | definition changed
ikev2_set_responder                                          | definition changed
ikev2_traffic_selector_details                               | only in image
ikev2_traffic_selector_dump                                  | only in image
ipsec_itf_create                                             | only in image
ipsec_itf_create_reply                                       | only in image
ipsec_itf_delete                                             | only in image
ipsec_itf_delete_reply                                       | only in image
ipsec_itf_details                                            | only in image
ipsec_itf_dump                                               | only in image
ipsec_set_async_mode                                         | only in image
ipsec_set_async_mode_reply                                   | only in image
map_domains_get                                              | only in image
map_domains_get_reply                                        | only in image
nat44_add_del_static_mapping_v2                              | only in image
nat44_add_del_static_mapping_v2_reply                        | only in image
nat_show_config_2                                            | only in image
nat_show_config_2_reply                                      | only in image
nsim_configure2                                              | only in image
nsim_configure2_reply                                        | only in image
pg_interface_enable_disable_coalesce                         | only in image
pg_interface_enable_disable_coalesce_reply                   | only in image
sr_policies_with_sl_index_details                            | only in image
sr_policies_with_sl_index_dump                               | only in image
sw_bond_interface_details                                    | only in image
sw_bond_interface_dump                                       | only in image
sw_member_interface_details                                  | only in image
sw_member_interface_dump                                     | only in image
trace_details                                                | only in image
trace_dump                                                   | only in image
trace_dump_reply                                             | only in image
virtio_pci_create_v2                                         | only in image
virtio_pci_create_v2_reply                                   | only in image
wireguard_interface_create                                   | only in image
wireguard_interface_create_reply                             | only in image
wireguard_interface_delete                                   | only in image
wireguard_interface_delete_reply                             | only in image
wireguard_interface_details                                  | only in image
wireguard_interface_dump                                     | only in image
wireguard_peer_add                                           | only in image
wireguard_peer_add_reply                                     | only in image
wireguard_peer_remove                                        | only in image
wireguard_peer_remove_reply                                  | only in image
wireguard_peers_details                                      | only in image
wireguard_peers_dump                                         | only in image

Found 123 api message signature differences


### Newly deprecated API messages

These messages are still there in the API, but can and probably
will disappear in the next release.

- bond_create
- bond_detach_slave
- bond_detach_slave_reply
- bond_enslave
- cop_interface_enable_disable
- cop_interface_enable_disable_reply
- cop_whitelist_enable_disable
- cop_whitelist_enable_disable_reply
- geneve_add_del_tunnel
- ipsec_tunnel_if_add_del
- ipsec_tunnel_if_set_sa
- ipsec_tunnel_if_set_sa_reply
- map_domain_dump
- nat_det_add_del_map
- nat_det_add_del_map_reply
- nat_det_close_session_in
- nat_det_close_session_in_reply
- nat_det_close_session_out
- nat_det_close_session_out_reply
- nat_det_forward
- nat_det_forward_reply
- nat_det_map_details
- nat_det_map_dump
- nat_det_reverse
- nat_det_reverse_reply
- nat_det_session_details
- nat_det_session_dump
- nat_show_config
- nsim_configure
- nsim_configure_reply
- sw_interface_bond_dump
- sw_interface_slave_dump
- virtio_pci_create
- virtio_pci_create_reply

### In-progress API messages

These messages are provided for testing and experimentation only.
They are *not* subject to any compatibility process,
and therefore can arbitrarily change or disappear at *any* moment.
Also they may have less than satisfactory testing, making
them unsuitable for other use than the technology preview.
If you are intending to use these messages in production projects,
please collaborate with the feature maintainer on their productization.

- abf_itf_attach_add_del
- abf_itf_attach_add_del_reply
- abf_itf_attach_details
- abf_itf_attach_dump
- abf_plugin_get_version
- abf_plugin_get_version_reply
- abf_policy_add_del
- abf_policy_add_del_reply
- abf_policy_details
- abf_policy_dump
- adl_allowlist_enable_disable
- adl_allowlist_enable_disable_reply
- adl_interface_enable_disable
- adl_interface_enable_disable_reply
- af_xdp_create
- af_xdp_create_reply
- af_xdp_delete
- af_xdp_delete_reply
- cnat_add_del_snat_prefix
- cnat_add_del_snat_prefix_reply
- cnat_session_details
- cnat_session_dump
- cnat_session_purge
- cnat_session_purge_reply
- cnat_set_snat_addresses
- cnat_set_snat_addresses_reply
- cnat_translation_del
- cnat_translation_del_reply
- cnat_translation_details
- cnat_translation_dump
- cnat_translation_update
- cnat_translation_update_reply
- crypto_sw_scheduler_set_worker
- crypto_sw_scheduler_set_worker_reply
- det44_get_timeouts_reply
- det44_interface_add_del_feature
- det44_interface_add_del_feature_reply
- det44_interface_details
- det44_interface_dump
- det44_plugin_enable_disable
- det44_plugin_enable_disable_reply
- det44_set_timeouts
- det44_set_timeouts_reply
- flow_add
- flow_add_reply
- flow_del
- flow_del_reply
- flow_disable
- flow_disable_reply
- flow_enable
- flow_enable_reply
- gbp_bridge_domain_add
- gbp_bridge_domain_add_reply
- gbp_bridge_domain_del
- gbp_bridge_domain_del_reply
- gbp_bridge_domain_details
- gbp_bridge_domain_dump
- gbp_bridge_domain_dump_reply
- gbp_contract_add_del
- gbp_contract_add_del_reply
- gbp_contract_details
- gbp_contract_dump
- gbp_endpoint_add
- gbp_endpoint_add_reply
- gbp_endpoint_del
- gbp_endpoint_del_reply
- gbp_endpoint_details
- gbp_endpoint_dump
- gbp_endpoint_group_add
- gbp_endpoint_group_add_reply
- gbp_endpoint_group_del
- gbp_endpoint_group_del_reply
- gbp_endpoint_group_details
- gbp_endpoint_group_dump
- gbp_ext_itf_add_del
- gbp_ext_itf_add_del_reply
- gbp_ext_itf_details
- gbp_ext_itf_dump
- gbp_recirc_add_del
- gbp_recirc_add_del_reply
- gbp_recirc_details
- gbp_recirc_dump
- gbp_route_domain_add
- gbp_route_domain_add_reply
- gbp_route_domain_del
- gbp_route_domain_del_reply
- gbp_route_domain_details
- gbp_route_domain_dump
- gbp_route_domain_dump_reply
- gbp_subnet_add_del
- gbp_subnet_add_del_reply
- gbp_subnet_details
- gbp_subnet_dump
- gbp_vxlan_tunnel_add
- gbp_vxlan_tunnel_add_reply
- gbp_vxlan_tunnel_del
- gbp_vxlan_tunnel_del_reply
- gbp_vxlan_tunnel_details
- gbp_vxlan_tunnel_dump
- ikev2_child_sa_details
- ikev2_child_sa_dump
- ikev2_initiate_del_child_sa
- ikev2_initiate_del_child_sa_reply
- ikev2_initiate_del_ike_sa
- ikev2_initiate_del_ike_sa_reply
- ikev2_initiate_rekey_child_sa
- ikev2_initiate_rekey_child_sa_reply
- ikev2_initiate_sa_init
- ikev2_initiate_sa_init_reply
- ikev2_nonce_get
- ikev2_nonce_get_reply
- ikev2_profile_add_del
- ikev2_profile_add_del_reply
- ikev2_profile_details
- ikev2_profile_dump
- ikev2_profile_set_auth
- ikev2_profile_set_auth_reply
- ikev2_profile_set_id
- ikev2_profile_set_id_reply
- ikev2_profile_set_ipsec_udp_port
- ikev2_profile_set_ipsec_udp_port_reply
- ikev2_profile_set_liveness
- ikev2_profile_set_liveness_reply
- ikev2_profile_set_ts
- ikev2_profile_set_ts_reply
- ikev2_profile_set_udp_encap
- ikev2_profile_set_udp_encap_reply
- ikev2_sa_details
- ikev2_sa_dump
- ikev2_set_esp_transforms
- ikev2_set_esp_transforms_reply
- ikev2_set_ike_transforms
- ikev2_set_ike_transforms_reply
- ikev2_set_local_key
- ikev2_set_local_key_reply
- ikev2_set_responder
- ikev2_set_responder_reply
- ikev2_set_sa_lifetime
- ikev2_set_sa_lifetime_reply
- ikev2_set_tunnel_interface
- ikev2_set_tunnel_interface_reply
- ikev2_traffic_selector_details
- ikev2_traffic_selector_dump
- l2_emulation
- l2_emulation_reply
- mdata_enable_disable
- mdata_enable_disable_reply
- nat44_add_del_static_mapping_v2
- nat44_add_del_static_mapping_v2_reply
- oddbuf_enable_disable
- oddbuf_enable_disable_reply
- pg_interface_enable_disable_coalesce
- pg_interface_enable_disable_coalesce_reply
- sample_macswap_enable_disable
- sample_macswap_enable_disable_reply
- sr_policies_with_sl_index_details
- sr_policies_with_sl_index_dump
- sw_interface_set_vxlan_gbp_bypass
- sw_interface_set_vxlan_gbp_bypass_reply
- trace_details
- trace_dump
- trace_dump_reply
- vxlan_gbp_tunnel_add_del
- vxlan_gbp_tunnel_add_del_reply
- vxlan_gbp_tunnel_details
- vxlan_gbp_tunnel_dump
- wireguard_interface_create
- wireguard_interface_create_reply
- wireguard_interface_delete
- wireguard_interface_delete_reply
- wireguard_interface_details
- wireguard_interface_dump
- wireguard_peer_add
- wireguard_peer_add_reply
- wireguard_peer_remove
- wireguard_peer_remove_reply
- wireguard_peers_details
- wireguard_peers_dump

### Patches that changed API definitions

| @c src/vpp/api/vpe.api ||
| ------- | ------- |
| [d0236f725](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=d0236f725) | flow: add vnet/flow formal API |

| @c src/vnet/crypto/crypto.api ||
| ------- | ------- |
| [4035daffd](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=4035daffd) | crypto: Crypto set handler API to support set all as CLI |
| [0c936b147](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=0c936b147) | crypto: Add async crypto APIs |

| @c src/vnet/cop/cop.api ||
| ------- | ------- |
| [00f21fb2f](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=00f21fb2f) | api: clean up use of deprecated flag |
| [ac0326fc5](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=ac0326fc5) | adl: move allow/deny list function to plugin |

| @c src/vnet/lisp-gpe/lisp_gpe.api ||
| ------- | ------- |
| [4ab5190eb](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=4ab5190eb) | lisp: API cleanup |

| @c src/vnet/vxlan-gbp/vxlan_gbp.api ||
| ------- | ------- |
| [f72b1aff7](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f72b1aff7) | vxlan-gbp: Mark APIs as in-progress |

| @c src/vnet/flow/flow_types.api ||
| ------- | ------- |
| [34bfa50b6](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=34bfa50b6) | flow: code refactor |
| [d0236f725](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=d0236f725) | flow: add vnet/flow formal API |

| @c src/vnet/flow/flow.api ||
| ------- | ------- |
| [d0236f725](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=d0236f725) | flow: add vnet/flow formal API |

| @c src/vnet/srv6/sr.api ||
| ------- | ------- |
| [30fa97dc6](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=30fa97dc6) | sr: new messages created to return sl index for segment lists in a sr policy |

| @c src/vnet/pg/pg.api ||
| ------- | ------- |
| [f382b06fe](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f382b06fe) | gso: packet coalesce library |
| [0cf528233](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=0cf528233) | gso: fix the udp checksum in test |

| @c src/vnet/geneve/geneve.api ||
| ------- | ------- |
| [00f21fb2f](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=00f21fb2f) | api: clean up use of deprecated flag |
| [7fc88cf3a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=7fc88cf3a) | geneve: support geneve interface acting as a bvi |

| @c src/vnet/lisp-cp/one.api ||
| ------- | ------- |
| [4ab5190eb](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=4ab5190eb) | lisp: API cleanup |

| @c src/vnet/lisp-cp/lisp.api ||
| ------- | ------- |
| [4ab5190eb](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=4ab5190eb) | lisp: API cleanup |

| @c src/vnet/devices/tap/tapv2.api ||
| ------- | ------- |
| [50bd16559](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=50bd16559) | tap: add virtio 1.1 API flag |

| @c src/vnet/devices/virtio/vhost_user.api ||
| ------- | ------- |
| [a0e8d9669](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=a0e8d9669) | virtio: add vhost sw_if_index filter for sw_interface_vhost_user_dump |

| @c src/vnet/devices/virtio/virtio.api ||
| ------- | ------- |
| [00f21fb2f](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=00f21fb2f) | api: clean up use of deprecated flag |
| [518251bc8](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=518251bc8) | virtio: add virtio 1.1 api flags |

| @c src/vnet/ipsec/ipsec.api ||
| ------- | ------- |
| [00f21fb2f](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=00f21fb2f) | api: clean up use of deprecated flag |
| [2e84d6655](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=2e84d6655) | ipsec: add ipsec set async mode api |
| [e6df80de4](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e6df80de4) | ipsec: Deprecate old interface API |
| [dd4ccf262](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=dd4ccf262) | ipsec: Dedicated IPSec interface type |

| @c src/vnet/bonding/bond.api ||
| ------- | ------- |
| [ea7178631](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=ea7178631) | bonding: add bond_create2 API to include gso option |
| [4c4223edf](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=4c4223edf) | bonding lacp: replace slave string with member |

| @c src/vnet/ip/ip_types.api ||
| ------- | ------- |
| [d0236f725](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=d0236f725) | flow: add vnet/flow formal API |

| @c src/plugins/wireguard/wireguard.api ||
| ------- | ------- |
| [edca1325c](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=edca1325c) | wireguard: initial implementation of wireguard protocol |

| @c src/plugins/map/map.api ||
| ------- | ------- |
| [00f21fb2f](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=00f21fb2f) | api: clean up use of deprecated flag |
| [ac0326fc5](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=ac0326fc5) | adl: move allow/deny list function to plugin |
| [f5db3711b](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f5db3711b) | api: add new stream message convention |

| @c src/plugins/lacp/lacp.api ||
| ------- | ------- |
| [4c4223edf](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=4c4223edf) | bonding lacp: replace slave string with member |

| @c src/plugins/l2e/l2e.api ||
| ------- | ------- |
| [f733e7ade](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f733e7ade) | l2e: mark API as in-progress |

| @c src/plugins/ikev2/ikev2.api ||
| ------- | ------- |
| [a340fe1ac](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=a340fe1ac) | ikev2: add SA dump API |
| [459d17bb7](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=459d17bb7) | ikev2: refactor and test profile dump API |
| [ac46e3b1d](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=ac46e3b1d) | ikev2: API downgrade due to lack of ikev2 tests |
| [6a9bd8188](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=6a9bd8188) | ikev2: add profile dump API |

| @c src/plugins/ikev2/ikev2_types.api ||
| ------- | ------- |
| [a340fe1ac](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=a340fe1ac) | ikev2: add SA dump API |
| [459d17bb7](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=459d17bb7) | ikev2: refactor and test profile dump API |
| [6a9bd8188](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=6a9bd8188) | ikev2: add profile dump API |

| @c src/plugins/tracedump/tracedump.api ||
| ------- | ------- |
| [65b65a469](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=65b65a469) | misc: add tracedump API plugin |

| @c src/plugins/gtpu/gtpu.api ||
| ------- | ------- |
| [9ebbb5c41](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9ebbb5c41) | gtpu: support separate rx-decap and encap-tx teid values |

| @c src/plugins/gbp/gbp.api ||
| ------- | ------- |
| [d2f8fb9c7](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=d2f8fb9c7) | gbp: mark APIs as in-progress |

| @c src/plugins/acl/acl.api ||
| ------- | ------- |
| [24ee40a5c](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=24ee40a5c) | acl: correct acl vat help message |

| @c src/plugins/nat/dslite/dslite.api ||
| ------- | ------- |
| [603e75465](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=603e75465) | nat: move deterministic nat to det44 sub feature |

| @c src/plugins/nat/det44/det44.api ||
| ------- | ------- |
| [00f21fb2f](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=00f21fb2f) | api: clean up use of deprecated flag |
| [603e75465](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=603e75465) | nat: move deterministic nat to det44 sub feature |

| @c src/plugins/nat/nat_types.api ||
| ------- | ------- |
| [96068d6b9](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=96068d6b9) | nat: nat66 to plugin |

| @c src/plugins/nat/nat.api ||
| ------- | ------- |
| [6484f4b9c](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=6484f4b9c) | nat: twice-nat static mapping pool address |
| [edc816355](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=edc816355) | nat: fix type in api message |
| [603e75465](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=603e75465) | nat: move deterministic nat to det44 sub feature |
| [96068d6b9](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=96068d6b9) | nat: nat66 to plugin |

| @c src/plugins/nat/nat66/nat66.api ||
| ------- | ------- |
| [96068d6b9](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=96068d6b9) | nat: nat66 to plugin |

| @c src/plugins/cnat/cnat.api ||
| ------- | ------- |
| [29f3c7d2e](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=29f3c7d2e) | cnat: Destination based NAT |

| @c src/plugins/abf/abf.api ||
| ------- | ------- |
| [df494dafa](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=df494dafa) | abf: mark API as in-progress |

| @c src/plugins/adl/adl.api ||
| ------- | ------- |
| [ac0326fc5](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=ac0326fc5) | adl: move allow/deny list function to plugin |

| @c src/plugins/nsim/nsim.api ||
| ------- | ------- |
| [00f21fb2f](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=00f21fb2f) | api: clean up use of deprecated flag |
| [e6c3e8f0e](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e6c3e8f0e) | nsim: basic reorder support |

| @c src/plugins/crypto_sw_scheduler/crypto_sw_scheduler.api ||
| ------- | ------- |
| [0c936b147](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=0c936b147) | crypto: Add async crypto APIs |

| @c src/plugins/dhcp/dhcp.api ||
| ------- | ------- |
| [bad679291](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=bad679291) | api: register endian handlers for reply messages |

| @c src/plugins/af_xdp/af_xdp.api ||
| ------- | ------- |
| [4a76d6f6d](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=4a76d6f6d) | af_xdp: AF_XDP input plugin |


@page release_notes_20051 Release notes for VPP 20.05.1

This is bug fix release.

For the full list of fixed issues please refer to:
- fd.io [JIRA](https://jira.fd.io)
- git [commit log](https://git.fd.io/vpp/log/?h=stable/2005)

@page release_notes_2005 Release notes for VPP 20.05

More than 751 commits since the 20.01 release.

## Release Highlights

### Feature Highlights

As per commits involving
FEATURE.yaml edits between the previous release and this release.
They are mentioned in the below "features" section as well,
together with the corresponding commits.

- TAP Drivers
  - Implement sw_interface_tap_v2_dump filtering by sw_if_index
  - Add support for persistence
- Native Virtio Drivers
  - Support virtio 1.1 packed ring in vhost
- gso
  - Add support for IP-IP
  - Add vxlan tunnel support
- VRRP
  - Add plugin providing VRRP support

### Ongoing Work On More Semantic-Typed API

This release, like the 20.01, continues the journey on defining
the semantic-based types instead of storage-based types within the API,
so you may have noticed this in the API changes.

Some of the changes
are related to the infrastructure, and may be bugfixes, they
do not change the CRC of the message but affect the representation
on the wire. One particular commit we want you to pay attention to,
is [b5c0d35f](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b5c0d35f), which
fixes the bug with the enum representation on the wire - before it,
even the enums declared as u8 or u16 were represented as u32 in
the API messages.

Another important commit we would like to call out explicitly as well is
[7dd63e5c](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=7dd63e5c), which
pinned the address_family and ip_proto enum types to be u8 instead of the default u32.

The above two commits will be primarily interesting for those who work with the low-level
APIs on VPP - the API frameworks should make these under-the-hood changes transparent.
However, we decided to call these out, given that for those affected these will
be pretty important changes.

Another commit, that does not have the immediate impact at the moment, but that
is poised to improve the user interaction with the API is [5c318c70](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=5c318c70).
This adds the tooling and ability to implement a structured process,
by which the API messages can evolve, while minimizing the impact to the
API users.

## Features

- Binary API Compiler for Python
  - Api crc checker (5c318c70d)
- Binary API Libraries
  - Add macro that zeros out api reply buffer (f24de1795)
- Build System
  - Add snap packaging (experimental) (6d97e62c0)
  - Support arch-specific compiling for Neoverse N1 (690ce8672)
- Crypto native Plugin
  - Add ARMv8 AES-CBC implementation (776644efe)
  - Add AArch64 AES-GCM native implementation (622b5ce61)
  - Calculate ghash using vpclmulqdq instructions (627fb6a16)
  - GCM implementation with vector AESNI instructions (47d8f5dcd)
- Infrastructure Library
  - Add x86 CPU definitions (38e0413b2)
  - Numa vector placement support (a690fdbfe)
  - Add cmake option to grow vectors by 1 (98bd75778)
  - Add tw\_timer\_2t\_2w\_512sl variant (907678977)
- Link Bonding
  - Add GSO support (2e1fa54b7)
- Plugins
  - DPDK
    - Output switch information (2347278d9)
    - Use port\_id as interface name suffix for representors (a80f8f371)
    - Add iova-mode to startup (4e96ddaec)
    - Bump DPDK version to 20.02 (76be887d8)
    - Enable DPDK iAVF PMD (162ea767c)
    - DPDK 20.05 iavf flow director backporting to DPDK 20.02 (7f83738b4)
  - GTPU
    - Offload RX flow (00fdf53c7)
    - RX offload for IPv6 payload supporting (ed63a0ff7)
  - Host Stack Applications
    - Proxy rcv wnd update acks after full fifos (dda2dbeda)
  - IPv6 Segment Routing Mobile
    - Support GTP4/6.DT and User Plane message mapping (9e722bd46)
  - Internet Key Exchange (IKEv2) Protocol
    - Configure a profile with an existing interface (44476c6b2)
    - Responder honours the protected tunnel config (685001f0a)
    - Add support for custom ipsec-over-udp port (e5d34919b)
    - Dead peer detection (c415d0a8e)
  - NAT
    - In2out-output nodes work with acl reflect (d539e256b)
    - Api & cli command for forcing session cleanup (edf777272)
    - Dslite ce mode in separate config entry (958919f36)
  - QUIC protocol
    - Update quicly to v0.0.10-VPP (62b1cea6e)
    - Quicly crypto offloading (92de6b65b)
    - Check quicly version tag at compile time (ffdc72da4)
  - RDMA (ibverb) driver
    - Bunp rdma-core version to v28.0 (eb89b9093)
    - Add Mellanox mlx5 Direct Verbs receive support (dd648aac0)
    - Introduce direct verb for Cx4/5 tx (dc812d9a7)
  - Unicast Reverse Path forwarding
    - Unicast reverse Path Forwarding (plugin) (d724e4f43)
  - VRRP
    - Add plugin providing vrrp support (39e9428b9)
- SVM Library
  - Numa awareness for ssvm segments (6fe8998fe)
  - Support multi-chunk fifo chunk alloc (8e755a16a)
  - Chunk alloc stats (d35887297)
  - New FIFO design/architecture (f22f4e562)
  - Fifo test (64e96613d)
- Test Infrastructure
  - Add running\_gcov\_tests to framework.py (d498c9eb2)
  - Implement ipaddress convenience methods (e64e5fff4)
- VNET
  - Crypto Infra
    - Add chained buffer support in ipsecmb (AES-GCM) (2fc409131)
    - Add support for testing quad loops in crypto algos (a9075dcf6)
    - Introduce async crypto infra (f539578ba)
  - Ethernet
    - Configure system default ethernet MTU (5fa452554)
  - FLOW
    - Add vlan tagged types for IPv4/IPv6 5-tuple flows (f13830ce7)
    - Add RSS support (24e2c50bf)
    - Add l2tpv3oip flow (8b43aaaf1)
  - GRE
    - Tunnel encap/decap flags (e5b94dded)
  - GSO
    - Add vxlan tunnel support (0b04209ed)
    - Add support for IP-IP (84f91fa9c)
  - IP Neighbors
    - Populate neighbor age via API (9c1928f81)
    - Replace feature for the ip-neighbor data-base (c87fbb417)
    - Add flush API (240dcb24a)
  - IPIP
    - Multi-point interface (14053c9db)
  - IPSec
    - Add support for chained buffers (efcad1a9d)
    - IPSec protection for multi-point tunnel interfaces (282872127)
    - Add input node bypass/discard functionality (0546483ce)
    - User can choose the UDP source port (abc5660c6)
    - Support 4o6 and 6o4 for SPD tunnel mode SAs (b1fd80f09)
  - IPv4 LPM
    - More detailed show reassembly commands (a877cf9f3)
    - Replace Sematics for Interface IP addresses (59f71132e)
  - MPLS
    - Add user defined name tag to mpls tunnels (39ae0a07a)
  - Native Virtio Drivers
    - Support virtio 1.1 packed ring in vhost (bc0d9ff67)
  - Packet Generator
    - Set vnet buffer flags in pg streams (08eb2bb20)
  - Segment Routing (IPv6 and MPLS)
    - Change the CLI keyword from address to prefix. (b24e287b9)
    - Support uSID function. (ec9cb9668)
  - Session Layer
    - Tracking segment memory usage (234fe894d)
    - Basic fifo-tuning-logic (d8f48e216)
    - Api to add new transport types (07063b8ea)
    - Support connect on listeners (0a1e183e5)
    - Adding debug events (7357043d2)
    - Add option to preallocate fifo headers (9845c20d7)
  - TAP Drivers
    - Add support for persistance (b49bc1ae6)
    - Add initial support for tun (206acf84d)
    - Implement sw\_interface\_tap\_v2\_dump filtering by sw\_if\_index (073d74d0b)
  - TCP
    - Add option to avoid endpoint cleanup (43818c1e0)
    - Minimal set of worker stats (5e6305fb0)
    - Allow custom mss on connects (ff19e3bf4)
  - TLS and TLS engine plugins
    - Picotls engine symmetric crypto enhancement by VPP crypto framework (3b8518164)
  - UDP
    - Track connection port sharing (a039620c2)
- VPP Comms Library
  - Udp session migration notifications (68b7e5888)
  - Propagate cleanup notifications to apps (9ace36d0f)
- Vector Library
  - Add plugin override support (8dc954a4e)
  - Calculate per-worker loops/second metric (000a029e4)
  - Leave SIGPROF signal with its default handler (6f533d780)
  - Add nosyslog unix option (e31820af1)
- Gomemif
  - Introduce gomemif (07363a45f)

## Known issues

For the full list of issues please refer to fd.io [JIRA](https://jira.fd.io).

## Fixed issues

For the full list of fixed issues please refer to:
- fd.io [JIRA](https://jira.fd.io)
- git [commit log](https://git.fd.io/vpp/log/?h=stable/2005)


## API changes

Description of results:

* _Definition changed_: indicates that the API file was modified between releases.
* _Only in image_: indicates the API is new for this release.
* _Only in file_: indicates the API has been removed in this release.

Message Name                                                 | Result
-------------------------------------------------------------|------------------
acl_add_replace                                              | definition changed
acl_details                                                  | definition changed
acl_interface_add_del                                        | definition changed
acl_interface_etype_whitelist_details                        | definition changed
acl_interface_etype_whitelist_dump                           | definition changed
acl_interface_list_details                                   | definition changed
acl_interface_list_dump                                      | definition changed
acl_interface_set_acl_list                                   | definition changed
acl_interface_set_etype_whitelist                            | definition changed
add_node_next                                                | definition changed
app_attach                                                   | definition changed
app_attach_reply                                             | definition changed
app_cut_through_registration_add                             | only in file
app_cut_through_registration_add_reply                       | only in file
app_namespace_add_del                                        | definition changed
app_worker_add_del                                           | definition changed
app_worker_add_del_reply                                     | definition changed
application_attach                                           | only in file
application_attach_reply                                     | only in file
bd_ip_mac_add_del                                            | definition changed
bind_sock                                                    | only in file
bind_sock_reply                                              | only in file
bind_uri                                                     | only in file
bind_uri_reply                                               | only in file
bridge_domain_add_del                                        | definition changed
bridge_domain_details                                        | definition changed
bridge_domain_dump                                           | definition changed
bridge_flags                                                 | definition changed
bvi_create_reply                                             | definition changed
bvi_delete                                                   | definition changed
connect_sock                                                 | only in file
connect_sock_reply                                           | only in file
connect_uri                                                  | only in file
connect_uri_reply                                            | only in file
create_vhost_user_if                                         | definition changed
disconnect_session                                           | only in file
disconnect_session_reply                                     | only in file
get_next_index                                               | definition changed
get_node_index                                               | definition changed
gpe_add_del_fwd_entry                                        | definition changed
gpe_add_del_iface                                            | definition changed
gpe_add_del_native_fwd_rpath                                 | definition changed
gpe_enable_disable                                           | definition changed
gpe_fwd_entries_get_reply                                    | definition changed
gpe_fwd_entry_path_details                                   | definition changed
gpe_native_fwd_rpaths_get                                    | definition changed
gpe_native_fwd_rpaths_get_reply                              | definition changed
gpe_set_encap_mode                                           | definition changed
gre_tunnel_add_del                                           | definition changed
gre_tunnel_details                                           | definition changed
gtpu_offload_rx                                              | only in image
gtpu_offload_rx_reply                                        | only in image
ikev2_profile_set_ipsec_udp_port                             | only in image
ikev2_profile_set_ipsec_udp_port_reply                       | only in image
ikev2_profile_set_liveness                                   | only in image
ikev2_profile_set_liveness_reply                             | only in image
ikev2_profile_set_udp_encap                                  | only in image
ikev2_profile_set_udp_encap_reply                            | only in image
ikev2_set_local_key                                          | definition changed
ikev2_set_tunnel_interface                                   | only in image
ikev2_set_tunnel_interface_reply                             | only in image
ip_neighbor_details                                          | definition changed
ip_neighbor_flush                                            | only in image
ip_neighbor_flush_reply                                      | only in image
ip_neighbor_replace_begin                                    | only in image
ip_neighbor_replace_begin_reply                              | only in image
ip_neighbor_replace_end                                      | only in image
ip_neighbor_replace_end_reply                                | only in image
ip_route_lookup                                              | only in image
ip_route_lookup_reply                                        | only in image
ip_source_check_interface_add_del                            | only in file
ip_source_check_interface_add_del_reply                      | only in file
ipfix_classify_table_add_del                                 | definition changed
ipfix_classify_table_details                                 | definition changed
ipip_add_tunnel                                              | definition changed
ipip_tunnel_details                                          | definition changed
ipsec_backend_details                                        | definition changed
ipsec_interface_add_del_spd                                  | definition changed
ipsec_sa_details                                             | definition changed
ipsec_sad_entry_add_del                                      | definition changed
ipsec_select_backend                                         | definition changed
ipsec_spd_add_del                                            | definition changed
ipsec_spd_details                                            | definition changed
ipsec_spd_entry_add_del                                      | definition changed
ipsec_spd_interface_details                                  | definition changed
ipsec_tunnel_if_add_del                                      | definition changed
ipsec_tunnel_if_add_del_reply                                | definition changed
ipsec_tunnel_if_set_sa                                       | definition changed
ipsec_tunnel_protect_del                                     | definition changed
ipsec_tunnel_protect_details                                 | definition changed
ipsec_tunnel_protect_update                                  | definition changed
l2_fib_table_details                                         | definition changed
l2_flags                                                     | definition changed
l2_interface_efp_filter                                      | definition changed
l2_interface_pbb_tag_rewrite                                 | definition changed
l2_interface_vlan_tag_rewrite                                | definition changed
l2_macs_event                                                | definition changed
l2_patch_add_del                                             | definition changed
l2_xconnect_details                                          | definition changed
l2fib_add_del                                                | definition changed
l2fib_flush_int                                              | definition changed
lisp_add_del_adjacency                                       | definition changed
lisp_add_del_local_eid                                       | definition changed
lisp_add_del_locator                                         | definition changed
lisp_add_del_locator_set                                     | definition changed
lisp_add_del_map_request_itr_rlocs                           | definition changed
lisp_add_del_map_resolver                                    | definition changed
lisp_add_del_map_server                                      | definition changed
lisp_add_del_remote_mapping                                  | definition changed
lisp_adjacencies_get_reply                                   | definition changed
lisp_eid_table_add_del_map                                   | definition changed
lisp_eid_table_details                                       | definition changed
lisp_eid_table_dump                                          | definition changed
lisp_eid_table_map_dump                                      | definition changed
lisp_enable_disable                                          | definition changed
lisp_get_map_request_itr_rlocs_reply                         | definition changed
lisp_locator_details                                         | definition changed
lisp_locator_dump                                            | definition changed
lisp_locator_set_details                                     | definition changed
lisp_locator_set_dump                                        | definition changed
lisp_map_register_enable_disable                             | definition changed
lisp_map_request_mode                                        | definition changed
lisp_map_resolver_details                                    | definition changed
lisp_map_server_details                                      | definition changed
lisp_pitr_set_locator_set                                    | definition changed
lisp_rloc_probe_enable_disable                               | definition changed
lisp_use_petr                                                | definition changed
lldp_config                                                  | definition changed
macip_acl_add                                                | definition changed
macip_acl_add_replace                                        | definition changed
macip_acl_details                                            | definition changed
macip_acl_interface_add_del                                  | definition changed
macip_acl_interface_list_details                             | definition changed
macip_acl_interface_list_dump                                | definition changed
map_another_segment                                          | only in file
map_another_segment_reply                                    | only in file
modify_vhost_user_if                                         | definition changed
mpls_tunnel_add_del                                          | definition changed
mpls_tunnel_details                                          | definition changed
nat44_del_user                                               | only in image
nat44_del_user_reply                                         | only in image
nat44_session_cleanup                                        | only in image
nat44_session_cleanup_reply                                  | only in image
nat44_set_session_limit                                      | only in image
nat44_set_session_limit_reply                                | only in image
nat_show_config_reply                                        | definition changed
netmap_create                                                | only in file
netmap_create_reply                                          | only in file
netmap_delete                                                | only in file
netmap_delete_reply                                          | only in file
nhrp_details                                                 | only in file
nhrp_dump                                                    | only in file
nhrp_entry_add_del                                           | only in file
nhrp_entry_add_del_reply                                     | only in file
one_add_del_adjacency                                        | definition changed
one_add_del_l2_arp_entry                                     | definition changed
one_add_del_local_eid                                        | definition changed
one_add_del_locator                                          | definition changed
one_add_del_locator_set                                      | definition changed
one_add_del_map_request_itr_rlocs                            | definition changed
one_add_del_map_resolver                                     | definition changed
one_add_del_map_server                                       | definition changed
one_add_del_ndp_entry                                        | definition changed
one_add_del_remote_mapping                                   | definition changed
one_adjacencies_get_reply                                    | definition changed
one_eid_table_add_del_map                                    | definition changed
one_eid_table_details                                        | definition changed
one_eid_table_dump                                           | definition changed
one_eid_table_map_dump                                       | definition changed
one_enable_disable                                           | definition changed
one_enable_disable_petr_mode                                 | definition changed
one_enable_disable_pitr_mode                                 | definition changed
one_enable_disable_xtr_mode                                  | definition changed
one_get_map_request_itr_rlocs_reply                          | definition changed
one_l2_arp_entries_get_reply                                 | definition changed
one_locator_details                                          | definition changed
one_locator_dump                                             | definition changed
one_locator_set_details                                      | definition changed
one_locator_set_dump                                         | definition changed
one_map_register_enable_disable                              | definition changed
one_map_request_mode                                         | definition changed
one_map_resolver_details                                     | definition changed
one_map_server_details                                       | definition changed
one_ndp_entries_get_reply                                    | definition changed
one_nsh_set_locator_set                                      | definition changed
one_pitr_set_locator_set                                     | definition changed
one_rloc_probe_enable_disable                                | definition changed
one_show_petr_mode_reply                                     | definition changed
one_show_pitr_mode_reply                                     | definition changed
one_show_xtr_mode_reply                                      | definition changed
one_stats_details                                            | definition changed
one_stats_enable_disable                                     | definition changed
one_use_petr                                                 | definition changed
pg_capture                                                   | definition changed
pg_create_interface                                          | definition changed
pg_create_interface_reply                                    | definition changed
pg_enable_disable                                            | definition changed
policer_add_del                                              | definition changed
policer_details                                              | definition changed
policer_dump                                                 | definition changed
session_enable_disable                                       | definition changed
session_rule_add_del                                         | definition changed
session_rules_details                                        | definition changed
show_lisp_map_register_state_reply                           | definition changed
show_lisp_map_request_mode_reply                             | definition changed
show_lisp_pitr_reply                                         | definition changed
show_lisp_rloc_probe_state_reply                             | definition changed
show_lisp_status_reply                                       | definition changed
show_lisp_use_petr_reply                                     | definition changed
show_one_map_register_state_reply                            | definition changed
show_one_map_request_mode_reply                              | definition changed
show_one_nsh_mapping_reply                                   | definition changed
show_one_pitr_reply                                          | definition changed
show_one_rloc_probe_state_reply                              | definition changed
show_one_stats_enable_disable_reply                          | definition changed
show_one_status_reply                                        | definition changed
show_one_use_petr_reply                                      | definition changed
show_threads_reply                                           | definition changed
sr_localsid_add_del                                          | definition changed
sr_localsids_details                                         | definition changed
sr_mpls_policy_add                                           | definition changed
sr_mpls_policy_assign_endpoint_color                         | definition changed
sr_mpls_policy_mod                                           | definition changed
sr_mpls_steering_add_del                                     | definition changed
sr_policies_details                                          | definition changed
sr_policy_add                                                | definition changed
sr_policy_del                                                | definition changed
sr_policy_mod                                                | definition changed
sr_set_encap_source                                          | definition changed
sr_steering_add_del                                          | definition changed
sr_steering_pol_details                                      | definition changed
sw_interface_address_replace_begin                           | only in image
sw_interface_address_replace_begin_reply                     | only in image
sw_interface_address_replace_end                             | only in image
sw_interface_address_replace_end_reply                       | only in image
sw_interface_set_l2_bridge                                   | definition changed
sw_interface_set_l2_xconnect                                 | definition changed
sw_interface_set_lldp                                        | definition changed
sw_interface_set_vpath                                       | definition changed
sw_interface_set_vxlan_bypass                                | definition changed
sw_interface_set_vxlan_gpe_bypass                            | definition changed
sw_interface_span_details                                    | definition changed
sw_interface_span_dump                                       | definition changed
sw_interface_span_enable_disable                             | definition changed
teib_details                                                 | only in image
teib_dump                                                    | only in image
teib_entry_add_del                                           | only in image
teib_entry_add_del_reply                                     | only in image
unbind_sock                                                  | only in file
unbind_sock_reply                                            | only in file
unbind_uri                                                   | only in file
unbind_uri_reply                                             | only in file
unmap_segment                                                | only in file
unmap_segment_reply                                          | only in file
urpf_update                                                  | only in image
urpf_update_reply                                            | only in image
vrrp_vr_add_del                                              | only in image
vrrp_vr_add_del_reply                                        | only in image
vrrp_vr_details                                              | only in image
vrrp_vr_dump                                                 | only in image
vrrp_vr_peer_details                                         | only in image
vrrp_vr_peer_dump                                            | only in image
vrrp_vr_set_peers                                            | only in image
vrrp_vr_set_peers_reply                                      | only in image
vrrp_vr_start_stop                                           | only in image
vrrp_vr_start_stop_reply                                     | only in image
vrrp_vr_track_if_add_del                                     | only in image
vrrp_vr_track_if_add_del_reply                               | only in image
vrrp_vr_track_if_details                                     | only in image
vrrp_vr_track_if_dump                                        | only in image
vxlan_add_del_tunnel                                         | definition changed
vxlan_add_del_tunnel_reply                                   | definition changed
vxlan_gpe_add_del_tunnel                                     | definition changed
vxlan_gpe_add_del_tunnel_reply                               | definition changed
vxlan_gpe_tunnel_details                                     | definition changed
vxlan_gpe_tunnel_dump                                        | definition changed
vxlan_offload_rx                                             | definition changed
vxlan_tunnel_details                                         | definition changed
vxlan_tunnel_dump                                            | definition changed

Found 279 api message signature differences

### Patches that changed API definitions

| @c extras/deprecated/dpdk-hqos/api/dpdk.api ||
| ------- | ------- |
| [548d70de6](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=548d70de6) | misc: deprecate dpdk hqos |

| @c extras/deprecated/netmap/netmap.api ||
| ------- | ------- |
| [7db6ab03d](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=7db6ab03d) | misc: deprecate netmap and ixge drivers |

| @c src/vpp/api/vpe.api ||
| ------- | ------- |
| [933fcf489](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=933fcf489) | api: API cleanup |
| [7db6ab03d](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=7db6ab03d) | misc: deprecate netmap and ixge drivers |

| @c src/vnet/tunnel/tunnel_types.api ||
| ------- | ------- |
| [14053c9db](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=14053c9db) | ipip: Multi-point interface |
| [59ff918ea](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=59ff918ea) | tunnel: Common types for IP tunnels |

| @c src/vnet/policer/policer_types.api ||
| ------- | ------- |
| [cd01fb423](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=cd01fb423) | policer: API cleanup |

| @c src/vnet/policer/policer.api ||
| ------- | ------- |
| [cd01fb423](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=cd01fb423) | policer: API cleanup |

| @c src/vnet/lisp-gpe/lisp_gpe.api ||
| ------- | ------- |
| [58db6e16c](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=58db6e16c) | lisp: API cleanup |

| @c src/vnet/teib/teib.api ||
| ------- | ------- |
| [03ce46219](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=03ce46219) | teib: Rename NHRP to TEIB |

| @c src/vnet/ip-neighbor/ip_neighbor.api ||
| ------- | ------- |
| [240dcb24a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=240dcb24a) | ip-neighbor: Add flush API |
| [e64e5fff4](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e64e5fff4) | tests: implement ipaddress convenience methods |
| [c87fbb417](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c87fbb417) | ip-neighbor: Replace feature for the ip-neighbor data-base |
| [8e7fdddd3](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=8e7fdddd3) | ip-neighbor: add description to the age parameter |
| [9c1928f81](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9c1928f81) | ip-neighbor: populate neighbor age via API |

| @c src/vnet/session/session.api ||
| ------- | ------- |
| [6fdd7a5f7](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=6fdd7a5f7) | session: improve .api comments slightly |
| [9845c20d7](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9845c20d7) | session: add option to preallocate fifo headers |
| [c0e9441e7](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c0e9441e7) | tests: move defaults from defaultmapping to .api files |
| [256779c85](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=256779c85) | udp: remove connected udp transport proto |
| [888d9f05e](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=888d9f05e) | session: remove obsolete apis |
| [07063b8ea](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=07063b8ea) | session: api to add new transport types |
| [b4e5e50fe](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b4e5e50fe) | session: API cleanup |
| [2de9c0f92](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=2de9c0f92) | svm: minimal initial fifo |

| @c src/vnet/interface_types.api ||
| ------- | ------- |
| [c4ae0fffb](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c4ae0fffb) | interface: fix interface_types.api enums |

| @c src/vnet/vxlan/vxlan.api ||
| ------- | ------- |
| [7c0eb56f4](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=7c0eb56f4) | vxlan: vxlan/vxlan.api API cleanup |

| @c src/vnet/vxlan-gbp/vxlan_gbp.api ||
| ------- | ------- |
| [c0e9441e7](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c0e9441e7) | tests: move defaults from defaultmapping to .api files |

| @c src/vnet/gre/gre.api ||
| ------- | ------- |
| [48ac1c2b2](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=48ac1c2b2) | gre: improve .api descriptions |
| [8ab4e507c](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=8ab4e507c) | gre: add missing .api edits |
| [e5b94dded](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e5b94dded) | gre: Tunnel encap/decap flags |
| [59ff918ea](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=59ff918ea) | tunnel: Common types for IP tunnels |

| @c src/vnet/span/span.api ||
| ------- | ------- |
| [908965db7](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=908965db7) | span: API cleanup |

| @c src/vnet/srv6/sr.api ||
| ------- | ------- |
| [c0e9441e7](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c0e9441e7) | tests: move defaults from defaultmapping to .api files |
| [0938eba15](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=0938eba15) | sr: srv6 API cleanup |
| [79bfd2725](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=79bfd2725) | sr: SRv6 uN behavior |

| @c src/vnet/srv6/sr_types.api ||
| ------- | ------- |
| [0938eba15](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=0938eba15) | sr: srv6 API cleanup |

| @c src/vnet/pg/pg.api ||
| ------- | ------- |
| [db86329ab](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=db86329ab) | pg: API cleanup |

| @c src/vnet/l2/l2.api ||
| ------- | ------- |
| [c0e9441e7](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c0e9441e7) | tests: move defaults from defaultmapping to .api files |
| [145e330f0](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=145e330f0) | l2: API cleanup |

| @c src/vnet/lldp/lldp.api ||
| ------- | ------- |
| [1c684f9af](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=1c684f9af) | lldp: API cleanup |

| @c src/vnet/vxlan-gpe/vxlan_gpe.api ||
| ------- | ------- |
| [1c2002a31](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=1c2002a31) | vxlan: vxlan-gpe/vxlan-gpe.cpi API cleanup |

| @c src/vnet/lisp-cp/one.api ||
| ------- | ------- |
| [58db6e16c](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=58db6e16c) | lisp: API cleanup |

| @c src/vnet/lisp-cp/lisp_types.api ||
| ------- | ------- |
| [58db6e16c](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=58db6e16c) | lisp: API cleanup |

| @c src/vnet/lisp-cp/lisp.api ||
| ------- | ------- |
| [58db6e16c](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=58db6e16c) | lisp: API cleanup |

| @c src/vnet/devices/tap/tapv2.api ||
| ------- | ------- |
| [d88fc0fce](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=d88fc0fce) | tap: refactor existing flags |
| [073d74d0b](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=073d74d0b) | tap: implement sw_interface_tap_v2_dump filtering by sw_if_index |
| [206acf84d](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=206acf84d) | tap: add initial support for tun |
| [b49bc1ae6](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b49bc1ae6) | tap: add support for persistance |

| @c src/vnet/devices/virtio/vhost_user.api ||
| ------- | ------- |
| [bc0d9ff67](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=bc0d9ff67) | virtio: support virtio 1.1 packed ring in vhost |

| @c src/vnet/devices/virtio/virtio.api ||
| ------- | ------- |
| [53f06a014](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=53f06a014) | vlib: move pci api types from vnet/pci to vlib/pci |

| @c src/vnet/ipsec/ipsec_types.api ||
| ------- | ------- |
| [abc5660c6](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=abc5660c6) | ipsec: User can choose the UDP source port |
| [287d5e109](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=287d5e109) | ipsec: API cleanup |
| [5893747d7](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=5893747d7) | api: ipsec: add missing IS_INBOUND flag. |
| [2fcd265d3](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=2fcd265d3) | ipsec: Revert API cleanup |
| [666ece35c](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=666ece35c) | ipsec: API cleanup |

| @c src/vnet/ipsec/ipsec.api ||
| ------- | ------- |
| [48d32b43c](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=48d32b43c) | ipsec: provide stat index in sa details |
| [287d5e109](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=287d5e109) | ipsec: API cleanup |
| [2fcd265d3](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=2fcd265d3) | ipsec: Revert API cleanup |
| [666ece35c](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=666ece35c) | ipsec: API cleanup |
| [282872127](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=282872127) | ipsec: IPSec protection for multi-point tunnel interfaces |

| @c src/vnet/ethernet/p2p_ethernet.api ||
| ------- | ------- |
| [bdfe5955f](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=bdfe5955f) | ethernet: add sanity checks to p2p_ethernet_add/del |

| @c src/vnet/bonding/bond.api ||
| ------- | ------- |
| [c0e9441e7](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c0e9441e7) | tests: move defaults from defaultmapping to .api files |

| @c src/vnet/mpls/mpls.api ||
| ------- | ------- |
| [c0e9441e7](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c0e9441e7) | tests: move defaults from defaultmapping to .api files |
| [39ae0a07a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=39ae0a07a) | mpls: add user defined name tag to mpls tunnels |

| @c src/vnet/syslog/syslog.api ||
| ------- | ------- |
| [c0e9441e7](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c0e9441e7) | tests: move defaults from defaultmapping to .api files |

| @c src/vnet/interface.api ||
| ------- | ------- |
| [59f71132e](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=59f71132e) | ip: Replace Sematics for Interface IP addresses |

| @c src/vnet/ipip/ipip.api ||
| ------- | ------- |
| [14053c9db](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=14053c9db) | ipip: Multi-point interface |
| [59ff918ea](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=59ff918ea) | tunnel: Common types for IP tunnels |

| @c src/vnet/srmpls/sr_mpls.api ||
| ------- | ------- |
| [0938eba15](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=0938eba15) | sr: srv6 API cleanup |
| [00ec4019b](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=00ec4019b) | sr: API cleanup |

| @c src/vnet/ip/ip.api ||
| ------- | ------- |
| [f5d38e05a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f5d38e05a) | api: ip: add IP_ROUTE_LOOKUP API |
| [c0e9441e7](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c0e9441e7) | tests: move defaults from defaultmapping to .api files |
| [d724e4f43](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=d724e4f43) | urpf: Unicast reverse Path Forwarding (plugin) |

| @c src/vnet/ip/ip_types.api ||
| ------- | ------- |
| [164c44f0b](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=164c44f0b) | ip: Fix the AH/ESP protocol numbers on the API |
| [7dd63e5cc](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=7dd63e5cc) | ip: change ip API enums address_family and ip_proto size to u8 |
| [3ec09e924](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=3ec09e924) | ip: ip_address_t uses ip46_address_t |

| @c src/plugins/map/map.api ||
| ------- | ------- |
| [c0e9441e7](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c0e9441e7) | tests: move defaults from defaultmapping to .api files |

| @c src/plugins/ikev2/ikev2.api ||
| ------- | ------- |
| [933c4ca5a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=933c4ca5a) | ikev2: fix string in api |
| [59fea5a6a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=59fea5a6a) | ikev2: make liveness params configurable |
| [8ceb44a89](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=8ceb44a89) | ikev2: fix typo in .api description |
| [e5d34919b](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e5d34919b) | ikev2: add support for custom ipsec-over-udp port |
| [b29d523af](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b29d523af) | ikev2: make UDP encap flag configurable |
| [44476c6b2](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=44476c6b2) | ikev2: Configure a profile with an existing interface |

| @c src/plugins/urpf/urpf.api ||
| ------- | ------- |
| [d724e4f43](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=d724e4f43) | urpf: Unicast reverse Path Forwarding (plugin) |

| @c src/plugins/lb/lb.api ||
| ------- | ------- |
| [c0e9441e7](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c0e9441e7) | tests: move defaults from defaultmapping to .api files |

| @c src/plugins/gtpu/gtpu.api ||
| ------- | ------- |
| [00fdf53c7](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=00fdf53c7) | gtpu: offload RX flow |

| @c src/plugins/acl/acl_types.api ||
| ------- | ------- |
| [2f8cd9145](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=2f8cd9145) | acl: API cleanup |
| [492a5d0bd](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=492a5d0bd) | acl: revert acl: api cleanup |
| [aad1ee149](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=aad1ee149) | acl: API cleanup |

| @c src/plugins/acl/acl.api ||
| ------- | ------- |
| [c0e9441e7](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c0e9441e7) | tests: move defaults from defaultmapping to .api files |
| [2f8cd9145](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=2f8cd9145) | acl: API cleanup |
| [492a5d0bd](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=492a5d0bd) | acl: revert acl: api cleanup |
| [aad1ee149](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=aad1ee149) | acl: API cleanup |

| @c src/plugins/nat/dslite/dslite.api ||
| ------- | ------- |
| [2c6639c69](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=2c6639c69) | nat: move dslite to separate sub-plugin |

| @c src/plugins/nat/nat.api ||
| ------- | ------- |
| [6bb080f1e](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=6bb080f1e) | nat: per vrf session limits |
| [61717cc38](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=61717cc38) | nat: use correct data types for memory sizes |
| [98301bd56](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=98301bd56) | nat: user deletion function & extra metrics |
| [edf777272](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=edf777272) | nat: api & cli command for forcing session cleanup |
| [2c6639c69](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=2c6639c69) | nat: move dslite to separate sub-plugin |

| @c src/plugins/vrrp/vrrp.api ||
| ------- | ------- |
| [3fccd0278](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=3fccd0278) | vrrp: do not define _details as autoreply |
| [39e9428b9](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=39e9428b9) | vrrp: add plugin providing vrrp support |

| @c src/vlib/pci/pci_types.api ||
| ------- | ------- |
| [53f06a014](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=53f06a014) | vlib: move pci api types from vnet/pci to vlib/pci |

@page release_notes_2001 Release notes for VPP 20.01

More than 1039 commits since the 19.08 release.

## Features

- API trace tool
  - Add text output (a2ac36c91)
- Binary API Compiler for Python
  - Raise ValueError when fieldname is python keyword (ff47fb645)
- Binary API Libraries
  - Add API support for marvell PP2 plugin (859b59133)
  - Add bapi thread handle to api main structure. (8229580e8)
  - Multiple connections per process (39d69112f)
  - Multiple socket connections per single process (59cea1a9d)
- Build System
  - Add build types helpstring to cmake project (952a7b8b7)
  - Add env variable to pass extra cmake args (297365403)
  - Add yaml file linting to make checkstyle (6b0dd5502)
  - Export vapi generation in vpp-dev (dc20371f8)
  - Fix 3rd party CI systems. (86a9441c2)
  - Pass 'no-pci' to autgenerated config (be7ef3b5c)
- Crypto ipsecmb Plugin
  - Bump to intel-ipsec-mb version 0.53 (d35fefe8b)
  - Improve gcm performance using dedicated API. (76a36e83e)
- Infrastructure Library
  - Bihash walk cb typedef and continue/stop controls (f50bac1bb)
  - Create unformat function for data size parsing (579b16506)
  - Implement CLIB\_PAUSE () for aarch64 platforms (18512b002)
- libmemif
  - Introduce 'memif\_per\_thread\_' namespace (17f2a7bbf)
- Link Bonding
  - Add/del secondary mac address callback (e83aa456b)
  - Add /if/lacp/bond-sw-if-index/slave-sw-if-index/partner-state (aa7257863)
  - Add weight support for active-backup mode (a1876b84e)
  - Fix interface deletion (cc3aac056)
- Miscellaneous
  - Add address sanitizer heap instrumentation (9fb6d40eb)
  - Add CentOS 8 package support (c025329bb)
  - Add gdb helpers for vlib buffers (2b65f9ca0)
  - Add lcov scripts, README.md (8d74caa0a)
  - Add "maxframe" and "rate" to packet-generator cli. (87d7bac5c)
  - Add "show run summary" (ac78f8a90)
  - Add vnet classify filter set support (f5667c305)
  - Classifier-based packet trace filter (9137e5400)
  - Improve pcap drop trace output (9382ad9b3)
  - Update gitignore for /test/ext/.d (8161d73d7)
- Physical Memory Allocator
  - Always lock pages (801c7016a)
- Plugins
  -  AVF Device driver
    - Improve timeout handling (1a7bb281f)
    - Print queue id in packet trace (c33eddebe)
  -  Buffer Metadata Modification Tracker
    - Buffer metadata change tracker plugin (d7b306657)
  -  builtinurl
    - New plugin (43765e2b4)
  -  DHCP
    - Ipv6 prefix delegation improvements (d318a996b)
    - Move to plugin (02bfd641b)
  -  DPDK
    - Add devargs support (f2bde7ac5)
    - Add function to add/del extra MAC addrs (153727743)
    - Add TSO support in dpdk plugin. (de5ed58fd)
    - Apply dual loop unrolling in DPDK TX (fe2523d1a)
    - Bump DPDK version to 19.08 (b6103105f)
    - Enable bnxt PMD (c3731ac89)
    - Ipsec tunnel support for ip6-in-ip4 (5025d40a1)
    - QAT devices update, add c4xxx and xeon d15xx (4d843b994)
  -  Group Based Policy (GBP)
    - Add extended SFC unit tests (a3c8ca10e)
  -  Host Stack Applications
    - Add ckpair & crypto engine in vpp\_echo (7c40a3837)
    - Add option for multiple ips (f98e59b86)
    - Add periodic timing (ff6cdcca2)
    - Improve for mq-intensive (b2fce36c8)
    - Less verbose logging for many sessions (08f26641f)
    - Make APP\_OPTIONS\_PREALLOC\_FIFO\_PAIRS configurable (7028a0157)
  -  http\_static
    - Add dynamic GET / POST method hooks (5554c56a6)
    - Add "http static cache clear" CLI (e0fd9ed11)
    - Add .json content (71a5da0c8)
  -  Internet Key Exchange (IKEv2) Protocol
    - Add support for GCM cipher (de2dd6c35)
  -  IPv6 Segment Routing Mobile
    - (57584d99d)
  -  Load Balancer
    - Add APIs for set interface nat4 and nat6 (33538a150)
  -  NAT
    - Handoff traffic matching for dynamic NAT (22bb417e9)
  -  Ping
    - Move the echo responder into the ping plugin (f6c8f5090)
  -  QUIC protocol
    - Add aggregated quicly stats (deaf97f45)
    - Add cli command for stats (922f0b211)
    - Add conn-timeout config option (2f566c23f)
    - Add more detailed statistics (1802fcc5f)
    - Add support for ckpair & crypto engine (dcbbf2833)
    - Add support for unidirectional streams (c00f480ba)
    - Add Tx, Rx and packet drop counters (ff1f6faaa)
    - Create custom event logger (dd4d8ac29)
    - Implement crypto contexts (d1b9e7068)
    - Make quic fifo size configurable via cli (00078b991)
    - Update quicly to v0.0.5 (72c159e64)
    - Update quicly to v0.0.6-vpp (3afac8f81)
    - Update quicly to v0.0.7-vpp (69885b72a)
    - Update quicly to v0.0.8-vpp (ecb9d18c5)
    - Update quicly to v0.0.9-vpp (84def7cb7)
  -  RDMA (ibverb) driver
    - Add rdma API (812afe712)
    - Add support for input feature arcs (74eba446b)
    - Add support for MAC changes (0dcafcc50)
    - API: prepare support for direct verb (d8c1ef925)
  -  Time-based MAC filter
    - Add a "top" command to watch device stats (2c41a61d5)
    - Add the "mactime.json" builtin URL (ef3c11ca9)
  -  vmxnet3 device driver
    - Per interface gso support (2985e0af6)
- Python binding for the VPP API
  - Add a per-call \_timeout option (e2ccdf031)
  - Add call stats (fd574087e)
  - Add repr to packer types for troubleshooting (14b0b4791)
  - Add wrapper to validate crc manifest (c046d709e)
  - Enhance MACAddress() equality (6af62565e)
  - Introduce read\_blocking (0938547ea)
  - Let async calls return context (2f6e0c600)
  - Support default for type alias decaying to basetype (418ebb711)
- Sphinx Documents
  - Add spellcheck to 'make docs' sphinx docs (340c15c6e)
- Statistics Segment
  - Add /if/\<n\>/\<n\>/state for lacp interface state (0f09a828a)
- SVM Library
  - Improve fifo segment verbose cli (f8461bfb4)
- Test Infrastructure
  - Add cli\_return\_response to vpp\_papi\_provider (5932ce17e)
  - Add test run time. (0c6293230)
  - Support setting random seed (45a95dd78)
  - Support worker threads (4ecbf105a)
  - Test tls case (419d31f81)
- Vector Library
  - Add flag to explicitelly mark nodes which can init per-node packet trace (7ca5aaac1)
  - Add max-size configuration parameter for pmalloc (842506f3c)
  - Add 'wait' cli command (bfd7d294d)
  - Enhance the "show cli" debug CLI command (a1f5a956e)
- VNET
  - Classify
    - Per-interface rx/tx pcap capture filters (d28437cdf)
    - Use vector code even when data is not aligned (830493392)
    - Vpp packet tracer support (87d24db65)
  - Ethernet
    - All dmac checks include secondary addrs (42bde459b)
    - Dmac filter checks secondary mac addrs (d459bf344)
  - FIB
    - Adjacency creation notifications for dlegates (77cfc0171)
    - Decouple source from priority and behaviour (3bab8f9c5)
    - Table Replace (9db6ada77)
  - FLOW
    - Add 'drop' and 'redirect-to-queue' actions support (e8c9f4f1c)
    - Add ethernet flow (4ff8d615c)
    - Add GTP support (bf85a98fb)
  - GRE
    - Multi-point interfaces (5f8f61733)
  - GSO
    - Add protocol header parser (72e7312af)
  - Interface Common
    - Callback to manage extra MAC addresses (e0792fdff)
    - Dump the interface device type (de312c2d5)
  - IPIP
    - Tunnel flags controlling copying data to/from payload/encap (9534696b4)
  - IPSec
    - Add 'detail' option to 'sh ipsec sa' (670027a50)
    - Add insecure option for format of SA (01d61e788)
    - Bind an SA to a worker (f62a8c013)
    - Remove dedicated IPSec tunnels (12989b538)
    - Support 4o6 and 6o4 for tunnel protect (b325983a4)
  - IPv4 LPM
    - Add shallow virtual reassembly functionality (de34c35fc)
    - Add tracing for ipv6 frag headers (0eb75d0e9)
    - Allow addrs from the same prefix on intf (6c92f5bab)
    - Apply dual loop unrolling in ip4\_input (86b1871ba)
    - Apply dual loop unrolling in ip4\_rewrite (840f64b4b)
  - IPv4 LPM
    - Protocol Independent IP Neighbors (cbe25aab3)
    - Punt rather than drop unkown IPv6 ICMP packets (1afe95272)
    - Reassembly: trace ip headers over worker handoffs (8563cb389)
  - Segment Routing (IPv6 and MPLS)
    - Add "set sr encaps hop-limit" command (eeb5fb3a5)
  - Session Layer
    - Add certificate store (79f89537c)
    - Add crypto context (de6caf481)
    - Add explicit reset api (dfb3b8771)
    - Add mq debug cli (cfdb10918)
    - Add session enable option in config file (1292d19c7)
    - Builtin app rx notifications regardless of state (5c29029ef)
    - Ckpair store & crypto engine as mq params (45ec9f49b)
    - Improve cli (5bb23ecd0)
    - Increasing the Header lengthe size (93e060aee)
    - Limit pacer bucket size (7c8f828ba)
    - More show cli output (91f90d082)
    - Reschedule asap when snd space constrained (dd97a48d9)
    - Support registration of custom crypto engines (79ba25d40)
    - Support for segments larger than 4GB (ef4f3e7fe)
    - Add opaque data to show cli (d9035a409)
    - Infra for transports to send buffers (2a7ea2ee9)
    - Support pacer idle timeouts (11e9e3510)
  - TAP Drivers
    - Add check for vhost-net backend (39807d02c)
    - Multiqueue support (7c6102b1a)
  - TCP
    - Add FEATURE.yaml (93e053ebe)
    - Add no csum offload config option (f4ce6ba22)
    - Add option for always on event logging (a436a4222)
    - Allow cc algos to set pacing rate (d206724e7)
    - Compute snd time for rate sample (7436b4367)
    - Custom checksum calculations for Ipv4/Ipv6 (02833ff32)
    - Enable gso in tcp hoststack (1146ff4bc)
    - Enable TCP timewait port use (b092b77cf)
    - Extend protocol configuration (9094b5c31)
    - Force zero window on full rx fifo (182d21983)
    - Handle sack reneging (558e3e095)
    - Improve lost rxt heuristic (b3dce89a7)
    - Improve pacing after idle send periods (c31dc31f8)
    - Retry lost retransmits (be237bf02)
    - Send rwnd update only if wnd is large enough (017dc4524)
    - Set cc\_algo on connection alloc (12f6936cd)
    - Track lost rxt segments in byte tracker (46ec6e018)
    - Track zero rwnd errors (a495a3ea1)
    - Use rate sample rtt in recovery if possible (1dbda64b4)
    - Use sacks for timer based recovery (36ebcfffb)
    - Validate connections in output (78dae0088)
    - Validate the IP address while checking TCP connection (cf4c2102d)
  - TLS and TLS engine plugins
    - Add C API for TLS openssl to set engine (be4d1aa2c)
    - Improve connection formating (0d74dd1f8)
    - Picotls engine basic enabling for TLS (f83194c2f)
- VPP Comms Library
  - Add api to set lcl ip (ef7cbf6ad)
  - Add config option for preferred tls engine (d747c3c36)
  - Allow non-blocking connects (57c88938f)
- VPP Object Model
  - Get interface type from vpp device type (3f4be92ce)


## Known issues

For the full list of issues please refer to fd.io [JIRA](https://jira.fd.io).

## Issues fixed

For the full list of fixed issues please refer to:
- fd.io [JIRA](https://jira.fd.io)
- git [commit log](https://git.fd.io/vpp/log/?h=stable/2001)

## API changes

Description of results:

* _Definition changed_: indicates that the API file was modified between releases.
* _Only in image_: indicates the API is new for this release.
* _Only in file_: indicates the API has been removed in this release.

Message Name                                                 | Result
-------------------------------------------------------------|------------------
abf_itf_attach_add_del                                       | definition changed
abf_itf_attach_details                                       | definition changed
abf_policy_add_del                                           | definition changed
abf_policy_details                                           | definition changed
af_packet_create                                             | definition changed
af_packet_create_reply                                       | definition changed
af_packet_delete                                             | definition changed
af_packet_details                                            | definition changed
af_packet_set_l4_cksum_offload                               | definition changed
api_versions_reply                                           | definition changed
app_add_cert_key_pair                                        | only in image
app_add_cert_key_pair_reply                                  | only in image
app_attach                                                   | only in image
app_attach_reply                                             | only in image
app_del_cert_key_pair                                        | only in image
app_del_cert_key_pair_reply                                  | only in image
avf_create_reply                                             | definition changed
avf_delete                                                   | definition changed
bd_ip_mac_add_del                                            | definition changed
bd_ip_mac_details                                            | definition changed
bfd_udp_add                                                  | definition changed
bfd_udp_auth_activate                                        | definition changed
bfd_udp_auth_deactivate                                      | definition changed
bfd_udp_del                                                  | definition changed
bfd_udp_get_echo_source_reply                                | definition changed
bfd_udp_mod                                                  | definition changed
bfd_udp_session_details                                      | definition changed
bfd_udp_session_set_flags                                    | definition changed
bfd_udp_set_echo_source                                      | definition changed
bier_disp_entry_add_del                                      | definition changed
bier_disp_entry_details                                      | definition changed
bier_disp_table_add_del                                      | definition changed
bier_route_add_del                                           | definition changed
bier_table_add_del                                           | definition changed
bond_create                                                  | definition changed
bond_create_reply                                            | definition changed
bond_delete                                                  | definition changed
bond_detach_slave                                            | definition changed
bond_enslave                                                 | definition changed
builtinurl_enable                                            | only in image
builtinurl_enable_reply                                      | only in image
bvi_create                                                   | definition changed
cdp_enable_disable                                           | definition changed
classify_add_del_session                                     | definition changed
classify_add_del_table                                       | definition changed
classify_set_interface_ip_table                              | definition changed
classify_set_interface_l2_tables                             | definition changed
classify_table_by_interface                                  | definition changed
classify_table_by_interface_reply                            | definition changed
cli_inband                                                   | definition changed
cli_inband_reply                                             | definition changed
collect_detailed_interface_stats                             | definition changed
connect_sock                                                 | definition changed
cop_interface_enable_disable                                 | definition changed
cop_whitelist_enable_disable                                 | definition changed
create_loopback                                              | definition changed
create_loopback_instance                                     | definition changed
create_loopback_instance_reply                               | definition changed
create_loopback_reply                                        | definition changed
create_subif                                                 | definition changed
create_subif_reply                                           | definition changed
create_vhost_user_if                                         | definition changed
create_vhost_user_if_reply                                   | definition changed
create_vlan_subif                                            | definition changed
create_vlan_subif_reply                                      | definition changed
ct6_enable_disable                                           | definition changed
delete_loopback                                              | definition changed
delete_subif                                                 | definition changed
delete_vhost_user_if                                         | definition changed
dhcp6_client_enable_disable                                  | definition changed
dhcp6_clients_enable_disable                                 | definition changed
dhcp6_pd_client_enable_disable                               | definition changed
dhcp6_pd_reply_event                                         | definition changed
dhcp6_pd_send_client_message                                 | definition changed
dhcp6_reply_event                                            | definition changed
dhcp6_send_client_message                                    | definition changed
dhcp_client_config                                           | definition changed
dhcp_client_details                                          | definition changed
dhcp_compl_event                                             | definition changed
dhcp_plugin_control_ping                                     | only in image
dhcp_plugin_control_ping_reply                               | only in image
dhcp_plugin_get_version                                      | only in image
dhcp_plugin_get_version_reply                                | only in image
dhcp_proxy_config                                            | definition changed
dhcp_proxy_details                                           | definition changed
dhcp_proxy_dump                                              | definition changed
dhcp_proxy_set_vss                                           | definition changed
dslite_add_del_pool_addr_range                               | definition changed
dslite_address_details                                       | definition changed
dslite_get_aftr_addr_reply                                   | definition changed
dslite_get_b4_addr_reply                                     | definition changed
dslite_set_aftr_addr                                         | definition changed
dslite_set_b4_addr                                           | definition changed
feature_enable_disable                                       | definition changed
feature_gso_enable_disable                                   | only in image
feature_gso_enable_disable_reply                             | only in image
flow_classify_details                                        | definition changed
flow_classify_dump                                           | definition changed
flow_classify_set_interface                                  | definition changed
flowprobe_params                                             | definition changed
flowprobe_tx_interface_add_del                               | definition changed
gbp_bridge_domain_add                                        | definition changed
gbp_bridge_domain_details                                    | definition changed
gbp_contract_add_del                                         | definition changed
gbp_contract_details                                         | definition changed
gbp_endpoint_add                                             | definition changed
gbp_endpoint_details                                         | definition changed
gbp_endpoint_group_add                                       | definition changed
gbp_endpoint_group_details                                   | definition changed
gbp_ext_itf_add_del                                          | definition changed
gbp_ext_itf_details                                          | definition changed
gbp_recirc_add_del                                           | definition changed
gbp_recirc_details                                           | definition changed
gbp_route_domain_add                                         | definition changed
gbp_route_domain_details                                     | definition changed
gbp_subnet_add_del                                           | definition changed
gbp_subnet_details                                           | definition changed
gbp_vxlan_tunnel_add                                         | definition changed
gbp_vxlan_tunnel_add_reply                                   | definition changed
gbp_vxlan_tunnel_details                                     | definition changed
geneve_add_del_tunnel                                        | definition changed
geneve_add_del_tunnel_reply                                  | definition changed
geneve_tunnel_details                                        | definition changed
geneve_tunnel_dump                                           | definition changed
get_first_msg_id                                             | definition changed
gre_tunnel_add_del                                           | definition changed
gre_tunnel_add_del_reply                                     | definition changed
gre_tunnel_details                                           | definition changed
gre_tunnel_dump                                              | definition changed
gtpu_add_del_tunnel                                          | definition changed
gtpu_add_del_tunnel_reply                                    | definition changed
gtpu_tunnel_details                                          | definition changed
gtpu_tunnel_dump                                             | definition changed
http_static_enable                                           | definition changed
hw_interface_set_mtu                                         | definition changed
igmp_clear_interface                                         | definition changed
igmp_details                                                 | definition changed
igmp_dump                                                    | definition changed
igmp_enable_disable                                          | definition changed
igmp_event                                                   | definition changed
igmp_group_prefix_details                                    | definition changed
igmp_group_prefix_set                                        | definition changed
igmp_listen                                                  | definition changed
igmp_proxy_device_add_del                                    | definition changed
igmp_proxy_device_add_del_interface                          | definition changed
ikev2_initiate_sa_init                                       | definition changed
ikev2_profile_add_del                                        | definition changed
ikev2_profile_set_auth                                       | definition changed
ikev2_profile_set_id                                         | definition changed
ikev2_profile_set_ts                                         | definition changed
ikev2_set_esp_transforms                                     | definition changed
ikev2_set_ike_transforms                                     | definition changed
ikev2_set_responder                                          | definition changed
ikev2_set_sa_lifetime                                        | definition changed
input_acl_set_interface                                      | definition changed
interface_name_renumber                                      | definition changed
ioam_cache_ip6_enable_disable                                | definition changed
ioam_enable                                                  | definition changed
ioam_export_ip6_enable_disable                               | definition changed
ip4_arp_event                                                | only in file
ip6_add_del_address_using_prefix                             | definition changed
ip6_nd_address_autoconfig                                    | definition changed
ip6_nd_event                                                 | only in file
ip6_ra_event                                                 | definition changed
ip6nd_proxy_add_del                                          | definition changed
ip6nd_proxy_details                                          | definition changed
ip6nd_send_router_solicitation                               | definition changed
ip_address_details                                           | definition changed
ip_address_dump                                              | definition changed
ip_container_proxy_add_del                                   | definition changed
ip_container_proxy_details                                   | definition changed
ip_details                                                   | definition changed
ip_dump                                                      | definition changed
ip_mroute_add_del                                            | definition changed
ip_mroute_details                                            | definition changed
ip_mroute_dump                                               | definition changed
ip_mtable_details                                            | definition changed
ip_neighbor_add_del                                          | definition changed
ip_neighbor_config                                           | only in image
ip_neighbor_config_reply                                     | only in image
ip_neighbor_details                                          | definition changed
ip_neighbor_dump                                             | definition changed
ip_neighbor_event                                            | only in image
ip_probe_neighbor                                            | only in file
ip_probe_neighbor_reply                                      | only in file
ip_punt_police                                               | definition changed
ip_punt_redirect                                             | definition changed
ip_punt_redirect_details                                     | definition changed
ip_punt_redirect_dump                                        | definition changed
ip_reassembly_enable_disable                                 | definition changed
ip_reassembly_get                                            | definition changed
ip_reassembly_get_reply                                      | definition changed
ip_reassembly_set                                            | definition changed
ip_route_add_del                                             | definition changed
ip_route_details                                             | definition changed
ip_route_dump                                                | definition changed
ip_scan_neighbor_enable_disable                              | only in file
ip_scan_neighbor_enable_disable_reply                        | only in file
ip_source_and_port_range_check_add_del                       | definition changed
ip_source_and_port_range_check_interface_add_del             | definition changed
ip_source_check_interface_add_del                            | definition changed
ip_table_add_del                                             | definition changed
ip_table_details                                             | definition changed
ip_table_flush                                               | only in image
ip_table_flush_reply                                         | only in image
ip_table_replace_begin                                       | only in image
ip_table_replace_begin_reply                                 | only in image
ip_table_replace_end                                         | only in image
ip_table_replace_end_reply                                   | only in image
ip_unnumbered_details                                        | definition changed
ip_unnumbered_dump                                           | definition changed
ipfix_classify_table_add_del                                 | definition changed
ipfix_classify_table_details                                 | definition changed
ipfix_exporter_details                                       | definition changed
ipip_6rd_add_tunnel                                          | definition changed
ipip_6rd_add_tunnel_reply                                    | definition changed
ipip_6rd_del_tunnel                                          | definition changed
ipip_add_tunnel                                              | definition changed
ipip_add_tunnel_reply                                        | definition changed
ipip_del_tunnel                                              | definition changed
ipip_tunnel_details                                          | definition changed
ipip_tunnel_dump                                             | definition changed
ipsec_spd_details                                            | definition changed
ipsec_spd_entry_add_del                                      | definition changed
ipsec_tunnel_if_add_del                                      | definition changed
ipsec_tunnel_protect_del                                     | definition changed
ipsec_tunnel_protect_details                                 | definition changed
ipsec_tunnel_protect_dump                                    | definition changed
ipsec_tunnel_protect_update                                  | definition changed
l2_arp_term_event                                            | only in image
l2_emulation                                                 | definition changed
l2tpv3_create_tunnel                                         | definition changed
l2tpv3_create_tunnel_reply                                   | definition changed
l2tpv3_interface_enable_disable                              | definition changed
l2tpv3_set_lookup_key                                        | definition changed
l2tpv3_set_tunnel_cookies                                    | definition changed
l3xc_del                                                     | definition changed
l3xc_details                                                 | definition changed
l3xc_dump                                                    | definition changed
l3xc_update                                                  | definition changed
lb_add_del_as                                                | definition changed
lb_add_del_intf_nat4                                         | only in image
lb_add_del_intf_nat4_reply                                   | only in image
lb_add_del_intf_nat6                                         | only in image
lb_add_del_intf_nat6_reply                                   | only in image
lb_add_del_vip                                               | definition changed
lb_as_details                                                | definition changed
lb_as_dump                                                   | definition changed
lb_conf                                                      | definition changed
lb_flush_vip                                                 | definition changed
lb_vip_details                                               | definition changed
lb_vip_dump                                                  | definition changed
log_details                                                  | definition changed
log_dump                                                     | definition changed
mactime_add_del_range                                        | definition changed
mactime_details                                              | only in image
mactime_dump                                                 | only in image
mactime_dump_reply                                           | only in image
mactime_enable_disable                                       | definition changed
map_add_del_rule                                             | definition changed
map_add_domain                                               | definition changed
map_domain_details                                           | definition changed
map_if_enable_disable                                        | definition changed
map_param_add_del_pre_resolve                                | definition changed
map_param_get_reply                                          | definition changed
map_param_set_icmp                                           | definition changed
map_param_set_reassembly                                     | only in file
map_param_set_reassembly_reply                               | only in file
map_param_set_traffic_class                                  | definition changed
map_rule_details                                             | definition changed
mdata_enable_disable                                         | only in image
mdata_enable_disable_reply                                   | only in image
memclnt_create                                               | definition changed
memclnt_delete                                               | definition changed
memif_create                                                 | definition changed
memif_create_reply                                           | definition changed
memif_delete                                                 | definition changed
memif_details                                                | definition changed
memif_socket_filename_add_del                                | definition changed
memif_socket_filename_details                                | definition changed
mfib_signal_details                                          | definition changed
modify_vhost_user_if                                         | definition changed
mpls_ip_bind_unbind                                          | definition changed
mpls_route_add_del                                           | definition changed
mpls_route_details                                           | definition changed
mpls_route_dump                                              | definition changed
mpls_table_add_del                                           | definition changed
mpls_table_details                                           | definition changed
mpls_tunnel_add_del                                          | definition changed
mpls_tunnel_add_del_reply                                    | definition changed
mpls_tunnel_details                                          | definition changed
mpls_tunnel_dump                                             | definition changed
nat44_add_del_address_range                                  | definition changed
nat44_add_del_identity_mapping                               | definition changed
nat44_add_del_interface_addr                                 | definition changed
nat44_add_del_lb_static_mapping                              | definition changed
nat44_add_del_static_mapping                                 | definition changed
nat44_address_details                                        | definition changed
nat44_del_session                                            | definition changed
nat44_identity_mapping_details                               | definition changed
nat44_interface_add_del_feature                              | definition changed
nat44_interface_add_del_output_feature                       | definition changed
nat44_interface_addr_details                                 | definition changed
nat44_interface_details                                      | definition changed
nat44_interface_output_feature_details                       | definition changed
nat44_lb_static_mapping_add_del_local                        | definition changed
nat44_lb_static_mapping_details                              | definition changed
nat44_static_mapping_details                                 | definition changed
nat44_user_details                                           | definition changed
nat44_user_session_details                                   | definition changed
nat44_user_session_dump                                      | definition changed
nat64_add_del_interface_addr                                 | definition changed
nat64_add_del_interface                                      | definition changed
nat64_add_del_pool_addr_range                                | definition changed
nat64_add_del_prefix                                         | definition changed
nat64_add_del_static_bib                                     | definition changed
nat64_bib_details                                            | definition changed
nat64_interface_details                                      | definition changed
nat64_pool_addr_details                                      | definition changed
nat64_prefix_details                                         | definition changed
nat64_st_details                                             | definition changed
nat66_add_del_interface                                      | definition changed
nat66_add_del_static_mapping                                 | definition changed
nat66_interface_details                                      | definition changed
nat66_static_mapping_details                                 | definition changed
nat_det_add_del_map                                          | definition changed
nat_det_close_session_in                                     | definition changed
nat_det_close_session_out                                    | definition changed
nat_det_forward                                              | definition changed
nat_det_forward_reply                                        | definition changed
nat_det_map_details                                          | definition changed
nat_det_reverse                                              | definition changed
nat_det_reverse_reply                                        | definition changed
nat_det_session_details                                      | definition changed
nat_det_session_dump                                         | definition changed
nat_get_reass                                                | only in file
nat_get_reass_reply                                          | only in file
nat_ha_get_failover_reply                                    | definition changed
nat_ha_get_listener_reply                                    | definition changed
nat_ha_set_failover                                          | definition changed
nat_ha_set_listener                                          | definition changed
nat_reass_details                                            | only in file
nat_reass_dump                                               | only in file
nat_set_reass                                                | only in file
nat_set_reass_reply                                          | only in file
nat_worker_details                                           | definition changed
nhrp_details                                                 | only in image
nhrp_dump                                                    | only in image
nhrp_entry_add_del                                           | only in image
nhrp_entry_add_del_reply                                     | only in image
nsh_add_del_entry                                            | definition changed
nsh_add_del_map                                              | definition changed
nsh_map_details                                              | definition changed
nsim_cross_connect_enable_disable                            | definition changed
nsim_output_feature_enable_disable                           | definition changed
output_acl_set_interface                                     | definition changed
p2p_ethernet_add                                             | definition changed
p2p_ethernet_add_reply                                       | definition changed
p2p_ethernet_del                                             | definition changed
pipe_create                                                  | definition changed
pipe_create_reply                                            | definition changed
pipe_delete                                                  | definition changed
pipe_details                                                 | definition changed
policer_classify_details                                     | definition changed
policer_classify_dump                                        | definition changed
policer_classify_set_interface                               | definition changed
pot_profile_activate                                         | definition changed
pot_profile_add                                              | definition changed
pot_profile_del                                              | definition changed
pppoe_add_del_session                                        | definition changed
pppoe_add_del_session_reply                                  | definition changed
pppoe_session_details                                        | definition changed
pppoe_session_dump                                           | definition changed
proxy_arp_add_del                                            | definition changed
proxy_arp_details                                            | definition changed
proxy_arp_intfc_enable_disable                               | definition changed
punt_reason_details                                          | definition changed
punt_reason_dump                                             | definition changed
punt_socket_details                                          | definition changed
punt_socket_register                                         | definition changed
punt_socket_register_reply                                   | definition changed
qos_mark_dump                                                | definition changed
qos_mark_enable_disable                                      | definition changed
qos_record_details                                           | definition changed
qos_record_enable_disable                                    | definition changed
qos_store_details                                            | definition changed
qos_store_enable_disable                                     | definition changed
rdma_create                                                  | only in image
rdma_create_reply                                            | only in image
rdma_delete                                                  | only in image
rdma_delete_reply                                            | only in image
reset_fib                                                    | only in file
reset_fib_reply                                              | only in file
set_arp_neighbor_limit                                       | only in file
set_arp_neighbor_limit_reply                                 | only in file
set_ip_flow_hash                                             | definition changed
set_ipfix_exporter                                           | definition changed
set_punt                                                     | definition changed
show_version_reply                                           | definition changed
show_vpe_system_time_reply                                   | definition changed
sockclnt_create                                              | definition changed
sockclnt_create_reply                                        | definition changed
sr_set_encap_hop_limit                                       | only in image
sr_set_encap_hop_limit_reply                                 | only in image
stn_add_del_rule                                             | definition changed
stn_rules_details                                            | definition changed
svs_details                                                  | definition changed
svs_enable_disable                                           | definition changed
svs_route_add_del                                            | definition changed
svs_table_add_del                                            | definition changed
sw_if_l2tpv3_tunnel_details                                  | definition changed
sw_interface_add_del_address                                 | definition changed
sw_interface_add_del_mac_address                             | only in image
sw_interface_add_del_mac_address_reply                       | only in image
sw_interface_bond_details                                    | definition changed
sw_interface_clear_stats                                     | definition changed
sw_interface_details                                         | definition changed
sw_interface_dump                                            | definition changed
sw_interface_event                                           | definition changed
sw_interface_get_mac_address                                 | definition changed
sw_interface_get_mac_address_reply                           | definition changed
sw_interface_get_table                                       | definition changed
sw_interface_ip6_enable_disable                              | definition changed
sw_interface_ip6_set_link_local_address                      | definition changed
sw_interface_ip6nd_ra_config                                 | definition changed
sw_interface_ip6nd_ra_prefix                                 | definition changed
sw_interface_lacp_details                                    | definition changed
sw_interface_rx_placement_details                            | definition changed
sw_interface_rx_placement_dump                               | definition changed
sw_interface_set_bond_weight                                 | only in image
sw_interface_set_bond_weight_reply                           | only in image
sw_interface_set_flags                                       | definition changed
sw_interface_set_geneve_bypass                               | definition changed
sw_interface_set_gtpu_bypass                                 | definition changed
sw_interface_set_ip_directed_broadcast                       | definition changed
sw_interface_set_mac_address                                 | definition changed
sw_interface_set_mpls_enable                                 | definition changed
sw_interface_set_mtu                                         | definition changed
sw_interface_set_rx_mode                                     | definition changed
sw_interface_set_rx_placement                                | definition changed
sw_interface_set_table                                       | definition changed
sw_interface_set_unnumbered                                  | definition changed
sw_interface_set_vxlan_gbp_bypass                            | definition changed
sw_interface_slave_details                                   | definition changed
sw_interface_slave_dump                                      | definition changed
sw_interface_tag_add_del                                     | definition changed
sw_interface_tap_v2_details                                  | definition changed
sw_interface_tap_v2_dump                                     | definition changed
sw_interface_vhost_user_details                              | definition changed
sw_interface_vhost_user_dump                                 | definition changed
sw_interface_virtio_pci_details                              | definition changed
syslog_get_sender_reply                                      | definition changed
syslog_set_sender                                            | definition changed
tap_create_v2                                                | definition changed
tap_create_v2_reply                                          | definition changed
tap_delete_v2                                                | definition changed
tcp_configure_src_addresses                                  | definition changed
tls_openssl_set_engine                                       | only in image
tls_openssl_set_engine_reply                                 | only in image
trace_plugin_msg_ids                                         | definition changed
udp_encap_add                                                | definition changed
udp_encap_details                                            | definition changed
udp_ping_add_del                                             | definition changed
udp_ping_export                                              | definition changed
virtio_pci_create                                            | definition changed
virtio_pci_create_reply                                      | definition changed
virtio_pci_delete                                            | definition changed
vmxnet3_create                                               | definition changed
vmxnet3_create_reply                                         | definition changed
vmxnet3_delete                                               | definition changed
vmxnet3_details                                              | definition changed
vxlan_gbp_tunnel_add_del                                     | definition changed
vxlan_gbp_tunnel_add_del_reply                               | definition changed
vxlan_gbp_tunnel_details                                     | definition changed
vxlan_gbp_tunnel_dump                                        | definition changed
vxlan_gpe_ioam_enable                                        | definition changed
vxlan_gpe_ioam_export_enable_disable                         | definition changed
vxlan_gpe_ioam_transit_disable                               | definition changed
vxlan_gpe_ioam_transit_enable                                | definition changed
vxlan_gpe_ioam_vni_disable                                   | definition changed
vxlan_gpe_ioam_vni_enable                                    | definition changed
want_bfd_events                                              | definition changed
want_dhcp6_pd_reply_events                                   | definition changed
want_ip4_arp_events                                          | only in file
want_ip4_arp_events_reply                                    | only in file
want_ip6_nd_events                                           | only in file
want_ip6_nd_events_reply                                     | only in file
want_ip6_ra_events                                           | definition changed
want_ip_neighbor_events                                      | only in image
want_ip_neighbor_events_reply                                | only in image
want_l2_arp_term_events                                      | only in image
want_l2_arp_term_events_reply                                | only in image
want_l2_macs_events                                          | definition changed

Found 493 api message signature differences

### Patches that changed API definitions

| @c src/vlibmemory/memclnt.api ||
| ------- | ------- |
| [8e388390d](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=8e388390d) | vlib: use explicit types in api |
| [daa4bff16](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=daa4bff16) | api: memclnt api use string type. |
| [7adaa226e](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=7adaa226e) | api: revert use string type for strings in memclnt.api |
| [2959d42fe](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=2959d42fe) | api: use string type for strings in memclnt.api |
| [e71748291](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e71748291) | vppapigen: remove support for legacy typedefs |

| @c src/examples/sample-plugin/sample/sample.api ||
| ------- | ------- |
| [33a58171e](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=33a58171e) | api: autogenerate api trace print/endian |
| [78d91cf9a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=78d91cf9a) | sample-plugin: refactor .api to use explicit types |

| @c src/vnet/interface.api ||
| ------- | ------- |
| [418ebb711](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=418ebb711) | papi: support default for type alias decaying to basetype |
| [9485d99bd](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9485d99bd) | interface: Allow VLAN tag-rewrite on non-sub-interfaces too. |
| [c12eae73f](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c12eae73f) | interface: shmemioerror while getting name_filter arg |
| [de312c2d5](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=de312c2d5) | interface: dump the interface device type |
| [e0792fdff](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e0792fdff) | interface: callback to manage extra MAC addresses |
| [75761b933](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=75761b933) | api: split vl_api_prefix into two |
| [e5ff5a36d](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e5ff5a36d) | api: enforce vla is last and fixed string type |
| [053204ab0](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=053204ab0) | api: Cleanup APIs interface.api |
| [0ad4a439d](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=0ad4a439d) | Fix vpp crash bug while deleting dhcp client |
| [9a29f795a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9a29f795a) | vpp_papi_provider.py: update defautmapping. |
| [b8591ac91](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b8591ac91) | API sw_interface_dump: Dump all if index is zero |
| [4a7240636](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=4a7240636) | Make sw_interface_dump more compatible with 2.2.0 |
| [6407ba56a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=6407ba56a) | api: Add to interface crud - read by sw_if_index. |

| @c src/vnet/interface_types.api ||
| ------- | ------- |
| [053204ab0](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=053204ab0) | api: Cleanup APIs interface.api |

| @c src/vnet/session/session.api ||
| ------- | ------- |
| [c4c4cf506](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c4c4cf506) | session: move add/del segment msg to mq |
| [79f89537c](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=79f89537c) | session: Add certificate store |
| [e5ff5a36d](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e5ff5a36d) | api: enforce vla is last and fixed string type |
| [458089bba](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=458089bba) | session: move ctrl messages from bapi to mq |
| [8ac1d6d05](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=8ac1d6d05) | session: Use parent_handle instead of transport_opts |
| [ba65ca496](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=ba65ca496) | Add transport_opts to connect_sock bapi |

| @c src/vnet/classify/classify.api ||
| ------- | ------- |
| [692bfc85f](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=692bfc85f) | classify: API cleanup |

| @c src/vnet/l2tp/l2tp.api ||
| ------- | ------- |
| [3ae526271](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=3ae526271) | l2: l2tp API cleanup |

| @c src/vnet/gre/gre.api ||
| ------- | ------- |
| [5f8f61733](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=5f8f61733) | gre: Multi-point interfaces |
| [814f15948](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=814f15948) | gre: update gre.api with explicit types |
| [d0aed2eb3](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=d0aed2eb3) | GRE: set gre_tunnel_type init value to zero in API |
| [5a8844bdb](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=5a8844bdb) | GRE: API update |

| @c src/vnet/fib/fib_types.api ||
| ------- | ------- |
| [1dbcf30b7](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=1dbcf30b7) | fib: Support the POP of a Psuedo Wire Control Word |
| [097fa66b9](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=097fa66b9) | fib: fib api updates |

| @c src/vnet/lisp-cp/one.api ||
| ------- | ------- |
| [e71748291](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e71748291) | vppapigen: remove support for legacy typedefs |

| @c src/vnet/lisp-cp/lisp.api ||
| ------- | ------- |
| [e71748291](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e71748291) | vppapigen: remove support for legacy typedefs |

| @c src/vnet/feature/feature.api ||
| ------- | ------- |
| [bf6c5c158](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=bf6c5c158) | feature: API cleanup |

| @c src/vnet/nhrp/nhrp.api ||
| ------- | ------- |
| [5f8f61733](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=5f8f61733) | gre: Multi-point interfaces |

| @c src/vnet/qos/qos.api ||
| ------- | ------- |
| [4b76c58be](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=4b76c58be) | qos: api clenup |
| [83832e7ce](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=83832e7ce) | qos: Store function |
| [5281a9029](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=5281a9029) | qos: QoS dump APIs |

| @c src/vnet/ipsec/ipsec.api ||
| ------- | ------- |
| [dbf68c9aa](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=dbf68c9aa) | ipsec: Changes to make ipsec encoder/decoders reusable by the plugins |
| [12989b538](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=12989b538) | ipsec: remove dedicated IPSec tunnels |
| [c87b66c86](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c87b66c86) | ipsec: ipsec-tun protect |
| [f2922422d](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f2922422d) | ipsec: remove the set_key API |
| [80f6fd53f](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=80f6fd53f) | IPSEC: Pass the algorithm salt (used in GCM) over the API |

| @c src/vnet/ipsec/ipsec_types.api ||
| ------- | ------- |
| [dbf68c9aa](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=dbf68c9aa) | ipsec: Changes to make ipsec encoder/decoders reusable by the plugins |

| @c src/vnet/lisp-gpe/lisp_gpe.api ||
| ------- | ------- |
| [e71748291](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e71748291) | vppapigen: remove support for legacy typedefs |

| @c src/vnet/pci/pci_types.api ||
| ------- | ------- |
| [2c504f89c](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=2c504f89c) | devices: virtio API cleanup |

| @c src/vnet/bonding/bond.api ||
| ------- | ------- |
| [3d1ef873d](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=3d1ef873d) | bonding: API cleanup |
| [a1876b84e](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=a1876b84e) | bonding: add weight support for active-backup mode |
| [751e3f382](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=751e3f382) | bonding: add support for numa-only in lacp mode |

| @c src/vnet/tcp/tcp.api ||
| ------- | ------- |
| [956819afa](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=956819afa) | tcp: api clenup |

| @c src/vnet/cop/cop.api ||
| ------- | ------- |
| [aa4438a31](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=aa4438a31) | cop: API cleanup |

| @c src/vnet/ip-neighbor/ip_neighbor.api ||
| ------- | ------- |
| [cbe25aab3](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=cbe25aab3) | ip: Protocol Independent IP Neighbors |

| @c src/vnet/ethernet/p2p_ethernet.api ||
| ------- | ------- |
| [8edca1361](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=8edca1361) | p2p ethernet: update p2p_ethernet.api with explicit types. |

| @c src/vnet/ethernet/ethernet_types.api ||
| ------- | ------- |
| [33a58171e](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=33a58171e) | api: autogenerate api trace print/endian |

| @c src/vnet/vxlan-gbp/vxlan_gbp.api ||
| ------- | ------- |
| [fb27096ee](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=fb27096ee) | vxlan-gbp: api cleanup |

| @c src/vnet/arp/arp.api ||
| ------- | ------- |
| [cbe25aab3](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=cbe25aab3) | ip: Protocol Independent IP Neighbors |

| @c src/vnet/ipip/ipip.api ||
| ------- | ------- |
| [9534696b4](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9534696b4) | ipip: Tunnel flags controlling copying data to/from payload/encap |
| [288e09362](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=288e09362) | ipip: refactor ipip.api with explicit types |
| [cbd0824d6](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=cbd0824d6) | IPIP tunnel: use address types on API |

| @c src/vnet/ipip/ipip_types.api ||
| ------- | ------- |
| [9534696b4](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9534696b4) | ipip: Tunnel flags controlling copying data to/from payload/encap |

| @c src/vnet/bfd/bfd.api ||
| ------- | ------- |
| [4682feb1f](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=4682feb1f) | bfd: API cleanup |

| @c src/vnet/l2/l2.api ||
| ------- | ------- |
| [cbe25aab3](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=cbe25aab3) | ip: Protocol Independent IP Neighbors |
| [e71748291](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e71748291) | vppapigen: remove support for legacy typedefs |
| [bc764c8bc](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=bc764c8bc) | l2: BD ARP termination entry API update |
| [54bc5e40c](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=54bc5e40c) | Update API description |
| [5e6f7348c](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=5e6f7348c) | l2: Add support for arp unicast forwarding |

| @c src/vnet/ip6-nd/ip6_nd.api ||
| ------- | ------- |
| [cbe25aab3](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=cbe25aab3) | ip: Protocol Independent IP Neighbors |

| @c src/vnet/ip6-nd/rd_cp.api ||
| ------- | ------- |
| [cbe25aab3](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=cbe25aab3) | ip: Protocol Independent IP Neighbors |

| @c src/vnet/udp/udp.api ||
| ------- | ------- |
| [10dc2eabd](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=10dc2eabd) | udp: fix copyright typo |

| @c src/vnet/mpls/mpls.api ||
| ------- | ------- |
| [3eb8f207b](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=3eb8f207b) | mpls: api cleanup |
| [75761b933](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=75761b933) | api: split vl_api_prefix into two |
| [e71748291](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e71748291) | vppapigen: remove support for legacy typedefs |
| [097fa66b9](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=097fa66b9) | fib: fib api updates |

| @c src/vnet/mfib/mfib_types.api ||
| ------- | ------- |
| [e71748291](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e71748291) | vppapigen: remove support for legacy typedefs |
| [097fa66b9](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=097fa66b9) | fib: fib api updates |

| @c src/vnet/ip/ip_types.api ||
| ------- | ------- |
| [75761b933](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=75761b933) | api: split vl_api_prefix into two |
| [33a58171e](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=33a58171e) | api: autogenerate api trace print/endian |
| [515eed425](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=515eed425) | api: add prefix matcher typedef |
| [038e1dfbd](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=038e1dfbd) | dhcp ip: DSCP settings for transmitted DHCP packets |
| [53c501512](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=53c501512) | api: add DSCP definitions to ip_types.api |
| [ab05508e1](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=ab05508e1) | api: refactor format_vl_api_prefix_t return keys |
| [b538dd868](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b538dd868) | Punt: specify packets by IP protocol Type |
| [50f0ac0f0](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=50f0ac0f0) | Punt: socket register for exception dispatched/punted packets based on reason |

| @c src/vnet/ip/punt.api ||
| ------- | ------- |
| [f158944cc](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f158944cc) | ip: trivial typos in docs |
| [f72ad93d6](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f72ad93d6) | ip: punt API cleanup |
| [e5ff5a36d](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e5ff5a36d) | api: enforce vla is last and fixed string type |
| [719beb709](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=719beb709) | ip ipsec: Remove IPSec SPI-0 punt reason |
| [b538dd868](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b538dd868) | Punt: specify packets by IP protocol Type |
| [50f0ac0f0](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=50f0ac0f0) | Punt: socket register for exception dispatched/punted packets based on reason |

| @c src/vnet/ip/ip.api ||
| ------- | ------- |
| [58989a37d](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=58989a37d) | ip: API cleanup |
| [cbe25aab3](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=cbe25aab3) | ip: Protocol Independent IP Neighbors |
| [668605fc8](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=668605fc8) | ip: use explicit types in api |
| [9db6ada77](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9db6ada77) | fib: Table Replace |
| [de34c35fc](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=de34c35fc) | ip: add shallow virtual reassembly functionality |
| [75761b933](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=75761b933) | api: split vl_api_prefix into two |
| [e71748291](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e71748291) | vppapigen: remove support for legacy typedefs |
| [097fa66b9](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=097fa66b9) | fib: fib api updates |
| [3a343d42d](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=3a343d42d) | reassembly: prevent long chain attack |

| @c src/vnet/pg/pg.api ||
| ------- | ------- |
| [22e9cfd76](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=22e9cfd76) | pg: add GSO support |

| @c src/vnet/bier/bier.api ||
| ------- | ------- |
| [f1f5a8a1a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f1f5a8a1a) | bier: API cleanup |
| [e71748291](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e71748291) | vppapigen: remove support for legacy typedefs |
| [097fa66b9](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=097fa66b9) | fib: fib api updates |
| [e6eefb6e3](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e6eefb6e3) | Trivial Typo's in bier comments/docs. |

| @c src/vnet/ipfix-export/ipfix_export.api ||
| ------- | ------- |
| [2f71a8889](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=2f71a8889) | ip: ipfix-export API update |
| [21b83e96d](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=21b83e96d) | api: implement ipfix_flush |

| @c src/vnet/gso/gso.api ||
| ------- | ------- |
| [29467b534](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=29467b534) | gso: Add gso feature arc |

| @c src/vnet/devices/af_packet/af_packet.api ||
| ------- | ------- |
| [97c998c28](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=97c998c28) | docs: devices-- add FEATURES.yaml |
| [3b2db9002](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=3b2db9002) | devices: af_packet API cleanup |

| @c src/vnet/devices/virtio/vhost_user.api ||
| ------- | ------- |
| [5d4c99f27](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=5d4c99f27) | devices: vhost API cleanup |
| [4208a4ce8](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=4208a4ce8) | devices interface tests: vhosst GSO support |

| @c src/vnet/devices/virtio/virtio_types.api ||
| ------- | ------- |
| [5d4c99f27](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=5d4c99f27) | devices: vhost API cleanup |

| @c src/vnet/devices/virtio/virtio.api ||
| ------- | ------- |
| [6d4af8918](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=6d4af8918) | virtio: split gso and checksum offload functionality |
| [2c504f89c](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=2c504f89c) | devices: virtio API cleanup |
| [97c998c28](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=97c998c28) | docs: devices-- add FEATURES.yaml |
| [bbd6b746e](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=bbd6b746e) | virtio: Add gso support for native virtio driver |
| [43b512cac](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=43b512cac) | virtio: remove configurable queue size support |

| @c src/vnet/devices/pipe/pipe.api ||
| ------- | ------- |
| [97c998c28](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=97c998c28) | docs: devices-- add FEATURES.yaml |
| [df40cb5b5](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=df40cb5b5) | devices: pipe API cleanup |

| @c src/vnet/devices/tap/tapv2.api ||
| ------- | ------- |
| [ba0061feb](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=ba0061feb) | tap: split gso and checksum offload functionality |
| [5de4fb707](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=5de4fb707) | devices: tap API cleanup |
| [44d06916b](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=44d06916b) | tap: Move client registration check to top |
| [97c998c28](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=97c998c28) | docs: devices-- add FEATURES.yaml |
| [97d54ed43](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=97d54ed43) | tap: add support to configure tap interface host MTU size |

| @c src/vnet/srv6/sr.api ||
| ------- | ------- |
| [eeb5fb3a5](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=eeb5fb3a5) | sr: add "set sr encaps hop-limit" command |
| [e71748291](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e71748291) | vppapigen: remove support for legacy typedefs |

| @c src/vnet/geneve/geneve.api ||
| ------- | ------- |
| [2d3282e17](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=2d3282e17) | geneve: API cleanup |

| @c src/plugins/marvell/pp2/pp2.api ||
| ------- | ------- |
| [4a65b910a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=4a65b910a) | marvell: use explicit types in api |
| [859b59133](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=859b59133) | api: Add API support for marvell PP2 plugin |

| @c src/plugins/svs/svs.api ||
| ------- | ------- |
| [5e913f374](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=5e913f374) | svs: use explicit types in api |

| @c src/plugins/acl/acl_types.api ||
| ------- | ------- |
| [e71748291](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e71748291) | vppapigen: remove support for legacy typedefs |
| [bb2e5221a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=bb2e5221a) | api acl: breakout acl_types.api for reuse by others |

| @c src/plugins/acl/acl.api ||
| ------- | ------- |
| [b5076cbe1](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b5076cbe1) | acl: add missing square brackets to vat_help option in acl api |
| [709dad304](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=709dad304) | acl: remove api boilerplate |
| [bb2e5221a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=bb2e5221a) | api acl: breakout acl_types.api for reuse by others |
| [f995c7122](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f995c7122) | acl: implement counters |

| @c src/plugins/memif/memif.api ||
| ------- | ------- |
| [3ae9f5a90](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=3ae9f5a90) | memif: remove api boilerplate |
| [546f955b3](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=546f955b3) | memif: API cleanup |

| @c src/plugins/cdp/cdp.api ||
| ------- | ------- |
| [07e557a73](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=07e557a73) | cdp: use explicit types in api |

| @c src/plugins/dhcp/dhcp6_ia_na_client_cp.api ||
| ------- | ------- |
| [02bfd641b](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=02bfd641b) | dhcp: Move to plugin |

| @c src/plugins/dhcp/dhcp6_pd_client_cp.api ||
| ------- | ------- |
| [d5262831a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=d5262831a) | dhcp: dhcp6_pd_client_cp API cleanup |
| [02bfd641b](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=02bfd641b) | dhcp: Move to plugin |

| @c src/plugins/dhcp/dhcp.api ||
| ------- | ------- |
| [6bcc6a455](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=6bcc6a455) | dhcp: fix crash on unicast renewal send |
| [02bfd641b](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=02bfd641b) | dhcp: Move to plugin |

| @c src/plugins/avf/avf.api ||
| ------- | ------- |
| [a0bf06d74](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=a0bf06d74) | avf: explicit types in api |
| [74af6f081](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=74af6f081) | avf: remote api boilerplate |

| @c src/plugins/dpdk/api/dpdk.api ||
| ------- | ------- |
| [6d75c20a6](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=6d75c20a6) | dpdk: use explicit types in api |
| [025166dc7](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=025166dc7) | dpdk: remove api boilerplate |

| @c src/plugins/builtinurl/builtinurl.api ||
| ------- | ------- |
| [43765e2b4](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=43765e2b4) | builtinurl: initial working attempt |

| @c src/plugins/mactime/mactime.api ||
| ------- | ------- |
| [7b22df06f](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=7b22df06f) | mactime: update api to use explicit types |
| [2c41a61d5](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=2c41a61d5) | mactime: add a "top" command to watch device stats |
| [7071952df](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=7071952df) | mactime: remove api boilerplate |
| [e71748291](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e71748291) | vppapigen: remove support for legacy typedefs |
| [7681b1c46](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=7681b1c46) | mactime: add per-mac allow-with-quota feature |
| [0c6ac791d](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=0c6ac791d) | mactime: upstream new features |

| @c src/plugins/ikev2/ikev2.api ||
| ------- | ------- |
| [6aaee8c7c](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=6aaee8c7c) | ikev2: use explicit api types |
| [fc7b77db7](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=fc7b77db7) | ikev2: remove api boilerplate |

| @c src/plugins/http_static/http_static.api ||
| ------- | ------- |
| [e5ff5a36d](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e5ff5a36d) | api: enforce vla is last and fixed string type |
| [68b24e2c9](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=68b24e2c9) | plugins: http_static. Migrate to use api string type. |
| [22bc2c46e](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=22bc2c46e) | Static http server |

| @c src/plugins/gbp/gbp.api ||
| ------- | ------- |
| [38277e407](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=38277e407) | gbp: use explicit types in api |
| [e71748291](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e71748291) | vppapigen: remove support for legacy typedefs |
| [3918bdbcb](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=3918bdbcb) | gbp: update gbp-ext-itf API |
| [3c0d84c98](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=3c0d84c98) | gbp: add anonymous l3-out subnets |
| [cfc7a107e](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=cfc7a107e) | gbp: add anonymous l3-out external interfaces |
| [160c923f9](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=160c923f9) | gbp: VRF scoped contracts |

| @c src/plugins/l2e/l2e.api ||
| ------- | ------- |
| [b2e463a10](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b2e463a10) | l2e: use explicit api types |

| @c src/plugins/gtpu/gtpu.api ||
| ------- | ------- |
| [55636cb62](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=55636cb62) | gtpu: use explicit types in api |
| [49228efce](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=49228efce) | gtpu: remove api boilerplate |

| @c src/plugins/igmp/igmp.api ||
| ------- | ------- |
| [4a7fc4cf1](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=4a7fc4cf1) | igmp: use explicit types in api |
| [e71748291](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e71748291) | vppapigen: remove support for legacy typedefs |
| [4ff09ae34](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=4ff09ae34) | API: Python and Unix domain socket improvement |

| @c src/plugins/ioam/lib-vxlan-gpe/ioam_vxlan_gpe.api ||
| ------- | ------- |
| [0fa66d618](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=0fa66d618) | ioam: use explicit api types |

| @c src/plugins/ioam/udp-ping/udp_ping.api ||
| ------- | ------- |
| [0fa66d618](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=0fa66d618) | ioam: use explicit api types |

| @c src/plugins/ioam/export/ioam_export.api ||
| ------- | ------- |
| [0fa66d618](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=0fa66d618) | ioam: use explicit api types |

| @c src/plugins/ioam/ip6/ioam_cache.api ||
| ------- | ------- |
| [0fa66d618](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=0fa66d618) | ioam: use explicit api types |

| @c src/plugins/ioam/lib-pot/pot.api ||
| ------- | ------- |
| [0fa66d618](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=0fa66d618) | ioam: use explicit api types |

| @c src/plugins/ioam/export-vxlan-gpe/vxlan_gpe_ioam_export.api ||
| ------- | ------- |
| [0fa66d618](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=0fa66d618) | ioam: use explicit api types |

| @c src/plugins/stn/stn.api ||
| ------- | ------- |
| [7929f9f5c](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=7929f9f5c) | stn: use explicit types in api |

| @c src/plugins/map/map.api ||
| ------- | ------- |
| [be31c2a25](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=be31c2a25) | map: use explicit types in api |
| [7b2e9fb1a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=7b2e9fb1a) | map: use ip6-full-reassembly instead of own code |
| [640edcd90](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=640edcd90) | map: use SVR for MAP-T |
| [e5ff5a36d](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e5ff5a36d) | api: enforce vla is last and fixed string type |
| [ff47fb645](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=ff47fb645) | vppapigen map: raise ValueError when fieldname is python keyword |
| [4d376f67a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=4d376f67a) | map: Use vl_api_string macros. |

| @c src/plugins/oddbuf/oddbuf.api ||
| ------- | ------- |
| [7ff64fb97](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=7ff64fb97) | oddbuf: remove api boilerplate |
| [a287a30dd](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=a287a30dd) | misc: fix coverity warning in the oddbuf plugin |
| [c4abafd83](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c4abafd83) | ip: fix udp/tcp checksum corner cases |

| @c src/plugins/l3xc/l3xc.api ||
| ------- | ------- |
| [60f5108a9](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=60f5108a9) | l3xc: use explicit types in api |
| [e71748291](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e71748291) | vppapigen: remove support for legacy typedefs |
| [59fa121f8](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=59fa121f8) | L3 cross connect |

| @c src/plugins/pppoe/pppoe.api ||
| ------- | ------- |
| [04338e85a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=04338e85a) | pppoe: use explicit types in api |
| [25fe57821](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=25fe57821) | pppoe: remove api boilerplate |

| @c src/plugins/mdata/mdata.api ||
| ------- | ------- |
| [d7b306657](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=d7b306657) | mdata: buffer metadata change tracker plugin |

| @c src/plugins/lb/lb.api ||
| ------- | ------- |
| [ae0724034](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=ae0724034) | lb: remove api boilerplate |
| [33538a150](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=33538a150) | lb: add APIs for set interface nat4 and nat6 |
| [75761b933](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=75761b933) | api: split vl_api_prefix into two |
| [3efcd0d7c](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=3efcd0d7c) | lb: vip and as dump/detail api's |
| [a0cb32cb9](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=a0cb32cb9) | lb: update api.c to use scaffolding from latest skel |

| @c src/plugins/lb/lb_types.api ||
| ------- | ------- |
| [75761b933](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=75761b933) | api: split vl_api_prefix into two |
| [e71748291](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e71748291) | vppapigen: remove support for legacy typedefs |
| [3efcd0d7c](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=3efcd0d7c) | lb: vip and as dump/detail api's |

| @c src/plugins/nsim/nsim.api ||
| ------- | ------- |
| [e06e7c672](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e06e7c672) | nsim: use explicit api types |
| [2e7a43ca4](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=2e7a43ca4) | nsim: remove api boilerplate |
| [7c91007e1](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=7c91007e1) | Make the loss / delay sim available as an output feature |

| @c src/plugins/vmxnet3/vmxnet3.api ||
| ------- | ------- |
| [277f03f06](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=277f03f06) | vmxnet3: use explicit types in api |
| [10bbfce02](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=10bbfce02) | vmxnet3: remove api boilerplate |
| [2985e0af6](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=2985e0af6) | vmxnet3: per interface gso support |
| [e71748291](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e71748291) | vppapigen: remove support for legacy typedefs |

| @c src/plugins/tlsopenssl/tls_openssl.api ||
| ------- | ------- |
| [1e582206a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=1e582206a) | tls: remove api boilerplate |
| [dd0cc9ec3](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=dd0cc9ec3) | tls: some rework based on TLS openssl C API |
| [be4d1aa2c](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=be4d1aa2c) | tls: Add C API for TLS openssl to set engine |

| @c src/plugins/abf/abf.api ||
| ------- | ------- |
| [bdde58534](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=bdde58534) | abf: use explicit types in api |
| [e71748291](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e71748291) | vppapigen: remove support for legacy typedefs |
| [097fa66b9](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=097fa66b9) | fib: fib api updates |

| @c src/plugins/nat/nat.api ||
| ------- | ------- |
| [f126e746f](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f126e746f) | nat: use SVR |
| [e5ff5a36d](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e5ff5a36d) | api: enforce vla is last and fixed string type |
| [e71748291](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e71748291) | vppapigen: remove support for legacy typedefs |
| [e6e09a4ac](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e6e09a4ac) | nat: elog rewrite for multi-worker support |
| [c1f93067e](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c1f93067e) | Add default value for API Nat flags |
| [dd1e3e780](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=dd1e3e780) | NAT: VPP-1531 api cleanup & update |
| [89fec713f](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=89fec713f) | Revert "NAT: VPP-1531 api cleanup & update" |
| [bed1421b9](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=bed1421b9) | NAT: VPP-1531 api cleanup & update |

| @c src/plugins/rdma/rdma.api ||
| ------- | ------- |
| [d8c1ef925](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=d8c1ef925) | rdma: api: prepare support for direct verb |
| [b644eb54f](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b644eb54f) | rdma: add explicit types in api |
| [812afe712](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=812afe712) | rdma: add rdma API |

| @c src/plugins/sctp/sctp.api ||
| ------- | ------- |
| [3ffe6cadf](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=3ffe6cadf) | sctp: move to plugins, disabled by default |

| @c src/plugins/ct6/ct6.api ||
| ------- | ------- |
| [d4efce2e0](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=d4efce2e0) | ct6: use explicit type in api |
| [ee98904e0](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=ee98904e0) | ct6: remove api boilerplate |

| @c src/plugins/nsh/nsh.api ||
| ------- | ------- |
| [d3f0a4869](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=d3f0a4869) | nsh: use explicit api types |

| @c src/plugins/flowprobe/flowprobe.api ||
| ------- | ------- |
| [3013e6988](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=3013e6988) | flowprobe: use explicit types in api |
| [2a1ca787b](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=2a1ca787b) | api: split api generated files |

| @c src/plugins/lacp/lacp.api ||
| ------- | ------- |
| [ebef4a9e5](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=ebef4a9e5) | lacp: use explit api types |

| @c src/plugins/dns/dns.api ||
| ------- | ------- |
| [b922f16ba](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b922f16ba) | dns: remove api boilerplate |
| [34af0ccf5](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=34af0ccf5) | dns: make the dns name resolver a plugin |

| @c src/vpp/api/vpe.api ||
| ------- | ------- |
| [e5ff5a36d](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e5ff5a36d) | api: enforce vla is last and fixed string type |
| [e71748291](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e71748291) | vppapigen: remove support for legacy typedefs |
| [a47a5f20a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=a47a5f20a) | api papi: add alias for timestamp(datetime)/timedelta |
| [888640a39](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=888640a39) | map gbp papi: match endianess of f64 |
| [03f1af23b](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=03f1af23b) | api: Implement log_dump/log_details |
| [c87b66c86](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c87b66c86) | ipsec: ipsec-tun protect |
| [9ac113815](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9ac113815) | API: Add support for limits to language. |

| @c src/vpp/api/vpe_types.api ||
| ------- | ------- |
| [e71748291](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e71748291) | vppapigen: remove support for legacy typedefs |
| [a47a5f20a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=a47a5f20a) | api papi: add alias for timestamp(datetime)/timedelta |
| [3cf9e67f5](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=3cf9e67f5) | api: add vl_api_version_t type |

@page release_notes_19083 Release notes for VPP 19.08.3

This is bug fix release.

For the full list of fixed issues please refer to:
- fd.io [JIRA](https://jira.fd.io)
- git [commit log](https://git.fd.io/vpp/log/?h=stable/1908)

@page release_notes_19082 Release notes for VPP 19.08.2

The 19.08.2 is an LTS release. It contains numerous fixes,
as well as new features and API additions.

## Features

- API trace tool
  - Add text output (c395ff143)
- Binary API Libraries
  - Add API support for PP2 plugin to stable/1908 (1c3c9f039)
- Build System
  - Pass 'no-pci' to autgenerated config (c0552134e)
  - Add env variable to pass extra cmake args (116e05f57)
- Infrastructure Library
  - Implement CLIB\_PAUSE () for aarch64 platforms (a3c45242b)
  - Create unformat function for data size parsing (cb19100c1)
- Link Bonding
  - Fix interface deletion (1517d5e72)
  - Add GSO support (a06f68556)
- Physical Memory Allocator
  - Always lock pages (5b2eea6e0)
- Plugins
  - AVF Device driver
    - Print queue id in packet trace (9e028d047)
  - DPDK
    - Ipsec tunnel support for ip6-in-ip4 (2dde5a478)
    - QAT devices update, add c4xxx and xeon d15xx (f5d6c80ac)
    - Add TSO support in DPDK plugin. (5564db853)
  - Group Based Policy (GBP)
    - Add extended SFC unit tests (30f7e4198)
  - Host Stack Applications
    - Make APP\_OPTIONS\_PREALLOC\_FIFO\_PAIRS configurable (47c6f36be)
  - Internet Key Exchange (IKEv2) Protocol
    - Add support for GCM cipher (2fa9f679c)
  - QUIC protocol
    - Add cli command for stats (88af6c3f4)
    - Add Tx, Rx and packet drop counters (3a61a40dd)
    - Create custom event logger (2f9ec5001)
    - Make quic fifo size configurable via cli (7fc3d97b8)
  - RDMA (ibverb) driver
    - Add support for input feature arcs (cbae1e1c5)
    - Add support for MAC changes (ffdfe308b)
  - Http\_static
    - Add dynamic GET / POST method hooks (faf5195e3)
- Python binding for the VPP API
  - Let async calls return context (e6b29a9df)
  - Introduce read\_blocking (1c45b85df)
- SVM Library
  - Improve fifo segment verbose cli (d2bff0786)
- Statistics Segment
  - Add /if/\<n\>/\<n\>/state for lacp interface state (d5e8ed7be)
- Test Infrastructure
  - Support worker threads (51699e62c)
  - Support setting random seed (fc000f0e1)
  - Add cli\_return\_response to vpp\_papi\_provider (64d744350)
  - Test tls case (87e1bcdd7)
- VNET
  - Classifier
    - Use vector code even when data is not aligned (bebbd7f62)
    - VPP packet tracer support (7c5a3536c)
  - IPSec
    - Add 'detail' option to 'sh ipsec sa' (56417fa94)
    - Add insecure option for format of SA (591aa64e8)
    - Support 4o6 and 6o4 for tunnel protect (2e6d73934)
  - IPv4 and IPv6 LPM
    - Allow addrs from the same prefix on intf (da900b25c)
    - Punt rather than drop unkown IPv6 ICMP packets (fd2f6f89e)
  - Session Layer
    - Add explicit reset api (a267cba29)
    - Improve cli (2ff21af39)
    - Add session enable option in config file (b1ef5567b)
    - Limit pacer bucket size (079895d95)
    - Builtin app rx notifications regardless of state (8e4afc86d)
    - Infra for transports to send buffers (57997c874)
    - Reschedule asap when snd space constrained (89ab1762d)
  - TCP
    - Allow cc algos to set pacing rate (82df1eb90)
    - Set cc\_algo on connection alloc (7fe501a4b)
    - Add option for always on event logging (e73bd8503)
    - Track zero rwnd errors (a2c063712)
    - Validate connections in output (ea584d137)
    - Force zero window on full rx fifo (fbe948c81)
    - Send rwnd update only if wnd is large enough (0ad8477ba)
    - Enable gso in tcp hoststack (6f3621d77)
    - Handle SACK reneging (9dba3dbf0)
    - Use rate sample RTT in recovery if possible (6702641f5)
    - Compute snd time for rate sample (69460ae11)
    - Use sacks for timer based recovery (d4aa3d9f8)
    - Custom checksum calculations for Ipv4/Ipv6 (3642782a2)
    - Retry lost retransmits (7b135c639)
    - Improve pacing after idle send periods (abdc7dfb5)
    - Track lost rxt segments in byte tracker (6de46b40d)
    - Validate the IP address while checking TCP connection (6c1ce53b4)
    - Improve lost rxt heuristic (04b4204d9)
- VPP Comms Library
  - Allow non-blocking connects (4767cf24f)
  - Add api to set lcl ip (2c55610e2)
- Vector Library
  - Add flag to explicitelly mark nodes which can init per-node packet trace (29dc11bde)
  - Enhance the "show cli" debug CLI command (b5a0108ac)
- Libmemif
  - Introduce 'memif\_per\_thread\_' namespace (2736fc7fc)

## API changes

Description of results:

* _Definition changed_: indicates that the API file was modified between releases.
* _Only in image_: indicates the API is new for this release.
* _Only in file_: indicates the API has been removed in this release.

Message Name                                                 | Result
-------------------------------------------------------------|------------------
app_attach                                                   | only in image
app_attach_reply                                             | only in image

Found 2 api message signature differences

## Fixed issues

For the full list of fixed issues please refer to:
- fd.io [JIRA](https://jira.fd.io)
- git [commit log](https://git.fd.io/vpp/log/?h=stable/1908)

@page release_notes_19081 Release notes for VPP 19.08.1

Exceptionally, this release has an API-changing fix introduced via
https://gerrit.fd.io/r/#/c/vpp/+/21762/ - documented in VPP-1767.
Given the exceptional nature of the change, also including the text here:

Bug: https://gerrit.fd.io/r/c/vpp/+/21492

Variable length strings were committed to VPP in 413f4a5b.
The VPP server side of the API does not use a wire encoder/decoder. It maps a C struct directly onto on-the-wire API messages.
The client side C language binding is the same, while other language bindings have their own encoder/decoders.

Multiple strings alone or combined with other variable length types turned out to be error prone to manually implement on the VPP side,
and not supported by VPP API (VAPI) very well at all.

To avoid having to rewrite VAPI significantly, and to mitigate the risk
and error prone server side support of multiple variable length fields,
this patch extends strings to have a fixed size (on the wire) and
a variable flavour, as well as adding detection in the API compiler
to detect multiple variable length fields in a message (or type).

Given that this change breaks the commitment to binary API compatibility,
normally present in point builds, ALL 19.08 build artifacts are being
deferred.

This means the artifacts for the VPP 19.08.1 will be installed
in the release repository (packagecloud.io/fdio/release), then
ALL 19.08 build artifacts will be moved into the deferred repository
(packagecloud.io/fdio/deferred). The 19.08 artifacts will always be
available for archive purposes in the deferred repository.

During the further testing by Networking-VPP team, they discovered
another issue documented in VPP-1769 - which requires a CRC-affecting
fix in https://gerrit.fd.io/r/#/c/vpp/+/22015/ - so the 19.08.1
will contain the fixes for both issues.

These two changes have resulted in the following 20 messages changing
their signatures:

Message Name                                                 | Result
-------------------------------------------------------------|------------------
cli_inband                                                   | definition changed
cli_inband_reply                                             | definition changed
connect_sock                                                 | definition changed
http_static_enable                                           | definition changed
log_details                                                  | definition changed
map_add_domain                                               | definition changed
map_domain_details                                           | definition changed
nat44_add_del_identity_mapping                               | definition changed
nat44_add_del_lb_static_mapping                              | definition changed
nat44_add_del_static_mapping                                 | definition changed
nat44_identity_mapping_details                               | definition changed
nat44_lb_static_mapping_details                              | definition changed
nat44_static_mapping_details                                 | definition changed
nat_worker_details                                           | definition changed
punt_reason_details                                          | definition changed
punt_reason_dump                                             | definition changed
show_version_reply                                           | definition changed
sw_interface_details                                         | definition changed
sw_interface_dump                                            | definition changed
sw_interface_tag_add_del                                     | definition changed

Please accept our apologies for the inconvenience this caused.

For the full list of fixed issues please refer to:
- fd.io [JIRA](https://jira.fd.io)
- git [commit log](https://git.fd.io/vpp/log/?h=stable/1904)

@page release_notes_1908 Release notes for VPP 19.08

More than 850 commits since the 19.04 release.

## Features

### Infrastructure
- API
  - API language: new types and limits support
  - Python API - add support for defaults
  - Export ip_types.api for out-of-tree plugins use
  - Refactor ipip.api with explicit types
- DPDK
  - 19.05 integration
  - Remove bonding code
  - Rework extended stats
- Debugging & Servicability
  - debug CLI leak-checker
  - vlib: add "memory-trace stats-segment"
  - vppapitrace JSON/API trace converter
  - ARP: add arp-disabled node
  - igmp: Trace more data from input packets
  - ip: Trace the packet from the punt node
  - Python API debug introspection improvements
  - Pin dependencies for make test infra
  - FEATURE.yaml meta-data infrastructure
  - tcp: add cc stats plotting tools
  - Packet tracer support for thread handoffs
- libmemif: support for multi-thread connection establishment
- svm
  - fifo ooo reads/writes with multiple chunks
  - support addition/removal of chunks to fifos
- vppinfra
  - Mapped pcap file support
  - More AVX2 and AVX512 inlines
  - VLIB_INIT_FUNCTION sequencing rework
  - refactor spinlocks and rwlocks
  - add rbtree
  - add doubly linked list
- rdma: bump rdma-core to v25.0
- stats
  - Add the number of worker threads and per worker thread vector rates
  - Support multiple workers for error counters

### VNET & Plugins
- New Plugins
  - HTTP static page server with TLS support
  - L3 cross connect
- acl: implement stat-segment counters
- arp: add feature arcs: arp-reply, arp-input, arp-proxy
- avf: improved logging and added 2.5/5 Gbps speeds
- bonding: NUMA-related improvements
- crypto: add support for AES-CTR cipher
- fib
  - FIB Entry tracking
  - Support the POP of a Pseudo Wire Control Word
- gbp
  - Anonymous l3-out subnets support
  - ARP unicast forward in gbp bridge domain
  - An Endpoint can change sclass
  - Consider data-plane learnt source better than control-plane
  - VRF scoped contracts
- gso (experimental)
  - Add support to pg interfaces
  - Add support to vhost user
  - Add support to native virtio
  - Add support for tagged interfaces
- punt: allow to specify packets by IP protocol Type
- ip6-local: hop-by-hop protocol demux table
- ipsec
  - intel-ipsec-mb version 0.52
  - AH encrypt rework
  - handle UDP keepalives
  - support GCM in ESP
- virtio
  - Refactor control queue support
- dhcp-client: DSCP marking for transmitted packets
- Idle resource usage improvements
  - Allocate bihash virtual space on demand
  - gre: don't register gre input nodes unless a gre tunnel is created
  - gtpu: don't register udp ports unless a tunnel is created
  - lacp: create lacp-process on demand
  - lisp-cp: start lisp retry service on demand
  - start the cdp period and dns resolver process on demand
  - vat: unload unused vat plugins
- nat: api cleanup & update
- nsim: make available as an output feature
- load-balance performance improvements
- l2: Add support for arp unicast forwarding
- mactime
  - Mini-ACLs
  - Per-MAC allow-with-quota feature
- qos
  - QoS dump APIs
  - Store function
- rdma: add support for promiscuous mode (l2-switching and xconnect)
- sr: update the Segment Routing definition to be compliant with current in IETF
- udp-ping: disable due to conflict with mldv2
- vxlan-gpe: improve encap performance
- vom
  - QoS support
  - Bridge domain arp unicast forwarding flag
  - Bridge domain unknown unicast flooding flag

### Host stack
- session
  - API to support manual svm fifo resizing
  - Improved session output scheduler and close state machine
  - Transport and session cleanup notifications for builtin apps
  - Session migration notifications for builtin apps
  - Support for no session layer lookup transports (quic and tls)
  - Ability to retrieve local/remote endpoint in transport vft
  - Cleanup segment manager and fifo segment
  - Fix vpp to app msg generation on enqueue fail
  - Improve event logging
  - Moved test applications to hsa plugin
- tcp
  - Congestion control algorithm enhancements
  - Delivery rate estimator
  - ACK/retransmission refactor and pacing
  - Add tcp-input sibling nodes without full 6-tuple lookup
  - More RFC4898 connection statistics
  - Allow custom output next node
  - Allow custom congestion control algorithms
- quic
  - Multi-thread support
  - Logs readability improvements
  - Multistream support
- tls
  - Fix close with data and listen failures
  - Handle TCP transport rests
  - Support endpoint retrieval interface
- vcl
  - support quic streams and "connectable listeners"
  - worker unregister api
  - fix epoll with large events batch
  - ldp: add option to eanble transparent TLS connections
- udp:
  - support close with data
  - fixed session migration
- sctp
  - add option to enable/disable default to disable
  - moved from vnet to plugins

## Known issues

For the full list of issues please refer to fd.io [JIRA](https://jira.fd.io).

## Issues fixed

For the full list of fixed issues please refer to:
- fd.io [JIRA](https://jira.fd.io)
- git [commit log](https://git.fd.io/vpp/log/?h=stable/1908)

## API changes

Description of results:

* _Definition changed_: indicates that the API file was modified between releases.
* _Only in image_: indicates the API is new for this release.
* _Only in file_: indicates the API has been removed in this release.


Message Name                                                 | Result
-------------------------------------------------------------|------------------
abf_itf_attach_add_del                                       | definition changed
abf_itf_attach_details                                       | definition changed
abf_policy_add_del                                           | definition changed
abf_policy_details                                           | definition changed
acl_add_replace                                              | definition changed
acl_details                                                  | definition changed
acl_stats_intf_counters_enable                               | only in image
acl_stats_intf_counters_enable_reply                         | only in image
api_versions_reply                                           | definition changed
bd_ip_mac_add_del                                            | definition changed
bd_ip_mac_details                                            | definition changed
bier_disp_entry_add_del                                      | definition changed
bier_disp_entry_details                                      | definition changed
bier_imp_add                                                 | definition changed
bier_imp_details                                             | definition changed
bier_route_add_del                                           | definition changed
bier_route_details                                           | definition changed
bier_route_dump                                              | definition changed
bier_table_add_del                                           | definition changed
bier_table_details                                           | definition changed
bond_create                                                  | definition changed
bridge_domain_add_del                                        | definition changed
bridge_domain_details                                        | definition changed
bridge_flags                                                 | definition changed
connect_sock                                                 | definition changed
create_vhost_user_if                                         | definition changed
ct6_enable                                                   | only in file
ct6_enable_disable                                           | only in image
ct6_enable_disable_reply                                     | only in image
ct6_enable_disable                                           | only in file
dhcp6_pd_reply_event                                         | definition changed
dhcp6_pd_send_client_message                                 | definition changed
dhcp6_reply_event                                            | definition changed
dhcp6_send_client_message                                    | definition changed
dhcp_client_config                                           | definition changed
dhcp_client_details                                          | definition changed
dhcp_compl_event                                             | definition changed
dhcp_proxy_details                                           | definition changed
dslite_add_del_pool_addr_range                               | definition changed
dslite_address_details                                       | definition changed
dslite_get_aftr_addr_reply                                   | definition changed
dslite_get_b4_addr_reply                                     | definition changed
dslite_set_aftr_addr                                         | definition changed
dslite_set_b4_addr                                           | definition changed
gbp_bridge_domain_add                                        | definition changed
gbp_bridge_domain_details                                    | definition changed
gbp_contract_add_del                                         | definition changed
gbp_contract_details                                         | definition changed
gbp_endpoint_add                                             | definition changed
gbp_endpoint_details                                         | definition changed
gbp_endpoint_group_add                                       | definition changed
gbp_endpoint_group_details                                   | definition changed
gbp_ext_itf_add_del                                          | definition changed
gbp_ext_itf_details                                          | definition changed
gbp_recirc_add_del                                           | definition changed
gbp_recirc_details                                           | definition changed
gbp_route_domain_add                                         | definition changed
gbp_route_domain_details                                     | definition changed
gbp_subnet_add_del                                           | definition changed
gbp_subnet_details                                           | definition changed
gbp_vxlan_tunnel_add                                         | definition changed
gbp_vxlan_tunnel_details                                     | definition changed
get_f64_endian_value                                         | only in image
get_f64_endian_value_reply                                   | only in image
get_f64_increment_by_one                                     | only in image
get_f64_increment_by_one_reply                               | only in image
gpe_add_del_fwd_entry                                        | definition changed
gpe_fwd_entries_get_reply                                    | definition changed
gpe_fwd_entry_path_details                                   | definition changed
gpe_native_fwd_rpaths_get_reply                              | definition changed
gre_add_del_tunnel                                           | only in file
gre_add_del_tunnel_reply                                     | only in file
gre_tunnel_add_del                                           | only in image
gre_tunnel_add_del_reply                                     | only in image
gre_tunnel_details                                           | definition changed
gre_tunnel_dump                                              | definition changed
http_static_enable                                           | only in image
http_static_enable_reply                                     | only in image
igmp_event                                                   | definition changed
igmp_group_prefix_details                                    | definition changed
igmp_group_prefix_set                                        | definition changed
igmp_listen                                                  | definition changed
ip6_fib_details                                              | only in file
ip6_fib_dump                                                 | only in file
ip6_mfib_details                                             | only in file
ip6_mfib_dump                                                | only in file
ip6_ra_event                                                 | definition changed
ip_add_del_route                                             | only in file
ip_add_del_route_reply                                       | only in file
ip_address_details                                           | definition changed
ip_container_proxy_add_del                                   | definition changed
ip_container_proxy_details                                   | definition changed
ip_fib_details                                               | only in file
ip_fib_dump                                                  | only in file
ip_mfib_details                                              | only in file
ip_mfib_dump                                                 | only in file
ip_mroute_add_del                                            | definition changed
ip_mroute_details                                            | only in image
ip_mroute_dump                                               | only in image
ip_mtable_details                                            | only in image
ip_mtable_dump                                               | only in image
ip_neighbor_add_del                                          | definition changed
ip_neighbor_details                                          | definition changed
ip_probe_neighbor                                            | definition changed
ip_punt_redirect                                             | definition changed
ip_punt_redirect_details                                     | definition changed
ip_reassembly_get_reply                                      | definition changed
ip_reassembly_set                                            | definition changed
ip_route_add_del                                             | only in image
ip_route_add_del_reply                                       | only in image
ip_route_details                                             | only in image
ip_route_dump                                                | only in image
ip_source_and_port_range_check_add_del                       | definition changed
ip_table_add_del                                             | definition changed
ip_table_details                                             | only in image
ip_table_dump                                                | only in image
ipfix_flush                                                  | only in image
ipfix_flush_reply                                            | only in image
ipip_6rd_add_tunnel                                          | definition changed
ipip_add_tunnel                                              | definition changed
ipip_tunnel_details                                          | definition changed
ipsec_backend_details                                        | definition changed
ipsec_gre_tunnel_add_del                                     | only in file
ipsec_gre_tunnel_add_del_reply                               | only in file
ipsec_gre_tunnel_details                                     | only in file
ipsec_gre_tunnel_dump                                        | only in file
ipsec_sa_details                                             | definition changed
ipsec_sa_set_key                                             | only in file
ipsec_sa_set_key_reply                                       | only in file
ipsec_sad_entry_add_del                                      | definition changed
ipsec_select_backend                                         | definition changed
ipsec_spd_details                                            | definition changed
ipsec_spd_entry_add_del                                      | definition changed
ipsec_tunnel_if_add_del                                      | definition changed
ipsec_tunnel_if_set_key                                      | only in file
ipsec_tunnel_if_set_key_reply                                | only in file
ipsec_tunnel_protect_del                                     | only in image
ipsec_tunnel_protect_del_reply                               | only in image
ipsec_tunnel_protect_details                                 | only in image
ipsec_tunnel_protect_dump                                    | only in image
ipsec_tunnel_protect_update                                  | only in image
ipsec_tunnel_protect_update_reply                            | only in image
l2_macs_event                                                | definition changed
l3xc_del                                                     | only in image
l3xc_del_reply                                               | only in image
l3xc_details                                                 | only in image
l3xc_dump                                                    | only in image
l3xc_plugin_get_version                                      | only in image
l3xc_plugin_get_version_reply                                | only in image
l3xc_update                                                  | only in image
l3xc_update_reply                                            | only in image
lb_add_del_as                                                | definition changed
lb_add_del_vip                                               | definition changed
lb_as_details                                                | only in image
lb_as_dump                                                   | only in image
lb_flush_vip                                                 | definition changed
lb_vip_details                                               | only in image
lb_vip_dump                                                  | only in image
lisp_add_del_locator_set                                     | definition changed
lisp_add_del_remote_mapping                                  | definition changed
lisp_adjacencies_get_reply                                   | definition changed
log_details                                                  | only in image
log_dump                                                     | only in image
macip_acl_add                                                | definition changed
macip_acl_add_replace                                        | definition changed
macip_acl_details                                            | definition changed
mactime_add_del_range                                        | definition changed
map_add_domain                                               | definition changed
map_domain_details                                           | definition changed
mfib_signal_details                                          | definition changed
modify_vhost_user_if                                         | definition changed
mpls_fib_details                                             | only in file
mpls_fib_dump                                                | only in file
mpls_ip_bind_unbind                                          | definition changed
mpls_route_add_del                                           | definition changed
mpls_route_details                                           | only in image
mpls_route_dump                                              | only in image
mpls_table_add_del                                           | definition changed
mpls_table_details                                           | only in image
mpls_table_dump                                              | only in image
mpls_tunnel_add_del                                          | definition changed
mpls_tunnel_details                                          | definition changed
nat44_add_del_address_range                                  | definition changed
nat44_add_del_identity_mapping                               | definition changed
nat44_add_del_interface_addr                                 | definition changed
nat44_add_del_lb_static_mapping                              | definition changed
nat44_add_del_static_mapping                                 | definition changed
nat44_address_details                                        | definition changed
nat44_del_session                                            | definition changed
nat44_forwarding_enable_disable                              | definition changed
nat44_forwarding_is_enabled_reply                            | definition changed
nat44_identity_mapping_details                               | definition changed
nat44_interface_add_del_feature                              | definition changed
nat44_interface_add_del_output_feature                       | definition changed
nat44_interface_addr_details                                 | definition changed
nat44_interface_details                                      | definition changed
nat44_interface_output_feature_details                       | definition changed
nat44_lb_static_mapping_add_del_local                        | definition changed
nat44_lb_static_mapping_details                              | definition changed
nat44_static_mapping_details                                 | definition changed
nat44_user_details                                           | definition changed
nat44_user_session_details                                   | definition changed
nat44_user_session_dump                                      | definition changed
nat64_add_del_interface_addr                                 | definition changed
nat64_add_del_interface                                      | definition changed
nat64_add_del_pool_addr_range                                | definition changed
nat64_add_del_prefix                                         | definition changed
nat64_add_del_static_bib                                     | definition changed
nat64_bib_details                                            | definition changed
nat64_interface_details                                      | definition changed
nat64_pool_addr_details                                      | definition changed
nat64_prefix_details                                         | definition changed
nat64_st_details                                             | definition changed
nat66_add_del_interface                                      | definition changed
nat66_add_del_static_mapping                                 | definition changed
nat66_interface_details                                      | definition changed
nat66_static_mapping_details                                 | definition changed
nat_det_add_del_map                                          | definition changed
nat_det_close_session_in                                     | definition changed
nat_det_close_session_out                                    | definition changed
nat_det_forward                                              | definition changed
nat_det_forward_reply                                        | definition changed
nat_det_map_details                                          | definition changed
nat_det_reverse                                              | definition changed
nat_det_reverse_reply                                        | definition changed
nat_det_session_details                                      | definition changed
nat_det_session_dump                                         | definition changed
nat_get_mss_clamping_reply                                   | definition changed
nat_ipfix_enable_disable                                     | definition changed
nat_reass_details                                            | definition changed
nat_set_log_level                                            | only in image
nat_set_log_level_reply                                      | only in image
nat_set_mss_clamping                                         | definition changed
nat_set_reass                                                | definition changed
nat_show_config_reply                                        | definition changed
nat_worker_details                                           | definition changed
nsim_cross_connect_enable_disable                            | only in image
nsim_cross_connect_enable_disable_reply                      | only in image
nsim_enable_disable                                          | only in file
nsim_enable_disable_reply                                    | only in file
nsim_output_feature_enable_disable                           | only in image
nsim_output_feature_enable_disable_reply                     | only in image
oam_add_del                                                  | only in file
oam_add_del_reply                                            | only in file
oam_event                                                    | only in file
one_add_del_locator_set                                      | definition changed
one_add_del_remote_mapping                                   | definition changed
one_adjacencies_get_reply                                    | definition changed
one_l2_arp_entries_get_reply                                 | definition changed
one_ndp_entries_get_reply                                    | definition changed
p2p_ethernet_add                                             | definition changed
p2p_ethernet_add_reply                                       | definition changed
p2p_ethernet_del                                             | definition changed
pg_create_interface                                          | definition changed
proxy_arp_add_del                                            | definition changed
proxy_arp_details                                            | definition changed
punt_details                                                 | only in file
punt_dump                                                    | only in file
punt_reason_details                                          | only in image
punt_reason_dump                                             | only in image
punt_socket_deregister                                       | definition changed
punt_socket_details                                          | definition changed
punt_socket_dump                                             | definition changed
punt_socket_register                                         | definition changed
qos_egress_map_delete                                        | definition changed
qos_egress_map_details                                       | only in image
qos_egress_map_dump                                          | only in image
qos_egress_map_update                                        | definition changed
qos_mark_details                                             | only in image
qos_mark_details_reply                                       | only in image
qos_mark_dump                                                | only in image
qos_mark_enable_disable                                      | definition changed
qos_record_details                                           | only in image
qos_record_dump                                              | only in image
qos_record_enable_disable                                    | definition changed
qos_store_details                                            | only in image
qos_store_dump                                               | only in image
qos_store_enable_disable                                     | only in image
qos_store_enable_disable_reply                               | only in image
sctp_add_src_dst_connection                                  | only in file
sctp_add_src_dst_connection_reply                            | only in file
sctp_config                                                  | only in file
sctp_config_reply                                            | only in file
sctp_del_src_dst_connection                                  | only in file
sctp_del_src_dst_connection_reply                            | only in file
set_punt                                                     | definition changed
show_threads_reply                                           | definition changed
show_vpe_system_time                                         | only in image
show_vpe_system_time_reply                                   | only in image
sockclnt_create_reply                                        | definition changed
sr_localsid_add_del                                          | definition changed
sr_localsids_details                                         | definition changed
sr_policies_details                                          | definition changed
sr_policy_add                                                | definition changed
sr_policy_del                                                | definition changed
sr_policy_mod                                                | definition changed
sr_steering_pol_details                                      | definition changed
svs_details                                                  | definition changed
svs_enable_disable                                           | definition changed
svs_route_add_del                                            | definition changed
svs_table_add_del                                            | definition changed
sw_interface_bond_details                                    | definition changed
sw_interface_dump                                            | definition changed
sw_interface_ip6_set_link_local_address                      | only in image
sw_interface_ip6_set_link_local_address_reply                | only in image
sw_interface_ip6nd_ra_prefix                                 | definition changed
sw_interface_set_l2_bridge                                   | definition changed
sw_interface_tap_v2_details                                  | definition changed
syslog_get_filter_reply                                      | definition changed
syslog_set_filter                                            | definition changed
tap_create_v2                                                | definition changed
udp_encap_add                                                | definition changed
udp_encap_details                                            | definition changed
virtio_pci_create                                            | definition changed
vmxnet3_details                                              | definition changed
vxlan_gbp_tunnel_add_del                                     | definition changed
vxlan_gbp_tunnel_details                                     | definition changed
want_oam_events                                              | only in file
want_oam_events_reply                                        | only in file

Found 319 api message signature differences

### Patches that changed API definitions

| @c src/vpp/api/vpe_types.api ||
| ------- | ------- |
| [b'a47a5f20a'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'a47a5f20a') | api papi: add alias for timestamp(datetime)/timedelta |
| [b'3cf9e67f5'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'3cf9e67f5') | api: add vl_api_version_t type |

| @c src/vpp/api/vpe.api ||
| ------- | ------- |
| [b'a47a5f20a'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'a47a5f20a') | api papi: add alias for timestamp(datetime)/timedelta |
| [b'888640a39'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'888640a39') | map gbp papi: match endianess of f64 |
| [b'03f1af23b'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'03f1af23b') | api: Implement log_dump/log_details |
| [b'c87b66c86'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'c87b66c86') | ipsec: ipsec-tun protect |
| [b'9ac113815'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'9ac113815') | API: Add support for limits to language. |

| @c src/examples/sample-plugin/sample/sample.api ||
| ------- | ------- |
| [b'78d91cf9a'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'78d91cf9a') | sample-plugin: refactor .api to use explicit types |

| @c src/vnet/interface.api ||
| ------- | ------- |
| [b'0ad4a439d'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'0ad4a439d') | Fix vpp crash bug while deleting dhcp client |
| [b'9a29f795a'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'9a29f795a') | vpp_papi_provider.py: update defautmapping. |
| [b'b8591ac91'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'b8591ac91') | API sw_interface_dump: Dump all if index is zero |
| [b'4a7240636'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'4a7240636') | Make sw_interface_dump more compatible with 2.2.0 |
| [b'6407ba56a'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'6407ba56a') | api: Add to interface crud - read by sw_if_index. |

| @c src/vnet/qos/qos.api ||
| ------- | ------- |
| [b'83832e7ce'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'83832e7ce') | qos: Store function |
| [b'5281a9029'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'5281a9029') | qos: QoS dump APIs |

| @c src/vnet/bier/bier.api ||
| ------- | ------- |
| [b'097fa66b9'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'097fa66b9') | fib: fib api updates |
| [b'e6eefb6e3'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'e6eefb6e3') | Trivial Typo's in bier comments/docs. |

| @c src/vnet/ipfix-export/ipfix_export.api ||
| ------- | ------- |
| [b'21b83e96d'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'21b83e96d') | api: implement ipfix_flush |

| @c src/vnet/session/session.api ||
| ------- | ------- |
| [b'8ac1d6d05'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'8ac1d6d05') | session: Use parent_handle instead of transport_opts |
| [b'ba65ca496'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'ba65ca496') | Add transport_opts to connect_sock bapi |

| @c src/vnet/gre/gre.api ||
| ------- | ------- |
| [b'814f15948'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'814f15948') | gre: update gre.api with explicit types |
| [b'd0aed2eb3'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'd0aed2eb3') | GRE: set gre_tunnel_type init value to zero in API |
| [b'5a8844bdb'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'5a8844bdb') | GRE: API update |

| @c src/vnet/pg/pg.api ||
| ------- | ------- |
| [b'22e9cfd76'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'22e9cfd76') | pg: add GSO support |

| @c src/vnet/l2/l2.api ||
| ------- | ------- |
| [b'bc764c8bc'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'bc764c8bc') | l2: BD ARP termination entry API update |
| [b'54bc5e40c'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'54bc5e40c') | Update API description |
| [b'5e6f7348c'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'5e6f7348c') | l2: Add support for arp unicast forwarding |

| @c src/vnet/udp/udp.api ||
| ------- | ------- |
| [b'10dc2eabd'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'10dc2eabd') | udp: fix copyright typo |

| @c src/vnet/devices/tap/tapv2.api ||
| ------- | ------- |
| [b'97d54ed43'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'97d54ed43') | tap: add support to configure tap interface host MTU size |

| @c src/vnet/devices/virtio/vhost_user.api ||
| ------- | ------- |
| [b'4208a4ce8'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'4208a4ce8') | devices interface tests: vhosst GSO support |

| @c src/vnet/devices/virtio/virtio.api ||
| ------- | ------- |
| [b'bbd6b746e'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'bbd6b746e') | virtio: Add gso support for native virtio driver |
| [b'43b512cac'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'43b512cac') | virtio: remove configurable queue size support |

| @c src/vnet/mfib/mfib_types.api ||
| ------- | ------- |
| [b'097fa66b9'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'097fa66b9') | fib: fib api updates |

| @c src/vnet/ipsec/ipsec.api ||
| ------- | ------- |
| [b'c87b66c86'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'c87b66c86') | ipsec: ipsec-tun protect |
| [b'f2922422d'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'f2922422d') | ipsec: remove the set_key API |
| [b'80f6fd53f'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'80f6fd53f') | IPSEC: Pass the algorithm salt (used in GCM) over the API |

| @c src/vnet/ethernet/p2p_ethernet.api ||
| ------- | ------- |
| [b'8edca1361'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'8edca1361') | p2p ethernet: update p2p_ethernet.api with explicit types. |

| @c src/vnet/bonding/bond.api ||
| ------- | ------- |
| [b'751e3f382'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'751e3f382') | bonding: add support for numa-only in lacp mode |

| @c src/vnet/mpls/mpls.api ||
| ------- | ------- |
| [b'097fa66b9'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'097fa66b9') | fib: fib api updates |

| @c src/vnet/ipip/ipip.api ||
| ------- | ------- |
| [b'288e09362'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'288e09362') | ipip: refactor ipip.api with explicit types |
| [b'cbd0824d6'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'cbd0824d6') | IPIP tunnel: use address types on API |

| @c src/vnet/fib/fib_types.api ||
| ------- | ------- |
| [b'1dbcf30b7'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'1dbcf30b7') | fib: Support the POP of a Psuedo Wire Control Word |
| [b'097fa66b9'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'097fa66b9') | fib: fib api updates |

| @c src/vnet/dhcp/dhcp.api ||
| ------- | ------- |
| [b'038e1dfbd'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'038e1dfbd') | dhcp ip: DSCP settings for transmitted DHCP packets |
| [b'56bc738dc'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'56bc738dc') | Fix VPP-1487 DHCP client does not support option 6-domain server |

| @c src/vnet/ip/punt.api ||
| ------- | ------- |
| [b'719beb709'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'719beb709') | ip ipsec: Remove IPSec SPI-0 punt reason |
| [b'b538dd868'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'b538dd868') | Punt: specify packets by IP protocol Type |
| [b'50f0ac0f0'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'50f0ac0f0') | Punt: socket register for exception dispatched/punted packets based on reason |

| @c src/vnet/ip/ip.api ||
| ------- | ------- |
| [b'097fa66b9'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'097fa66b9') | fib: fib api updates |
| [b'3a343d42d'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'3a343d42d') | reassembly: prevent long chain attack |

| @c src/vnet/ip/ip_types.api ||
| ------- | ------- |
| [b'515eed425'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'515eed425') | api: add prefix matcher typedef |
| [b'038e1dfbd'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'038e1dfbd') | dhcp ip: DSCP settings for transmitted DHCP packets |
| [b'53c501512'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'53c501512') | api: add DSCP definitions to ip_types.api |
| [b'ab05508e1'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'ab05508e1') | api: refactor format_vl_api_prefix_t return keys |
| [b'b538dd868'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'b538dd868') | Punt: specify packets by IP protocol Type |
| [b'50f0ac0f0'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'50f0ac0f0') | Punt: socket register for exception dispatched/punted packets based on reason |

| @c src/plugins/l3xc/l3xc.api ||
| ------- | ------- |
| [b'59fa121f8'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'59fa121f8') | L3 cross connect |

| @c src/plugins/map/map.api ||
| ------- | ------- |
| [b'4d376f67a'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'4d376f67a') | map: Use vl_api_string macros. |

| @c src/plugins/http_static/http_static.api ||
| ------- | ------- |
| [b'68b24e2c9'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'68b24e2c9') | plugins: http_static. Migrate to use api string type. |
| [b'22bc2c46e'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'22bc2c46e') | Static http server |

| @c src/plugins/igmp/igmp.api ||
| ------- | ------- |
| [b'4ff09ae34'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'4ff09ae34') | API: Python and Unix domain socket improvement |

| @c src/plugins/sctp/sctp.api ||
| ------- | ------- |
| [b'3ffe6cadf'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'3ffe6cadf') | sctp: move to plugins, disabled by default |

| @c src/plugins/lb/lb.api ||
| ------- | ------- |
| [b'3efcd0d7c'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'3efcd0d7c') | lb: vip and as dump/detail api's |
| [b'a0cb32cb9'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'a0cb32cb9') | lb: update api.c to use scaffolding from latest skel |

| @c src/plugins/lb/lb_types.api ||
| ------- | ------- |
| [b'3efcd0d7c'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'3efcd0d7c') | lb: vip and as dump/detail api's |

| @c src/plugins/mactime/mactime.api ||
| ------- | ------- |
| [b'7681b1c46'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'7681b1c46') | mactime: add per-mac allow-with-quota feature |
| [b'0c6ac791d'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'0c6ac791d') | mactime: upstream new features |

| @c src/plugins/gbp/gbp.api ||
| ------- | ------- |
| [b'3918bdbcb'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'3918bdbcb') | gbp: update gbp-ext-itf API |
| [b'3c0d84c98'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'3c0d84c98') | gbp: add anonymous l3-out subnets |
| [b'cfc7a107e'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'cfc7a107e') | gbp: add anonymous l3-out external interfaces |
| [b'160c923f9'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'160c923f9') | gbp: VRF scoped contracts |

| @c src/plugins/acl/acl_types.api ||
| ------- | ------- |
| [b'bb2e5221a'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'bb2e5221a') | api acl: breakout acl_types.api for reuse by others |

| @c src/plugins/acl/acl.api ||
| ------- | ------- |
| [b'bb2e5221a'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'bb2e5221a') | api acl: breakout acl_types.api for reuse by others |
| [b'f995c7122'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'f995c7122') | acl: implement counters |

| @c src/plugins/nat/nat.api ||
| ------- | ------- |
| [b'e6e09a4ac'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'e6e09a4ac') | nat: elog rewrite for multi-worker support |
| [b'c1f93067e'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'c1f93067e') | Add default value for API Nat flags |
| [b'dd1e3e780'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'dd1e3e780') | NAT: VPP-1531 api cleanup & update |
| [b'89fec713f'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'89fec713f') | Revert "NAT: VPP-1531 api cleanup & update" |
| [b'bed1421b9'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'bed1421b9') | NAT: VPP-1531 api cleanup & update |

| @c src/plugins/abf/abf.api ||
| ------- | ------- |
| [b'097fa66b9'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'097fa66b9') | fib: fib api updates |

| @c src/plugins/nsim/nsim.api ||
| ------- | ------- |
| [b'7c91007e1'](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b'7c91007e1') | Make the loss / delay sim available as an output feature |


@page release_notes_19043 Release notes for VPP 19.04.3

This is bug fix release.

For the full list of fixed issues please refer to:
- fd.io [JIRA](https://jira.fd.io)
- git [commit log](https://git.fd.io/vpp/log/?h=stable/1904)

@page release_notes_19042 Release notes for VPP 19.04.2

This is bug fix release.

For the full list of fixed issues please refer to:
- fd.io [JIRA](https://jira.fd.io)
- git [commit log](https://git.fd.io/vpp/log/?h=stable/1904)

@page release_notes_19041 Release notes for VPP 19.04.1

This is bug fix release.

For the full list of fixed issues please refer to:
- fd.io [JIRA](https://jira.fd.io)
- git [commit log](https://git.fd.io/vpp/log/?h=stable/1904)

@page release_notes_1904 Release notes for VPP 19.04

More than 700 commits since the 19.01 release.

## Features

### Infrastructure
- DPDK 19.02 integration
- Buffer manager rework and improvements
- Python3 migration (work in progress)
  - vppapigen
  - Python API wrappers
  - Docs generation
  - vpp_config
  - "make test" python3 readiness and refactoring
- Add "make test-gcov" target to main Makefile
- Refactor multiarch code
- vfctl script: bind VF to vfio-pci after VF is created
- cmake cross-compilation support
- CLI control of graph dispatch elogs
- AppImage packaging (disabled by default)
- Complete upstreaming of wireshark dissector
- Remove JVPP which is now an FD.io project
- Punt infra: manage dispatch of exception packets

### VNET & Plugins
- BVI Interface
- Deprecate TAP cli
- Experimental TAP interface TCP segmentation offload
- Vmxnet3 driver plugin
- LACP passive mode
- ACL plugin refactoring
- RDMA (ibverb) driver plugin - MLX5 with multiqueue
- IPSEC
  - Intel IPSEC-MB engine plugin
  - Tunnel fragmentation
  - CLI improvements
  - Performance improvements
  - API modernisation and improvements
  - New Tests and test refactoring
- Crypto
  - Introduce crypto infra
  - crypto_ia32 plugin
  - Add support for AEAD and AES-GCM
  - Implement rfc4231 test cases
  - Implement crypto tests per RFC2202
- Perfmon improvements
  - Python to C parser for intel CPUs
  - 2-way parallel stat collection
  - Collect data on selected thread(s)

### Host stack
- Improve ldp/vls/vcl support for multi-process and multi-threaded applications
- Major refactor/cleanup of session layer
- Refactor cut-through sessions to use a custom transport
- Baseline QUIC transport support

## Known issues

For the full list of issues please refer to fd.io [JIRA](https://jira.fd.io).

## Issues fixed

For the full list of fixed issues please refer to:
- fd.io [JIRA](https://jira.fd.io)
- git [commit log](https://git.fd.io/vpp/log/?h=stable/1904)

## API changes

Description of results:

* _Definition changed_: indicates that the API file was modified between releases.
* _Only in image_: indicates the API is new for this release.
* _Only in file_: indicates the API has been removed in this release.


Message Name                                                 | Result
-------------------------------------------------------------|------------------
accept_session                                               | only in file
accept_session_reply                                         | only in file
bind_sock_reply                                              | definition changed
bind_uri_reply                                               | definition changed
bvi_create                                                   | only in image
bvi_create_reply                                             | only in image
bvi_delete                                                   | only in image
bvi_delete_reply                                             | only in image
connect_session                                              | only in file
connect_session_reply                                        | only in file
ct6_enable                                                   | only in image
ct6_enable_disable                                           | only in image
gbp_contract_add_del_reply                                   | definition changed
gbp_endpoint_group_del                                       | definition changed
gbp_endpoint_learn_set_inactive_threshold                    | only in file
gbp_endpoint_learn_set_inactive_threshold_reply              | only in file
ikev2_plugin_get_version                                     | only in image
ikev2_plugin_get_version_reply                               | only in image
ip4_arp_event                                                | definition changed
ip6_nd_event                                                 | definition changed
ip6_ra_event                                                 | definition changed
ip6nd_proxy_add_del                                          | definition changed
ip6nd_proxy_details                                          | definition changed
ip_container_proxy_add_del                                   | definition changed
ip_neighbor_add_del                                          | definition changed
ip_neighbor_details                                          | definition changed
ip_probe_neighbor                                            | definition changed
ip_source_and_port_range_check_add_del                       | definition changed
ipsec_backend_details                                        | definition changed
ipsec_gre_add_del_tunnel                                     | only in file
ipsec_gre_add_del_tunnel_reply                               | only in file
ipsec_gre_tunnel_add_del                                     | only in image
ipsec_gre_tunnel_add_del_reply                               | only in image
ipsec_gre_tunnel_details                                     | definition changed
ipsec_sa_details                                             | definition changed
ipsec_sa_set_key                                             | definition changed
ipsec_sad_add_del_entry                                      | only in file
ipsec_sad_add_del_entry_reply                                | only in file
ipsec_sad_entry_add_del                                      | only in image
ipsec_sad_entry_add_del_reply                                | only in image
ipsec_select_backend                                         | definition changed
ipsec_spd_add_del_entry                                      | only in file
ipsec_spd_add_del_entry_reply                                | only in file
ipsec_spd_details                                            | definition changed
ipsec_spd_entry_add_del                                      | only in image
ipsec_spd_entry_add_del_reply                                | only in image
ipsec_tunnel_if_add_del                                      | definition changed
lb_conf                                                      | definition changed
map_add_domain                                               | definition changed
map_domain_details                                           | definition changed
nat_ha_flush                                                 | only in image
nat_ha_flush_reply                                           | only in image
nat_ha_get_failover                                          | only in image
nat_ha_get_failover_reply                                    | only in image
nat_ha_get_listener                                          | only in image
nat_ha_get_listener_reply                                    | only in image
nat_ha_resync                                                | only in image
nat_ha_resync_completed_event                                | only in image
nat_ha_resync_reply                                          | only in image
nat_ha_set_failover                                          | only in image
nat_ha_set_failover_reply                                    | only in image
nat_ha_set_listener                                          | only in image
nat_ha_set_listener_reply                                    | only in image
reset_session                                                | only in file
reset_session_reply                                          | only in file
sw_interface_ip6nd_ra_prefix                                 | definition changed
sw_interface_set_dpdk_hqos_pipe                              | only in file
sw_interface_set_dpdk_hqos_pipe_reply                        | only in file
sw_interface_set_dpdk_hqos_subport                           | only in file
sw_interface_set_dpdk_hqos_subport_reply                     | only in file
sw_interface_set_dpdk_hqos_tctbl                             | only in file
sw_interface_set_dpdk_hqos_tctbl_reply                       | only in file
sw_interface_tap_details                                     | only in file
sw_interface_tap_dump                                        | only in file
sw_interface_virtio_pci_details                              | only in image
sw_interface_virtio_pci_dump                                 | only in image
tap_connect                                                  | only in file
tap_connect_reply                                            | only in file
tap_delete                                                   | only in file
tap_delete_reply                                             | only in file
tap_modify                                                   | only in file
tap_modify_reply                                             | only in file
virtio_pci_create                                            | only in image
virtio_pci_create_reply                                      | only in image
virtio_pci_delete                                            | only in image
virtio_pci_delete_reply                                      | only in image
vmxnet3_create                                               | definition changed
vmxnet3_details                                              | definition changed
want_ip4_arp_events                                          | definition changed
want_ip6_nd_events                                           | definition changed

Found 90 api message signature differences

### Patches that changed API definitions

| @c src/vlibmemory/memclnt.api ||
| ------- | ------- |
| [eaec2a6d9](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=eaec2a6d9) | bapi: add options to have vpp cleanup client registration |

| @c src/vpp/api/vpe.api ||
| ------- | ------- |
| [1aaf0e343](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=1aaf0e343) | deprecate tapcli |
| [f49ba0e81](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f49ba0e81) | stats: Deprecate old stats framework |
| [413f4a5b2](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=413f4a5b2) | API: Use string type instead of u8. |

| @c src/vnet/interface.api ||
| ------- | ------- |
| [3b0d7e42f](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=3b0d7e42f) | Revert "API: Cleanup APIs interface.api" |
| [e63325e3c](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e63325e3c) | API: Cleanup APIs interface.api |
| [bb2c7b580](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=bb2c7b580) | Update documentation for src/vnet/interface.api sw_interface_dump |
| [f49ba0e81](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f49ba0e81) | stats: Deprecate old stats framework |
| [53fffa1db](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=53fffa1db) | API: Add support for type aliases |
| [5100aa9cb](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=5100aa9cb) | vnet: store hw interface speed in kbps instead of using flags |

| @c src/vnet/interface_types.api ||
| ------- | ------- |
| [3b0d7e42f](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=3b0d7e42f) | Revert "API: Cleanup APIs interface.api" |
| [e63325e3c](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e63325e3c) | API: Cleanup APIs interface.api |
| [53fffa1db](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=53fffa1db) | API: Add support for type aliases |

| @c src/vnet/bonding/bond.api ||
| ------- | ------- |
| [ad9d52831](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=ad9d52831) | bonding: support custom interface IDs |

| @c src/vnet/ipip/ipip.api ||
| ------- | ------- |
| [53fffa1db](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=53fffa1db) | API: Add support for type aliases |

| @c src/vnet/ipsec-gre/ipsec_gre.api ||
| ------- | ------- |
| [e524d45ef](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e524d45ef) | IPSEC-GRE: fixes and API update to common types. |

| @c src/vnet/syslog/syslog.api ||
| ------- | ------- |
| [b4515b4be](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b4515b4be) | Add RFC5424 syslog protocol support (VPP-1139) |

| @c src/vnet/devices/tap/tapv2.api ||
| ------- | ------- |
| [754f24b35](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=754f24b35) | tapv2: add "tap_flags" field to the TAPv2 interface API |

| @c src/vnet/devices/virtio/virtio.api ||
| ------- | ------- |
| [d6c15af33](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=d6c15af33) | virtio: Native virtio driver |

| @c src/vnet/fib/fib_types.api ||
| ------- | ------- |
| [775f73c6b](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=775f73c6b) | FIB: encode the label stack in the FIB path during table dump |

| @c src/vnet/ip/ip_types.api ||
| ------- | ------- |
| [8c8acc027](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=8c8acc027) | API: Change ip4_address and ip6_address to use type alias. |
| [ffba3c377](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=ffba3c377) | MAP: Use explicit address/prefix types in API |

| @c src/vnet/ip/ip.api ||
| ------- | ------- |
| [48ae19e90](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=48ae19e90) | API: Add python2.7 support for enum flags via aenum |
| [37029305c](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=37029305c) | Use IP and MAC API types for neighbors |
| [7c03ed47d](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=7c03ed47d) | VOM: mroutes |
| [3460b014a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=3460b014a) | api: ip_source_check_interface_add_del api is added. |
| [609e1210c](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=609e1210c) | VPP-1507: Added binary api to dump configured ip_punt_redirect |
| [2af0e3a74](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=2af0e3a74) | flow-hash: Add symmetric flag for flow hashing |
| [47527b24a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=47527b24a) | IP-punt: add documentation to the API and fix IP address init |
| [5bb1ecae8](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=5bb1ecae8) | IPv6: Make link-local configurable per-interface (VPP-1446) |
| [75b9f45a1](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=75b9f45a1) | ip: add container proxy dump API (VPP-1364) |

| @c src/vnet/ip/punt.api ||
| ------- | ------- |
| [e88865d7b](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e88865d7b) | VPP-1506: dump local punts and registered punt sockets |

| @c src/vnet/vxlan-gbp/vxlan_gbp.api ||
| ------- | ------- |
| [4dd4cf4f9](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=4dd4cf4f9) | GBP: fixes for l3-out routing |
| [93cc3ee3b](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=93cc3ee3b) | GBP Endpoint Learning |

| @c src/vnet/ethernet/ethernet_types.api ||
| ------- | ------- |
| [8006c6aa4](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=8006c6aa4) | PAPI: Add MACAddress object wrapper for vl_api_mac_address_t |

| @c src/vnet/ipsec/ipsec.api ||
| ------- | ------- |
| [1e3aa5e21](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=1e3aa5e21) | ipsec: USE_EXTENDED_SEQ_NUM -> USE_ESN |
| [1ba5bc8d8](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=1ba5bc8d8) | ipsec: add ipv6 support for ipsec tunnel interface |
| [5d704aea5](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=5d704aea5) | updates now that flags are supported on the API |
| [53f526b68](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=53f526b68) | TEST: IPSEC NAT-T with UDP header |
| [7c44d78ef](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=7c44d78ef) | IKEv2 to plugin |
| [eba31eceb](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=eba31eceb) | IPSEC: move SA counters into the stats segment |
| [8d7c50200](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=8d7c50200) | IPSEC: no second lookup after tunnel encap |
| [a09c1ff5b](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=a09c1ff5b) | IPSEC: SPD counters in the stats sgement |
| [17dcec0b9](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=17dcec0b9) | IPSEC: API modernisation |
| [4c422f9a3](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=4c422f9a3) | Add IPSec interface FIB index for TX packet |
| [b4a7a7dcf](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b4a7a7dcf) | Add UDP encap flag |
| [b4d305344](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b4d305344) | ipsec: infra for selecting backends |
| [871bca9aa](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=871bca9aa) | VPP-1450: binary api call for dumping SPD to interface registration |

| @c src/vnet/tcp/tcp.api ||
| ------- | ------- |
| [c5df8c71c](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c5df8c71c) | host stack: update stale copyright |

| @c src/vnet/l2/l2.api ||
| ------- | ------- |
| [192b13f96](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=192b13f96) | BVI Interface |
| [5daf0c55c](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=5daf0c55c) | add default NONE flag for bd_flags |
| [e26c81fc8](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e26c81fc8) | L2 BD API to flush all IP-MAC entries in the specified BD |
| [8006c6aa4](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=8006c6aa4) | PAPI: Add MACAddress object wrapper for vl_api_mac_address_t |
| [93cc3ee3b](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=93cc3ee3b) | GBP Endpoint Learning |
| [4d5b917b1](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=4d5b917b1) | BD ARP entry use common API types |

| @c src/vnet/session/session.api ||
| ------- | ------- |
| [6442401c2](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=6442401c2) | session: remove deprecated binary apis |
| [d85de68ec](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=d85de68ec) | vcl: wait for segments with segment handle |
| [fa76a76bf](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=fa76a76bf) | session: segment handle in accept/connect notifications |
| [c1f5a4336](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c1f5a4336) | session: cleanup use of api_client_index |
| [c0d532d17](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c0d532d17) | session: mark apis for deprecation |

| @c src/vnet/udp/udp.api ||
| ------- | ------- |
| [c5df8c71c](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c5df8c71c) | host stack: update stale copyright |

| @c src/plugins/cdp/cdp.api ||
| ------- | ------- |
| [76ef6094c](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=76ef6094c) | tests: cdp plugin. Replace cdp enable cli command with API call. |

| @c src/plugins/nat/nat.api ||
| ------- | ------- |
| [8feeaff56](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=8feeaff56) | Typos. A bunch of typos I've been collecting. |
| [34931eb47](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=34931eb47) | NAT44: active-passive HA (VPP-1571) |
| [b686508c4](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b686508c4) | NAT44: nat44_add_del_lb_static_mapping enhancements (VPP-1514) |

| @c src/plugins/map/map.api ||
| ------- | ------- |
| [4dc5c7b90](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=4dc5c7b90) | MAP: Add optional user-supplied 'tag' field in MAPs. |
| [fc7344f9b](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=fc7344f9b) | MAP: Convert from DPO to input feature. |
| [f34597fc8](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f34597fc8) | MAP: Add API support for MAP input feature. |
| [5a2e278a0](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=5a2e278a0) | MAP: Add API support for setting parameters. |
| [a173a7a07](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=a173a7a07) | MAP: Use bool type in map.api instead of u8. |
| [ffba3c377](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=ffba3c377) | MAP: Use explicit address/prefix types in API |

| @c src/plugins/gbp/gbp.api ||
| ------- | ------- |
| [1aa35576e](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=1aa35576e) | GBP: Counters per-contract |
| [8ea109e40](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=8ea109e40) | gbp: Add bd flags |
| [7bd343509](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=7bd343509) | GBP: custom-dump functions |
| [fa0ac2c56](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=fa0ac2c56) | GBP: contracts API fixed length of allowed ethertypes |
| [5d704aea5](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=5d704aea5) | updates now that flags are supported on the API |
| [4ba67723d](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=4ba67723d) | GBP: use sclass in the DP for policy |
| [8da9fc659](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=8da9fc659) | GBP: learn from ARP and L2 packets |
| [32f6d8e0c](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=32f6d8e0c) | GBP: per-group EP retention policy |
| [879d11c25](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=879d11c25) | GBP: Sclass to src-epg conversions |
| [1c17e2eca](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=1c17e2eca) | GBP: add allowed ethertypes to contracts |
| [b6a479539](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b6a479539) | GBP: l3-out subnets |
| [33b81da54](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=33b81da54) | vom: Add support for redirect contracts in gbp |
| [13a08cc09](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=13a08cc09) | GBP: redirect contracts |
| [c29c0af40](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c29c0af40) | GBP: Endpoints with VLAN tags and birdges that don't learn |
| [93cc3ee3b](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=93cc3ee3b) | GBP Endpoint Learning |

| @c src/plugins/acl/acl.api ||
| ------- | ------- |
| [bb5d22daf](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=bb5d22daf) | New api in order to get max entries of connection table is added. |

| @c src/plugins/vmxnet3/vmxnet3.api ||
| ------- | ------- |
| [ee8ba6877](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=ee8ba6877) | vmxnet3: auto bind support |
| [854559d15](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=854559d15) | vmxnet3: RSS support |
| [773291163](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=773291163) | vmxnet3: multiple TX queues support |

| @c src/plugins/nsim/nsim.api ||
| ------- | ------- |
| [10c5ff143](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=10c5ff143) | nsim: add packet loss simulation, docs |

| @c src/plugins/igmp/igmp.api ||
| ------- | ------- |
| [97748cae2](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=97748cae2) | IGMP: proxy device |

| @c src/plugins/lb/lb.api ||
| ------- | ------- |
| [f7f13347b](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f7f13347b) | tests: update test_lb.py to use api call lb_conf. |

| @c src/plugins/ct6/ct6.api ||
| ------- | ------- |
| [a55df1081](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=a55df1081) | ipv6 connection tracking plugin |

| @c src/plugins/ikev2/ikev2.api ||
| ------- | ------- |
| [7c44d78ef](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=7c44d78ef) | IKEv2 to plugin |


@page release_notes_19013 Release notes for VPP 19.01.3

This is bug fix release.

For the full list of fixed issues please refer to:
- fd.io [JIRA](https://jira.fd.io)
- git [commit log](https://git.fd.io/vpp/log/?h=stable/1901)

@page release_notes_19012 Release notes for VPP 19.01.2

This is bug fix release.

For the full list of fixed issues please refer to:
- fd.io [JIRA](https://jira.fd.io)
- git [commit log](https://git.fd.io/vpp/log/?h=stable/1901)

@page release_notes_19011 Release notes for VPP 19.01.1

This is bug fix release.

For the full list of fixed issues please refer to:
- fd.io [JIRA](https://jira.fd.io)
- git [commit log](https://git.fd.io/vpp/log/?h=stable/1901)

@page release_notes_1901 Release notes for VPP 19.01

More than 649 commits since the 18.10 release.

## Features

### Infrastructure
- NUMA-aware, growable physical memory allocator (pmalloc)
- FIB: sticky load-balance
- C11 safe string handling: provide and use "safe" C string handling functions
- vlib: allocate buffers on local numa, not on numa 1
- vppinfra: autodetect default hugepage size
- Move RPC traffic off the shared-memory API queue
- IPv6: Make link-local configurable per-interface
- IGMP: improve CLI debug output
- IPSec: split ipsec nodes into ip4/ip6 nodes
- IPSec: infra for selecting backends
- vhost-user: cleanup and performance optimizations
- ethernet-input, memif improvements and optimizations
- DPDK: bump to DPDK 18.11
- reassembly: harden reassembly code
- stats: Deprecate old (event-based) stats framework
- vlib: support Hyper-V/Azure VMBus
- binary api clients: wait for vpp to start
- graph dispatch trace: capture packet data and buffer metadata, output in pcap format
- improve feature arc order constraint specification

### VNET & Plugins
- pktgen: correctly replay a mix of single and multi-buffer packets
- add wireshark dissector to extras
- avf: optimizations
- acl-plugin: use L2 feature arc instead of L2 classifier
- acl-plugin: performance enhancement
- dpdk: allow interface name to be specified from startup.conf
- dpdk: blacklist PCI devices by type
- dpdk: switch to in-memory mode, deprecate use of socket-mem
- vnet: store hw interface speed in kbps instead of using flags
- vmxnet3: enable promiscuous mode & cli enhancements
- gbp: Add support for flow hash profile & l3-out subnets
- map: Add API support for setting parameters.
- map: Convert from DPO to input feature
- nat: improve expired sessions reuse in NAT44
- nat: syslog - sessions logging
- nsim: add packet loss simulation, docs
- perfmon: x86_64 perf counter plugin
- vnet: L2 feature arc infrastructure

### Host stack
- TCP congestion control improvements
- TCP Cubic congestion control algorithm
- TCP fast path optimizations
- Transport tx connection pacer. TCP uses it by default
- Basic support for session flushing and TCP PSH segments
- TCP/session api support for configuring custom local src ip/port
- VCL/LDP basic support for multi-process applications
- Overall code hardening, cleanup and bugfixing for tcp, session, vcl and ldp

### PAPI & Test framework
- add specific API types for IP addresses, MAC address, interface index etc.
- add timeout support for socket transport
- add support for format/unformat functions
- generic API types format/unformat support for VAT and custom dump
- python3 test adjustments
- make test: create virtualenv under /test/
- make test: print TEST= values for failed tests
- add human-friendly annotations to log messages

### VOM
- Add support for redirect contracts in gbp
- deprecate TAP add ip-punt redirect dump
- vxlan-gbp support

## Known issues

For the full list of issues please refer to fd.io [JIRA](https://jira.fd.io).

## Issues fixed

For the full list of fixed issues please refer to:
- fd.io [JIRA](https://jira.fd.io)
- git [commit log](https://git.fd.io/vpp/log/?h=stable/1810)

## API changes

Description of results:

* _Definition changed_: indicates that the API file was modified between releases.
* _Only in image_: indicates the API is new for this release.
* _Only in file_: indicates the API has been removed in this release.

Message Name                                                 | Results
------------------------------------------------------------ | ----------------
acl_plugin_get_conn_table_max_entries                        | only in image
acl_plugin_get_conn_table_max_entries_reply                  | only in image
app_worker_add_del                                           | definition changed
app_worker_add_del_reply                                     | definition changed
application_attach_reply                                     | definition changed
bd_ip_mac_add_del                                            | definition changed
bd_ip_mac_details                                            | definition changed
bd_ip_mac_flush                                              | only in image
bd_ip_mac_flush_reply                                        | only in image
bond_create                                                  | definition changed
cli_inband                                                   | definition changed
cli_inband_reply                                             | definition changed
gbp_bridge_domain_add                                        | only in image
gbp_bridge_domain_add_reply                                  | only in image
gbp_bridge_domain_del                                        | only in image
gbp_bridge_domain_del_reply                                  | only in image
gbp_bridge_domain_details                                    | only in image
gbp_bridge_domain_dump                                       | only in image
gbp_bridge_domain_dump_reply                                 | only in image
gbp_endpoint_details                                         | definition changed
gbp_endpoint_group_add                                       | only in image
gbp_endpoint_group_add_del                                   | only in file
gbp_endpoint_group_add_del_reply                             | only in file
gbp_endpoint_group_add_reply                                 | only in image
gbp_endpoint_group_del                                       | only in image
gbp_endpoint_group_del_reply                                 | only in image
gbp_endpoint_learn_set_inactive_threshold                    | only in image
gbp_endpoint_learn_set_inactive_threshold_reply              | only in image
gbp_ext_itf_add_del                                          | only in image
gbp_ext_itf_add_del_reply                                    | only in image
gbp_ext_itf_details                                          | only in image
gbp_ext_itf_dump                                             | only in image
gbp_route_domain_add                                         | only in image
gbp_route_domain_add_reply                                   | only in image
gbp_route_domain_del                                         | only in image
gbp_route_domain_del_reply                                   | only in image
gbp_route_domain_details                                     | only in image
gbp_route_domain_dump                                        | only in image
gbp_route_domain_dump_reply                                  | only in image
gbp_vxlan_tunnel_add                                         | only in image
gbp_vxlan_tunnel_add_reply                                   | only in image
gbp_vxlan_tunnel_del                                         | only in image
gbp_vxlan_tunnel_del_reply                                   | only in image
gbp_vxlan_tunnel_details                                     | only in image
gbp_vxlan_tunnel_dump                                        | only in image
igmp_proxy_device_add_del                                    | only in image
igmp_proxy_device_add_del_interface                          | only in image
igmp_proxy_device_add_del_interface_reply                    | only in image
igmp_proxy_device_add_del_reply                              | only in image
ip6_mfib_details                                             | definition changed
ip_container_proxy_details                                   | only in image
ip_container_proxy_dump                                      | only in image
ip_mfib_details                                              | definition changed
ip_punt_redirect                                             | definition changed
ip_punt_redirect_details                                     | only in image
ip_punt_redirect_dump                                        | only in image
ip_source_check_interface_add_del                            | only in image
ip_source_check_interface_add_del_reply                      | only in image
ipip_6rd_add_tunnel_reply                                    | definition changed
ipip_6rd_del_tunnel                                          | definition changed
ipip_add_tunnel_reply                                        | definition changed
ipip_del_tunnel                                              | definition changed
ipip_tunnel_details                                          | definition changed
ipip_tunnel_dump                                             | definition changed
ipsec_backend_details                                        | only in image
ipsec_backend_dump                                           | only in image
ipsec_sa_details                                             | definition changed
ipsec_select_backend                                         | only in image
ipsec_select_backend_reply                                   | only in image
ipsec_tunnel_if_add_del                                      | definition changed
map_add_del_rule                                             | definition changed
map_add_domain                                               | definition changed
map_another_segment                                          | definition changed
map_domain_details                                           | definition changed
map_if_enable_disable                                        | only in image
map_if_enable_disable_reply                                  | only in image
map_param_add_del_pre_resolve                                | only in image
map_param_add_del_pre_resolve_reply                          | only in image
map_param_get                                                | only in image
map_param_get_reply                                          | only in image
map_param_set_fragmentation                                  | only in image
map_param_set_fragmentation_reply                            | only in image
map_param_set_icmp6                                          | only in image
map_param_set_icmp6_reply                                    | only in image
map_param_set_icmp                                           | only in image
map_param_set_icmp_reply                                     | only in image
map_param_set_reassembly                                     | only in image
map_param_set_reassembly_reply                               | only in image
map_param_set_security_check                                 | only in image
map_param_set_security_check_reply                           | only in image
map_param_set_tcp                                            | only in image
map_param_set_tcp_reply                                      | only in image
map_param_set_traffic_class                                  | only in image
map_param_set_traffic_class_reply                            | only in image
map_rule_details                                             | definition changed
memclnt_delete                                               | definition changed
nat44_add_del_lb_static_mapping                              | definition changed
nat44_lb_static_mapping_add_del_local                        | only in image
nat44_lb_static_mapping_add_del_local_reply                  | only in image
nat44_lb_static_mapping_details                              | definition changed
nsim_configure                                               | definition changed
punt                                                         | only in file
punt_details                                                 | only in image
punt_dump                                                    | only in image
punt_reply                                                   | only in file
punt_socket_deregister                                       | definition changed
punt_socket_details                                          | only in image
punt_socket_dump                                             | only in image
punt_socket_register                                         | definition changed
set_ip_flow_hash                                             | definition changed
set_punt                                                     | only in image
set_punt_reply                                               | only in image
show_version_reply                                           | definition changed
stats_get_poller_delay                                       | only in file
stats_get_poller_delay_reply                                 | only in file
sw_interface_bond_details                                    | definition changed
sw_interface_details                                         | definition changed
sw_interface_ip6_set_link_local_address                      | only in file
sw_interface_ip6_set_link_local_address_reply                | only in file
sw_interface_tap_v2_details                                  | definition changed
syslog_get_filter                                            | only in image
syslog_get_filter_reply                                      | only in image
syslog_get_sender                                            | only in image
syslog_get_sender_reply                                      | only in image
syslog_set_filter                                            | only in image
syslog_set_filter_reply                                      | only in image
syslog_set_sender                                            | only in image
syslog_set_sender_reply                                      | only in image
tap_create_v2                                                | definition changed
unmap_segment                                                | definition changed
vnet_bier_neighbor_counters                                  | only in file
vnet_get_summary_stats                                       | only in file
vnet_get_summary_stats_reply                                 | only in file
vnet_interface_combined_counters                             | only in file
vnet_interface_simple_counters                               | only in file
vnet_ip4_fib_counters                                        | only in file
vnet_ip4_mfib_counters                                       | only in file
vnet_ip4_nbr_counters                                        | only in file
vnet_ip6_fib_counters                                        | only in file
vnet_ip6_mfib_counters                                       | only in file
vnet_ip6_nbr_counters                                        | only in file
vnet_per_interface_combined_counters                         | only in file
vnet_per_interface_simple_counters                           | only in file
vnet_udp_encap_counters                                      | only in file
want_bier_neighbor_stats                                     | only in file
want_bier_neighbor_stats_reply                               | only in file
want_interface_combined_stats                                | only in file
want_interface_combined_stats_reply                          | only in file
want_interface_simple_stats                                  | only in file
want_interface_simple_stats_reply                            | only in file
want_ip4_fib_stats                                           | only in file
want_ip4_fib_stats_reply                                     | only in file
want_ip4_mfib_stats                                          | only in file
want_ip4_mfib_stats_reply                                    | only in file
want_ip4_nbr_stats                                           | only in file
want_ip4_nbr_stats_reply                                     | only in file
want_ip6_fib_stats                                           | only in file
want_ip6_fib_stats_reply                                     | only in file
want_ip6_mfib_stats                                          | only in file
want_ip6_mfib_stats_reply                                    | only in file
want_ip6_nbr_stats                                           | only in file
want_ip6_nbr_stats_reply                                     | only in file
want_per_interface_combined_stats                            | only in file
want_per_interface_combined_stats_reply                      | only in file
want_per_interface_simple_stats                              | only in file
want_per_interface_simple_stats_reply                        | only in file
want_stats                                                   | only in file
want_stats_reply                                             | only in file
want_udp_encap_stats                                         | only in file
want_udp_encap_stats_reply                                   | only in file

Found 170 api message signature differences

### Patches that changed API definitions

| @c src/vnet/interface_types.api ||
| ------- | ------- |
| [53fffa1](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=53fffa1) | API: Add support for type aliases |

| @c src/vnet/interface.api ||
| ------- | ------- |
| [f49ba0e](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f49ba0e) | stats: Deprecate old stats framework |
| [53fffa1](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=53fffa1) | API: Add support for type aliases |
| [5100aa9](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=5100aa9) | vnet: store hw interface speed in kbps instead of using flags |

| @c src/vnet/syslog/syslog.api ||
| ------- | ------- |
| [b4515b4](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b4515b4) | Add RFC5424 syslog protocol support (VPP-1139) |

| @c src/vnet/fib/fib_types.api ||
| ------- | ------- |
| [775f73c](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=775f73c) | FIB: encode the label stack in the FIB path during table dump |

| @c src/vnet/ip/ip.api ||
| ------- | ------- |
| [7c03ed4](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=7c03ed4) | VOM: mroutes |
| [3460b01](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=3460b01) | api: ip_source_check_interface_add_del api is added. |
| [609e121](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=609e121) | VPP-1507: Added binary api to dump configured ip_punt_redirect |
| [2af0e3a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=2af0e3a) | flow-hash: Add symmetric flag for flow hashing |
| [47527b2](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=47527b2) | IP-punt: add documentation to the API and fix IP address init |
| [5bb1eca](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=5bb1eca) | IPv6: Make link-local configurable per-interface (VPP-1446) |
| [75b9f45](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=75b9f45) | ip: add container proxy dump API (VPP-1364) |

| @c src/vnet/ip/ip_types.api ||
| ------- | ------- |
| [8c8acc0](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=8c8acc0) | API: Change ip4_address and ip6_address to use type alias. |
| [ffba3c3](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=ffba3c3) | MAP: Use explicit address/prefix types in API |

| @c src/vnet/ip/punt.api ||
| ------- | ------- |
| [e88865d](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e88865d) | VPP-1506: dump local punts and registered punt sockets |

| @c src/vnet/ipsec/ipsec.api ||
| ------- | ------- |
| [4c422f9](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=4c422f9) | Add IPSec interface FIB index for TX packet |
| [b4a7a7d](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b4a7a7d) | Add UDP encap flag |
| [b4d3053](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b4d3053) | ipsec: infra for selecting backends |
| [871bca9](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=871bca9) | VPP-1450: binary api call for dumping SPD to interface registration |

| @c src/vnet/l2/l2.api ||
| ------- | ------- |
| [e26c81f](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e26c81f) | L2 BD API to flush all IP-MAC entries in the specified BD |
| [8006c6a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=8006c6a) | PAPI: Add MACAddress object wrapper for vl_api_mac_address_t |
| [93cc3ee](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=93cc3ee) | GBP Endpoint Learning |
| [4d5b917](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=4d5b917) | BD ARP entry use common API types |

| @c src/vnet/vxlan-gbp/vxlan_gbp.api ||
| ------- | ------- |
| [93cc3ee](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=93cc3ee) | GBP Endpoint Learning |

| @c src/vnet/ipip/ipip.api ||
| ------- | ------- |
| [53fffa1](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=53fffa1) | API: Add support for type aliases |

| @c src/vnet/session/session.api ||
| ------- | ------- |
| [d85de68](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=d85de68) | vcl: wait for segments with segment handle |
| [fa76a76](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=fa76a76) | session: segment handle in accept/connect notifications |
| [c1f5a43](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c1f5a43) | session: cleanup use of api_client_index |
| [c0d532d](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c0d532d) | session: mark apis for deprecation |

| @c src/vnet/ethernet/ethernet_types.api ||
| ------- | ------- |
| [8006c6a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=8006c6a) | PAPI: Add MACAddress object wrapper for vl_api_mac_address_t |

| @c src/vnet/bonding/bond.api ||
| ------- | ------- |
| [ad9d528](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=ad9d528) | bonding: support custom interface IDs |

| @c src/vnet/devices/tap/tapv2.api ||
| ------- | ------- |
| [754f24b](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=754f24b) | tapv2: add "tap_flags" field to the TAPv2 interface API |

| @c src/vlibmemory/memclnt.api ||
| ------- | ------- |
| [eaec2a6](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=eaec2a6) | bapi: add options to have vpp cleanup client registration |

| @c src/vpp/api/vpe.api ||
| ------- | ------- |
| [f49ba0e](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f49ba0e) | stats: Deprecate old stats framework |
| [413f4a5](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=413f4a5) | API: Use string type instead of u8. |

| @c src/plugins/acl/acl.api ||
| ------- | ------- |
| [bb5d22d](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=bb5d22d) | New api in order to get max entries of connection table is added. |

| @c src/plugins/nsim/nsim.api ||
| ------- | ------- |
| [10c5ff1](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=10c5ff1) | nsim: add packet loss simulation, docs |

| @c src/plugins/gbp/gbp.api ||
| ------- | ------- |
| [1c17e2e](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=1c17e2e) | GBP: add allowed ethertypes to contracts |
| [b6a4795](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b6a4795) | GBP: l3-out subnets |
| [33b81da](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=33b81da) | vom: Add support for redirect contracts in gbp |
| [13a08cc](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=13a08cc) | GBP: redirect contracts |
| [c29c0af](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c29c0af) | GBP: Endpoints with VLAN tags and birdges that don't learn |
| [93cc3ee](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=93cc3ee) | GBP Endpoint Learning |

| @c src/plugins/nat/nat.api ||
| ------- | ------- |
| [b686508](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b686508) | NAT44: nat44_add_del_lb_static_mapping enhancements (VPP-1514) |

| @c src/plugins/map/map.api ||
| ------- | ------- |
| [fc7344f](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=fc7344f) | MAP: Convert from DPO to input feature. |
| [f34597f](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f34597f) | MAP: Add API support for MAP input feature. |
| [5a2e278](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=5a2e278) | MAP: Add API support for setting parameters. |
| [a173a7a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=a173a7a) | MAP: Use bool type in map.api instead of u8. |
| [ffba3c3](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=ffba3c3) | MAP: Use explicit address/prefix types in API |

| @c src/plugins/igmp/igmp.api ||
| ------- | ------- |
| [97748ca](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=97748ca) | IGMP: proxy device |


@page release_notes_1810 Release notes for VPP 18.10

More than 632 commits since the 18.07 release.

## Features

### Infrastructure
- DPDK 18.08 integration
- New Stats infrastructure (interface, error, node performance counters)
- Add configurable "Doug Lea malloc" support

### VNET & Plugins
- Load balancing: support per-port VIP and all-port VIP
- Port NSH plugin to VPP
- NAT
  - Configurable port range
  - Virtual Fragmentation Reassembly for endpoint-dependent mode
  - Client-IP based session affinity for load-balancing
  - TCP MSS clamping
  - Session timeout
  - Bug-fixing and performance optimizations

### Host stack
- Support for applications with multiple workers
- Support for binds from multiple app workers to same ip:port
- Switched to a message queue for io and control event notifications
- Support for eventfd based notifications as alternative to mutext-condvar pair
- VCL refactor to support async event notifications and multiple workers
- TLS async support in client for HW accleration
- Performance optimizations and bug-fixing
- A number of binary APIs will be deprecated in favor of using the event
  message queue. Details in the API section.

## Known issues

For the full list of issues please refer to fd.io [JIRA](https://jira.fd.io).

## Issues fixed

For the full list of fixed issues please refer to:
- fd.io [JIRA](https://jira.fd.io)
- git [commit log](https://git.fd.io/vpp/log/?h=stable/1810)

## API changes

Description of results:

* _Definition changed_: indicates that the API file was modified between releases.
* _Only in image_: indicates the API is new for this release.
* _Only in file_: indicates the API has been removed in this release.

                        Message Name                         Result
api_versions_reply                                           definition changed
app_cut_through_registration_add                             definition changed
app_worker_add_del                                           definition changed
application_attach_reply                                     definition changed
bd_ip_mac_details                                            only in image
bd_ip_mac_dump                                               only in image
bfd_udp_get_echo_source                                      definition changed
bier_imp_details                                             definition changed
bier_route_details                                           definition changed
bind_sock                                                    definition changed
bridge_domain_details                                        definition changed
bridge_flags                                                 definition changed
classify_add_del_session                                     definition changed
classify_add_del_table                                       definition changed
connect_sock                                                 definition changed
create_vhost_user_if                                         definition changed
get_first_msg_id_reply                                       definition changed
gpe_add_del_fwd_entry_reply                                  definition changed
gpe_fwd_entry_path_details                                   definition changed
ip6_fib_details                                              definition changed
ip6nd_proxy_details                                          definition changed
ip_add_del_route_reply                                       definition changed
ip_address_details                                           definition changed
ip_details                                                   definition changed
ip_fib_details                                               definition changed
ip_mfib_details                                              definition changed
ip_mroute_add_del_reply                                      definition changed
ip_neighbor_add_del_reply                                    definition changed
ip_neighbor_details                                          definition changed
ip_reassembly_get_reply                                      definition changed
ip_unnumbered_details                                        definition changed
ipip_6rd_add_tunnel                                          definition changed
ipip_add_tunnel                                              definition changed
ipsec_spds_details                                           only in image
ipsec_spds_dump                                              only in image
l2_interface_efp_filter                                      definition changed
lisp_eid_table_vni_details                                   definition changed
map_another_segment                                          definition changed
mfib_signal_details                                          definition changed
mpls_route_add_del_reply                                     definition changed
mpls_tunnel_add_del                                          definition changed
mpls_tunnel_add_del_reply                                    definition changed
mpls_tunnel_details                                          definition changed
mpls_tunnel_dump                                             definition changed
one_eid_table_vni_details                                    definition changed
qos_mark_enable_disable                                      definition changed
qos_record_enable_disable                                    definition changed
reset_session_reply                                          definition changed
rpc_call                                                     definition changed
show_threads                                                 definition changed
sockclnt_create_reply                                        definition changed
sockclnt_delete                                              definition changed
sockclnt_delete_reply                                        definition changed
sw_interface_rx_placement_details                            only in image
sw_interface_rx_placement_dump                               only in image
sw_interface_set_ip_directed_broadcast                       definition changed
sw_interface_set_l2_bridge                                   definition changed
sw_interface_set_rx_placement                                definition changed
sw_interface_set_vxlan_gbp_bypass                            definition changed
udp_encap_add                                                definition changed
udp_encap_add_del_reply                                      only in file
udp_encap_add_reply                                          only in image
udp_encap_del                                                definition changed
udp_encap_details                                            definition changed
unbind_sock                                                  definition changed
vxlan_gbp_tunnel_add_del                                     definition changed
vxlan_gbp_tunnel_details                                     only in image
vxlan_gbp_tunnel_dump                                        only in image
Found 68 api message signature differences

### Patches that changed API definitions

| @c src/plugins/avf/avf.api ||
| ------- | ------- |
| [149d0e28](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=149d0e28) | avf: RSS support |
| [4e6014fc](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=4e6014fc) | avf: api fix |

| @c src/plugins/gbp/gbp.api ||
| ------- | ------- |
| [c0a93143](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c0a93143) | GBP Endpoint Updates |
| [61b94c6b](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=61b94c6b) | vxlan-gbp: Add support for vxlan gbp |

| @c src/plugins/igmp/igmp.api ||
| ------- | ------- |
| [bdc0e6b7](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=bdc0e6b7) | Trivial: Clean up some typos. |

| @c src/plugins/lb/lb.api ||
| ------- | ------- |
| [6a4375e0](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=6a4375e0) | LB: fix flush flow table issue |
| [49ca2601](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=49ca2601) | Add flush flag on del as command |
| [219cc90c](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=219cc90c) | Support lb on both vip and per-port-vip case |

| @c src/plugins/nat/nat.api ||
| ------- | ------- |
| [bb4e0225](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=bb4e0225) | NAT: TCP MSS clamping |
| [5d28c7af](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=5d28c7af) | NAT: add support for configurable port range (VPP-1346) |
| [ea5b5be4](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=ea5b5be4) | NAT44: client-IP based session affinity for load-balancing (VPP-1297) |
| [878c646a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=878c646a) | NAT44: add support for session timeout (VPP-1272) |
| [69ce30d6](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=69ce30d6) | NAT: update nat_show_config_reply API (VPP-1403) |
| [6bd197eb](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=6bd197eb) | Remove client_index field from replies in API |
| [c6c0d2a0](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c6c0d2a0) | NAT44: LB NAT - local backends in multiple VRFs (VPP-1345) |

| @c src/plugins/vmxnet3/vmxnet3.api ||
| ------- | ------- |
| [df7f8e8c](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=df7f8e8c) | vmxnet3 device driver |

| @c src/plugins/nsh/nsh.api ||
| ------- | ------- |
| [d313f9e6](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=d313f9e6) | Port NSH plugin to VPP |

| @c src/plugins/nsim/nsim.api ||
| ------- | ------- |
| [9e3252b5](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9e3252b5) | Network delay simulator plugin |

| @c src/plugins/svs/svs.api ||
| ------- | ------- |
| [d1e68ab7](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=d1e68ab7) | Source VRF Select |

| @c src/vlibmemory/memclnt.api ||
| ------- | ------- |
| [94495f2a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=94495f2a) | PAPI: Use UNIX domain sockets instead of shared memory |
| [6bd197eb](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=6bd197eb) | Remove client_index field from replies in API |
| [75282457](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=75282457) | Fix "Old Style VLA" build warnings |

| @c src/vnet/interface.api ||
| ------- | ------- |
| [f0b42f48](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f0b42f48) | itf: dump interface rx-placement |
| [bdc0e6b7](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=bdc0e6b7) | Trivial: Clean up some typos. |
| [54f7c51f](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=54f7c51f) | rx-placement: Add API call for interface rx-placement |
| [1855b8e4](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=1855b8e4) | IP directed broadcast |

| @c src/vnet/bfd/bfd.api ||
| ------- | ------- |
| [2d3c7b9c](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=2d3c7b9c) | BFD: add get echo source API (VPP-1367) |

| @c src/vnet/bier/bier.api ||
| ------- | ------- |
| [ef90ed08](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=ef90ed08) | BIER API and load-balancing fixes |
| [6bd197eb](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=6bd197eb) | Remove client_index field from replies in API |

| @c src/vnet/classify/classify.api ||
| ------- | ------- |
| [34eb5d42](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=34eb5d42) | classify_add_del_session API: Use more descriptive docstring (VPP-1385) |
| [75282457](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=75282457) | Fix "Old Style VLA" build warnings |

| @c src/vnet/devices/pipe/pipe.api ||
| ------- | ------- |
| [208c29aa](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=208c29aa) | VOM: support for pipes |

| @c src/vnet/devices/virtio/vhost_user.api ||
| ------- | ------- |
| [ee2e58f6](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=ee2e58f6) | vhost-user: Add disable feature support in api |

| @c src/vnet/ethernet/ethernet_types.api ||
| ------- | ------- |
| [de5b08fb](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=de5b08fb) | Introduce a mac_address_t on the API and in VPP |

| @c src/vnet/ip/ip_types.api ||
| ------- | ------- |
| [d0df49f2](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=d0df49f2) | Use IP address types on UDP encap API |

| @c src/vnet/ip/ip.api ||
| ------- | ------- |
| [412ecd32](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=412ecd32) | Improve ip_mroute_add_del documentation |
| [14260393](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=14260393) | Add adjacency counters to the stats segment |
| [28c142e3](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=28c142e3) | mroute routers in the stats segment |
| [008dbe10](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=008dbe10) | Route counters in the stats segment |
| [de5b08fb](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=de5b08fb) | Introduce a mac_address_t on the API and in VPP |
| [6bd197eb](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=6bd197eb) | Remove client_index field from replies in API |
| [b11f903a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b11f903a) | Fix context field position in API definition |

| @c src/vnet/ipip/ipip.api ||
| ------- | ------- |
| [61502115](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=61502115) | IPIP and SIXRD tunnels create API needs table-IDs not fib-indexes |

| @c src/vnet/ipsec/ipsec.api ||
| ------- | ------- |
| [a9a0b2ce](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=a9a0b2ce) | IPsec: add API for SPDs dump (VPP-1363) |
| [bdc0e6b7](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=bdc0e6b7) | Trivial: Clean up some typos. |

| @c src/vnet/l2/l2.api ||
| ------- | ------- |
| [0a4e0063](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=0a4e0063) | Fix documentation about sw_interface_set_l2_bridge |
| [b474380f](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b474380f) | L2 BD: introduce a BD interface on which to send UU packets |
| [bdc0e6b7](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=bdc0e6b7) | Trivial: Clean up some typos. |
| [5c7c49d1](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=5c7c49d1) | Fix documentation for SHG in bridge domain |
| [5d82d2f1](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=5d82d2f1) | l2: arp termination dump |
| [6b9b41c8](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=6b9b41c8) | L2 EFP: byteswap sw_if_index, enable flag can be u8 on .api |

| @c src/vnet/lisp-cp/lisp.api ||
| ------- | ------- |
| [bdc0e6b7](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=bdc0e6b7) | Trivial: Clean up some typos. |
| [6bd197eb](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=6bd197eb) | Remove client_index field from replies in API |

| @c src/vnet/lisp-cp/one.api ||
| ------- | ------- |
| [bdc0e6b7](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=bdc0e6b7) | Trivial: Clean up some typos. |
| [6bd197eb](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=6bd197eb) | Remove client_index field from replies in API |

| @c src/vnet/lisp-gpe/lisp_gpe.api ||
| ------- | ------- |
| [6bd197eb](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=6bd197eb) | Remove client_index field from replies in API |
| [b11f903a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=b11f903a) | Fix context field position in API definition |

| @c src/vnet/mpls/mpls.api ||
| ------- | ------- |
| [f5fa5ae2](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f5fa5ae2) | MPLS tunnel dump: use sw_if_index not tunnel_index |
| [6a30b5f9](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=6a30b5f9) | MPLS tunnel dump fix |
| [008dbe10](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=008dbe10) | Route counters in the stats segment |
| [7c922dc4](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=7c922dc4) | SR-MPLS: fixes and tests |

| @c src/vnet/qos/qos.api ||
| ------- | ------- |
| [bdc0e6b7](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=bdc0e6b7) | Trivial: Clean up some typos. |
| [ed234e7f](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=ed234e7f) | Enum type on the API for QoS sources |

| @c src/vnet/session/session.api ||
| ------- | ------- |
| [ab2f6dbf](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=ab2f6dbf) | session: support multiple worker binds |
| [134a996a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=134a996a) | vcl: add support for multi-worker apps |
| [1553197f](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=1553197f) | session: add support for multiple app workers |
| [6bd197eb](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=6bd197eb) | Remove client_index field from replies in API |
| [99368315](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=99368315) | vcl: support for eventfd mq signaling |

| @c src/vnet/span/span.api ||
| ------- | ------- |
| [bdc0e6b7](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=bdc0e6b7) | Trivial: Clean up some typos. |

| @c src/vnet/udp/udp.api ||
| ------- | ------- |
| [9c0a3c42](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9c0a3c42) | UDP-Encap: name counters for the stats segment |
| [d0df49f2](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=d0df49f2) | Use IP address types on UDP encap API |

| @c src/vnet/unix/tap.api ||
| ------- | ------- |
| [bdc0e6b7](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=bdc0e6b7) | Trivial: Clean up some typos. |

| @c src/vnet/vxlan-gbp/vxlan_gbp.api ||
| ------- | ------- |
| [79a05f54](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=79a05f54) | VXLAN-GBP: use common types on the API |
| [61b94c6b](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=61b94c6b) | vxlan-gbp: Add support for vxlan gbp |

| @c src/vpp/api/vpe.api ||
| ------- | ------- |
| [5d64c786](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=5d64c786) | thread: Add show threads api |
| [ec11b13a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=ec11b13a) | Trivial: Cleanup some typos. |

| @c src/vpp/stats/stats.api ||
| ------- | ------- |
| [ec11b13a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=ec11b13a) | Trivial: Cleanup some typos. |

### Notice of future API deprecation
- bind_uri_reply
- accept_session
- accept_session_reply
- disconnect_session_reply
- reset_session
- reset_session_reply
- bind_sock_reply
- connect_session_reply


@page release_notes_1807 Release notes for VPP 18.07

More than 533 commits since the 18.04 release.

## Features

### Infrastructure
- DPDK 18.02.1
  - Complete rework of the dpdk-input node
  - Display rx/tx burst function name in "show hardware detail"
  - Improve buffer alloc perfomance
      - This is ~50% improvement in buffer alloc performance.  For a 256 buffer allocation, it was ~10 clocks/buffer, now is < 5 clocks.
  - Add per-numa page allocation info to 'show memory'
  - Vectorized bihash_{48,40,24,16}_8 key compare
      - bihash_48_8 case:
          - Scalar code: 6 clocks
          - SSE4.2 code: 3 clocks
          - AVX2 code: 2.27 clocks
          - AVX512 code: 1.5 clocks
  - Pollable Stats
     - Stats are now available to a client in a shared memory segment and
       in the form of a directory, allowing very high performance polling
       of stats without directly querying VPP.

### VNET & Plugins
- IGMP improvements
  - Enable/Disable an interface for IGMP
  - improve logging
  - refactor common code
  - no orphaned timers
  - IGMP state changes in main thread only
  - Large groups split over multiple state-change reports
  - SSM range configuration API.
  - more tests
- IP: vectorized IP checksum
- VXLAN : HW offload RX flow
- Rework kube-proxy into LB plugin and add NATA66
- NAT:
    - Code refactor
    - Syslog
    - Multiple outside interfaces
    - Endpoint dependent filtering and mapping
- ACL:
    - Tuple Merge algorithm cleanup and integration
    - Processing pipeline optimizations
    - Refactoring
- Experimental AVF driver

### Host stack

- Session: performance improvements, add support for connectionless transports, datagram reception and transmission
- TCP: congestion control improvements and overall fixes
- UDP: datagram mode
- TLS async support


## Known issues

For the full list of issues please refer to fd.io [JIRA](https://jira.fd.io).

## Issues fixed

For the full list of fixed issues please refer to:
- fd.io [JIRA](https://jira.fd.io)
- git [commit log](https://git.fd.io/vpp/log/?h=stable/1807)

## API changes

Description of results:

* _Definition changed_: indicates that the API file was modified between releases.
* _Only in image_: indicates the API is new for this release.
* _Only in file_: indicates the API has been removed in this release.

                        Message Name                         Result
abf_itf_attach_add_del                                       definition changed
abf_itf_attach_details                                       only in image
abf_itf_attach_dump                                          only in image
abf_plugin_get_version                                       definition changed
abf_policy_add_del                                           definition changed
abf_policy_details                                           only in image
abf_policy_dump                                              only in image
af_packet_details                                            only in image
af_packet_dump                                               only in image
avf_create                                                   definition changed
avf_delete                                                   definition changed
bind_sock_reply                                              definition changed
bind_uri_reply                                               definition changed
dhcp6_client_enable_disable                                  definition changed
dhcp6_clients_enable_disable                                 definition changed
dhcp6_duid_ll_set                                            definition changed
dhcp6_pd_client_enable_disable                               definition changed
dhcp6_pd_reply_event                                         only in image
dhcp6_pd_send_client_message                                 definition changed
dhcp6_reply_event                                            only in image
dhcp6_send_client_message                                    definition changed
dhcp_client_config                                           definition changed
dhcp_client_details                                          only in image
dhcp_client_dump                                             only in image
dhcp_compl_event                                             definition changed
dslite_address_details                                       only in image
dslite_address_dump                                          only in image
gbp_endpoint_group_add_del                                   definition changed
gbp_endpoint_group_details                                   only in image
gbp_endpoint_group_dump                                      only in image
gbp_recirc_add_del                                           definition changed
gbp_recirc_details                                           only in image
gbp_recirc_dump                                              only in image
gbp_subnet_add_del                                           definition changed
gbp_subnet_details                                           only in image
gbp_subnet_dump                                              only in image
hw_interface_set_mtu                                         definition changed
igmp_details                                                 definition changed
igmp_dump                                                    definition changed
igmp_enable_disable                                          definition changed
igmp_event                                                   definition changed
igmp_group_prefix_details                                    only in image
igmp_group_prefix_dump                                       only in image
igmp_group_prefix_set                                        definition changed
igmp_listen                                                  definition changed
ikev2_profile_set_auth                                       definition changed
ikev2_profile_set_id                                         definition changed
ip6_add_del_address_using_prefix                             definition changed
ip_mroute_add_del                                            definition changed
ip_probe_neighbor                                            definition changed
ip_scan_neighbor_enable_disable                              definition changed
ip_unnumbered_details                                        only in image
ip_unnumbered_dump                                           only in image
ipip_6rd_add_tunnel                                          definition changed
ipip_add_tunnel                                              definition changed
ipip_tunnel_details                                          definition changed
ipsec_sa_details                                             definition changed
ipsec_sad_add_del_entry                                      definition changed
ipsec_tunnel_if_add_del                                      definition changed
kp_add_del_pod                                               definition changed
kp_add_del_vip                                               definition changed
kp_conf                                                      definition changed
lb_add_del_vip                                               definition changed
mactime_add_del                                              definition changed
mactime_enable                                               definition changed
memclnt_create                                               definition changed
memclnt_create_reply                                         definition changed
memfd_segment_create                                         definition changed
nat44_add_del_lb_static_mapping                              definition changed
nat44_add_del_static_mapping                                 definition changed
nat44_del_session                                            definition changed
nat44_lb_static_mapping_details                              definition changed
nat44_static_mapping_details                                 definition changed
nat44_user_session_details                                   definition changed
pipe_create                                                  definition changed
pipe_delete                                                  definition changed
pipe_details                                                 only in image
pipe_dump                                                    only in image
pot_profile_activate                                         definition changed
pot_profile_add                                              definition changed
pot_profile_del                                              definition changed
proxy_arp_add_del                                            definition changed
proxy_arp_details                                            only in image
proxy_arp_dump                                               only in image
proxy_arp_intfc_details                                      only in image
proxy_arp_intfc_dump                                         only in image
sock_init_shm_reply                                          definition changed
sockclnt_create                                              definition changed
sockclnt_create_reply                                        definition changed
sr_localsid_add_del                                          definition changed
sr_localsids_details                                         definition changed
sr_policies_details                                          only in image
sr_policies_dump                                             only in image
sr_policy_add                                                definition changed
sr_policy_del                                                definition changed
sr_policy_mod                                                definition changed
sr_steering_pol_details                                      only in image
sr_steering_pol_dump                                         only in image
sw_interface_details                                         definition changed
sw_interface_set_mtu                                         definition changed
tap_create_v2                                                definition changed
vnet_bier_neighbor_counters                                  only in image
vnet_get_summary_stats_reply                                 definition changed
vxlan_offload_rx                                             definition changed
want_bier_neighbor_stats                                     definition changed
want_dhcp6_pd_reply_events                                   definition changed
want_dhcp6_reply_events                                      definition changed
Found 107 api message signature differences

### Patches that changed API definitions

| @c src/plugins/ioam/lib-pot/pot.api ||
| ------- | ------- |
| [e9fcf23](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e9fcf23) | Fix some build warnings about "Old Style VLA" |

| @c src/plugins/gbp/gbp.api ||
| ------- | ------- |
| [25b0494](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=25b0494) | GBP V2 |

| @c src/plugins/map/map.api ||
| ------- | ------- |
| [381e9a9](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=381e9a9) | MAP: Move MAP-E/T to a plugin. |

| @c src/plugins/igmp/igmp.api ||
| ------- | ------- |
| [947ea62](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=947ea62) | IGMP improvements |

| @c src/plugins/lb/lb.api ||
| ------- | ------- |
| [d92a0b5](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=d92a0b5) | Rework kube-proxy into LB plugin |

| @c src/plugins/nat/nat.api ||
| ------- | ------- |
| [70a26ac](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=70a26ac) | NAT44: nat44_del_session and nat44_user_session_details API update (VPP-1271) |
| [ebdf190](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=ebdf190) | NAT44: TCP connection close detection (VPP-1266) |
| [1e5c07d](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=1e5c07d) | Add special Twice-NAT feature (VPP-1221) |
| [16aa7f8](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=16aa7f8) | DSLite: Implement new API call DSLITE_ADDRESS_DUMP. |

| @c src/plugins/avf/avf.api ||
| ------- | ------- |
| [258a189](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=258a189) | avf: api fix |
| [6c9b964](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=6c9b964) | avf: binary API and configurable RX/TX queue size |

| @c src/plugins/mactime/mactime.api ||
| ------- | ------- |
| [7055e26](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=7055e26) | Driver level time-based src mac filter |

| @c src/plugins/abf/abf.api ||
| ------- | ------- |
| [669d07d](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=669d07d) | ACL based forwarding |

| @c src/vlibmemory/memclnt.api ||
| ------- | ------- |
| [dab732a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=dab732a) | VPP-1335 vapi crash when memclnt_keepalive received |
| [7895872](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=7895872) | Remove the historical memfd api segment bootstrap |

| @c src/vpp/stats/stats.api ||
| ------- | ------- |
| [a21a367](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=a21a367) | VPP-1324 SIGSEGV vl_msg_api_handler_with_vm_node() |
| [586479a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=586479a) | BIER neighbor stats |
| [e906aac](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e906aac) | STATS: Separate socket for fd exchange. |
| [048a4e5](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=048a4e5) | export counters in a memfd segment |

| @c src/vnet/interface.api ||
| ------- | ------- |
| [d723161](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=d723161) | MTU: Software interface / Per-protocol MTU support |
| [fe7d4a2](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=fe7d4a2) | Revert "MTU: Setting of MTU on software interface (instead of hardware interface)" |
| [70083ee](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=70083ee) | MTU: Setting of MTU on software interface (instead of hardware interface) |

| @c src/vnet/ipfix-export/ipfix_export.api ||
| ------- | ------- |
| [a9855ef](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=a9855ef) | Flow: Rename IPFIX exporter. |

| @c src/vnet/dhcp/dhcp6_pd_client_cp.api ||
| ------- | ------- |
| [81119e8](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=81119e8) | Implement DHCPv6 PD client (VPP-718, VPP-1050) |

| @c src/vnet/dhcp/dhcp.api ||
| ------- | ------- |
| [dd3b8f7](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=dd3b8f7) | Implement DHCPv6 IA NA client (VPP-1094) |
| [d9778c2](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=d9778c2) | Update DHCPv6 DUID code and fix coverity warnings |
| [81119e8](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=81119e8) | Implement DHCPv6 PD client (VPP-718, VPP-1050) |
| [daff178](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=daff178) | DHCP Client Dump |

| @c src/vnet/dhcp/dhcp6_ia_na_client_cp.api ||
| ------- | ------- |
| [dd3b8f7](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=dd3b8f7) | Implement DHCPv6 IA NA client (VPP-1094) |

| @c src/vnet/ip/ip.api ||
| ------- | ------- |
| [947ea62](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=947ea62) | IGMP improvements |
| [7eaaf74](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=7eaaf74) | proxy_arp: remove unused is_add |
| [0053de6](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=0053de6) | ARP proxy dumps |
| [9e2f915](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9e2f915) | IP unnumbered dump |
| [7f358b3](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=7f358b3) | Periodic scan and probe of IP neighbors to maintain neighbor pools |
| [e821ab1](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e821ab1) | IP mcast: allow unicast address as a next-hop |
| [c7b4304](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c7b4304) | Implement ip_probe_neighbor API |

| @c src/vnet/ip/ip_types.api ||
| ------- | ------- |
| [947ea62](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=947ea62) | IGMP improvements |
| [2c2feab](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=2c2feab) | VPPAPIGEN: Add union and enum support and IP4/IP6 address type. |

| @c src/vnet/devices/af_packet/af_packet.api ||
| ------- | ------- |
| [04e0bb2](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=04e0bb2) | af_packet: Add support for dump interfaces |

| @c src/vnet/devices/tap/tapv2.api ||
| ------- | ------- |
| [d600ffe](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=d600ffe) | Update tapv2 documentation |
| [0b06111](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=0b06111) | VPP-1305: Add support for tags |

| @c src/vnet/devices/pipe/pipe.api ||
| ------- | ------- |
| [ee8b973](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=ee8b973) | VOM: support for pipes |
| [17ff3c1](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=17ff3c1) | Pipes |

| @c src/vnet/ipip/ipip.api ||
| ------- | ------- |
| [d57f636](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=d57f636) | VPP-1277: IPIP - Copy TOS/TC from inner packet to outer. |

| @c src/vnet/session/session.api ||
| ------- | ------- |
| [7fb0fe1](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=7fb0fe1) | udp/session: refactor to support dgram mode |

| @c src/vnet/ipsec/ipsec.api ||
| ------- | ------- |
| [4b089f2](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=4b089f2) | ipsec: support UDP encap/decap for NAT traversal |
| [e9fcf23](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e9fcf23) | Fix some build warnings about "Old Style VLA" |
| [8e1039a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=8e1039a) | Allow an IPsec tunnel interface to be renumbered |

| @c src/vnet/vxlan/vxlan.api ||
| ------- | ------- |
| [af86a48](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=af86a48) | vxlan:offload RX flow |

| @c src/vnet/srv6/sr.api ||
| ------- | ------- |
| [3337bd2](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=3337bd2) | Fixed bugs in SRv6 API |
| [e9fcf23](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e9fcf23) | Fix some build warnings about "Old Style VLA" |



@page release_notes_1804 Release notes for VPP 18.04

More than 570 commits since the 18.01 release.

## Features

### Infrastructure
- DPDK 18.02.1
- ARM aarch64 integrated into CI

### VNET & Plugins
- ERSPAN
- L3DSR load balancing support
- VPC bonding / LACP
- IPv4/IPv6 packet reassembly
- IPv6 link-local support
- Asymmetrical static NAT
- 464XLAT for NAT44
- MAP-T CE support
- Intel Adaptive Virtual Function native device driver plugin
- Marvell device plugin
- SRv6 static, dynamic and masquerading proxy plugins
- MPLS Uniform mode
- IGMP plugin
- IPIP tunnel support (IPv4/IPv6 over IPv4/IPv6)
- IPv6 Router Discovery mechanism

### VLIB
- ARM-optimized library variations for key functions
- Better handling of physmem on non-NUMA kernels

### Host stack
- TLS support via OpenSSL or mbedtls software engines
- Session layer can utilize both shm and memfd (secure) FIFO segments
- STCP
- VCL logging / tracing

### API framework
- New API definition compiler (vppapigen)
- Memory (shm) and socket APIs refactored
- API handlers refactored to make them transport (shared memory or socket)
    agnostic
- Improved support for bootstrapping of the shm API with memfd segments
    over the socket API

### Packaging
- SELinux for RPM builds
- Debuginfo RPMs
- ARM aarch64 for Ubuntu

## Known issues

For the full list of issues please refer to fd.io [JIRA](https://jira.fd.io).

## Issues fixed

For the full list of fixed issues please refer to:
- fd.io [JIRA](https://jira.fd.io)
- git [commit log](https://git.fd.io/vpp/log/?h=stable/1804)

## API changes

Description of results:

* _Definition changed_: indicates that the API file was modified between releases.
* _Only in image_: indicates the API is new for this release.
* _Only in file_: indicates the API has been removed in this release.

Message Name                                                 | Results
------------------------------------------------------------ | ----------------
accept_session                                               | definition changed
accept_session_reply                                         | definition changed
acl_add_replace                                              | definition changed
acl_add_replace_reply                                        | definition changed
acl_del                                                      | definition changed
acl_del_reply                                                | definition changed
acl_details                                                  | definition changed
acl_dump                                                     | definition changed
acl_interface_add_del                                        | definition changed
acl_interface_add_del_reply                                  | definition changed
acl_interface_etype_whitelist_details                        | only in image
acl_interface_etype_whitelist_dump                           | only in image
acl_interface_list_details                                   | definition changed
acl_interface_list_dump                                      | definition changed
acl_interface_set_acl_list                                   | definition changed
acl_interface_set_acl_list_reply                             | definition changed
acl_interface_set_etype_whitelist                            | definition changed
acl_plugin_control_ping                                      | definition changed
acl_plugin_control_ping_reply                                | definition changed
acl_plugin_get_version                                       | definition changed
acl_plugin_get_version_reply                                 | definition changed
add_node_next                                                | definition changed
add_node_next_reply                                          | definition changed
af_packet_create                                             | definition changed
af_packet_create_reply                                       | definition changed
af_packet_delete                                             | definition changed
af_packet_delete_reply                                       | definition changed
af_packet_set_l4_cksum_offload                               | definition changed
af_packet_set_l4_cksum_offload_reply                         | definition changed
api_versions                                                 | definition changed
api_versions_reply                                           | definition changed
app_namespace_add_del                                        | definition changed
app_namespace_add_del_reply                                  | definition changed
application_attach                                           | definition changed
application_attach_reply                                     | definition changed
application_detach                                           | definition changed
application_detach_reply                                     | definition changed
application_tls_cert_add                                     | definition changed
application_tls_key_add                                      | definition changed
bd_ip_mac_add_del                                            | definition changed
bd_ip_mac_add_del_reply                                      | definition changed
bfd_auth_del_key                                             | definition changed
bfd_auth_del_key_reply                                       | definition changed
bfd_auth_keys_details                                        | definition changed
bfd_auth_keys_dump                                           | definition changed
bfd_auth_set_key                                             | definition changed
bfd_auth_set_key_reply                                       | definition changed
bfd_udp_add                                                  | definition changed
bfd_udp_add_reply                                            | definition changed
bfd_udp_auth_activate                                        | definition changed
bfd_udp_auth_activate_reply                                  | definition changed
bfd_udp_auth_deactivate                                      | definition changed
bfd_udp_auth_deactivate_reply                                | definition changed
bfd_udp_del                                                  | definition changed
bfd_udp_del_echo_source                                      | definition changed
bfd_udp_del_echo_source_reply                                | definition changed
bfd_udp_del_reply                                            | definition changed
bfd_udp_mod                                                  | definition changed
bfd_udp_mod_reply                                            | definition changed
bfd_udp_session_details                                      | definition changed
bfd_udp_session_dump                                         | definition changed
bfd_udp_session_set_flags                                    | definition changed
bfd_udp_session_set_flags_reply                              | definition changed
bfd_udp_set_echo_source                                      | definition changed
bfd_udp_set_echo_source_reply                                | definition changed
bier_disp_entry_add_del                                      | definition changed
bier_disp_entry_add_del_reply                                | definition changed
bier_disp_entry_details                                      | definition changed
bier_disp_entry_dump                                         | definition changed
bier_disp_table_add_del                                      | definition changed
bier_disp_table_add_del_reply                                | definition changed
bier_disp_table_details                                      | definition changed
bier_disp_table_dump                                         | definition changed
bier_imp_add                                                 | definition changed
bier_imp_add_reply                                           | definition changed
bier_imp_del                                                 | definition changed
bier_imp_del_reply                                           | definition changed
bier_imp_details                                             | definition changed
bier_imp_dump                                                | definition changed
bier_route_add_del                                           | definition changed
bier_route_add_del_reply                                     | definition changed
bier_route_details                                           | definition changed
bier_route_dump                                              | definition changed
bier_table_add_del                                           | definition changed
bier_table_add_del_reply                                     | definition changed
bier_table_details                                           | definition changed
bier_table_dump                                              | definition changed
bind_sock                                                    | definition changed
bind_sock_reply                                              | definition changed
bind_uri                                                     | definition changed
bind_uri_reply                                               | definition changed
bond_create                                                  | definition changed
bond_delete                                                  | definition changed
bond_detach_slave                                            | definition changed
bond_enslave                                                 | definition changed
bridge_domain_add_del                                        | definition changed
bridge_domain_add_del_reply                                  | definition changed
bridge_domain_details                                        | definition changed
bridge_domain_dump                                           | definition changed
bridge_domain_set_mac_age                                    | definition changed
bridge_domain_set_mac_age_reply                              | definition changed
bridge_flags                                                 | definition changed
bridge_flags_reply                                           | definition changed
cdp_enable                                                   | definition changed
classify_add_del_session                                     | definition changed
classify_add_del_session_reply                               | definition changed
classify_add_del_table                                       | definition changed
classify_add_del_table_reply                                 | definition changed
classify_session_details                                     | definition changed
classify_session_dump                                        | definition changed
classify_set_interface_ip_table                              | definition changed
classify_set_interface_ip_table_reply                        | definition changed
classify_set_interface_l2_tables                             | definition changed
classify_set_interface_l2_tables_reply                       | definition changed
classify_table_by_interface                                  | definition changed
classify_table_by_interface_reply                            | definition changed
classify_table_ids                                           | definition changed
classify_table_ids_reply                                     | definition changed
classify_table_info                                          | definition changed
classify_table_info_reply                                    | definition changed
cli                                                          | definition changed
cli_inband                                                   | definition changed
cli_inband_reply                                             | definition changed
cli_reply                                                    | definition changed
collect_detailed_interface_stats                             | definition changed
connect_session                                              | definition changed
connect_session_reply                                        | definition changed
connect_sock                                                 | definition changed
connect_sock_reply                                           | definition changed
connect_uri                                                  | definition changed
connect_uri_reply                                            | definition changed
control_ping                                                 | definition changed
control_ping_reply                                           | definition changed
cop_interface_enable_disable                                 | definition changed
cop_interface_enable_disable_reply                           | definition changed
cop_whitelist_enable_disable                                 | definition changed
cop_whitelist_enable_disable_reply                           | definition changed
create_loopback                                              | definition changed
create_loopback_instance                                     | definition changed
create_loopback_instance_reply                               | definition changed
create_loopback_reply                                        | definition changed
create_subif                                                 | definition changed
create_subif_reply                                           | definition changed
create_vhost_user_if                                         | definition changed
create_vhost_user_if_reply                                   | definition changed
create_vlan_subif                                            | definition changed
create_vlan_subif_reply                                      | definition changed
delete_loopback                                              | definition changed
delete_loopback_reply                                        | definition changed
delete_subif                                                 | definition changed
delete_subif_reply                                           | definition changed
delete_vhost_user_if                                         | definition changed
delete_vhost_user_if_reply                                   | definition changed
dhcp_client_config                                           | definition changed
dhcp_client_config_reply                                     | definition changed
dhcp_compl_event                                             | definition changed
dhcp_proxy_config                                            | definition changed
dhcp_proxy_config_reply                                      | definition changed
dhcp_proxy_details                                           | definition changed
dhcp_proxy_dump                                              | definition changed
dhcp_proxy_set_vss                                           | definition changed
dhcp_proxy_set_vss_reply                                     | definition changed
disconnect_session                                           | definition changed
disconnect_session_reply                                     | definition changed
dns_enable_disable                                           | definition changed
dns_enable_disable_reply                                     | definition changed
dns_name_server_add_del                                      | definition changed
dns_name_server_add_del_reply                                | definition changed
dns_resolve_ip                                               | definition changed
dns_resolve_ip_reply                                         | definition changed
dns_resolve_name                                             | definition changed
dns_resolve_name_reply                                       | definition changed
dslite_add_del_pool_addr_range                               | definition changed
dslite_add_del_pool_addr_range_reply                         | definition changed
dslite_get_aftr_addr                                         | definition changed
dslite_get_b4_addr                                           | definition changed
dslite_set_aftr_addr                                         | definition changed
dslite_set_aftr_addr_reply                                   | definition changed
dslite_set_b4_addr                                           | definition changed
feature_enable_disable                                       | definition changed
feature_enable_disable_reply                                 | definition changed
flow_classify_details                                        | definition changed
flow_classify_dump                                           | definition changed
flow_classify_set_interface                                  | definition changed
flow_classify_set_interface_reply                            | definition changed
flowprobe_params                                             | definition changed
flowprobe_params_reply                                       | definition changed
flowprobe_tx_interface_add_del                               | definition changed
flowprobe_tx_interface_add_del_reply                         | definition changed
gbp_contract_add_del                                         | definition changed
gbp_contract_details                                         | only in image
gbp_contract_dump                                            | only in image
gbp_endpoint_add_del                                         | definition changed
gbp_endpoint_details                                         | only in image
gbp_endpoint_dump                                            | only in image
geneve_add_del_tunnel                                        | definition changed
geneve_add_del_tunnel_reply                                  | definition changed
geneve_tunnel_details                                        | definition changed
geneve_tunnel_dump                                           | definition changed
get_first_msg_id                                             | definition changed
get_first_msg_id_reply                                       | definition changed
get_next_index                                               | definition changed
get_next_index_reply                                         | definition changed
get_node_graph                                               | definition changed
get_node_graph_reply                                         | definition changed
get_node_index                                               | definition changed
get_node_index_reply                                         | definition changed
gpe_add_del_fwd_entry                                        | definition changed
gpe_add_del_fwd_entry_reply                                  | definition changed
gpe_add_del_iface                                            | definition changed
gpe_add_del_iface_reply                                      | definition changed
gpe_add_del_native_fwd_rpath                                 | definition changed
gpe_add_del_native_fwd_rpath_reply                           | definition changed
gpe_enable_disable                                           | definition changed
gpe_enable_disable_reply                                     | definition changed
gpe_fwd_entries_get                                          | definition changed
gpe_fwd_entries_get_reply                                    | definition changed
gpe_fwd_entry_path_details                                   | definition changed
gpe_fwd_entry_path_dump                                      | definition changed
gpe_fwd_entry_vnis_get                                       | definition changed
gpe_fwd_entry_vnis_get_reply                                 | definition changed
gpe_get_encap_mode                                           | definition changed
gpe_get_encap_mode_reply                                     | definition changed
gpe_native_fwd_rpaths_get                                    | definition changed
gpe_native_fwd_rpaths_get_reply                              | definition changed
gpe_set_encap_mode                                           | definition changed
gpe_set_encap_mode_reply                                     | definition changed
gre_add_del_tunnel                                           | definition changed
gre_add_del_tunnel_reply                                     | definition changed
gre_tunnel_details                                           | definition changed
gre_tunnel_dump                                              | definition changed
gtpu_add_del_tunnel                                          | definition changed
gtpu_add_del_tunnel_reply                                    | definition changed
gtpu_tunnel_details                                          | definition changed
gtpu_tunnel_dump                                             | definition changed
igmp_clear_interface                                         | definition changed
igmp_details                                                 | only in image
igmp_dump                                                    | only in image
igmp_enable_disable                                          | definition changed
igmp_event                                                   | only in image
igmp_listen                                                  | definition changed
ikev2_initiate_del_child_sa                                  | definition changed
ikev2_initiate_del_child_sa_reply                            | definition changed
ikev2_initiate_del_ike_sa                                    | definition changed
ikev2_initiate_del_ike_sa_reply                              | definition changed
ikev2_initiate_rekey_child_sa                                | definition changed
ikev2_initiate_rekey_child_sa_reply                          | definition changed
ikev2_initiate_sa_init                                       | definition changed
ikev2_initiate_sa_init_reply                                 | definition changed
ikev2_profile_add_del                                        | definition changed
ikev2_profile_add_del_reply                                  | definition changed
ikev2_profile_set_auth                                       | definition changed
ikev2_profile_set_auth_reply                                 | definition changed
ikev2_profile_set_id                                         | definition changed
ikev2_profile_set_id_reply                                   | definition changed
ikev2_profile_set_ts                                         | definition changed
ikev2_profile_set_ts_reply                                   | definition changed
ikev2_set_esp_transforms                                     | definition changed
ikev2_set_esp_transforms_reply                               | definition changed
ikev2_set_ike_transforms                                     | definition changed
ikev2_set_ike_transforms_reply                               | definition changed
ikev2_set_local_key                                          | definition changed
ikev2_set_local_key_reply                                    | definition changed
ikev2_set_responder                                          | definition changed
ikev2_set_responder_reply                                    | definition changed
ikev2_set_sa_lifetime                                        | definition changed
ikev2_set_sa_lifetime_reply                                  | definition changed
input_acl_set_interface                                      | definition changed
input_acl_set_interface_reply                                | definition changed
interface_name_renumber                                      | definition changed
interface_name_renumber_reply                                | definition changed
ioam_cache_ip6_enable_disable                                | definition changed
ioam_cache_ip6_enable_disable_reply                          | definition changed
ioam_disable                                                 | definition changed
ioam_disable_reply                                           | definition changed
ioam_enable                                                  | definition changed
ioam_enable_reply                                            | definition changed
ioam_export_ip6_enable_disable                               | definition changed
ioam_export_ip6_enable_disable_reply                         | definition changed
ip4_arp_event                                                | definition changed
ip6_fib_details                                              | definition changed
ip6_fib_dump                                                 | definition changed
ip6_mfib_details                                             | definition changed
ip6_mfib_dump                                                | definition changed
ip6_nd_address_autoconfig                                    | definition changed
ip6_nd_event                                                 | definition changed
ip6_ra_event                                                 | only in image
ip6nd_proxy_add_del                                          | definition changed
ip6nd_proxy_add_del_reply                                    | definition changed
ip6nd_proxy_details                                          | definition changed
ip6nd_proxy_dump                                             | definition changed
ip6nd_send_router_solicitation                               | definition changed
ip_add_del_route                                             | definition changed
ip_add_del_route_reply                                       | definition changed
ip_address_details                                           | definition changed
ip_address_dump                                              | definition changed
ip_container_proxy_add_del                                   | definition changed
ip_container_proxy_add_del_reply                             | definition changed
ip_details                                                   | definition changed
ip_dump                                                      | definition changed
ip_fib_details                                               | definition changed
ip_fib_dump                                                  | definition changed
ip_mfib_details                                              | definition changed
ip_mfib_dump                                                 | definition changed
ip_mroute_add_del                                            | definition changed
ip_mroute_add_del_reply                                      | definition changed
ip_neighbor_add_del                                          | definition changed
ip_neighbor_add_del_reply                                    | definition changed
ip_neighbor_details                                          | definition changed
ip_neighbor_dump                                             | definition changed
ip_punt_police                                               | definition changed
ip_punt_police_reply                                         | definition changed
ip_punt_redirect                                             | definition changed
ip_punt_redirect_reply                                       | definition changed
ip_reassembly_enable_disable                                 | definition changed
ip_reassembly_get                                            | definition changed
ip_reassembly_set                                            | definition changed
ip_source_and_port_range_check_add_del                       | definition changed
ip_source_and_port_range_check_add_del_reply                 | definition changed
ip_source_and_port_range_check_interface_add_del             | definition changed
ip_source_and_port_range_check_interface_add_del_reply       | definition changed
ip_table_add_del                                             | definition changed
ip_table_add_del_reply                                       | definition changed
ipfix_classify_stream_details                                | definition changed
ipfix_classify_stream_dump                                   | definition changed
ipfix_classify_table_add_del                                 | definition changed
ipfix_classify_table_add_del_reply                           | definition changed
ipfix_classify_table_details                                 | definition changed
ipfix_classify_table_dump                                    | definition changed
ipfix_exporter_details                                       | definition changed
ipfix_exporter_dump                                          | definition changed
ipip_6rd_add_tunnel                                          | definition changed
ipip_6rd_del_tunnel                                          | definition changed
ipip_add_tunnel                                              | definition changed
ipip_del_tunnel                                              | definition changed
ipip_tunnel_details                                          | only in image
ipip_tunnel_dump                                             | only in image
ipsec_gre_add_del_tunnel                                     | definition changed
ipsec_gre_add_del_tunnel_reply                               | definition changed
ipsec_gre_tunnel_details                                     | definition changed
ipsec_gre_tunnel_dump                                        | definition changed
ipsec_interface_add_del_spd                                  | definition changed
ipsec_interface_add_del_spd_reply                            | definition changed
ipsec_sa_details                                             | definition changed
ipsec_sa_dump                                                | definition changed
ipsec_sa_set_key                                             | definition changed
ipsec_sa_set_key_reply                                       | definition changed
ipsec_sad_add_del_entry                                      | definition changed
ipsec_sad_add_del_entry_reply                                | definition changed
ipsec_spd_add_del                                            | definition changed
ipsec_spd_add_del_entry                                      | definition changed
ipsec_spd_add_del_entry_reply                                | definition changed
ipsec_spd_add_del_reply                                      | definition changed
ipsec_spd_details                                            | definition changed
ipsec_spd_dump                                               | definition changed
ipsec_tunnel_if_add_del                                      | definition changed
ipsec_tunnel_if_add_del_reply                                | definition changed
ipsec_tunnel_if_set_key                                      | definition changed
ipsec_tunnel_if_set_key_reply                                | definition changed
ipsec_tunnel_if_set_sa                                       | definition changed
ipsec_tunnel_if_set_sa_reply                                 | definition changed
kp_add_del_pod                                               | definition changed
kp_add_del_pod_reply                                         | definition changed
kp_add_del_vip                                               | definition changed
kp_add_del_vip_reply                                         | definition changed
kp_conf                                                      | definition changed
kp_conf_reply                                                | definition changed
l2_emulation                                                 | definition changed
l2_emulation_reply                                           | definition changed
l2_fib_clear_table                                           | definition changed
l2_fib_clear_table_reply                                     | definition changed
l2_fib_table_details                                         | definition changed
l2_fib_table_dump                                            | definition changed
l2_flags                                                     | definition changed
l2_flags_reply                                               | definition changed
l2_interface_efp_filter                                      | definition changed
l2_interface_efp_filter_reply                                | definition changed
l2_interface_pbb_tag_rewrite                                 | definition changed
l2_interface_pbb_tag_rewrite_reply                           | definition changed
l2_interface_vlan_tag_rewrite                                | definition changed
l2_interface_vlan_tag_rewrite_reply                          | definition changed
l2_macs_event                                                | definition changed
l2_patch_add_del                                             | definition changed
l2_patch_add_del_reply                                       | definition changed
l2_xconnect_details                                          | definition changed
l2_xconnect_dump                                             | definition changed
l2fib_add_del                                                | definition changed
l2fib_add_del_reply                                          | definition changed
l2fib_flush_all                                              | definition changed
l2fib_flush_all_reply                                        | definition changed
l2fib_flush_bd                                               | definition changed
l2fib_flush_bd_reply                                         | definition changed
l2fib_flush_int                                              | definition changed
l2fib_flush_int_reply                                        | definition changed
l2tpv3_create_tunnel                                         | definition changed
l2tpv3_create_tunnel_reply                                   | definition changed
l2tpv3_interface_enable_disable                              | definition changed
l2tpv3_interface_enable_disable_reply                        | definition changed
l2tpv3_set_lookup_key                                        | definition changed
l2tpv3_set_lookup_key_reply                                  | definition changed
l2tpv3_set_tunnel_cookies                                    | definition changed
l2tpv3_set_tunnel_cookies_reply                              | definition changed
lb_add_del_as                                                | definition changed
lb_add_del_as_reply                                          | definition changed
lb_add_del_vip                                               | definition changed
lb_add_del_vip_reply                                         | definition changed
lb_conf                                                      | definition changed
lb_conf_reply                                                | definition changed
lisp_add_del_adjacency                                       | definition changed
lisp_add_del_adjacency_reply                                 | definition changed
lisp_add_del_local_eid                                       | definition changed
lisp_add_del_local_eid_reply                                 | definition changed
lisp_add_del_locator                                         | definition changed
lisp_add_del_locator_reply                                   | definition changed
lisp_add_del_locator_set                                     | definition changed
lisp_add_del_locator_set_reply                               | definition changed
lisp_add_del_map_request_itr_rlocs                           | definition changed
lisp_add_del_map_request_itr_rlocs_reply                     | definition changed
lisp_add_del_map_resolver                                    | definition changed
lisp_add_del_map_resolver_reply                              | definition changed
lisp_add_del_map_server                                      | definition changed
lisp_add_del_map_server_reply                                | definition changed
lisp_add_del_remote_mapping                                  | definition changed
lisp_add_del_remote_mapping_reply                            | definition changed
lisp_adjacencies_get                                         | definition changed
lisp_adjacencies_get_reply                                   | definition changed
lisp_eid_table_add_del_map                                   | definition changed
lisp_eid_table_add_del_map_reply                             | definition changed
lisp_eid_table_details                                       | definition changed
lisp_eid_table_dump                                          | definition changed
lisp_eid_table_map_details                                   | definition changed
lisp_eid_table_map_dump                                      | definition changed
lisp_eid_table_vni_details                                   | definition changed
lisp_eid_table_vni_dump                                      | definition changed
lisp_enable_disable                                          | definition changed
lisp_enable_disable_reply                                    | definition changed
lisp_get_map_request_itr_rlocs                               | definition changed
lisp_get_map_request_itr_rlocs_reply                         | definition changed
lisp_locator_details                                         | definition changed
lisp_locator_dump                                            | definition changed
lisp_locator_set_details                                     | definition changed
lisp_locator_set_dump                                        | definition changed
lisp_map_register_enable_disable                             | definition changed
lisp_map_register_enable_disable_reply                       | definition changed
lisp_map_request_mode                                        | definition changed
lisp_map_request_mode_reply                                  | definition changed
lisp_map_resolver_details                                    | definition changed
lisp_map_resolver_dump                                       | definition changed
lisp_map_server_details                                      | definition changed
lisp_map_server_dump                                         | definition changed
lisp_pitr_set_locator_set                                    | definition changed
lisp_pitr_set_locator_set_reply                              | definition changed
lisp_rloc_probe_enable_disable                               | definition changed
lisp_rloc_probe_enable_disable_reply                         | definition changed
lisp_use_petr                                                | definition changed
lisp_use_petr_reply                                          | definition changed
lldp_config                                                  | definition changed
lldp_config_reply                                            | definition changed
macip_acl_add                                                | definition changed
macip_acl_add_replace                                        | definition changed
macip_acl_add_replace_reply                                  | definition changed
macip_acl_add_reply                                          | definition changed
macip_acl_del                                                | definition changed
macip_acl_del_reply                                          | definition changed
macip_acl_details                                            | definition changed
macip_acl_dump                                               | definition changed
macip_acl_interface_add_del                                  | definition changed
macip_acl_interface_add_del_reply                            | definition changed
macip_acl_interface_get                                      | definition changed
macip_acl_interface_get_reply                                | definition changed
macip_acl_interface_list_details                             | definition changed
macip_acl_interface_list_dump                                | definition changed
map_add_del_rule                                             | definition changed
map_add_del_rule_reply                                       | definition changed
map_add_domain                                               | definition changed
map_add_domain_reply                                         | definition changed
map_another_segment                                          | definition changed
map_another_segment_reply                                    | definition changed
map_del_domain                                               | definition changed
map_del_domain_reply                                         | definition changed
map_domain_details                                           | definition changed
map_domain_dump                                              | definition changed
map_rule_details                                             | definition changed
map_rule_dump                                                | definition changed
map_summary_stats                                            | definition changed
map_summary_stats_reply                                      | definition changed
memclnt_create                                               | definition changed
memclnt_create_reply                                         | definition changed
memclnt_delete                                               | definition changed
memclnt_delete_reply                                         | definition changed
memclnt_keepalive                                            | definition changed
memclnt_keepalive_reply                                      | definition changed
memclnt_read_timeout                                         | definition changed
memclnt_rx_thread_suspend                                    | definition changed
memfd_segment_create                                         | definition changed
memfd_segment_create_reply                                   | definition changed
memif_create                                                 | definition changed
memif_create_reply                                           | definition changed
memif_delete                                                 | definition changed
memif_delete_reply                                           | definition changed
memif_details                                                | definition changed
memif_dump                                                   | definition changed
memif_socket_filename_add_del                                | definition changed
memif_socket_filename_details                                | only in image
memif_socket_filename_dump                                   | only in image
mfib_signal_details                                          | definition changed
mfib_signal_dump                                             | definition changed
modify_vhost_user_if                                         | definition changed
modify_vhost_user_if_reply                                   | definition changed
mpls_fib_details                                             | definition changed
mpls_fib_dump                                                | definition changed
mpls_ip_bind_unbind                                          | definition changed
mpls_ip_bind_unbind_reply                                    | definition changed
mpls_route_add_del                                           | definition changed
mpls_route_add_del_reply                                     | definition changed
mpls_table_add_del                                           | definition changed
mpls_table_add_del_reply                                     | definition changed
mpls_tunnel_add_del                                          | definition changed
mpls_tunnel_add_del_reply                                    | definition changed
mpls_tunnel_details                                          | definition changed
mpls_tunnel_dump                                             | definition changed
nat44_add_del_address_range                                  | definition changed
nat44_add_del_address_range_reply                            | definition changed
nat44_add_del_identity_mapping                               | definition changed
nat44_add_del_identity_mapping_reply                         | definition changed
nat44_add_del_interface_addr                                 | definition changed
nat44_add_del_interface_addr_reply                           | definition changed
nat44_add_del_lb_static_mapping                              | definition changed
nat44_add_del_lb_static_mapping_reply                        | definition changed
nat44_add_del_static_mapping                                 | definition changed
nat44_add_del_static_mapping_reply                           | definition changed
nat44_address_details                                        | definition changed
nat44_address_dump                                           | definition changed
nat44_del_session                                            | definition changed
nat44_del_session_reply                                      | definition changed
nat44_forwarding_enable_disable                              | definition changed
nat44_forwarding_enable_disable_reply                        | definition changed
nat44_forwarding_is_enabled                                  | definition changed
nat44_forwarding_is_enabled_reply                            | definition changed
nat44_identity_mapping_details                               | definition changed
nat44_identity_mapping_dump                                  | definition changed
nat44_interface_add_del_feature                              | definition changed
nat44_interface_add_del_feature_reply                        | definition changed
nat44_interface_add_del_output_feature                       | definition changed
nat44_interface_add_del_output_feature_reply                 | definition changed
nat44_interface_addr_details                                 | definition changed
nat44_interface_addr_dump                                    | definition changed
nat44_interface_details                                      | definition changed
nat44_interface_dump                                         | definition changed
nat44_interface_output_feature_details                       | definition changed
nat44_interface_output_feature_dump                          | definition changed
nat44_lb_static_mapping_details                              | definition changed
nat44_lb_static_mapping_dump                                 | definition changed
nat44_static_mapping_details                                 | definition changed
nat44_static_mapping_dump                                    | definition changed
nat44_user_details                                           | definition changed
nat44_user_dump                                              | definition changed
nat44_user_session_details                                   | definition changed
nat44_user_session_dump                                      | definition changed
nat64_add_del_interface_addr                                 | definition changed
nat64_add_del_interface_addr_reply                           | definition changed
nat64_add_del_interface                                      | definition changed
nat64_add_del_interface_reply                                | definition changed
nat64_add_del_pool_addr_range                                | definition changed
nat64_add_del_pool_addr_range_reply                          | definition changed
nat64_add_del_prefix                                         | definition changed
nat64_add_del_prefix_reply                                   | definition changed
nat64_add_del_static_bib                                     | definition changed
nat64_add_del_static_bib_reply                               | definition changed
nat64_bib_details                                            | definition changed
nat64_bib_dump                                               | definition changed
nat64_get_timeouts                                           | definition changed
nat64_get_timeouts_reply                                     | definition changed
nat64_interface_details                                      | definition changed
nat64_interface_dump                                         | definition changed
nat64_pool_addr_details                                      | definition changed
nat64_pool_addr_dump                                         | definition changed
nat64_prefix_details                                         | definition changed
nat64_prefix_dump                                            | definition changed
nat64_set_timeouts                                           | definition changed
nat64_set_timeouts_reply                                     | definition changed
nat64_st_details                                             | definition changed
nat64_st_dump                                                | definition changed
nat66_add_del_interface                                      | definition changed
nat66_add_del_static_mapping                                 | definition changed
nat66_interface_details                                      | only in image
nat66_interface_dump                                         | only in image
nat66_static_mapping_details                                 | only in image
nat66_static_mapping_dump                                    | only in image
nat_control_ping                                             | definition changed
nat_control_ping_reply                                       | definition changed
nat_det_add_del_map                                          | definition changed
nat_det_add_del_map_reply                                    | definition changed
nat_det_close_session_in                                     | definition changed
nat_det_close_session_in_reply                               | definition changed
nat_det_close_session_out                                    | definition changed
nat_det_close_session_out_reply                              | definition changed
nat_det_forward                                              | definition changed
nat_det_forward_reply                                        | definition changed
nat_det_get_timeouts                                         | definition changed
nat_det_get_timeouts_reply                                   | definition changed
nat_det_map_details                                          | definition changed
nat_det_map_dump                                             | definition changed
nat_det_reverse                                              | definition changed
nat_det_reverse_reply                                        | definition changed
nat_det_session_details                                      | definition changed
nat_det_session_dump                                         | definition changed
nat_det_set_timeouts                                         | definition changed
nat_det_set_timeouts_reply                                   | definition changed
nat_get_reass                                                | definition changed
nat_get_reass_reply                                          | definition changed
nat_ipfix_enable_disable                                     | definition changed
nat_ipfix_enable_disable_reply                               | definition changed
nat_reass_details                                            | definition changed
nat_reass_dump                                               | definition changed
nat_set_reass                                                | definition changed
nat_set_reass_reply                                          | definition changed
nat_set_workers                                              | definition changed
nat_set_workers_reply                                        | definition changed
nat_show_config                                              | definition changed
nat_show_config_reply                                        | definition changed
nat_worker_details                                           | definition changed
nat_worker_dump                                              | definition changed
netmap_create                                                | definition changed
netmap_create_reply                                          | definition changed
netmap_delete                                                | definition changed
netmap_delete_reply                                          | definition changed
oam_add_del                                                  | definition changed
oam_add_del_reply                                            | definition changed
oam_event                                                    | definition changed
one_add_del_adjacency                                        | definition changed
one_add_del_adjacency_reply                                  | definition changed
one_add_del_l2_arp_entry                                     | definition changed
one_add_del_l2_arp_entry_reply                               | definition changed
one_add_del_local_eid                                        | definition changed
one_add_del_local_eid_reply                                  | definition changed
one_add_del_locator                                          | definition changed
one_add_del_locator_reply                                    | definition changed
one_add_del_locator_set                                      | definition changed
one_add_del_locator_set_reply                                | definition changed
one_add_del_map_request_itr_rlocs                            | definition changed
one_add_del_map_request_itr_rlocs_reply                      | definition changed
one_add_del_map_resolver                                     | definition changed
one_add_del_map_resolver_reply                               | definition changed
one_add_del_map_server                                       | definition changed
one_add_del_map_server_reply                                 | definition changed
one_add_del_ndp_entry                                        | definition changed
one_add_del_ndp_entry_reply                                  | definition changed
one_add_del_remote_mapping                                   | definition changed
one_add_del_remote_mapping_reply                             | definition changed
one_adjacencies_get                                          | definition changed
one_adjacencies_get_reply                                    | definition changed
one_eid_table_add_del_map                                    | definition changed
one_eid_table_add_del_map_reply                              | definition changed
one_eid_table_details                                        | definition changed
one_eid_table_dump                                           | definition changed
one_eid_table_map_details                                    | definition changed
one_eid_table_map_dump                                       | definition changed
one_eid_table_vni_details                                    | definition changed
one_eid_table_vni_dump                                       | definition changed
one_enable_disable                                           | definition changed
one_enable_disable_petr_mode                                 | definition changed
one_enable_disable_petr_mode_reply                           | definition changed
one_enable_disable_pitr_mode                                 | definition changed
one_enable_disable_pitr_mode_reply                           | definition changed
one_enable_disable_reply                                     | definition changed
one_enable_disable_xtr_mode                                  | definition changed
one_enable_disable_xtr_mode_reply                            | definition changed
one_get_map_request_itr_rlocs                                | definition changed
one_get_map_request_itr_rlocs_reply                          | definition changed
one_get_transport_protocol                                   | definition changed
one_get_transport_protocol_reply                             | definition changed
one_l2_arp_bd_get                                            | definition changed
one_l2_arp_bd_get_reply                                      | definition changed
one_l2_arp_entries_get                                       | definition changed
one_l2_arp_entries_get_reply                                 | definition changed
one_locator_details                                          | definition changed
one_locator_dump                                             | definition changed
one_locator_set_details                                      | definition changed
one_locator_set_dump                                         | definition changed
one_map_register_enable_disable                              | definition changed
one_map_register_enable_disable_reply                        | definition changed
one_map_register_fallback_threshold                          | definition changed
one_map_register_fallback_threshold_reply                    | definition changed
one_map_register_set_ttl                                     | definition changed
one_map_register_set_ttl_reply                               | definition changed
one_map_request_mode                                         | definition changed
one_map_request_mode_reply                                   | definition changed
one_map_resolver_details                                     | definition changed
one_map_resolver_dump                                        | definition changed
one_map_server_details                                       | definition changed
one_map_server_dump                                          | definition changed
one_ndp_bd_get                                               | definition changed
one_ndp_bd_get_reply                                         | definition changed
one_ndp_entries_get                                          | definition changed
one_ndp_entries_get_reply                                    | definition changed
one_nsh_set_locator_set                                      | definition changed
one_nsh_set_locator_set_reply                                | definition changed
one_pitr_set_locator_set                                     | definition changed
one_pitr_set_locator_set_reply                               | definition changed
one_rloc_probe_enable_disable                                | definition changed
one_rloc_probe_enable_disable_reply                          | definition changed
one_set_transport_protocol                                   | definition changed
one_set_transport_protocol_reply                             | definition changed
one_show_petr_mode                                           | definition changed
one_show_petr_mode_reply                                     | definition changed
one_show_pitr_mode                                           | definition changed
one_show_pitr_mode_reply                                     | definition changed
one_show_xtr_mode                                            | definition changed
one_show_xtr_mode_reply                                      | definition changed
one_stats_details                                            | definition changed
one_stats_dump                                               | definition changed
one_stats_enable_disable                                     | definition changed
one_stats_enable_disable_reply                               | definition changed
one_stats_flush                                              | definition changed
one_stats_flush_reply                                        | definition changed
one_use_petr                                                 | definition changed
one_use_petr_reply                                           | definition changed
output_acl_set_interface                                     | definition changed
p2p_ethernet_add                                             | definition changed
p2p_ethernet_add_reply                                       | definition changed
p2p_ethernet_del                                             | definition changed
p2p_ethernet_del_reply                                       | definition changed
pg_capture                                                   | definition changed
pg_capture_reply                                             | definition changed
pg_create_interface                                          | definition changed
pg_create_interface_reply                                    | definition changed
pg_enable_disable                                            | definition changed
pg_enable_disable_reply                                      | definition changed
policer_add_del                                              | definition changed
policer_add_del_reply                                        | definition changed
policer_classify_details                                     | definition changed
policer_classify_dump                                        | definition changed
policer_classify_set_interface                               | definition changed
policer_classify_set_interface_reply                         | definition changed
policer_details                                              | definition changed
policer_dump                                                 | definition changed
pot_profile_activate                                         | definition changed
pot_profile_activate_reply                                   | definition changed
pot_profile_add                                              | definition changed
pot_profile_add_reply                                        | definition changed
pot_profile_del                                              | definition changed
pot_profile_del_reply                                        | definition changed
pot_profile_show_config_details                              | definition changed
pot_profile_show_config_dump                                 | definition changed
pppoe_add_del_session                                        | definition changed
pppoe_add_del_session_reply                                  | definition changed
pppoe_session_details                                        | definition changed
pppoe_session_dump                                           | definition changed
proxy_arp_add_del                                            | definition changed
proxy_arp_add_del_reply                                      | definition changed
proxy_arp_intfc_enable_disable                               | definition changed
proxy_arp_intfc_enable_disable_reply                         | definition changed
punt                                                         | definition changed
punt_reply                                                   | definition changed
punt_socket_deregister                                       | definition changed
punt_socket_deregister_reply                                 | definition changed
punt_socket_register                                         | definition changed
punt_socket_register_reply                                   | definition changed
qos_egress_map_delete                                        | definition changed
qos_egress_map_update                                        | definition changed
qos_mark_enable_disable                                      | definition changed
qos_record_enable_disable                                    | definition changed
reset_fib                                                    | definition changed
reset_fib_reply                                              | definition changed
reset_session                                                | definition changed
reset_session_reply                                          | definition changed
rpc_call                                                     | definition changed
rpc_call_reply                                               | definition changed
rx_thread_exit                                               | definition changed
sctp_add_src_dst_connection                                  | definition changed
sctp_config                                                  | definition changed
sctp_del_src_dst_connection                                  | definition changed
session_enable_disable                                       | definition changed
session_enable_disable_reply                                 | definition changed
session_rule_add_del                                         | definition changed
session_rule_add_del_reply                                   | definition changed
session_rules_details                                        | definition changed
session_rules_dump                                           | definition changed
set_arp_neighbor_limit                                       | definition changed
set_arp_neighbor_limit_reply                                 | definition changed
set_ip_flow_hash                                             | definition changed
set_ip_flow_hash_reply                                       | definition changed
set_ipfix_classify_stream                                    | definition changed
set_ipfix_classify_stream_reply                              | definition changed
set_ipfix_exporter                                           | definition changed
set_ipfix_exporter_reply                                     | definition changed
show_lisp_map_register_state                                 | definition changed
show_lisp_map_register_state_reply                           | definition changed
show_lisp_map_request_mode                                   | definition changed
show_lisp_map_request_mode_reply                             | definition changed
show_lisp_pitr                                               | definition changed
show_lisp_pitr_reply                                         | definition changed
show_lisp_rloc_probe_state                                   | definition changed
show_lisp_rloc_probe_state_reply                             | definition changed
show_lisp_status                                             | definition changed
show_lisp_status_reply                                       | definition changed
show_lisp_use_petr                                           | definition changed
show_lisp_use_petr_reply                                     | definition changed
show_one_map_register_fallback_threshold                     | definition changed
show_one_map_register_fallback_threshold_reply               | definition changed
show_one_map_register_state                                  | definition changed
show_one_map_register_state_reply                            | definition changed
show_one_map_register_ttl                                    | definition changed
show_one_map_register_ttl_reply                              | definition changed
show_one_map_request_mode                                    | definition changed
show_one_map_request_mode_reply                              | definition changed
show_one_nsh_mapping                                         | definition changed
show_one_nsh_mapping_reply                                   | definition changed
show_one_pitr                                                | definition changed
show_one_pitr_reply                                          | definition changed
show_one_rloc_probe_state                                    | definition changed
show_one_rloc_probe_state_reply                              | definition changed
show_one_stats_enable_disable                                | definition changed
show_one_stats_enable_disable_reply                          | definition changed
show_one_status                                              | definition changed
show_one_status_reply                                        | definition changed
show_one_use_petr                                            | definition changed
show_one_use_petr_reply                                      | definition changed
show_version                                                 | definition changed
show_version_reply                                           | definition changed
sock_init_shm                                                | definition changed
sockclnt_create                                              | definition changed
sockclnt_create_reply                                        | definition changed
sockclnt_delete                                              | definition changed
sockclnt_delete_reply                                        | definition changed
sr_localsid_add_del                                          | definition changed
sr_localsid_add_del_reply                                    | definition changed
sr_localsids_details                                         | definition changed
sr_localsids_dump                                            | definition changed
sr_mpls_policy_add                                           | definition changed
sr_mpls_policy_add_reply                                     | definition changed
sr_mpls_policy_assign_endpoint_color                         | definition changed
sr_mpls_policy_assign_endpoint_color_reply                   | definition changed
sr_mpls_policy_del                                           | definition changed
sr_mpls_policy_del_reply                                     | definition changed
sr_mpls_policy_mod                                           | definition changed
sr_mpls_policy_mod_reply                                     | definition changed
sr_mpls_steering_add_del                                     | definition changed
sr_mpls_steering_add_del_reply                               | definition changed
sr_policy_add                                                | definition changed
sr_policy_add_reply                                          | definition changed
sr_policy_del                                                | definition changed
sr_policy_del_reply                                          | definition changed
sr_policy_mod                                                | definition changed
sr_policy_mod_reply                                          | definition changed
sr_set_encap_source                                          | definition changed
sr_set_encap_source_reply                                    | definition changed
sr_steering_add_del                                          | definition changed
sr_steering_add_del_reply                                    | definition changed
stats_get_poller_delay                                       | definition changed
stn_add_del_rule                                             | definition changed
stn_add_del_rule_reply                                       | definition changed
stn_rule_details                                             | only in file
stn_rules_details                                            | only in image
stn_rules_dump                                               | definition changed
sw_if_l2tpv3_tunnel_details                                  | definition changed
sw_if_l2tpv3_tunnel_dump                                     | definition changed
sw_interface_add_del_address                                 | definition changed
sw_interface_add_del_address_reply                           | definition changed
sw_interface_bond_details                                    | only in image
sw_interface_bond_dump                                       | only in image
sw_interface_clear_stats                                     | definition changed
sw_interface_clear_stats_reply                               | definition changed
sw_interface_details                                         | definition changed
sw_interface_dump                                            | definition changed
sw_interface_event                                           | definition changed
sw_interface_get_mac_address                                 | definition changed
sw_interface_get_table                                       | definition changed
sw_interface_get_table_reply                                 | definition changed
sw_interface_ip6_enable_disable                              | definition changed
sw_interface_ip6_enable_disable_reply                        | definition changed
sw_interface_ip6_set_link_local_address                      | definition changed
sw_interface_ip6_set_link_local_address_reply                | definition changed
sw_interface_ip6nd_ra_config                                 | definition changed
sw_interface_ip6nd_ra_config_reply                           | definition changed
sw_interface_ip6nd_ra_prefix                                 | definition changed
sw_interface_ip6nd_ra_prefix_reply                           | definition changed
sw_interface_lacp_details                                    | only in image
sw_interface_lacp_dump                                       | only in image
sw_interface_set_dpdk_hqos_pipe                              | definition changed
sw_interface_set_dpdk_hqos_pipe_reply                        | definition changed
sw_interface_set_dpdk_hqos_subport                           | definition changed
sw_interface_set_dpdk_hqos_subport_reply                     | definition changed
sw_interface_set_dpdk_hqos_tctbl                             | definition changed
sw_interface_set_dpdk_hqos_tctbl_reply                       | definition changed
sw_interface_set_flags                                       | definition changed
sw_interface_set_flags_reply                                 | definition changed
sw_interface_set_geneve_bypass                               | definition changed
sw_interface_set_geneve_bypass_reply                         | definition changed
sw_interface_set_gtpu_bypass                                 | definition changed
sw_interface_set_gtpu_bypass_reply                           | definition changed
sw_interface_set_l2_bridge                                   | definition changed
sw_interface_set_l2_bridge_reply                             | definition changed
sw_interface_set_l2_xconnect                                 | definition changed
sw_interface_set_l2_xconnect_reply                           | definition changed
sw_interface_set_lldp                                        | definition changed
sw_interface_set_lldp_reply                                  | definition changed
sw_interface_set_mac_address                                 | definition changed
sw_interface_set_mac_address_reply                           | definition changed
sw_interface_set_mpls_enable                                 | definition changed
sw_interface_set_mpls_enable_reply                           | definition changed
sw_interface_set_mtu                                         | definition changed
sw_interface_set_mtu_reply                                   | definition changed
sw_interface_set_rx_mode                                     | definition changed
sw_interface_set_rx_mode_reply                               | definition changed
sw_interface_set_table                                       | definition changed
sw_interface_set_table_reply                                 | definition changed
sw_interface_set_unnumbered                                  | definition changed
sw_interface_set_unnumbered_reply                            | definition changed
sw_interface_set_vpath                                       | definition changed
sw_interface_set_vpath_reply                                 | definition changed
sw_interface_set_vxlan_bypass                                | definition changed
sw_interface_set_vxlan_bypass_reply                          | definition changed
sw_interface_set_vxlan_gpe_bypass                            | definition changed
sw_interface_set_vxlan_gpe_bypass_reply                      | definition changed
sw_interface_slave_details                                   | only in image
sw_interface_slave_dump                                      | only in image
sw_interface_span_details                                    | definition changed
sw_interface_span_dump                                       | definition changed
sw_interface_span_enable_disable                             | definition changed
sw_interface_span_enable_disable_reply                       | definition changed
sw_interface_tag_add_del                                     | definition changed
sw_interface_tag_add_del_reply                               | definition changed
sw_interface_tap_details                                     | definition changed
sw_interface_tap_dump                                        | definition changed
sw_interface_tap_v2_details                                  | definition changed
sw_interface_tap_v2_dump                                     | definition changed
sw_interface_vhost_user_details                              | definition changed
sw_interface_vhost_user_dump                                 | definition changed
tap_connect                                                  | definition changed
tap_connect_reply                                            | definition changed
tap_create_v2                                                | definition changed
tap_create_v2_reply                                          | definition changed
tap_delete                                                   | definition changed
tap_delete_reply                                             | definition changed
tap_delete_v2                                                | definition changed
tap_delete_v2_reply                                          | definition changed
tap_modify                                                   | definition changed
tap_modify_reply                                             | definition changed
tcp_configure_src_addresses                                  | definition changed
tcp_configure_src_addresses_reply                            | definition changed
trace_plugin_msg_ids                                         | definition changed
trace_profile_add                                            | definition changed
trace_profile_add_reply                                      | definition changed
trace_profile_del                                            | definition changed
trace_profile_del_reply                                      | definition changed
trace_profile_show_config                                    | definition changed
trace_profile_show_config_reply                              | definition changed
udp_encap_add_del                                            | definition changed
udp_encap_add_del_reply                                      | definition changed
udp_encap_details                                            | definition changed
udp_encap_dump                                               | definition changed
udp_ping_add_del                                             | definition changed
udp_ping_add_del_reply                                       | only in image
udp_ping_add_del_req                                         | only in file
udp_ping_export                                              | definition changed
udp_ping_export_reply                                        | only in image
udp_ping_export_req                                          | only in file
unbind_sock                                                  | definition changed
unbind_sock_reply                                            | definition changed
unbind_uri                                                   | definition changed
unbind_uri_reply                                             | definition changed
unmap_segment                                                | definition changed
vnet_get_summary_stats                                       | definition changed
vnet_get_summary_stats_reply                                 | definition changed
vnet_interface_combined_counters                             | definition changed
vnet_interface_simple_counters                               | definition changed
vnet_ip4_fib_counters                                        | definition changed
vnet_ip4_mfib_counters                                       | definition changed
vnet_ip4_nbr_counters                                        | definition changed
vnet_ip6_fib_counters                                        | definition changed
vnet_ip6_mfib_counters                                       | definition changed
vnet_ip6_nbr_counters                                        | definition changed
vnet_per_interface_combined_counters                         | definition changed
vnet_per_interface_simple_counters                           | definition changed
vnet_udp_encap_counters                                      | only in image
vxlan_add_del_tunnel                                         | definition changed
vxlan_add_del_tunnel_reply                                   | definition changed
vxlan_gpe_add_del_tunnel                                     | definition changed
vxlan_gpe_add_del_tunnel_reply                               | definition changed
vxlan_gpe_ioam_disable                                       | definition changed
vxlan_gpe_ioam_disable_reply                                 | definition changed
vxlan_gpe_ioam_enable                                        | definition changed
vxlan_gpe_ioam_enable_reply                                  | definition changed
vxlan_gpe_ioam_export_enable_disable                         | definition changed
vxlan_gpe_ioam_export_enable_disable_reply                   | definition changed
vxlan_gpe_ioam_transit_disable                               | definition changed
vxlan_gpe_ioam_transit_disable_reply                         | definition changed
vxlan_gpe_ioam_transit_enable                                | definition changed
vxlan_gpe_ioam_transit_enable_reply                          | definition changed
vxlan_gpe_ioam_vni_disable                                   | definition changed
vxlan_gpe_ioam_vni_disable_reply                             | definition changed
vxlan_gpe_ioam_vni_enable                                    | definition changed
vxlan_gpe_ioam_vni_enable_reply                              | definition changed
vxlan_gpe_tunnel_details                                     | definition changed
vxlan_gpe_tunnel_dump                                        | definition changed
vxlan_tunnel_details                                         | definition changed
vxlan_tunnel_dump                                            | definition changed
want_bfd_events                                              | definition changed
want_bfd_events_reply                                        | definition changed
want_igmp_events                                             | definition changed
want_interface_combined_stats                                | definition changed
want_interface_combined_stats_reply                          | definition changed
want_interface_events                                        | definition changed
want_interface_events_reply                                  | definition changed
want_interface_simple_stats                                  | definition changed
want_interface_simple_stats_reply                            | definition changed
want_ip4_arp_events                                          | definition changed
want_ip4_arp_events_reply                                    | definition changed
want_ip4_fib_stats                                           | definition changed
want_ip4_fib_stats_reply                                     | definition changed
want_ip4_mfib_stats                                          | definition changed
want_ip4_mfib_stats_reply                                    | definition changed
want_ip4_nbr_stats                                           | definition changed
want_ip4_nbr_stats_reply                                     | definition changed
want_ip6_fib_stats                                           | definition changed
want_ip6_fib_stats_reply                                     | definition changed
want_ip6_mfib_stats                                          | definition changed
want_ip6_mfib_stats_reply                                    | definition changed
want_ip6_nbr_stats                                           | definition changed
want_ip6_nbr_stats_reply                                     | definition changed
want_ip6_nd_events                                           | definition changed
want_ip6_nd_events_reply                                     | definition changed
want_ip6_ra_events                                           | definition changed
want_l2_macs_events                                          | definition changed
want_l2_macs_events_reply                                    | definition changed
want_oam_events                                              | definition changed
want_oam_events_reply                                        | definition changed
want_per_interface_combined_stats                            | definition changed
want_per_interface_combined_stats_reply                      | definition changed
want_per_interface_simple_stats                              | definition changed
want_per_interface_simple_stats_reply                        | definition changed
want_stats                                                   | definition changed
want_stats_reply                                             | definition changed
want_udp_encap_stats                                         | definition changed

Found 1036 api message signature differences

### Patches that changed API definitions

| @c src/vpp/stats/stats.api ||
| ------- | ------- |
| [43b1f44](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=43b1f44) | UDP Encap counters |
| [ff92efe](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=ff92efe) | stats: allow configuring poller delay |
| [51e5968](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=51e5968) | API: Add service definitions for events and singleton messages (second attempt) |
| [2de1f15](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=2de1f15) | Revert "API: Add service definitions for events and singleton messages." |
| [f7b7fa5](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f7b7fa5) | API: Add service definitions for events and singleton messages. |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vpp/oam/oam.api ||
| ------- | ------- |
| [51e5968](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=51e5968) | API: Add service definitions for events and singleton messages (second attempt) |
| [2de1f15](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=2de1f15) | Revert "API: Add service definitions for events and singleton messages." |
| [f7b7fa5](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f7b7fa5) | API: Add service definitions for events and singleton messages. |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vpp/api/vpe.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vnet/interface.api ||
| ------- | ------- |
| [0cae3f7](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=0cae3f7) | Detailed Interface stats API takes sw_if_index |
| [6f4a6be](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=6f4a6be) | Interface Unicast, Multicast and Broadcast stats on the API |
| [c037423](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c037423) | IPv6 ND Router discovery control plane (VPP-1095) |
| [51e5968](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=51e5968) | API: Add service definitions for events and singleton messages (second attempt) |
| [2de1f15](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=2de1f15) | Revert "API: Add service definitions for events and singleton messages." |
| [f7b7fa5](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f7b7fa5) | API: Add service definitions for events and singleton messages. |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vnet/unix/tap.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vnet/qos/qos.api ||
| ------- | ------- |
| [039cbfe](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=039cbfe) | QoS recording and marking |

| @c src/vnet/policer/policer.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vnet/mpls/mpls.api ||
| ------- | ------- |
| [31ed744](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=31ed744) | MPLS Unifom mode |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vnet/span/span.api ||
| ------- | ------- |
| [179ab36](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=179ab36) | SPAN: Add "is_l2" flag to DETAILS response messages. |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vnet/vxlan-gpe/vxlan_gpe.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vnet/l2tp/l2tp.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vnet/lldp/lldp.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vnet/srmpls/sr_mpls.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vnet/cop/cop.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vnet/feature/feature.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vnet/ipsec-gre/ipsec_gre.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vnet/geneve/geneve.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vnet/lisp-gpe/lisp_gpe.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vnet/map/map.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |
| [e31d956](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e31d956) | MAP: Add RFC6052 mapping to MAP-T |

| @c src/vnet/lisp-cp/lisp.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vnet/lisp-cp/one.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vnet/tcp/tcp.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vnet/dhcp/dhcp.api ||
| ------- | ------- |
| [51e5968](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=51e5968) | API: Add service definitions for events and singleton messages (second attempt) |
| [2de1f15](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=2de1f15) | Revert "API: Add service definitions for events and singleton messages." |
| [f7b7fa5](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f7b7fa5) | API: Add service definitions for events and singleton messages. |
| [54c6dc4](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=54c6dc4) | For DHCP client configuration control the setting of the broadcast flag in the DISCOVER message sent. |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vnet/gre/gre.api ||
| ------- | ------- |
| [a43ccae](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=a43ccae) | Optimize GRE Tunnel and add support for ERSPAN encap |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vnet/flow/flow.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vnet/devices/virtio/vhost_user.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vnet/devices/af_packet/af_packet.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vnet/devices/tap/tapv2.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |
| [7866c45](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=7866c45) | tapv2: add option to set host-side default gw |

| @c src/vnet/devices/netmap/netmap.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vnet/dns/dns.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vnet/bonding/bond.api ||
| ------- | ------- |
| [9cd2d7a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9cd2d7a) | bond: Add bonding driver and LACP protocol |

| @c src/vnet/session/session.api ||
| ------- | ------- |
| [8f89dd0](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=8f89dd0) | tls: enforce certificate verification |
| [371ca50](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=371ca50) | session: first approximation implementation of tls |
| [f8f516a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f8f516a) | session: support local sessions and deprecate redirects |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vnet/ethernet/p2p_ethernet.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vnet/ip/rd_cp.api ||
| ------- | ------- |
| [c037423](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c037423) | IPv6 ND Router discovery control plane (VPP-1095) |

| @c src/vnet/ip/punt.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vnet/ip/ip.api ||
| ------- | ------- |
| [4c53313](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=4c53313) | reassembly: feature/concurrency |
| [4b9669d](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=4b9669d) | IPv6 ND Router discovery data plane (VPP-1095) |
| [31ed744](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=31ed744) | MPLS Unifom mode |
| [51e5968](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=51e5968) | API: Add service definitions for events and singleton messages (second attempt) |
| [2de1f15](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=2de1f15) | Revert "API: Add service definitions for events and singleton messages." |
| [f7b7fa5](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f7b7fa5) | API: Add service definitions for events and singleton messages. |
| [75e7d13](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=75e7d13) | IPv4/6 reassembly |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |
| [f068c3e](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f068c3e) | DVR: run L3 output features |

| @c src/vnet/classify/classify.api ||
| ------- | ------- |
| [815d7d5](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=815d7d5) | classifier-based ACL: refactor + add output ACL |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vnet/ipip/ipip.api ||
| ------- | ------- |
| [298c695](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=298c695) | IPIP: Add IP{v4,v6} over IP{v4,v6} configured tunnel support. |

| @c src/vnet/udp/udp.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vnet/bfd/bfd.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vnet/srv6/sr.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vnet/ipsec/ipsec.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vnet/bier/bier.api ||
| ------- | ------- |
| [31ed744](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=31ed744) | MPLS Unifom mode |
| [f051072](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f051072) | BIER: fix support for longer bit-string lengths |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vnet/sctp/sctp.api ||
| ------- | ------- |
| [c7fe4f3](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c7fe4f3) | SCTP: API to configure some tunables |
| [465c087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=465c087) | SCTP: API to delete a sub-connection |
| [3c6a976](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=3c6a976) | SCTP: API to add a sub-connection |

| @c src/vnet/l2/l2.api ||
| ------- | ------- |
| [e23c99e](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e23c99e) | Improve l2_macs_events API to provide MAC move information |
| [51e5968](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=51e5968) | API: Add service definitions for events and singleton messages (second attempt) |
| [2de1f15](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=2de1f15) | Revert "API: Add service definitions for events and singleton messages." |
| [f7b7fa5](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f7b7fa5) | API: Add service definitions for events and singleton messages. |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vnet/vxlan/vxlan.api ||
| ------- | ------- |
| [31ed744](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=31ed744) | MPLS Unifom mode |
| [3d460bd](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=3d460bd) | VXLAN: Allow user to specify a custom vxlan tunnel instance id. |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vnet/fib/fib_types.api ||
| ------- | ------- |
| [2303cb1](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=2303cb1) | FIB Interpose Source |
| [8145842](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=8145842) | Common form of fib-path reproting in dumps |
| [31ed744](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=31ed744) | MPLS Unifom mode |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/vnet/pg/pg.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/examples/sample-plugin/sample/sample.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/plugins/lb/lb.api ||
| ------- | ------- |
| [647f609](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=647f609) | Add L3DSR feature in LB plugin |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/plugins/gtpu/gtpu.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/plugins/kubeproxy/kp.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/plugins/pppoe/pppoe.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/plugins/nat/nat.api ||
| ------- | ------- |
| [f2a23cc](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f2a23cc) | NAT66 1:1 mapping (VPP-1108) |
| [9dba781](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9dba781) | NAT44: nat44_static_mapping_details protocol=0 if addr_only=0 (VPP-1158) |
| [bc39e34](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=bc39e34) | NAT: add missing CLI and API documentation (VPP-1142) |
| [5f22499](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=5f22499) | NAT44: add opaque string tag to static mapping APIs (VPP-1147) |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |
| [e82488f](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=e82488f) | NAT44: asymmetrical static mapping rule (VPP-1135) |
| [240b5ef](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=240b5ef) | NAT44: asymmetrical load balancing static mapping rule (VPP-1132) |
| [c5c6a33](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c5c6a33) | Add basic support for DS-Lite CE (VPP-1059) |

| @c src/plugins/l2e/l2e.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/plugins/ioam/lib-pot/pot.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/plugins/ioam/ip6/ioam_cache.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/plugins/ioam/udp-ping/udp_ping.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |
| [149a143](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=149a143) | fix udp_ping api naming error |

| @c src/plugins/ioam/export/ioam_export.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/plugins/ioam/export-vxlan-gpe/vxlan_gpe_ioam_export.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/plugins/ioam/lib-vxlan-gpe/ioam_vxlan_gpe.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/plugins/ioam/lib-trace/trace.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/plugins/igmp/igmp.api ||
| ------- | ------- |
| [7b867a8](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=7b867a8) | IGMP plugin |

| @c src/plugins/memif/memif.api ||
| ------- | ------- |
| [30349b0](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=30349b0) | memif: Add new API calls to manage memif socket names. |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/plugins/lacp/lacp.api ||
| ------- | ------- |
| [9cd2d7a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9cd2d7a) | bond: Add bonding driver and LACP protocol |

| @c src/plugins/acl/acl.api ||
| ------- | ------- |
| [27fe75a](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=27fe75a) | acl-plugin: add the support for dumping the ethertype whitelist (VPP-1163) |
| [c43b3f9](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=c43b3f9) | acl-plugin: add whitelisted ethertype mode (VPP-1163) |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/plugins/flowprobe/flowprobe.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/plugins/dpdk/api/dpdk.api ||
| ------- | ------- |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/plugins/gbp/gbp.api ||
| ------- | ------- |
| [bc27d1b](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=bc27d1b) | GBP plugin |

| @c src/plugins/stn/stn.api ||
| ------- | ------- |
| [62bab65](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=62bab65) | STN: Fix stn_rules_dump/details to follow API convention |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |

| @c src/plugins/cdp/cdp.api ||
| ------- | ------- |
| [aaacfbc](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=aaacfbc) | Move the vnet cdp protocol implementation to a plugin |

| @c src/vlibmemory/memclnt.api ||
| ------- | ------- |
| [51e5968](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=51e5968) | API: Add service definitions for events and singleton messages (second attempt) |
| [2de1f15](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=2de1f15) | Revert "API: Add service definitions for events and singleton messages." |
| [f7b7fa5](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=f7b7fa5) | API: Add service definitions for events and singleton messages. |
| [9d42087](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=9d42087) | VPPAPIGEN: vppapigen replacement in Python PLY. |
| [90a6398](https://gerrit.fd.io/r/gitweb?p=vpp.git;a=commit;h=90a6398) | sock api: add infra for bootstrapping shm clients |



@page release_notes_18012 Release notes for VPP 18.01.2

This is bug fix release.

For the full list of fixed issues please refer to:
- fd.io [JIRA](https://jira.fd.io)
- git [commit log](https://git.fd.io/vpp/log/?h=stable/1801)


@page release_notes_18011 Release notes for VPP 18.01.1

This is bug fix release.

For the full list of fixed issues please reffer to:
- fd.io [JIRA](https://jira.fd.io)
- git [commit log](https://git.fd.io/vpp/log/?h=stable/1801)


@page release_notes_1801 Release notes for VPP 18.01

More than 560 commits since the 17.10 release.

## Features
- Infrastructure
  - DPDK 17.11
  - TCP Checksum Offload
  - Arm64/Arm-v8 support
  - SUSE packaging
  - bihash_vec8_8 variant
  - PCI rework to support VFIO
  - chi-squared test calculator
  
- SNAT / NAT
  - One armed NAT
  - Twice NAT44
  - NAT hairpinning rework
  - NAT64 multi-thread
  - NAT64 IPFIX
  - NAT64 Fragmentation
  - NAT: DS-Lite
  - Remove old SNAT API
  - ACL-based NAT

- VNET
  - DNS name resolver
  - BIER
  - GENEVE Tunnel
  - IPSec Openssl 1.1.0 api support
  - FIB improvements
  - tap v2
  
- API
  - VPP stats (Broadcast & Multicast support)
  - SR MPLS
  - VPP Object Model (VOM)
  
- Host Stack
  - VPP TCP Stack scale / congestion improvements
  - Refactor UDP
  - Namespace support
  - Session rules table
  - VPP Comms Library (VCL) improvements

- ACL
  - ACL stats

- Plugins
  - Kube-proxy
  - L2 Emulation
  - Memif

## Known issues

For the full list of issues please refer to fd.io [JIRA](https://jira.fd.io).

## Issues fixed

For the full list of fixed issues please refer to:
- fd.io [JIRA](https://jira.fd.io)
- git [commit log](https://git.fd.io/vpp/log/?h=stable/1801)

## API changes

Message Name                                                 | Result
-------------------------------------------------------------|-----------------
af_packet_set_l4_cksum_offload                               | definition changed
api_versions                                                 | definition changed
app_namespace_add_del                                        | definition changed
application_attach                                           | definition changed
bier_disp_entry_add_del                                      | definition changed
bier_disp_entry_details                                      | only in image
bier_disp_entry_dump                                         | only in image
bier_disp_table_add_del                                      | definition changed
bier_disp_table_details                                      | only in image
bier_disp_table_dump                                         | only in image
bier_imp_add                                                 | definition changed
bier_imp_del                                                 | definition changed
bier_imp_details                                             | only in image
bier_imp_dump                                                | only in image
bier_route_add_del                                           | definition changed
bier_route_details                                           | only in image
bier_route_dump                                              | only in image
bier_table_add_del                                           | definition changed
bier_table_details                                           | only in image
bier_table_dump                                              | only in image
bind_sock_reply                                              | definition changed
connect_session_reply                                        | definition changed
connect_sock                                                 | definition changed
connect_uri                                                  | definition changed
dhcp_proxy_details                                           | definition changed
dhcp_proxy_set_vss                                           | definition changed
dns_enable_disable                                           | definition changed
dns_name_server_add_del                                      | definition changed
dns_resolve_ip                                               | definition changed
dns_resolve_name                                             | definition changed
dslite_add_del_pool_addr_range                               | definition changed
dslite_set_aftr_addr                                         | definition changed
geneve_add_del_tunnel                                        | definition changed
geneve_tunnel_details                                        | only in image
geneve_tunnel_dump                                           | only in image
ip_add_del_route                                             | definition changed
ip_container_proxy_add_del                                   | definition changed
ip_mroute_add_del                                            | definition changed
ip_neighbor_details                                          | definition changed
ip_punt_police                                               | definition changed
ip_punt_redirect                                             | definition changed
ipsec_sa_details                                             | only in image
ipsec_sa_dump                                                | only in image
ipsec_sad_add_del_entry                                      | definition changed
ipsec_tunnel_if_set_key                                      | definition changed
ipsec_tunnel_if_set_sa                                       | definition changed
kp_add_del_pod                                               | definition changed
kp_add_del_vip                                               | definition changed
kp_conf                                                      | definition changed
l2_emulation                                                 | definition changed
l2_fib_table_details                                         | definition changed
l2fib_add_del                                                | definition changed
memclnt_keepalive                                            | definition changed
memfd_segment_create                                         | definition changed
mpls_ip_bind_unbind                                          | definition changed
mpls_route_add_del                                           | definition changed
nat44_add_del_address_range                                  | definition changed
nat44_add_del_identity_mapping                               | definition changed
nat44_add_del_interface_addr                                 | definition changed
nat44_add_del_lb_static_mapping                              | definition changed
nat44_add_del_static_mapping                                 | definition changed
nat44_address_details                                        | definition changed
nat44_del_session                                            | definition changed
nat44_forwarding_enable_disable                              | definition changed
nat44_forwarding_is_enabled                                  | definition changed
nat44_identity_mapping_details                               | only in image
nat44_identity_mapping_dump                                  | only in image
nat44_interface_addr_details                                 | definition changed
nat44_lb_static_mapping_details                              | definition changed
nat44_static_mapping_details                                 | definition changed
nat64_add_del_interface_addr                                 | definition changed
nat_get_reass                                                | definition changed
nat_reass_details                                            | only in image
nat_reass_dump                                               | only in image
nat_set_reass                                                | definition changed
reset_vrf                                                    | definition changed
session_rule_add_del                                         | definition changed
session_rules_details                                        | only in image
session_rules_dump                                           | only in image
snat_add_address_range                                       | definition changed
snat_add_del_interface_addr                                  | definition changed
snat_add_det_map                                             | definition changed
snat_add_static_mapping                                      | definition changed
snat_address_details                                         | only in file
snat_address_dump                                            | only in file
snat_control_ping                                            | definition changed
snat_det_close_session_in                                    | definition changed
snat_det_close_session_out                                   | definition changed
snat_det_forward                                             | definition changed
snat_det_get_timeouts                                        | definition changed
snat_det_map_details                                         | only in file
snat_det_map_dump                                            | only in file
snat_det_reverse                                             | definition changed
snat_det_session_details                                     | only in file
snat_det_session_dump                                        | only in file
snat_det_set_timeouts                                        | definition changed
snat_interface_add_del_feature                               | definition changed
snat_interface_add_del_output_feature                        | definition changed
snat_interface_addr_details                                  | only in file
snat_interface_addr_dump                                     | only in file
snat_interface_details                                       | only in file
snat_interface_dump                                          | only in file
snat_interface_output_feature_details                        | only in file
snat_interface_output_feature_dump                           | only in file
snat_ipfix_enable_disable                                    | definition changed
snat_set_workers                                             | definition changed
snat_show_config                                             | definition changed
snat_static_mapping_details                                  | only in file
snat_static_mapping_dump                                     | only in file
snat_user_details                                            | only in file
snat_user_dump                                               | only in file
snat_user_session_details                                    | only in file
snat_user_session_dump                                       | only in file
snat_worker_details                                          | only in file
snat_worker_dump                                             | only in file
sockclnt_create                                              | definition changed
sockclnt_delete                                              | definition changed
sr_localsids_details                                         | only in image
sr_localsids_dump                                            | only in image
sr_mpls_policy_add                                           | definition changed
sr_mpls_policy_assign_endpoint_color                         | definition changed
sr_mpls_policy_del                                           | definition changed
sr_mpls_policy_mod                                           | definition changed
sr_mpls_steering_add_del                                     | definition changed
sr_set_encap_source                                          | definition changed
stn_add_del_rule                                             | definition changed
stn_rule_details                                             | only in image
stn_rules_dump                                               | only in image
sw_interface_set_geneve_bypass                               | definition changed
sw_interface_set_lldp                                        | definition changed
sw_interface_set_rx_mode                                     | definition changed
sw_interface_tap_v2_details                                  | only in image
sw_interface_tap_v2_dump                                     | only in image
tap_create_v2                                                | definition changed
tap_delete_v2                                                | definition changed
udp_encap_add_del                                            | definition changed
udp_encap_details                                            | only in image
udp_encap_dump                                               | only in image
vnet_ip4_mfib_counters                                       | only in image
vnet_ip6_mfib_counters                                       | only in image
want_ip4_mfib_stats                                          | definition changed
want_ip6_mfib_stats                                          | definition changed

Found 142 api message signature differences

### Patches that changed API definitions

./src/examples/sample-plugin/sample/sample.api
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/vnet/interface.api
b8d4481a Break up vpe.api
ad8015be devices: Add binary API for set interface <interface> rx-mode
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/vnet/feature/feature.api
b8d4481a Break up vpe.api

./src/vnet/srv6/sr.api
1a5e301f SRv6 improvements to binary API
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/vnet/bier/bier.api
be302d72 BIER coverity fix in route downlaod
ceb4d05b BIER disposition default route
fa1da15c BIER: API documentation fixes.
9128637e BIER in non-MPLS netowrks
d792d9c0 BIER

./src/vnet/vxlan-gpe/vxlan_gpe.api
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/vnet/unix/tap.api
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/vnet/lldp/lldp.api
9a6fcef4 LLDP: Add Management Address TLV
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/vnet/dns/dns.api
d2080159 Add reverse DNS (ip to name) resolution
6545716c VPP-1027: DNS name resolver

./src/vnet/session/session.api
dcf55ce2 vppcom: improve listener session handling
6e8c6679 session: add app ns index to ns create api
c97a7398 session: add rule tags
6c36f53f session: add api to dump rules
1c710451 session: rules tables
ade70e45 session: return local transport endpoint in connect reply
cea194d8 session: add support for application namespacing
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/vnet/devices/af_packet/af_packet.api
92b0275a af_packet: invalid TCP/UDP offload checksum on RX node recalculation
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/vnet/devices/netmap/netmap.api
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/vnet/devices/tap/tapv2.api
73e7f427 tap_v2: include host-side parameters in the dump binary API
2df39094 tapv2: multiple improvements
c99b4cd1 tap_v2: move code to vnet/devices/tap

./src/vnet/devices/virtio/vhost_user.api
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/vnet/lisp-gpe/lisp_gpe.api
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/vnet/srmpls/sr_mpls.api
42998828 SR-MPLS: binary API and automated steering

./src/vnet/l2/l2.api
b8d4481a Break up vpe.api
57938f63 l2fib: MAC: Fix uint64 to u8 byte array
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/vnet/udp/udp.api
810086d8 UDP Encapsulation.

./src/vnet/policer/policer.api
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/vnet/bfd/bfd.api
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/vnet/geneve/geneve.api
556033a0 Add API versioning to GENEVE tunnel implementation.
b598f1d3 Initial GENEVE TUNNEL implementation and tests.

./src/vnet/gre/gre.api
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/vnet/map/map.api
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/vnet/flow/flow.api
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/vnet/pg/pg.api
b8d4481a Break up vpe.api

./src/vnet/dhcp/dhcp.api
70bfcaf4 Add Support of DHCP VSS Type 0 where VPN-ID is ASCII
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/vnet/ipsec/ipsec.api
ca514fda Allow IPsec interface to have SAs reset
75d85609 Add API call to set keys on IPsec tunnel intf
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps
28029530 Add API support to dump IPsec SAs

./src/vnet/mpls/mpls.api
c42fc05b Remove the unused 'create VRF if needed' API parameters
b8d4481a Break up vpe.api
d792d9c0 BIER
d0a59722 Revert "Enforce FIB table creation before use"
f9342023 Enforce FIB table creation before use
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/vnet/ethernet/p2p_ethernet.api
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/vnet/span/span.api
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/vnet/lisp-cp/lisp.api
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/vnet/lisp-cp/one.api
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/vnet/vxlan/vxlan.api
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/vnet/ipsec-gre/ipsec_gre.api
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/vnet/classify/classify.api
b8d4481a Break up vpe.api
8527f12b add classify session action set-sr-policy-index
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/vnet/ip/punt.api
b8d4481a Break up vpe.api

./src/vnet/ip/ip.api
c42fc05b Remove the unused 'create VRF if needed' API parameters
b8d4481a Break up vpe.api
af8dfbf6 Add sw_if_index to the ip_neighbor_details_t response.
d792d9c0 BIER
810086d8 UDP Encapsulation.
595992c5 ip: add container proxy api
0164a06d Remove unused 'not_last' parameter from ip_add_del_route
d0a59722 Revert "Enforce FIB table creation before use"
054c03ac Source Lookup progammable via API
f9342023 Enforce FIB table creation before use
d91c1dbd punt and drop features:  - new IPv4 and IPv6 feature arcs on the punt and drop nodes  - new features:    - redirect punted traffic to an interface and nexthop    - police punted traffic.
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps
6f631156 Distributed Virtual Router Support

./src/vnet/cop/cop.api
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/vnet/l2tp/l2tp.api
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/vpp/oam/oam.api
b8d4481a Break up vpe.api

./src/vpp/stats/stats.api
ff233898 Stats for Multicast FIB
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/vpp/api/vpe.api
b8d4481a Break up vpe.api
d792d9c0 BIER
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps
b598f1d3 Initial GENEVE TUNNEL implementation and tests.

./src/plugins/ioam/udp-ping/udp_ping.api
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/plugins/ioam/ip6/ioam_cache.api
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/plugins/ioam/lib-pot/pot.api
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/plugins/ioam/lib-trace/trace.api
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/plugins/ioam/export/ioam_export.api
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/plugins/ioam/export-vxlan-gpe/vxlan_gpe_ioam_export.api
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/plugins/ioam/lib-vxlan-gpe/ioam_vxlan_gpe.api
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/plugins/pppoe/pppoe.api
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/plugins/dpdk/api/dpdk.api
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/plugins/acl/acl.api
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/plugins/gtpu/gtpu.api
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/plugins/l2e/l2e.api
4ec38711 L2 emulation: remove usued ip-table-id from API
55d03788 L2 Emulation

./src/plugins/flowprobe/flowprobe.api
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/plugins/nat/nat.api
7b929793 Translate matching packets using NAT (VPP-1069)
b932d26e NAT: Twice NAT44 (VPP-969)
ab7a805f NAT44: identity NAT (VPP-1073)
c6fb36fc NAT: Remove old SNAT API (VPP-1070)
0938dcf1 NAT64 to use IPv4 address from interface (VPP-1051)
efcd1e9e SNAT: IP fragmentation (VPP-890)
8ebe6253 NAT: DS-Lite (VPP-1040)
5ba86f72 NAT: delete session API/CLI (VPP-1041)
36ea2d6d One armed NAT (VPP-1035)
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/plugins/memif/memif.api
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/plugins/kubeproxy/kp.api
c91f5024 Support kube-proxy data plane

./src/plugins/lb/lb.api
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps

./src/plugins/stn/stn.api
0906c5cf Plugin for IP-Address to Interface Punting

./src/vlibmemory/memclnt.api
0d056e5e vppapigen: support per-file (major,minor,patch) version stamps
59b2565c Repair vlib API socket server


@page release_notes_1710 Release notes for VPP 17.10

More than 400 commits since the 1707 release.

## Features
- Infrastructure
  - DPDK 17.08
  - IP reassembly
  - Bounded-index extensible hash bucket-level LRU cache
  - Templated timer wheel improvements

- API
  - C/C++ language binding
  - API stats

- Host stack
  - VPP TCP stack scale/congestion improvements
  - VPP Comms Library (VCL)
  - Overall performance, scale and hardening

- Network features
  - IPSec rework - utilize new FIB
  - VPLS and VPWS implementation

  - NAT
    - Renamed SNAT to NAT
    - Performance / Scale
    - Destination NAT44 with load-balancing
    - In2out translation as an output feature on the outside interface
    - Fullback to 3-tuple key for non TCP/UDP/ICMP sessions

  - Security Groups/ACLs
    - "Replace" semantics for adding a new MacIP acl
    - Test suite tests for MacIP ACLs

  - ONE-LISP
    - Map-server fallback support
    - Preemptive re-fetch of active mappings that are about to expire
    - ND termination

  - PPPoE
    - PPPoE Control Plane packet dispatch
    - PPPoE decapsulation
    - PPPoE encapsulation

## Known issues

For the full list of issues please refer to fd.io [JIRA](https://jira.fd.io).

## Issues fixed

For the full list of fixed issues please refer to:
- fd.io [JIRA](https://jira.fd.io)
- git [commit log](https://git.fd.io/vpp/log/?h=stable/1710)

## API changes

Message Name                         			     | Result
-------------------------------------------------------------|----------------
bridge_domain_add_del                                        | definition changed
bridge_domain_details                                        | definition changed
connect_session                                              | definition changed
connect_sock                                                 | definition changed
connect_sock_reply                                           | definition changed
connect_uri_reply                                            | definition changed
create_vhost_user_if                                         | definition changed
dhcp_client_config                                           | definition changed
ip4_arp_event                                                | definition changed
ip6_fib_details                                              | definition changed
ip6_nd_event                                                 | definition changed
ip_add_del_route                                             | definition changed
ip_fib_details                                               | definition changed
ip_table_add_del                                             | definition changed
l2_macs_event                                                | only in image
macip_acl_add_replace                                        | definition changed
macip_acl_interface_list_details                             | only in image
macip_acl_interface_list_dump                                | only in image
modify_vhost_user_if                                         | definition changed
mpls_fib_details                                             | definition changed
mpls_route_add_del                                           | definition changed
mpls_table_add_del                                           | definition changed
mpls_tunnel_add_del                                          | definition changed
nat44_add_del_address_range                                  | definition changed
nat44_add_del_interface_addr                                 | definition changed
nat44_add_del_lb_static_mapping                              | definition changed
nat44_add_del_static_mapping                                 | definition changed
nat44_address_details                                        | only in image
nat44_address_dump                                           | only in image
nat44_interface_add_del_feature                              | definition changed
nat44_interface_add_del_output_feature                       | definition changed
nat44_interface_addr_details                                 | only in image
nat44_interface_addr_dump                                    | only in image
nat44_interface_details                                      | only in image
nat44_interface_dump                                         | only in image
nat44_interface_output_feature_details                       | only in image
nat44_interface_output_feature_dump                          | only in image
nat44_lb_static_mapping_details                              | only in image
nat44_lb_static_mapping_dump                                 | only in image
nat44_static_mapping_details                                 | only in image
nat44_static_mapping_dump                                    | only in image
nat44_user_details                                           | only in image
nat44_user_dump                                              | only in image
nat44_user_session_details                                   | only in image
nat44_user_session_dump                                      | only in image
nat_control_ping                                             | definition changed
nat_det_add_del_map                                          | definition changed
nat_det_close_session_in                                     | definition changed
nat_det_close_session_out                                    | definition changed
nat_det_forward                                              | definition changed
nat_det_get_timeouts                                         | definition changed
nat_det_map_details                                          | only in image
nat_det_map_dump                                             | only in image
nat_det_reverse                                              | definition changed
nat_det_session_details                                      | only in image
nat_det_session_dump                                         | only in image
nat_det_set_timeouts                                         | definition changed
nat_ipfix_enable_disable                                     | definition changed
nat_set_workers                                              | definition changed
nat_show_config                                              | definition changed
nat_worker_details                                           | only in image
nat_worker_dump                                              | only in image
one_add_del_ndp_entry                                        | definition changed
one_enable_disable_petr_mode                                 | definition changed
one_enable_disable_pitr_mode                                 | definition changed
one_enable_disable_xtr_mode                                  | definition changed
one_get_transport_protocol                                   | definition changed
one_map_register_fallback_threshold                          | definition changed
one_map_register_set_ttl                                     | definition changed
one_ndp_bd_get                                               | definition changed
one_ndp_entries_get                                          | definition changed
one_set_transport_protocol                                   | definition changed
one_show_petr_mode                                           | definition changed
one_show_pitr_mode                                           | definition changed
one_show_xtr_mode                                            | definition changed
p2p_ethernet_add                                             | definition changed
pppoe_add_del_session                                        | definition changed
pppoe_session_details                                        | only in image
pppoe_session_dump                                           | only in image
punt_socket_deregister                                       | definition changed
punt_socket_register                                         | definition changed
show_one_map_register_fallback_threshold                     | definition changed
show_one_map_register_ttl                                    | definition changed
snat_interface_add_del_output_feature                        | definition changed
snat_interface_output_feature_details                        | only in image
snat_interface_output_feature_dump                           | only in image
sw_interface_event                                           | only in image
sw_interface_set_flags                                       | definition changed
sw_interface_span_dump                                       | definition changed
sw_interface_span_enable_disable                             | definition changed
sw_interface_vhost_user_details                              | definition changed
tcp_configure_src_addresses                                  | definition changed
vnet_per_interface_combined_counters                         | only in image
vnet_per_interface_simple_counters                           | only in image
want_interface_combined_stats                                | definition changed
want_interface_simple_stats                                  | definition changed
want_ip4_fib_stats                                           | definition changed
want_ip4_nbr_stats                                           | definition changed
want_ip6_fib_stats                                           | definition changed
want_ip6_nbr_stats                                           | definition changed
want_l2_macs_events                                          | definition changed
want_per_interface_combined_stats                            | definition changed
want_per_interface_simple_stats                              | definition changed

Found 103 api message signature differences

Patches that updated the API files:

./src/plugins/pppoe/pppoe.api
62f9cdd8 Add PPPoE Plugin

./src/plugins/acl/acl.api
c29940c5 ACL-plugin add "replace" semantics for adding a new MacIP acl
de9fbf43 MAC IP ACL interface list dump (as an alternative to the get/reply)

./src/plugins/nat/nat.api
704018cf NAT: Destination NAT44 with load-balancing (VPP-954)
2ba92e32 NAT: Rename snat plugin to nat (VPP-955)

./src/vnet/interface.api
831fb59f Stats refactor
d292ab1e No context in SW interface event
a07bd708 Dedicated SW Interface Event

./src/vnet/dhcp/dhcp.api
51822bf0 DHCP client option 61 "client_id"
4729b1ec DHCP complete event sends mask length

./src/vnet/lldp/lldp.api
99a0e60e Add API support for LLDP config/interface set

./src/vnet/lisp-cp/one.api
d630713d LISP: add neighbor discovery and CP protocol separation APIs
111a5cea LISP: Add APIs for enable/disable xTR/P-ITR/P-ETR modes
7048ff1e LISP: Map-server fallback feature
1e553a00 LISP: make TTL for map register messages configurable

./src/vnet/ethernet/p2p_ethernet.api
15ac81c1 P2P Ethernet

./src/vnet/mpls/mpls.api
2297af01 Add a name to the creation of an IP and MPLS table
28ab9cc1 FIB table add/delete API only
da78f957 L2 over MPLS
a0a908f1 FIB path weight incorrect in dump (VPP-922)
57b5860f FIB path preference

./src/vnet/session/session.api
33e002b1 Fix session connect api message handling.

./src/vnet/span/span.api
5b311202 SPAN/API:enable L2 dump
001fd406 SPAN:add l2 mirror

./src/vnet/devices/virtio/vhost_user.api
4ba75f54 vhost: Remove operation mode in the API

./src/vnet/vxlan-gpe/vxlan_gpe.api
04ffd0ad VPP crash on creating vxlan gpe interface. VPP-875

./src/vnet/tcp/tcp.api
3bbcfab1 TCP source address automation

./src/vnet/ip/ip.api
2297af01 Add a name to the creation of an IP and MPLS table
28ab9cc1 FIB table add/delete API only
57b5860f FIB path preference

./src/vnet/lisp-gpe/lisp_gpe.api
af3d9771 Remove unused retval from gpe_native_fwd_rpath type definition

./src/vnet/l2/l2.api
50570ece Update of free text tag patch for BD
48304141 Support for bridge domain free text tag
e531f4cb Increase default MAC learn limit and check it in learn-update path
8d00fff8 Add support for API client to receive L2 MAC events

./src/vpp/api/vpe.api
8a19f12a Allow individual stats API and introduce stats.api
4802632d Punt socket: Fix coverity error for pathname length mismatch between API and sun_path.
f7a55ad7 PUNT socket: External control plane processes connected via UNIX domain sockets.
75e2f2ac API:fix arp/ND event messages - remove context
99a0e60e Add API support for LLDP config/interface set

./src/vpp/stats/stats.api
831fb59f Stats refactor
8a19f12a Allow individual stats API and introduce stats.api


@page release_notes_1707 Release notes for VPP 17.07

More than 400 commits since the 1704 release.

## Features
- Infrastructure
  - make test; improved debuggability.
  - TAB auto-completion on the CLI
  - DPDK 17.05
  - python 3 support in test infra

- Host stack
  - Improved Linux TCP stack compatibility using IWL test suite (https://jira.fd.io/browse/VPP-720)
  - Improved loss recovery (RFC5681, RFC6582, RF6675)
  - Basic implementation of Eifel detection algorithm (RFC3522)
  - Basic support for buffer chains
  - Refactored session layer API
  - Overall performance, scale and hardening

- Interfaces
  - memif: IP mode, jumbo frames, multi queue
  - virtio-user support
  - vhost-usr; adaptive (poll/interupt) support.

- Network features
  - MPLS Multicast FIB

  - BFD FIB integration

  - NAT64 support

  - GRE over IPv6

  - Segement routing MPLS

  - IOAM configuration for SRv6 localsid

  - LISP
    - NSH support
    - native forward static routes
    - L2 ARP

  - ACL multi-core suuport

  - Flowprobe:
    - Add flowstartns, flowendns and tcpcontrolbits
    - Stateful flows and IPv6, L4 recording

  - GTP-U support

  - VXLAN GPE support for FIB2.0 and bypass.


## Known issues

For the full list of issues please reffer to fd.io [JIRA](https://jira.fd.io).

## Issues fixed

For the full list of fixed issues please reffer to:
- fd.io [JIRA](https://jira.fd.io)
- git [commit log](https://git.fd.io/vpp/log/?h=stable/1707)


@page release_notes_1704 Release notes for VPP 17.04

More than 500 commits since the 1701 release.

## Features
- Infrastructure
  - make test improvements
  - vnet: add device-input threadplacement infra
  - 64 bit per-thread counters
  - process restart cli
  - High performance timer wheels
  - Plugin infrastructure improvements
    - Support for .default_disabled, .version_required
  - Added MAINTAINERS file

- Host stack
  - TCP stack (experimental)
  - DHCPv4 / DHCPv6 relay multi-destination
  - DHCPv4 option 82
  - ND proxy
  - Attached hosts
  - Consolidated DHCPv4 and DHCPv6 implementation

- Interfaces
  - DPDK 17.02 (retire support for DPDK 16.07)
  - Add memif - packet memory interface for intra-host communication
  - vhost: support interrupt mode
  - DPDK as plugin (retired vpp_lite)
  - DPDPK input optimizations
  - Loopback interface allocation scheme

- Network features
  - IP Multicast FIB

  - Bridging
    - Learning on local interfaces
    - Flushing of MACs from the L2 FIB

  - SNAT
    - CGN (Deterministic and dynamic)
    - CGN configurable port allocation algorithm
    - ICMP support
    - Tentant VRF id for SNAT outside addresses
    - Session dump / User dump
    - Port allocation per protocol

  - Security groups
    - Routed interface support
    - L2+L3 unified processing node
    - Improve fragment handling

  - Segement routing v6
    - SR policies with weighted SID lists
    - Binding SID
    - SR steering policies
    - SR Local SIDs
    - Framework to expand local SIDs w/plugins
    - Documentation

  - IOAM
    - UDP Pinger w/path fault isolation
    - IOAM as type 2 metadata in NSH
    - IAOM raw IPFIX collector and analyzer
    - Anycast active server selection
    - Documentation
    - SRv6 Local SID
    - IP6 HBH header and SR header co-existence
    - Active probe

  - LISP
    - Statistics collection
    - Generalize encap for overlay transport (vxlan-gpe support)
    - Improve data plane speed

  - GPE
    - CLI
    - NSH added to encap/decap path
    - Renamed LISP GPE API to GPE

  - MPLS
    - Performance improvements (quad loop)

  - BFD
    - Command line interface
    - Echo function
    - Remote demand mode
    - SHA1 authentication

  - IPsec
    - IKEv2 initiator features

  - VXLAN
    - unify IP4/IP6 control plane handling

## API changes

- Python API: To avoid conflicts between VPP API messages names and
  the Python API binding function names, VPP API methods are put in a
  separate proxy object.
  https://gerrit.fd.io/r/#/c/5570/
  The api methods are now referenced as:
    vpp_handle = VPP(jsonfiles)
    vpp_handle.connect(...)
    vpp = vpp_handle.api
    vpp.show_version()
    vpp_handle.disconnect()

  For backwards compatibility VPP API methods are left in the main
  name space (VPP), but will be removed from 17.07.

  - Python API: Change from cPython to CFFI.

- create_loopback message to be replaced with create_loopback_instance
  create_loopback will be removed from 17.07.
  https://gerrit.fd.io/r/#/c/5572/

## Known issues

For the full list of issues please reffer to fd.io [JIRA](https://jira.fd.io).

## Issues fixed

For the full list of fixed issues please reffer to:
- fd.io [JIRA](https://jira.fd.io)
- git [commit log](https://git.fd.io/vpp/log/?h=stable/1704)


@page release_notes_17011 Release notes for VPP 17.01.1

This is bug fix release.

For the full list of fixed issues please reffer to:
- fd.io [JIRA](https://jira.fd.io)
- git [commit log](https://git.fd.io/vpp/log/?h=stable/1701)


@page release_notes_1701 Release notes for VPP 17.01

@note This release was for a while known as 16.12.

## Features

- [Integrated November 2016 DPDK release](http://www.dpdk.org/doc/guides/rel_notes/release_16_11.html)

- Complete rework of Forwarding Information Base (FIB)

- Performance Improvements
  - Improvements in DPDK input and output nodes
  - Improvements in L2 path
  - Improvmeents in IPv4 lookup node

- Feature Arcs Improvements
  - Consolidation of the code
  - New feature arcs
    - device-input
    - interface-output

- DPDK Cryptodev Support
  - Software and Hardware Crypto Support

- DPDK HQoS support

- Simple Port Analyzer (SPAN)

- Bidirectional Forwarding Detection
  - Basic implementation

- IPFIX Improvements

- L2 GRE over IPSec tunnels

- Link Layer Discovery Protocol (LLDP)

- Vhost-user Improvements
  - Performance Improvements
  - Multiqueue
  - Reconnect

- LISP Enhancements
  - Source/Dest control plane support
  - L2 over LISP and GRE
  - Map-Register/Map-Notify/RLOC-probing support
  - L2 API improvements, overall code hardening

- Plugins:
  - New: ACL
  - New: Flow per Packet
  - Improved: SNAT
    - Mutlithreading
    - Flow export

- Doxygen Enhancements

- Luajit API bindings

- API Refactoring
  - file split
  - message signatures

- Python and Scapy based unit testing infrastructure
  - Infrastructure
  - Various tests

- Packet Generator improvements

- TUN/TAP jumbo frames support

- Other various bug fixes and improvements

## Known issues

For the full list of issues please reffer to fd.io [JIRA](https://jira.fd.io).

## Issues fixed

For the full list of fixed issues please reffer to:
- fd.io [JIRA](https://jira.fd.io)
- git [commit log](https://git.fd.io/vpp/log/?h=stable/1701)


@page release_notes_1609 Release notes for VPP 16.09

## Features

- [Integrated July 2016 DPDK release](http://www.dpdk.org/doc/guides/rel_notes/release_16_07.html)
  - DPDK-vhost is depreciated pending a complete rework of the original integration and
    addressing of rx performance deltas.
  - Patches required for DPDK 16.07:
    - Correctly setting the Packet Type in the IGB, IXGBE and i40e drivers.
    - Correctly setting checksum in the i40e driver.
    - NXP DPAA2 PMD Driver.
    - rte_delay (yield) functionality.

- Add “in tree” plugins:
  - IPv6 ILA.
  - iOAM.
  - Load Balancer.
  - SNAT.

- High-performance (line-rate) “neutron like” L4 port-filtering.

- API refactoring - addressing some of the issues around JVPP bindings.
  - Accommodating plugins [(e.g. NSH_SFC)](https://wiki.fd.io/view/NSH_SFC)
  - Binding for [python](https://wiki.fd.io/view/VPP/Python_API)

- LISP
  - L2 LISP overlays
  -  Multitenancy
  - Multihoming
  - RTR mode
  - Map-resolver failover algorithm

- Support 64-bit vector lengths, huge shared-memory segments.

- Dynamic IP Feature ordering
  - IP Features can now specify features they appear before and after

- 16.09 Builds
  - Ubuntu 14.04 LTS - Trusty Tahr
  - Ubuntu 16.04 LTS - Xenial Xerus
  - CentOS 7
  - More information on [VPP wiki](https://wiki.fd.io/view/VPP/Installing_VPP_binaries_from_packages)

- Performance, characterize and document performance for this release
  [(more information on CSIT page)](https://wiki.fd.io/view/CSIT)

   - IPv4 and IPv6 Scale - performance tests.
     - Bidirectional 10k/100k/1M flows.
     - 64B,570B, 1518B,9000B packet sizes.
   - IPv6 iACL - performance
     - DUT1 and DUT2 are configured with IPv6 routing, two static IPv6 /64 routes and IPv6 iAcl
       security whitelist ingress /64 filter entries applied on links.
     - TG traffic profile contains two L3 flow-groups (flow-group per direction, 253 flows per
       flow-group) with all packets containing Ethernet header, IPv6 header and generated payload.
       MAC addresses are matching MAC addresses of the TG node interfaces.

   - L2XC VXLANoIPv4 - performance
     - DUT1 and DUT2 are configured with L2 cross-connect. VXLAN tunnels are configured between
       L2XCs on DUT1 and DUT2.
     - TG traffic profile contains two L3 flow-groups (flow-group per direction, 253 flows per
       flow-group) with all packets containing Ethernet header, IPv4 header with IP protocol=61
       and generated payload. MAC addresses are matching MAC addresses of the TG node interfaces.

- Documentation
  - Autogenerated CLI documentation.
  - Using doxygen to automate API/Node documentation.
  - [(available online)](https://docs.fd.io/vpp/16.09/)

- Resolved all static analysis issues found by Coverity
  - Beginning of 16.09 cycle: 505 issues.
  - Release: 0 outstanding issues.


## Known issues

Issues in fd.io are tracked in [JIRA](https://jira.fd.io).

Issue | Description
--- | ---
VPP-391 |   vpp debug version assert appeared in the process of start
VPP-380 |   Mapping algorithm compute wrong ea-bits when IPv4 prefix 0.0.0.0/0
VPP-371 |   load_one_plugin:63: Loaded plugin: message from vppctl
VPP-367 |   vpp packages need to depend on specific versions of each other
VPP-312 |   IP6 FIB gets in indeterminate state by duplicating commands
VPP-224 |   Lookup-in-vrf can not be set correctly
VPP-206 |   Fix classify table delete
VPP-203 |   Fix binary API for reading vpp node graph
VPP-147 |   Inconsistent behaviour when adding L2 FIB filter entry
VPP-99  |  VPP doesn't discard DHCPOFFER message with wrong XID


## Issues fixed

Issues in fd.io are tracked in [JIRA](https://jira.fd.io).

Issue | Description
--- | ---
VPP-396 |   Ubuntu systems Graphviz bug
VPP-390 |   vpp-lib rpm fails to include *.so symlinks, causing linking problems with out of tree builds
VPP-388 |   IPSec output feature assumes packets have been ethernet rewritten
VPP-385 |   ARP for indirect adjacencies not working correctly
VPP-361 |   Memory leak on delete of VXLAN over IPv6 tunnel
VPP-357 |   VNI not set correctly when removing LISP fwd entries
VPP-349 |   sw_interface_vhost_user_dump not working
VPP-345 |   net/enic: bad L4 checksum ptype set on ICMP packets
VPP-340 |   MAP-T wrong destination address
VPP-330 |   Use fifo to store LISP pending map-requests
VPP-326 |   map_add_domain VAT command: unable to configure domain with mtu parameter
VPP-318 |   The map_add_domain VAT command accepts invalid arguments
VPP-315 |   Fix "show vxlan-gpe" issue
VPP-310 |   Mapping algorithm compute wrong ea-bits
VPP-239 |   LISP IP forwarding does not tag packets that hit negative mapping entries
VPP-235 |   Invalid help in VAT for sw_interface_set_l2_bridge
VPP-228 |   Mapping algorithm sends packet to wrong IPv6 address
VPP-214 |   vpp-api-test: api_ipsec_sad_add_del_entry: vector "ck" not initialized
VPP-200 |   VPP - TAP port create problem
VPP-189 |   Coverity Issues for 16.09
VPP-184 |   u16 translating to char ,not short
VPP-179 |   Adjacency share-count botch
VPP-163 |   "show ip6 interface" ignores non-global addresses
VPP-155 |   Netmap: Inconsistency in interface state between "show hardware" and "show interface"
VPP-145 |   Dynamically compute IP feature ordering based on constraints
VPP-137 |   VPP sends ARP with wrong requested IP
VPP-118 |   JVpp: 0 length arrays not handled properly in VPP responses
VPP-112 |   linux kernel info missing from build log
VPP-110 |   vxlan encap node should never touch a deleted tunnel
VPP-107 |   RPM build broken in master
VPP-92  |   segment routing is not properly filling out the segment list
VPP-91  |   segment routing add/del tunnel lookup doesn't work
VPP-84  |   af_packet throws a fatal error on EAGAIN
VPP-74  |   Clang compile fails due to warning in vlib/unix/cli.c
VPP-64  |   Top level "make pkg-deb" fails if CDPATH is set in user env.
VPP-48  |   Traceroute does not terminate when VPP is the target
VPP-23  |   CLI pager does not gracefully handle lines longer than the terminal width


@page release_notes_1606 Release notes for VPP 16.06


The FD.io Project, relentlessly focused on data IO speed and efficiency
supporting the creation of high performance, flexible, and scalable software
defined infrastructures, announces the availability of the community’s first
software release (16.06).

In the four months since launching, FD.io has brought together more than 75
developers from 11 different companies including network operators, solution
providers chip vendors, and network equipment vendors who are collaborating to
enhance and innovate around the Vector Packet Processing (VPP) technology. The
FD.io community has quickly formed to grow the number of projects from the
initial VPP project to an additional 6 projects addressing a diverse set of
requirements and usability across a variety of deployment environments.

The 16.06 release brings unprecedented performance: 480Gbps/200mpps with 8
million routes and 2k whitelist entries on standard high volume x86 servers.


## Features

In addition to the existing full suite of vswitch/vrouter features, the new
16.06 release adds:

* Enhanced Switching and Routing:
  * IPv6 Segment Routing multicast support.
  * LISP xTR support.
  * VXLAN over IPv6 underlay.
  * Per interface whitelists.
  * Shared adjacencies in FIB.

* New and improved interface support:
  * Jumbo frame support for vhost-user.
  * Netmap interface support.
  * AF_Packet interface support.

* Expanded and improved programmability:
  * Python API bindings.
  * Enhanced JVPP Java API bindings.
  * Debugging CLI.

* Expanded Hardware and Software Support:
  * Support for ARM 32 targets including Rasberry Pi single-board computer.
  * Support for DPDK 16.04.

