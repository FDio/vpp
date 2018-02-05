# Release Notes    {#release_notes}

* @subpage release_notes_18011
* @subpage release_notes_1801
* @subpage release_notes_1710
* @subpage release_notes_1707
* @subpage release_notes_1704
* @subpage release_notes_17011
* @subpage release_notes_1701
* @subpage release_notes_1609
* @subpage release_notes_1606

@page release_notes_18011 Release notes for VPP 18.01.1

This is bug fix release.

For the full list of fixed issues please refer to:
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
  - NAT64 IPFix
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

Message Name                                                 Result
af_packet_set_l4_cksum_offload                               definition changed
api_versions                                                 definition changed
app_namespace_add_del                                        definition changed
application_attach                                           definition changed
bier_disp_entry_add_del                                      definition changed
bier_disp_entry_details                                      only in image
bier_disp_entry_dump                                         only in image
bier_disp_table_add_del                                      definition changed
bier_disp_table_details                                      only in image
bier_disp_table_dump                                         only in image
bier_imp_add                                                 definition changed
bier_imp_del                                                 definition changed
bier_imp_details                                             only in image
bier_imp_dump                                                only in image
bier_route_add_del                                           definition changed
bier_route_details                                           only in image
bier_route_dump                                              only in image
bier_table_add_del                                           definition changed
bier_table_details                                           only in image
bier_table_dump                                              only in image
bind_sock_reply                                              definition changed
connect_session_reply                                        definition changed
connect_sock                                                 definition changed
connect_uri                                                  definition changed
dhcp_proxy_details                                           definition changed
dhcp_proxy_set_vss                                           definition changed
dns_enable_disable                                           definition changed
dns_name_server_add_del                                      definition changed
dns_resolve_ip                                               definition changed
dns_resolve_name                                             definition changed
dslite_add_del_pool_addr_range                               definition changed
dslite_set_aftr_addr                                         definition changed
geneve_add_del_tunnel                                        definition changed
geneve_tunnel_details                                        only in image
geneve_tunnel_dump                                           only in image
ip_add_del_route                                             definition changed
ip_container_proxy_add_del                                   definition changed
ip_mroute_add_del                                            definition changed
ip_neighbor_details                                          definition changed
ip_punt_police                                               definition changed
ip_punt_redirect                                             definition changed
ipsec_sa_details                                             only in image
ipsec_sa_dump                                                only in image
ipsec_sad_add_del_entry                                      definition changed
ipsec_tunnel_if_set_key                                      definition changed
ipsec_tunnel_if_set_sa                                       definition changed
kp_add_del_pod                                               definition changed
kp_add_del_vip                                               definition changed
kp_conf                                                      definition changed
l2_emulation                                                 definition changed
l2_fib_table_details                                         definition changed
l2fib_add_del                                                definition changed
memclnt_keepalive                                            definition changed
memfd_segment_create                                         definition changed
mpls_ip_bind_unbind                                          definition changed
mpls_route_add_del                                           definition changed
nat44_add_del_address_range                                  definition changed
nat44_add_del_identity_mapping                               definition changed
nat44_add_del_interface_addr                                 definition changed
nat44_add_del_lb_static_mapping                              definition changed
nat44_add_del_static_mapping                                 definition changed
nat44_address_details                                        definition changed
nat44_del_session                                            definition changed
nat44_forwarding_enable_disable                              definition changed
nat44_forwarding_is_enabled                                  definition changed
nat44_identity_mapping_details                               only in image
nat44_identity_mapping_dump                                  only in image
nat44_interface_addr_details                                 definition changed
nat44_lb_static_mapping_details                              definition changed
nat44_static_mapping_details                                 definition changed
nat64_add_del_interface_addr                                 definition changed
nat_get_reass                                                definition changed
nat_reass_details                                            only in image
nat_reass_dump                                               only in image
nat_set_reass                                                definition changed
reset_vrf                                                    definition changed
session_rule_add_del                                         definition changed
session_rules_details                                        only in image
session_rules_dump                                           only in image
snat_add_address_range                                       definition changed
snat_add_del_interface_addr                                  definition changed
snat_add_det_map                                             definition changed
snat_add_static_mapping                                      definition changed
snat_address_details                                         only in file
snat_address_dump                                            only in file
snat_control_ping                                            definition changed
snat_det_close_session_in                                    definition changed
snat_det_close_session_out                                   definition changed
snat_det_forward                                             definition changed
snat_det_get_timeouts                                        definition changed
snat_det_map_details                                         only in file
snat_det_map_dump                                            only in file
snat_det_reverse                                             definition changed
snat_det_session_details                                     only in file
snat_det_session_dump                                        only in file
snat_det_set_timeouts                                        definition changed
snat_interface_add_del_feature                               definition changed
snat_interface_add_del_output_feature                        definition changed
snat_interface_addr_details                                  only in file
snat_interface_addr_dump                                     only in file
snat_interface_details                                       only in file
snat_interface_dump                                          only in file
snat_interface_output_feature_details                        only in file
snat_interface_output_feature_dump                           only in file
snat_ipfix_enable_disable                                    definition changed
snat_set_workers                                             definition changed
snat_show_config                                             definition changed
snat_static_mapping_details                                  only in file
snat_static_mapping_dump                                     only in file
snat_user_details                                            only in file
snat_user_dump                                               only in file
snat_user_session_details                                    only in file
snat_user_session_dump                                       only in file
snat_worker_details                                          only in file
snat_worker_dump                                             only in file
sockclnt_create                                              definition changed
sockclnt_delete                                              definition changed
sr_localsids_details                                         only in image
sr_localsids_dump                                            only in image
sr_mpls_policy_add                                           definition changed
sr_mpls_policy_assign_endpoint_color                         definition changed
sr_mpls_policy_del                                           definition changed
sr_mpls_policy_mod                                           definition changed
sr_mpls_steering_add_del                                     definition changed
sr_set_encap_source                                          definition changed
stn_add_del_rule                                             definition changed
stn_rule_details                                             only in image
stn_rules_dump                                               only in image
sw_interface_set_geneve_bypass                               definition changed
sw_interface_set_lldp                                        definition changed
sw_interface_set_rx_mode                                     definition changed
sw_interface_tap_v2_details                                  only in image
sw_interface_tap_v2_dump                                     only in image
tap_create_v2                                                definition changed
tap_delete_v2                                                definition changed
udp_encap_add_del                                            definition changed
udp_encap_details                                            only in image
udp_encap_dump                                               only in image
vnet_ip4_mfib_counters                                       only in image
vnet_ip6_mfib_counters                                       only in image
want_ip4_mfib_stats                                          definition changed
want_ip6_mfib_stats                                          definition changed
Found 142 api message signature differences

- patches that changed api files

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

Message Name                         			     Result
bridge_domain_add_del                                        definition changed
bridge_domain_details                                        definition changed
connect_session                                              definition changed
connect_sock                                                 definition changed
connect_sock_reply                                           definition changed
connect_uri_reply                                            definition changed
create_vhost_user_if                                         definition changed
dhcp_client_config                                           definition changed
ip4_arp_event                                                definition changed
ip6_fib_details                                              definition changed
ip6_nd_event                                                 definition changed
ip_add_del_route                                             definition changed
ip_fib_details                                               definition changed
ip_table_add_del                                             definition changed
l2_macs_event                                                only in image
macip_acl_add_replace                                        definition changed
macip_acl_interface_list_details                             only in image
macip_acl_interface_list_dump                                only in image
modify_vhost_user_if                                         definition changed
mpls_fib_details                                             definition changed
mpls_route_add_del                                           definition changed
mpls_table_add_del                                           definition changed
mpls_tunnel_add_del                                          definition changed
nat44_add_del_address_range                                  definition changed
nat44_add_del_interface_addr                                 definition changed
nat44_add_del_lb_static_mapping                              definition changed
nat44_add_del_static_mapping                                 definition changed
nat44_address_details                                        only in image
nat44_address_dump                                           only in image
nat44_interface_add_del_feature                              definition changed
nat44_interface_add_del_output_feature                       definition changed
nat44_interface_addr_details                                 only in image
nat44_interface_addr_dump                                    only in image
nat44_interface_details                                      only in image
nat44_interface_dump                                         only in image
nat44_interface_output_feature_details                       only in image
nat44_interface_output_feature_dump                          only in image
nat44_lb_static_mapping_details                              only in image
nat44_lb_static_mapping_dump                                 only in image
nat44_static_mapping_details                                 only in image
nat44_static_mapping_dump                                    only in image
nat44_user_details                                           only in image
nat44_user_dump                                              only in image
nat44_user_session_details                                   only in image
nat44_user_session_dump                                      only in image
nat_control_ping                                             definition changed
nat_det_add_del_map                                          definition changed
nat_det_close_session_in                                     definition changed
nat_det_close_session_out                                    definition changed
nat_det_forward                                              definition changed
nat_det_get_timeouts                                         definition changed
nat_det_map_details                                          only in image
nat_det_map_dump                                             only in image
nat_det_reverse                                              definition changed
nat_det_session_details                                      only in image
nat_det_session_dump                                         only in image
nat_det_set_timeouts                                         definition changed
nat_ipfix_enable_disable                                     definition changed
nat_set_workers                                              definition changed
nat_show_config                                              definition changed
nat_worker_details                                           only in image
nat_worker_dump                                              only in image
one_add_del_ndp_entry                                        definition changed
one_enable_disable_petr_mode                                 definition changed
one_enable_disable_pitr_mode                                 definition changed
one_enable_disable_xtr_mode                                  definition changed
one_get_transport_protocol                                   definition changed
one_map_register_fallback_threshold                          definition changed
one_map_register_set_ttl                                     definition changed
one_ndp_bd_get                                               definition changed
one_ndp_entries_get                                          definition changed
one_set_transport_protocol                                   definition changed
one_show_petr_mode                                           definition changed
one_show_pitr_mode                                           definition changed
one_show_xtr_mode                                            definition changed
p2p_ethernet_add                                             definition changed
pppoe_add_del_session                                        definition changed
pppoe_session_details                                        only in image
pppoe_session_dump                                           only in image
punt_socket_deregister                                       definition changed
punt_socket_register                                         definition changed
show_one_map_register_fallback_threshold                     definition changed
show_one_map_register_ttl                                    definition changed
snat_interface_add_del_output_feature                        definition changed
snat_interface_output_feature_details                        only in image
snat_interface_output_feature_dump                           only in image
sw_interface_event                                           only in image
sw_interface_set_flags                                       definition changed
sw_interface_span_dump                                       definition changed
sw_interface_span_enable_disable                             definition changed
sw_interface_vhost_user_details                              definition changed
tcp_configure_src_addresses                                  definition changed
vnet_per_interface_combined_counters                         only in image
vnet_per_interface_simple_counters                           only in image
want_interface_combined_stats                                definition changed
want_interface_simple_stats                                  definition changed
want_ip4_fib_stats                                           definition changed
want_ip4_nbr_stats                                           definition changed
want_ip6_fib_stats                                           definition changed
want_ip6_nbr_stats                                           definition changed
want_l2_macs_events                                          definition changed
want_per_interface_combined_stats                            definition changed
want_per_interface_simple_stats                              definition changed
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

