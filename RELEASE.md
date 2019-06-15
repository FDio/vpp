# Release Notes    {#release_notes}

* @subpage release_notes_1908
* @subpage release_notes_1904
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

@page release_notes_1908 Release notes for VPP 19.08

TBD

@page release_notes_1904 Release notes for VPP 19.04

TBD

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

