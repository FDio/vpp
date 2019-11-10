# NB NB NB NB NB NB NB NB NB NB NB
#
# NOTE: The API binary wrappers in this file are in the process of being
# deprecated. DO NOT ADD NEW WRAPPERS HERE. Call the functions using
# named arguments directly instead.
#

import os
import time
from collections import deque

from six import iteritems, moves
from vpp_papi import VPPApiClient, mac_pton

from hook import Hook
from vpp_ip_route import (
    MPLS_IETF_MAX_LABEL,
    MPLS_LABEL_INVALID,
)

#
# Dictionary keyed on message name to override default values for
# named parameters
#
defaultmapping = {
    'map_add_domain': {'mtu': 1280},
    'syslog_set_sender': {'collector_port': 514,
                          'max_msg_size': 480},
    'acl_interface_add_del': {'is_add': 1, 'is_input': 1},
    'acl_interface_list_dump': {'sw_if_index': 4294967295, },
    'app_namespace_add_del': {'sw_if_index': 4294967295, },
    'bd_ip_mac_add_del': {'is_add': 1, },
    'bfd_udp_add': {'is_authenticated': False, 'bfd_key_id': None,
                    'conf_key_id': None},
    'bfd_udp_auth_activate': {'bfd_key_id': None, 'conf_key_id': None,
                              'is_delayed': False},
    'bier_disp_entry_add_del': {'next_hop_rpf_id': -1, 'next_hop_is_ip4': 1,
                                'is_add': 1, },
    'bier_disp_table_add_del': {'is_add': 1, },
    'bier_imp_add': {'is_add': 1, },
    'bier_route_add_del': {'is_add': 1, },
    'bier_table_add_del': {'is_add': 1, },
    'bond_create': {'mac_address': '', 'id': 0xFFFFFFFF},
    'bridge_domain_add_del': {'flood': 1, 'uu_flood': 1, 'forward': 1,
                              'learn': 1, 'is_add': 1, },
    'bvi_create': {'user_instance': 4294967295, },
    'bvi_delete': {},
    'classify_add_del_table': {'match_n_vectors': 1, 'table_index': 4294967295,
                               'nbuckets': 2, 'memory_size': 2097152,
                               'next_table_index': 4294967295,
                               'miss_next_index': 4294967295, },
    'gbp_subnet_add_del': {'sw_if_index': 4294967295, 'epg_id': 65535, },
    'geneve_add_del_tunnel': {'mcast_sw_if_index': 4294967295, 'is_add': 1,
                              'decap_next_index': 4294967295, },
    'gre_tunnel_add_del': {'instance': 4294967295, 'is_add': 1, },
    'gtpu_add_del_tunnel': {'is_add': 1, 'mcast_sw_if_index': 4294967295,
                            'decap_next_index': 4294967295, },
    'input_acl_set_interface': {'ip4_table_index': 4294967295,
                                'ip6_table_index': 4294967295,
                                'l2_table_index': 4294967295, },
    'ip6_add_del_address_using_prefix': {'is_add': 1, },
    'ip6nd_send_router_solicitation': {'irt': 1, 'mrt': 120, },
    'ip_add_del_route': {'next_hop_sw_if_index': 4294967295,
                         'next_hop_weight': 1, 'next_hop_via_label': 1048576,
                         'classify_table_index': 4294967295, 'is_add': 1, },
    'ip_mroute_add_del': {'is_add': 1, },
    'ip_neighbor_add_del': {'is_add': 1, },
    'ip_punt_police': {'is_add': 1, },
    'ip_punt_redirect': {'is_add': 1, },
    'ip_route_add_del': {'is_add': 1, },
    'ip_table_add_del': {'is_add': 1, },
    'ip_unnumbered_dump': {'sw_if_index': 4294967295, },
    'ipsec_interface_add_del_spd': {'is_add': 1, },
    'ipsec_sad_entry_add_del': {'is_add': 1, },
    'ipsec_spd_add_del': {'is_add': 1, },
    'ipsec_spd_dump': {'sa_id': 4294967295, },
    'ipsec_spd_entry_add_del': {'local_port_stop': 65535,
                                'remote_port_stop': 65535, 'priority': 100,
                                'is_outbound': 1,
                                'is_add': 1, },
    'ipsec_tunnel_if_add_del': {'is_add': 1, 'anti_replay': 1, },
    'l2_emulation': {'enable': 1, },
    'l2fib_add_del': {'is_add': 1, },
    'lb_conf': {'sticky_buckets_per_core': 4294967295,
                'flow_timeout': 4294967295},
    'lisp_add_del_adjacency': {'is_add': 1, },
    'lisp_add_del_local_eid': {'is_add': 1, },
    'lisp_add_del_locator': {'priority': 1, 'weight': 1, 'is_add': 1, },
    'lisp_add_del_locator_set': {'is_add': 1, },
    'lisp_add_del_remote_mapping': {'is_add': 1, },
    'macip_acl_add_replace': {'acl_index': 4294967295, },
    'macip_acl_dump': {'acl_index': 4294967295, },
    'macip_acl_interface_add_del': {'is_add': 1, },
    'mpls_ip_bind_unbind': {'is_ip4': 1, 'is_bind': 1, },
    'mpls_route_add_del': {'mr_next_hop_sw_if_index': 4294967295,
                           'mr_next_hop_weight': 1,
                           'mr_next_hop_via_label': 1048576,
                           'mr_is_add': 1,
                           'mr_classify_table_index': 4294967295, },
    'mpls_table_add_del': {'is_add': 1, },
    'mpls_tunnel_add_del': {'next_hop_sw_if_index': 4294967295,
                            'next_hop_weight': 1,
                            'next_hop_via_label': 1048576,
                            'is_add': 1, },
    'mpls_tunnel_dump': {'sw_if_index': 4294967295, },
    'output_acl_set_interface': {'ip4_table_index': 4294967295,
                                 'ip6_table_index': 4294967295,
                                 'l2_table_index': 4294967295, },
    'pppoe_add_del_session': {'is_add': 1, },
    'policer_add_del': {'is_add': 1, 'conform_action_type': 1, },
    'proxy_arp_add_del': {'is_add': 1, },
    'proxy_arp_intfc_enable_disable': {'is_enable': 1, },
    'set_ip_flow_hash': {'src': 1, 'dst': 1, 'sport': 1, 'dport': 1,
                         'proto': 1, },
    'set_ipfix_exporter': {'collector_port': 4739, },
    'sr_localsid_add_del': {'sw_if_index': 4294967295, },
    'sr_policy_add': {'weight': 1, 'is_encap': 1, },
    'svs_enable_disable': {'is_enable': 1, },
    'svs_route_add_del': {'is_add': 1, },
    'svs_table_add_del': {'is_add': 1, },
    'sw_interface_add_del_address': {'is_add': 1, },
    'sw_interface_dump': {'sw_if_index': 4294967295, },
    'sw_interface_ip6nd_ra_prefix': {'val_lifetime': 4294967295,
                                     'pref_lifetime': 4294967295, },
    'sw_interface_set_ip_directed_broadcast': {'enable': 1, },
    'sw_interface_set_l2_bridge': {'enable': 1, },
    'sw_interface_set_mpls_enable': {'enable': 1, },
    'sw_interface_set_mtu': {'mtu': [0, 0, 0, 0], },
    'sw_interface_set_unnumbered': {'is_add': 1, },
    'sw_interface_span_enable_disable': {'state': 1, },
    'vxlan_add_del_tunnel': {'mcast_sw_if_index': 4294967295, 'is_add': 1,
                             'decap_next_index': 4294967295,
                             'instance': 4294967295, },
    'vxlan_gbp_tunnel_dump': {'sw_if_index': 4294967295, },
    'vxlan_gpe_add_del_tunnel': {'mcast_sw_if_index': 4294967295, 'is_add': 1,
                                 'protocol': 3, },
    'want_bfd_events': {'enable_disable': 1, },
    'want_igmp_events': {'enable': 1, },
    'want_interface_events': {'enable_disable': 1, },
    'want_ip4_arp_events': {'enable_disable': 1, 'ip': '0.0.0.0', },
    'want_ip6_nd_events': {'enable_disable': 1, 'ip': '::', },
    'want_ip6_ra_events': {'enable_disable': 1, },
    'want_l2_macs_events': {'enable_disable': 1, },
}


class CliFailedCommandError(Exception):
    """ cli command failed."""


class CliSyntaxError(Exception):
    """ cli command had a syntax error."""


class UnexpectedApiReturnValueError(Exception):
    """ exception raised when the API return value is unexpected """
    pass


class VppPapiProvider(object):
    """VPP-api provider using vpp-papi

    @property hook: hook object providing before and after api/cli hooks
    """

    _zero, _negative = range(2)

    def __init__(self, name, shm_prefix, test_class, read_timeout):
        self.hook = Hook(test_class)
        self.name = name
        self.shm_prefix = shm_prefix
        self.test_class = test_class
        self._expect_api_retval = self._zero
        self._expect_stack = []

        # install_dir is a class attribute. We need to set it before
        # calling the constructor.
        VPPApiClient.apidir = os.getenv('VPP_INSTALL_PATH')

        use_socket = False
        try:
            if os.environ['SOCKET'] == '1':
                use_socket = True
        except KeyError:
            pass

        self.vpp = VPPApiClient(logger=test_class.logger,
                                read_timeout=read_timeout,
                                use_socket=use_socket,
                                server_address=test_class.api_sock)
        self._events = deque()

    def __enter__(self):
        return self

    def assert_negative_api_retval(self):
        """ Expect API failure - used with with, e.g.:
            with self.vapi.assert_negative_api_retval():
                self.vapi.<api call expected to fail>
        """
        self._expect_stack.append(self._expect_api_retval)
        self._expect_api_retval = self._negative
        return self

    def assert_zero_api_retval(self):
        """ Expect API success - used with with, e.g.:
            with self.vapi.assert_negative_api_retval():
                self.vapi.<api call expected to succeed>

            note: this is useful only inside another with block
                  as success is the default expected value
        """
        self._expect_stack.append(self._expect_api_retval)
        self._expect_api_retval = self._zero
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._expect_api_retval = self._expect_stack.pop()

    def register_hook(self, hook):
        """Replace hook registration with new hook

        :param hook:

        """
        self.hook = hook

    def collect_events(self):
        """ Collect all events from the internal queue and clear the queue. """
        e = self._events
        self._events = deque()
        return e

    def wait_for_event(self, timeout, name=None):
        """ Wait for and return next event. """
        if name:
            self.test_class.logger.debug("Expecting event '%s' within %ss",
                                         name, timeout)
        else:
            self.test_class.logger.debug("Expecting event within %ss",
                                         timeout)
        if self._events:
            self.test_class.logger.debug("Not waiting, event already queued")
        limit = time.time() + timeout
        while time.time() < limit:
            if self._events:
                e = self._events.popleft()
                if name and type(e).__name__ != name:
                    raise Exception(
                        "Unexpected event received: %s, expected: %s" %
                        (type(e).__name__, name))
                self.test_class.logger.debug("Returning event %s:%s" %
                                             (name, e))
                return e
            self.test_class.sleep(0)  # yield
        raise Exception("Event did not occur within timeout")

    def __call__(self, name, event):
        """ Enqueue event in the internal event queue. """
        # FIXME use the name instead of relying on type(e).__name__ ?
        # FIXME #2 if this throws, it is eaten silently, Ole?
        self.test_class.logger.debug("New event: %s: %s" % (name, event))
        self._events.append(event)

    def factory(self, name, apifn):
        def f(*a, **ka):
            fields = apifn._func.msg.fields

            # add positional and kw arguments
            d = ka
            for i, o in enumerate(fields[3:]):
                try:
                    d[o] = a[i]
                except BaseException:
                    break

            # Default override
            if name in defaultmapping:
                for k, v in iteritems(defaultmapping[name]):
                    if k in d:
                        continue
                    d[k] = v
            return self.api(apifn, d)

        return f

    def __getattribute__(self, name):
        try:
            method = super(VppPapiProvider, self).__getattribute__(name)
        except AttributeError:
            method = self.factory(name, getattr(self.papi, name))
            # lazily load the method so we don't need to call factory
            # again for this name.
            setattr(self, name, method)
        return method

    def connect(self):
        """Connect the API to VPP"""
        self.vpp.connect(self.name, self.shm_prefix)
        self.papi = self.vpp.api
        self.vpp.register_event_callback(self)

    def disconnect(self):
        """Disconnect the API from VPP"""
        self.vpp.disconnect()

    def api(self, api_fn, api_args, expected_retval=0):
        """ Call API function and check it's return value.
        Call the appropriate hooks before and after the API call

        :param api_fn: API function to call
        :param api_args: tuple of API function arguments
        :param expected_retval: Expected return value (Default value = 0)
        :returns: reply from the API

        """
        self.hook.before_api(api_fn.__name__, api_args)
        reply = api_fn(**api_args)
        if self._expect_api_retval == self._negative:
            if hasattr(reply, 'retval') and reply.retval >= 0:
                msg = "API call passed unexpectedly: expected negative " \
                      "return value instead of %d in %s" % \
                      (reply.retval, moves.reprlib.repr(reply))
                self.test_class.logger.info(msg)
                raise UnexpectedApiReturnValueError(msg)
        elif self._expect_api_retval == self._zero:
            if hasattr(reply, 'retval') and reply.retval != expected_retval:
                msg = "API call failed, expected %d return value instead " \
                      "of %d in %s" % (expected_retval, reply.retval,
                                       repr(reply))
                self.test_class.logger.info(msg)
                raise UnexpectedApiReturnValueError(msg)
        else:
            raise Exception("Internal error, unexpected value for "
                            "self._expect_api_retval %s" %
                            self._expect_api_retval)
        self.hook.after_api(api_fn.__name__, api_args)
        return reply

    def cli_return_response(self, cli):
        """ Execute a CLI, calling the before/after hooks appropriately.
        Return the reply without examining it

        :param cli: CLI to execute
        :returns: response object

        """
        self.hook.before_cli(cli)
        cli += '\n'
        r = self.papi.cli_inband(cmd=cli)
        self.hook.after_cli(cli)
        return r

    def cli(self, cli):
        """ Execute a CLI, calling the before/after hooks appropriately.

        :param cli: CLI to execute
        :returns: CLI output

        """
        r = self.cli_return_response(cli)
        if r.retval == -156:
            raise CliSyntaxError(r.reply)
        if r.retval != 0:
            raise CliFailedCommandError(r.reply)
        if hasattr(r, 'reply'):
            return r.reply

    def ppcli(self, cli):
        """ Helper method to print CLI command in case of info logging level.

        :param cli: CLI to execute
        :returns: CLI output
        """
        return cli + "\n" + self.cli(cli)

    def want_ip4_arp_events(self, enable_disable=1, ip="0.0.0.0"):
        return self.api(self.papi.want_ip4_arp_events,
                        {'enable_disable': enable_disable,
                         'ip': ip,
                         'pid': os.getpid(), })

    def want_ip6_nd_events(self, enable_disable=1, ip="::"):
        return self.api(self.papi.want_ip6_nd_events,
                        {'enable_disable': enable_disable,
                         'ip': ip,
                         'pid': os.getpid(), })

    def want_ip6_ra_events(self, enable_disable=1):
        return self.api(self.papi.want_ip6_ra_events,
                        {'enable_disable': enable_disable,
                         'pid': os.getpid(), })

    def ip6nd_send_router_solicitation(self, sw_if_index, irt=1, mrt=120,
                                       mrc=0, mrd=0):
        return self.api(self.papi.ip6nd_send_router_solicitation,
                        {'irt': irt,
                         'mrt': mrt,
                         'mrc': mrc,
                         'mrd': mrd,
                         'sw_if_index': sw_if_index})

    def want_interface_events(self, enable_disable=1):
        return self.api(self.papi.want_interface_events,
                        {'enable_disable': enable_disable,
                         'pid': os.getpid(), })

    def want_l2_macs_events(self, enable_disable=1, scan_delay=0,
                            max_macs_in_event=0, learn_limit=0):
        return self.api(self.papi.want_l2_macs_events,
                        {'enable_disable': enable_disable,
                         'scan_delay': scan_delay,
                         'max_macs_in_event': max_macs_in_event,
                         'learn_limit': learn_limit,
                         'pid': os.getpid(), })

    def sw_interface_set_mac_address(self, sw_if_index, mac):
        return self.api(self.papi.sw_interface_set_mac_address,
                        {'sw_if_index': sw_if_index,
                         'mac_address': mac})

    def p2p_ethernet_add(self, sw_if_index, remote_mac, subif_id):
        """Create p2p ethernet subinterface

        :param sw_if_index: main (parent) interface
        :param remote_mac: client (remote) mac address

        """
        return self.api(
            self.papi.p2p_ethernet_add,
            {'parent_if_index': sw_if_index,
             'remote_mac': remote_mac,
             'subif_id': subif_id})

    def p2p_ethernet_del(self, sw_if_index, remote_mac):
        """Delete p2p ethernet subinterface

        :param sw_if_index: main (parent) interface
        :param remote_mac: client (remote) mac address

        """
        return self.api(
            self.papi.p2p_ethernet_del,
            {'parent_if_index': sw_if_index,
             'remote_mac': remote_mac})

    def create_vlan_subif(self, sw_if_index, vlan):
        """

        :param vlan:
        :param sw_if_index:

        """
        return self.api(self.papi.create_vlan_subif,
                        {'sw_if_index': sw_if_index,
                         'vlan_id': vlan})

    def create_loopback(self, mac=''):
        """

        :param mac: (Optional)
        """
        return self.api(self.papi.create_loopback,
                        {'mac_address': mac})

    def ip_table_add_del(self,
                         table_id,
                         is_add=1,
                         is_ipv6=0):
        """

        :param table_id
        :param is_add:  (Default value = 1)
        :param is_ipv6:  (Default value = 0)

        """

        return self.api(
            self.papi.ip_table_add_del,
            {'table':
             {
                 'table_id': table_id,
                 'is_ip6': is_ipv6
             },
             'is_add': is_add})

    def ip_table_dump(self):
        return self.api(self.papi.ip_table_dump, {})

    def ip_route_dump(self, table_id, is_ip6=False):
        return self.api(self.papi.ip_route_dump,
                        {'table': {
                            'table_id': table_id,
                            'is_ip6': is_ip6
                        }})

    def ip_neighbor_add_del(self,
                            sw_if_index,
                            mac_address,
                            ip_address,
                            is_add=1,
                            flags=0):
        """ Add neighbor MAC to IPv4 or IPv6 address.

        :param sw_if_index:
        :param mac_address:
        :param dst_address:
        :param is_add:  (Default value = 1)
        :param flags:  (Default value = 0/NONE)
        """
        return self.api(
            self.papi.ip_neighbor_add_del,
            {
                'is_add': is_add,
                'neighbor': {
                    'sw_if_index': sw_if_index,
                    'flags': flags,
                    'mac_address': mac_address,
                    'ip_address': ip_address
                }
            }
        )

    def proxy_arp_add_del(self,
                          low,
                          hi,
                          table_id=0,
                          is_add=1):
        """ Config Proxy Arp Range.

        :param low_address: Start address in the rnage to Proxy for
        :param hi_address: End address in the rnage to Proxy for
        :param vrf_id: The VRF/table in which to proxy
        """

        return self.api(
            self.papi.proxy_arp_add_del,
            {'proxy':
                {
                    'table_id': table_id,
                    'low': low,
                    'hi': hi,
                },
                'is_add': is_add})

    def proxy_arp_intfc_enable_disable(self,
                                       sw_if_index,
                                       is_enable=1):
        """ Enable/Disable an interface for proxy ARP requests

        :param sw_if_index: Interface
        :param enable_disable: Enable/Disable
        """

        return self.api(
            self.papi.proxy_arp_intfc_enable_disable,
            {'sw_if_index': sw_if_index,
             'enable_disable': is_enable
             }
        )

    def gre_tunnel_add_del(self,
                           src,
                           dst,
                           outer_fib_id=0,
                           tunnel_type=0,
                           instance=0xFFFFFFFF,
                           session_id=0,
                           is_add=1):
        """ Add a GRE tunnel

        :param src_address:
        :param dst_address:
        :param outer_fib_id:  (Default value = 0)
        :param tunnel_type:  (Default value = 0)
        :param instance:  (Default value = 0xFFFFFFFF)
        :param session_id: (Default value = 0)
        :param is_add:  (Default value = 1)
        :param is_ipv6:  (Default value = 0)
        """

        return self.api(
            self.papi.gre_tunnel_add_del,
            {'is_add': is_add,
             'tunnel':
             {
                 'type': tunnel_type,
                 'instance': instance,
                 'src': src,
                 'dst': dst,
                 'outer_fib_id': outer_fib_id,
                 'session_id': session_id}
             }
        )

    def udp_encap_add(self,
                      src_ip,
                      dst_ip,
                      src_port,
                      dst_port,
                      table_id=0):
        """ Add a GRE tunnel
        :param src_ip:
        :param dst_ip:
        :param src_port:
        :param dst_port:
        :param outer_fib_id:  (Default value = 0)
        """

        return self.api(
            self.papi.udp_encap_add,
            {
                'udp_encap': {
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'table_id': table_id
                }
            })

    def udp_encap_del(self, id):
        return self.api(self.papi.udp_encap_del, {'id': id})

    def udp_encap_dump(self):
        return self.api(self.papi.udp_encap_dump, {})

    def want_udp_encap_stats(self, enable=1):
        return self.api(self.papi.want_udp_encap_stats,
                        {'enable': enable,
                         'pid': os.getpid()})

    def mpls_route_dump(self, table_id):
        return self.api(self.papi.mpls_route_dump,
                        {'table': {
                            'mt_table_id': table_id
                        }})

    def mpls_table_dump(self):
        return self.api(self.papi.mpls_table_dump, {})

    def mpls_table_add_del(
            self,
            table_id,
            is_add=1):
        """

        :param table_id
        :param is_add:  (Default value = 1)

        """

        return self.api(
            self.papi.mpls_table_add_del,
            {'mt_table':
             {
                 'mt_table_id': table_id,
             },
             'mt_is_add': is_add})

    def mpls_route_add_del(self,
                           table_id,
                           label,
                           eos,
                           eos_proto,
                           is_multicast,
                           paths,
                           is_add,
                           is_multipath):
        """ MPLS Route add/del """
        return self.api(
            self.papi.mpls_route_add_del,
            {'mr_route':
             {
                 'mr_table_id': table_id,
                 'mr_label': label,
                 'mr_eos': eos,
                 'mr_eos_proto': eos_proto,
                 'mr_is_multicast': is_multicast,
                 'mr_n_paths': len(paths),
                 'mr_paths': paths,
             },
             'mr_is_add': is_add,
             'mr_is_multipath': is_multipath})

    def mpls_ip_bind_unbind(
            self,
            label,
            prefix,
            table_id=0,
            ip_table_id=0,
            is_bind=1):
        """
        """
        return self.api(
            self.papi.mpls_ip_bind_unbind,
            {'mb_mpls_table_id': table_id,
             'mb_label': label,
             'mb_ip_table_id': ip_table_id,
             'mb_is_bind': is_bind,
             'mb_prefix': prefix})

    def mpls_tunnel_add_del(
            self,
            tun_sw_if_index,
            paths,
            is_add=1,
            l2_only=0,
            is_multicast=0):
        """
        """
        return self.api(
            self.papi.mpls_tunnel_add_del,
            {'mt_is_add': is_add,
             'mt_tunnel':
             {
                 'mt_sw_if_index': tun_sw_if_index,
                 'mt_l2_only': l2_only,
                 'mt_is_multicast': is_multicast,
                 'mt_n_paths': len(paths),
                 'mt_paths': paths,
             }})

    def classify_add_del_table(
            self,
            is_add,
            mask,
            match_n_vectors=1,
            table_index=0xFFFFFFFF,
            nbuckets=2,
            memory_size=2097152,
            skip_n_vectors=0,
            next_table_index=0xFFFFFFFF,
            miss_next_index=0xFFFFFFFF,
            current_data_flag=0,
            current_data_offset=0):
        """
        :param is_add:
        :param mask:
        :param match_n_vectors: (Default value = 1)
        :param table_index: (Default value = 0xFFFFFFFF)
        :param nbuckets:  (Default value = 2)
        :param memory_size:  (Default value = 2097152)
        :param skip_n_vectors:  (Default value = 0)
        :param next_table_index:  (Default value = 0xFFFFFFFF)
        :param miss_next_index:  (Default value = 0xFFFFFFFF)
        :param current_data_flag:  (Default value = 0)
        :param current_data_offset:  (Default value = 0)
        """
        mask_len = ((len(mask) - 1) // 16 + 1) * 16
        mask = mask + b'\0' * (mask_len - len(mask))
        return self.api(
            self.papi.classify_add_del_table,
            {'is_add': is_add,
             'table_index': table_index,
             'nbuckets': nbuckets,
             'memory_size': memory_size,
             'skip_n_vectors': skip_n_vectors,
             'match_n_vectors': match_n_vectors,
             'next_table_index': next_table_index,
             'miss_next_index': miss_next_index,
             'current_data_flag': current_data_flag,
             'current_data_offset': current_data_offset,
             'mask_len': mask_len,
             'mask': mask})

    def classify_add_del_session(
            self,
            is_add,
            table_index,
            match,
            opaque_index=0xFFFFFFFF,
            hit_next_index=0xFFFFFFFF,
            advance=0,
            action=0,
            metadata=0):
        """
        :param is_add:
        :param table_index:
        :param match:
        :param opaque_index:  (Default value = 0xFFFFFFFF)
        :param hit_next_index:  (Default value = 0xFFFFFFFF)
        :param advance:  (Default value = 0)
        :param action:  (Default value = 0)
        :param metadata:  (Default value = 0)
        """

        match_len = ((len(match) - 1) // 16 + 1) * 16
        match = match + b'\0' * (match_len - len(match))
        return self.api(
            self.papi.classify_add_del_session,
            {'is_add': is_add,
             'table_index': table_index,
             'hit_next_index': hit_next_index,
             'opaque_index': opaque_index,
             'advance': advance,
             'action': action,
             'metadata': metadata,
             'match_len': match_len,
             'match': match})

    def input_acl_set_interface(
            self,
            is_add,
            sw_if_index,
            ip4_table_index=0xFFFFFFFF,
            ip6_table_index=0xFFFFFFFF,
            l2_table_index=0xFFFFFFFF):
        """
        :param is_add:
        :param sw_if_index:
        :param ip4_table_index:  (Default value = 0xFFFFFFFF)
        :param ip6_table_index:  (Default value = 0xFFFFFFFF)
        :param l2_table_index:  (Default value = 0xFFFFFFFF)
        """

        return self.api(
            self.papi.input_acl_set_interface,
            {'sw_if_index': sw_if_index,
             'ip4_table_index': ip4_table_index,
             'ip6_table_index': ip6_table_index,
             'l2_table_index': l2_table_index,
             'is_add': is_add})

    def output_acl_set_interface(
            self,
            is_add,
            sw_if_index,
            ip4_table_index=0xFFFFFFFF,
            ip6_table_index=0xFFFFFFFF,
            l2_table_index=0xFFFFFFFF):
        """
        :param is_add:
        :param sw_if_index:
        :param ip4_table_index:  (Default value = 0xFFFFFFFF)
        :param ip6_table_index:  (Default value = 0xFFFFFFFF)
        :param l2_table_index:  (Default value = 0xFFFFFFFF)
        """

        return self.api(
            self.papi.output_acl_set_interface,
            {'sw_if_index': sw_if_index,
             'ip4_table_index': ip4_table_index,
             'ip6_table_index': ip6_table_index,
             'l2_table_index': l2_table_index,
             'is_add': is_add})

    def set_ipfix_exporter(
            self,
            collector_address,
            src_address,
            path_mtu,
            template_interval,
            vrf_id=0,
            collector_port=4739,
            udp_checksum=0):
        return self.api(
            self.papi.set_ipfix_exporter,
            {
                'collector_address': collector_address,
                'collector_port': collector_port,
                'src_address': src_address,
                'vrf_id': vrf_id,
                'path_mtu': path_mtu,
                'template_interval': template_interval,
                'udp_checksum': udp_checksum,
            })

    def ip_mroute_add_del(self,
                          table_id,
                          prefix,
                          e_flags,
                          rpf_id,
                          paths,
                          is_add=1,
                          is_multipath=1):
        """
        IP Multicast Route add/del
        """
        return self.api(
            self.papi.ip_mroute_add_del,
            {
                'is_add': is_add,
                'is_multipath': is_multipath,
                'route': {
                    'table_id': table_id,
                    'entry_flags': e_flags,
                    'rpf_id': rpf_id,
                    'prefix': prefix,
                    'n_paths': len(paths),
                    'paths': paths,
                }
            })

    def mfib_signal_dump(self):
        return self.api(self.papi.mfib_signal_dump, {})

    def ip_mroute_dump(self, table_id, is_ip6=False):
        return self.api(self.papi.ip_mroute_dump,
                        {'table': {
                            'table_id': table_id,
                            'is_ip6': is_ip6
                        }})

    def lisp_enable_disable(self, is_enabled):
        return self.api(
            self.papi.lisp_enable_disable,
            {
                'is_en': is_enabled,
            })

    def lisp_add_del_locator_set(self,
                                 ls_name,
                                 is_add=1):
        return self.api(
            self.papi.lisp_add_del_locator_set,
            {
                'is_add': is_add,
                'locator_set_name': ls_name
            })

    def lisp_add_del_locator(self,
                             ls_name,
                             sw_if_index,
                             priority=1,
                             weight=1,
                             is_add=1):
        return self.api(
            self.papi.lisp_add_del_locator,
            {
                'is_add': is_add,
                'locator_set_name': ls_name,
                'sw_if_index': sw_if_index,
                'priority': priority,
                'weight': weight
            })

    def lisp_locator_dump(self, is_index_set, ls_name=None, ls_index=0):
        return self.api(
            self.papi.lisp_locator_dump,
            {
                'is_index_set': is_index_set,
                'ls_name': ls_name,
                'ls_index': ls_index,
            })

    def lisp_add_del_local_eid(self,
                               ls_name,
                               eid_type,
                               eid,
                               prefix_len,
                               vni=0,
                               key_id=0,
                               key="",
                               is_add=1):
        return self.api(
            self.papi.lisp_add_del_local_eid,
            {
                'locator_set_name': ls_name,
                'is_add': is_add,
                'eid_type': eid_type,
                'eid': eid,
                'prefix_len': prefix_len,
                'vni': vni,
                'key_id': key_id,
                'key': key
            })

    def lisp_eid_table_dump(self,
                            eid_set=0,
                            prefix_length=0,
                            vni=0,
                            eid_type=0,
                            eid=None,
                            filter_opt=0):
        return self.api(
            self.papi.lisp_eid_table_dump,
            {
                'eid_set': eid_set,
                'prefix_length': prefix_length,
                'vni': vni,
                'eid_type': eid_type,
                'eid': eid,
                'filter': filter_opt,
            })

    def lisp_add_del_remote_mapping(self,
                                    eid_type,
                                    eid,
                                    eid_prefix_len=0,
                                    vni=0,
                                    rlocs=[],
                                    rlocs_num=0,
                                    is_src_dst=0,
                                    is_add=1):
        return self.api(
            self.papi.lisp_add_del_remote_mapping,
            {
                'is_add': is_add,
                'eid_type': eid_type,
                'eid': eid,
                'eid_len': eid_prefix_len,
                'rloc_num': rlocs_num,
                'rlocs': rlocs,
                'vni': vni,
                'is_src_dst': is_src_dst,
            })

    def lisp_add_del_adjacency(self,
                               leid,
                               reid,
                               leid_len,
                               reid_len,
                               eid_type,
                               is_add=1,
                               vni=0):
        return self.api(
            self.papi.lisp_add_del_adjacency,
            {
                'is_add': is_add,
                'vni': vni,
                'eid_type': eid_type,
                'leid': leid,
                'reid': reid,
                'leid_len': leid_len,
                'reid_len': reid_len,
            })

    def gtpu_add_del_tunnel(
            self,
            src_addr,
            dst_addr,
            is_add=1,
            is_ipv6=0,
            mcast_sw_if_index=0xFFFFFFFF,
            encap_vrf_id=0,
            decap_next_index=0xFFFFFFFF,
            teid=0):
        """

        :param is_add:  (Default value = 1)
        :param is_ipv6:  (Default value = 0)
        :param src_addr:
        :param dst_addr:
        :param mcast_sw_if_index:  (Default value = 0xFFFFFFFF)
        :param encap_vrf_id:  (Default value = 0)
        :param decap_next_index:  (Default value = 0xFFFFFFFF)
        :param teid:  (Default value = 0)

        """
        return self.api(self.papi.gtpu_add_del_tunnel,
                        {'is_add': is_add,
                         'is_ipv6': is_ipv6,
                         'src_address': src_addr,
                         'dst_address': dst_addr,
                         'mcast_sw_if_index': mcast_sw_if_index,
                         'encap_vrf_id': encap_vrf_id,
                         'decap_next_index': decap_next_index,
                         'teid': teid})

    def vxlan_gpe_add_del_tunnel(
            self,
            src_addr,
            dst_addr,
            mcast_sw_if_index=0xFFFFFFFF,
            is_add=1,
            is_ipv6=0,
            encap_vrf_id=0,
            decap_vrf_id=0,
            protocol=3,
            vni=0):
        """

        :param local:
        :param remote:
        :param is_add:  (Default value = 1)
        :param is_ipv6:  (Default value = 0)
        :param encap_vrf_id:  (Default value = 0)
        :param decap_vrf_id:  (Default value = 0)
        :param mcast_sw_if_index:  (Default value = 0xFFFFFFFF)
        :param protocol:  (Default value = 3)
        :param vni:  (Default value = 0)

        """
        return self.api(self.papi.vxlan_gpe_add_del_tunnel,
                        {'is_add': is_add,
                         'is_ipv6': is_ipv6,
                         'local': src_addr,
                         'remote': dst_addr,
                         'mcast_sw_if_index': mcast_sw_if_index,
                         'encap_vrf_id': encap_vrf_id,
                         'decap_vrf_id': decap_vrf_id,
                         'protocol': protocol,
                         'vni': vni})

    def vxlan_gbp_tunnel_dump(self, sw_if_index=0xffffffff):
        return self.api(self.papi.vxlan_gbp_tunnel_dump,
                        {'sw_if_index': sw_if_index})

    def pppoe_add_del_session(
            self,
            client_ip,
            client_mac,
            session_id=0,
            is_add=1,
            is_ipv6=0,
            decap_vrf_id=0):
        """

        :param is_add:  (Default value = 1)
        :param is_ipv6:  (Default value = 0)
        :param client_ip:
        :param session_id:  (Default value = 0)
        :param client_mac:
        :param decap_vrf_id:  (Default value = 0)

        """
        return self.api(self.papi.pppoe_add_del_session,
                        {'is_add': is_add,
                         'is_ipv6': is_ipv6,
                         'session_id': session_id,
                         'client_ip': client_ip,
                         'decap_vrf_id': decap_vrf_id,
                         'client_mac': client_mac})

    def sr_mpls_policy_add(self, bsid, weight, type, segments):
        return self.api(self.papi.sr_mpls_policy_add,
                        {'bsid': bsid,
                         'weight': weight,
                         'type': type,
                         'n_segments': len(segments),
                         'segments': segments})

    def sr_mpls_policy_del(self, bsid):
        return self.api(self.papi.sr_mpls_policy_del,
                        {'bsid': bsid})

    def sr_localsid_add_del(self,
                            localsid,
                            behavior,
                            nh_addr4,
                            nh_addr6,
                            is_del=0,
                            end_psp=0,
                            sw_if_index=0xFFFFFFFF,
                            vlan_index=0,
                            fib_table=0,
                            ):
        """ Add/del IPv6 SR local-SID.

        :param localsid:
        :param behavior: END=1; END.X=2; END.DX2=4; END.DX6=5;
        :param behavior: END.DX4=6; END.DT6=7; END.DT4=8
        :param nh_addr4:
        :param nh_addr6:
        :param is_del:  (Default value = 0)
        :param end_psp: (Default value = 0)
        :param sw_if_index: (Default value = 0xFFFFFFFF)
        :param vlan_index:  (Default value = 0)
        :param fib_table:   (Default value = 0)
        """
        return self.api(
            self.papi.sr_localsid_add_del,
            {'is_del': is_del,
             'localsid': localsid,
             'end_psp': end_psp,
             'behavior': behavior,
             'sw_if_index': sw_if_index,
             'vlan_index': vlan_index,
             'fib_table': fib_table,
             'nh_addr4': nh_addr4,
             'nh_addr6': nh_addr6
             }
        )

    def sr_policy_add(
            self,
            bsid_addr,
            weight=1,
            is_encap=1,
            type=0,
            fib_table=0,
            n_segments=0,
            segments=[]):
        """
        :param bsid_addr: bindingSID of the SR Policy
        :param weight: weight of the sid list. optional. (default: 1)
        :param is_encap: (bool) whether SR policy should Encap or SRH insert \
            (default: Encap)
        :param type: type/behavior of the SR policy. (default or spray) \
            (default: default)
        :param fib_table: VRF where to install the FIB entry for the BSID \
            (default: 0)
        :param n_segments: number of segments \
            (default: 0)
        :param segments: a vector of IPv6 address composing the segment list \
            (default: [])
        """
        return self.api(
            self.papi.sr_policy_add,
            {'bsid_addr': bsid_addr,
             'weight': weight,
             'is_encap': is_encap,
             'type': type,
             'fib_table': fib_table,
             'n_segments': n_segments,
             'segments': segments
             }
        )

    def sr_policy_del(
            self,
            bsid_addr,
            sr_policy_index=0):
        """
        :param bsid: bindingSID of the SR Policy
        :param sr_policy_index: index of the sr policy (default: 0)
        """
        return self.api(
            self.papi.sr_policy_del,
            {'bsid_addr': bsid_addr,
             'sr_policy_index': sr_policy_index
             })

    def sr_steering_add_del(
            self,
            is_del,
            bsid_addr,
            sr_policy_index,
            table_id,
            prefix_addr,
            mask_width,
            sw_if_index,
            traffic_type):
        """
        Steer traffic L2 and L3 traffic through a given SR policy

        :param is_del: delete or add
        :param bsid_addr: bindingSID of the SR Policy (alt to sr_policy_index)
        :param sr_policy: is the index of the SR Policy (alt to bsid)
        :param table_id: is the VRF where to install the FIB entry for the BSID
        :param prefix_addr: is the IPv4/v6 address for L3 traffic type
        :param mask_width: is the mask for L3 traffic type
        :param sw_if_index: is the incoming interface for L2 traffic
        :param traffic_type: type of traffic (IPv4: 4, IPv6: 6, L2: 2)
        """
        return self.api(
            self.papi.sr_steering_add_del,
            {'is_del': is_del,
             'bsid_addr': bsid_addr,
             'sr_policy_index': sr_policy_index,
             'table_id': table_id,
             'prefix_addr': prefix_addr,
             'mask_width': mask_width,
             'sw_if_index': sw_if_index,
             'traffic_type': traffic_type
             })

    def acl_add_replace(self, acl_index, r, tag='',
                        expected_retval=0):
        """Add/replace an ACL
        :param int acl_index: ACL index to replace, 2^32-1 to create new ACL.
        :param acl_rule r: ACL rules array.
        :param str tag: symbolic tag (description) for this ACL.
        :param int count: number of rules.
        """
        return self.api(self.papi.acl_add_replace,
                        {'acl_index': acl_index,
                         'r': r,
                         'count': len(r),
                         'tag': tag},
                        expected_retval=expected_retval)

    def acl_del(self, acl_index, expected_retval=0):
        """

        :param acl_index:
        :return:
        """
        return self.api(self.papi.acl_del,
                        {'acl_index': acl_index},
                        expected_retval=expected_retval)

    def acl_interface_set_acl_list(self, sw_if_index, n_input, acls,
                                   expected_retval=0):
        return self.api(self.papi.acl_interface_set_acl_list,
                        {'sw_if_index': sw_if_index,
                         'count': len(acls),
                         'n_input': n_input,
                         'acls': acls},
                        expected_retval=expected_retval)

    def acl_interface_set_etype_whitelist(self, sw_if_index,
                                          n_input, whitelist,
                                          expected_retval=0):
        return self.api(self.papi.acl_interface_set_etype_whitelist,
                        {'sw_if_index': sw_if_index,
                         'count': len(whitelist),
                         'n_input': n_input,
                         'whitelist': whitelist},
                        expected_retval=expected_retval)

    def acl_interface_add_del(self,
                              sw_if_index,
                              acl_index,
                              is_add=1):
        """ Add/Delete ACL to/from interface

        :param sw_if_index:
        :param acl_index:
        :param is_add:  (Default value = 1)
        """

        return self.api(self.papi.acl_interface_add_del,
                        {'is_add': is_add,
                         'is_input': 1,
                         'sw_if_index': sw_if_index,
                         'acl_index': acl_index})

    def acl_dump(self, acl_index, expected_retval=0):
        return self.api(self.papi.acl_dump,
                        {'acl_index': acl_index},
                        expected_retval=expected_retval)

    def acl_interface_list_dump(self, sw_if_index=0xFFFFFFFF,
                                expected_retval=0):
        return self.api(self.papi.acl_interface_list_dump,
                        {'sw_if_index': sw_if_index},
                        expected_retval=expected_retval)

    def macip_acl_add(self, rules, tag=""):
        """ Add MACIP acl

        :param rules: list of rules for given acl
        :param tag: acl tag
        """

        return self.api(self.papi.macip_acl_add,
                        {'r': rules,
                         'count': len(rules),
                         'tag': tag})

    def macip_acl_add_replace(self, rules, acl_index=0xFFFFFFFF, tag=""):
        """ Add MACIP acl

        :param rules: list of rules for given acl
        :param tag: acl tag
        """

        return self.api(self.papi.macip_acl_add_replace,
                        {'acl_index': acl_index,
                         'r': rules,
                         'count': len(rules),
                         'tag': tag})

    def macip_acl_interface_add_del(self,
                                    sw_if_index,
                                    acl_index,
                                    is_add=1):
        """ Add MACIP acl to interface

        :param sw_if_index:
        :param acl_index:
        :param is_add:  (Default value = 1)
        """

        return self.api(self.papi.macip_acl_interface_add_del,
                        {'is_add': is_add,
                         'sw_if_index': sw_if_index,
                         'acl_index': acl_index})

    def macip_acl_dump(self, acl_index=4294967295):
        """ Return MACIP acl dump
        """

        return self.api(
            self.papi.macip_acl_dump, {'acl_index': acl_index})

    def policer_add_del(self,
                        name,
                        cir,
                        eir,
                        cb,
                        eb,
                        is_add=1,
                        rate_type=0,
                        round_type=0,
                        ptype=0,
                        color_aware=0,
                        conform_action_type=1,
                        conform_dscp=0,
                        exceed_action_type=0,
                        exceed_dscp=0,
                        violate_action_type=0,
                        violate_dscp=0):
        return self.api(self.papi.policer_add_del,
                        {'name': name,
                         'cir': cir,
                         'eir': eir,
                         'cb': cb,
                         'eb': eb,
                         'is_add': is_add,
                         'rate_type': rate_type,
                         'round_type': round_type,
                         'type': ptype,
                         'color_aware': color_aware,
                         'conform_action_type': conform_action_type,
                         'conform_dscp': conform_dscp,
                         'exceed_action_type': exceed_action_type,
                         'exceed_dscp': exceed_dscp,
                         'violate_action_type': violate_action_type,
                         'violate_dscp': violate_dscp})

    def ip_punt_police(self,
                       policer_index,
                       is_ip6=0,
                       is_add=1):
        return self.api(self.papi.ip_punt_police,
                        {'policer_index': policer_index,
                         'is_add': is_add,
                         'is_ip6': is_ip6})

    def ip_punt_redirect(self,
                         rx_sw_if_index,
                         tx_sw_if_index,
                         address,
                         is_add=1):
        return self.api(self.papi.ip_punt_redirect,
                        {'punt': {'rx_sw_if_index': rx_sw_if_index,
                                  'tx_sw_if_index': tx_sw_if_index,
                                  'nh': address},
                         'is_add': is_add})

    def ip_punt_redirect_dump(self, sw_if_index, is_ipv6=0):
        return self.api(self.papi.ip_punt_redirect_dump,
                        {'sw_if_index': sw_if_index,
                         'is_ipv6': is_ipv6})

    def bier_table_add_del(self,
                           bti,
                           mpls_label,
                           is_add=1):
        """ BIER Table add/del """
        return self.api(
            self.papi.bier_table_add_del,
            {'bt_tbl_id': {"bt_set": bti.set_id,
                           "bt_sub_domain": bti.sub_domain_id,
                           "bt_hdr_len_id": bti.hdr_len_id},
             'bt_label': mpls_label,
             'bt_is_add': is_add})

    def bier_table_dump(self):
        return self.api(self.papi.bier_table_dump, {})

    def bier_route_add_del(self,
                           bti,
                           bp,
                           paths,
                           is_add=1,
                           is_replace=0):
        """ BIER Route add/del """
        return self.api(
            self.papi.bier_route_add_del,
            {
                'br_route': {
                    'br_tbl_id': {"bt_set": bti.set_id,
                                  "bt_sub_domain": bti.sub_domain_id,
                                  "bt_hdr_len_id": bti.hdr_len_id},
                    'br_bp': bp,
                    'br_n_paths': len(paths),
                    'br_paths': paths,
                },
                'br_is_add': is_add,
                'br_is_replace': is_replace
            })

    def bier_route_dump(self, bti):
        return self.api(
            self.papi.bier_route_dump,
            {'br_tbl_id': {"bt_set": bti.set_id,
                           "bt_sub_domain": bti.sub_domain_id,
                           "bt_hdr_len_id": bti.hdr_len_id}})

    def bier_imp_add(self,
                     bti,
                     src,
                     ibytes,
                     is_add=1):
        """ BIER Imposition Add """
        return self.api(
            self.papi.bier_imp_add,
            {'bi_tbl_id': {"bt_set": bti.set_id,
                           "bt_sub_domain": bti.sub_domain_id,
                           "bt_hdr_len_id": bti.hdr_len_id},
             'bi_src': src,
             'bi_n_bytes': len(ibytes),
             'bi_bytes': ibytes})

    def bier_imp_del(self, bi_index):
        """ BIER Imposition del """
        return self.api(
            self.papi.bier_imp_del,
            {'bi_index': bi_index})

    def bier_imp_dump(self):
        return self.api(self.papi.bier_imp_dump, {})

    def bier_disp_table_add_del(self,
                                bdti,
                                is_add=1):
        """ BIER Disposition Table add/del """
        return self.api(
            self.papi.bier_disp_table_add_del,
            {'bdt_tbl_id': bdti,
             'bdt_is_add': is_add})

    def bier_disp_table_dump(self):
        return self.api(self.papi.bier_disp_table_dump, {})

    def bier_disp_entry_add_del(self,
                                bdti,
                                bp,
                                payload_proto,
                                next_hop_afi,
                                next_hop,
                                next_hop_tbl_id=0,
                                next_hop_rpf_id=~0,
                                next_hop_is_ip4=1,
                                is_add=1):
        """ BIER Route add/del """
        lstack = []
        while (len(lstack) < 16):
            lstack.append({})
        return self.api(
            self.papi.bier_disp_entry_add_del,
            {'bde_tbl_id': bdti,
             'bde_bp': bp,
             'bde_payload_proto': payload_proto,
             'bde_n_paths': 1,
             'bde_paths': [{'table_id': next_hop_tbl_id,
                            'rpf_id': next_hop_rpf_id,
                            'n_labels': 0,
                            'label_stack': lstack}],
             'bde_is_add': is_add})

    def bier_disp_entry_dump(self, bdti):
        return self.api(
            self.papi.bier_disp_entry_dump,
            {'bde_tbl_id': bdti})

    def session_enable_disable(self, is_enabled):
        return self.api(
            self.papi.session_enable_disable,
            {'is_enable': is_enabled})

    def ipsec_spd_add_del(self, spd_id, is_add=1):
        """ SPD add/del - Wrapper to add or del ipsec SPD
        Sample CLI : 'ipsec spd add 1'

        :param spd_id - SPD ID to be created in the vpp . mandatory
        :param is_add - create (1) or delete(0) SPD (Default 1 - add) .
              optional
        :returns: reply from the API
        """
        return self.api(
            self.papi.ipsec_spd_add_del, {
                'spd_id': spd_id, 'is_add': is_add})

    def ipsec_spds_dump(self):
        return self.api(self.papi.ipsec_spds_dump, {})

    def ipsec_interface_add_del_spd(self, spd_id, sw_if_index, is_add=1):
        """ IPSEC interface SPD add/del - \
             Wrapper to associate/disassociate SPD to interface in VPP
        Sample CLI : 'set interface ipsec spd GigabitEthernet0/6/0 1'

        :param spd_id - SPD ID to associate with the interface . mandatory
        :param sw_if_index - Interface Index which needs to ipsec \
            association mandatory
        :param is_add - add(1) or del(0) association with interface \
                (Default 1 - add) . optional
        :returns: reply from the API
        """
        return self.api(
            self.papi.ipsec_interface_add_del_spd,
            {'spd_id': spd_id, 'sw_if_index': sw_if_index, 'is_add': is_add})

    def ipsec_spd_interface_dump(self, spd_index=None):
        return self.api(self.papi.ipsec_spd_interface_dump,
                        {'spd_index': spd_index if spd_index else 0,
                         'spd_index_valid': 1 if spd_index else 0})

    def ipsec_sad_entry_add_del(self,
                                sad_id,
                                spi,
                                integrity_algorithm,
                                integrity_key,
                                crypto_algorithm,
                                crypto_key,
                                protocol,
                                tunnel_src_address='',
                                tunnel_dst_address='',
                                flags=0,
                                salt=0,
                                is_add=1):
        """ IPSEC SA add/del
        :param sad_id: security association ID
        :param spi: security param index of the SA in decimal
        :param integrity_algorithm:
        :param integrity_key:
        :param crypto_algorithm:
        :param crypto_key:
        :param protocol: AH(0) or ESP(1) protocol
        :param tunnel_src_address: tunnel mode outer src address
        :param tunnel_dst_address: tunnel mode outer dst address
        :param is_add:
        :param is_tunnel:
        :** reference /vpp/src/vnet/ipsec/ipsec.h file for enum values of
             crypto and ipsec algorithms
        """
        return self.api(
            self.papi.ipsec_sad_entry_add_del,
            {
                'is_add': is_add,
                'entry':
                    {
                        'sad_id': sad_id,
                        'spi': spi,
                        'tunnel_src': tunnel_src_address,
                        'tunnel_dst': tunnel_dst_address,
                        'protocol': protocol,
                        'integrity_algorithm': integrity_algorithm,
                        'integrity_key': {
                            'length': len(integrity_key),
                            'data': integrity_key,
                        },
                        'crypto_algorithm': crypto_algorithm,
                        'crypto_key': {
                            'length': len(crypto_key),
                            'data': crypto_key,
                        },
                        'flags': flags,
                        'salt': salt,
                    }
            })

    def ipsec_sa_dump(self, sa_id=None):
        return self.api(self.papi.ipsec_sa_dump,
                        {'sa_id': sa_id if sa_id else 0xffffffff})

    def ipsec_spd_entry_add_del(self,
                                spd_id,
                                sa_id,
                                local_address_start,
                                local_address_stop,
                                remote_address_start,
                                remote_address_stop,
                                local_port_start=0,
                                local_port_stop=65535,
                                remote_port_start=0,
                                remote_port_stop=65535,
                                protocol=0,
                                policy=0,
                                priority=100,
                                is_outbound=1,
                                is_add=1,
                                is_ipv6=0,
                                is_ip_any=0):
        """ IPSEC policy SPD add/del   -
                    Wrapper to configure ipsec SPD policy entries in VPP
        :param spd_id: SPD ID for the policy
        :param local_address_start: local-ip-range start address
        :param local_address_stop : local-ip-range stop address
        :param remote_address_start: remote-ip-range start address
        :param remote_address_stop : remote-ip-range stop address
        :param local_port_start: (Default value = 0)
        :param local_port_stop: (Default value = 65535)
        :param remote_port_start: (Default value = 0)
        :param remote_port_stop: (Default value = 65535)
        :param protocol: Any(0), AH(51) & ESP(50) protocol (Default value = 0)
        :param sa_id: Security Association ID for mapping it to SPD
        :param policy: bypass(0), discard(1), resolve(2) or protect(3) action
               (Default value = 0)
        :param priority: value for the spd action (Default value = 100)
        :param is_outbound: flag for inbound(0) or outbound(1)
               (Default value = 1)
        :param is_add: (Default value = 1)
        """
        return self.api(
            self.papi.ipsec_spd_entry_add_del,
            {
                'is_add': is_add,
                'entry':
                    {
                        'spd_id': spd_id,
                        'sa_id': sa_id,
                        'local_address_start': local_address_start,
                        'local_address_stop': local_address_stop,
                        'remote_address_start': remote_address_start,
                        'remote_address_stop': remote_address_stop,
                        'local_port_start': local_port_start,
                        'local_port_stop': local_port_stop,
                        'remote_port_start': remote_port_start,
                        'remote_port_stop': remote_port_stop,
                        'protocol': protocol,
                        'policy': policy,
                        'priority': priority,
                        'is_outbound': is_outbound,
                    }
            })

    def ipsec_spd_dump(self, spd_id, sa_id=0xffffffff):
        return self.api(self.papi.ipsec_spd_dump,
                        {'spd_id': spd_id,
                         'sa_id': sa_id})

    def ipsec_tunnel_if_add_del(self, local_ip, remote_ip, local_spi,
                                remote_spi, crypto_alg, local_crypto_key,
                                remote_crypto_key, integ_alg, local_integ_key,
                                remote_integ_key, is_add=1, esn=0, salt=0,
                                anti_replay=1, renumber=0,
                                udp_encap=0, show_instance=0xffffffff):
        return self.api(
            self.papi.ipsec_tunnel_if_add_del,
            {
                'local_ip': local_ip,
                'remote_ip': remote_ip,
                'local_spi': local_spi,
                'remote_spi': remote_spi,
                'crypto_alg': crypto_alg,
                'local_crypto_key_len': len(local_crypto_key),
                'local_crypto_key': local_crypto_key,
                'remote_crypto_key_len': len(remote_crypto_key),
                'remote_crypto_key': remote_crypto_key,
                'integ_alg': integ_alg,
                'local_integ_key_len': len(local_integ_key),
                'local_integ_key': local_integ_key,
                'remote_integ_key_len': len(remote_integ_key),
                'remote_integ_key': remote_integ_key,
                'is_add': is_add,
                'esn': esn,
                'anti_replay': anti_replay,
                'renumber': renumber,
                'show_instance': show_instance,
                'udp_encap': udp_encap,
                'salt': salt
            })

    def ipsec_select_backend(self, protocol, index):
        return self.api(self.papi.ipsec_select_backend,
                        {'protocol': protocol, 'index': index})

    def ipsec_backend_dump(self):
        return self.api(self.papi.ipsec_backend_dump, {})

    def app_namespace_add_del(self,
                              namespace_id,
                              ip4_fib_id=0,
                              ip6_fib_id=0,
                              sw_if_index=0xFFFFFFFF,
                              secret=0):
        return self.api(
            self.papi.app_namespace_add_del,
            {'secret': secret,
             'sw_if_index': sw_if_index,
             'ip4_fib_id': ip4_fib_id,
             'ip6_fib_id': ip6_fib_id,
             'namespace_id': namespace_id,
             'namespace_id_len': len(namespace_id)})

    def punt_socket_register(self, reg, pathname,
                             header_version=1):
        """ Register punt socket """
        return self.api(self.papi.punt_socket_register,
                        {'header_version': header_version,
                         'punt': reg,
                         'pathname': pathname})

    def punt_socket_deregister(self, reg):
        """ Unregister punt socket """
        return self.api(self.papi.punt_socket_deregister,
                        {'punt': reg})

    def gbp_endpoint_add(self, sw_if_index, ips, mac, sclass, flags,
                         tun_src, tun_dst):
        """ GBP endpoint Add """
        return self.api(self.papi.gbp_endpoint_add,
                        {'endpoint': {
                            'sw_if_index': sw_if_index,
                            'ips': ips,
                            'n_ips': len(ips),
                            'mac': mac,
                            'sclass': sclass,
                            'flags': flags,
                            'tun': {
                                'src': tun_src,
                                'dst': tun_dst,
                            }}})

    def gbp_endpoint_del(self, handle):
        """ GBP endpoint Del """
        return self.api(self.papi.gbp_endpoint_del,
                        {'handle': handle})

    def gbp_endpoint_dump(self):
        """ GBP endpoint Dump """
        return self.api(self.papi.gbp_endpoint_dump, {})

    def gbp_endpoint_group_add(self, vnid, sclass, bd,
                               rd, uplink_sw_if_index,
                               retention):
        """ GBP endpoint group Add """
        return self.api(self.papi.gbp_endpoint_group_add,
                        {'epg':
                            {
                                'uplink_sw_if_index': uplink_sw_if_index,
                                'bd_id': bd,
                                'rd_id': rd,
                                'vnid': vnid,
                                'sclass': sclass,
                                'retention': retention
                            }})

    def gbp_endpoint_group_del(self, sclass):
        """ GBP endpoint group Del """
        return self.api(self.papi.gbp_endpoint_group_del,
                        {'sclass': sclass})

    def gbp_bridge_domain_add(self, bd_id, rd_id, flags,
                              bvi_sw_if_index,
                              uu_fwd_sw_if_index,
                              bm_flood_sw_if_index):
        """ GBP bridge-domain Add """
        return self.api(self.papi.gbp_bridge_domain_add,
                        {'bd':
                            {
                                'flags': flags,
                                'bvi_sw_if_index': bvi_sw_if_index,
                                'uu_fwd_sw_if_index': uu_fwd_sw_if_index,
                                'bm_flood_sw_if_index': bm_flood_sw_if_index,
                                'bd_id': bd_id,
                                'rd_id': rd_id
                            }})

    def gbp_bridge_domain_del(self, bd_id):
        """ GBP bridge-domain Del """
        return self.api(self.papi.gbp_bridge_domain_del,
                        {'bd_id': bd_id})

    def gbp_route_domain_add(self, rd_id,
                             scope,
                             ip4_table_id,
                             ip6_table_id,
                             ip4_uu_sw_if_index,
                             ip6_uu_sw_if_index):
        """ GBP route-domain Add """
        return self.api(self.papi.gbp_route_domain_add,
                        {'rd':
                            {
                                'scope': scope,
                                'ip4_table_id': ip4_table_id,
                                'ip6_table_id': ip6_table_id,
                                'ip4_uu_sw_if_index': ip4_uu_sw_if_index,
                                'ip6_uu_sw_if_index': ip6_uu_sw_if_index,
                                'rd_id': rd_id
                            }})

    def gbp_route_domain_del(self, rd_id):
        """ GBP route-domain Del """
        return self.api(self.papi.gbp_route_domain_del,
                        {'rd_id': rd_id})

    def gbp_recirc_add_del(self, is_add, sw_if_index, sclass, is_ext):
        """ GBP recirc Add/Del """
        return self.api(self.papi.gbp_recirc_add_del,
                        {'is_add': is_add,
                         'recirc': {
                             'is_ext': is_ext,
                             'sw_if_index': sw_if_index,
                             'sclass': sclass}})

    def gbp_recirc_dump(self):
        """ GBP recirc Dump """
        return self.api(self.papi.gbp_recirc_dump, {})

    def gbp_ext_itf_add_del(self, is_add, sw_if_index, bd_id, rd_id, flags):
        """ GBP recirc Add/Del """
        return self.api(self.papi.gbp_ext_itf_add_del,
                        {'is_add': is_add,
                         'ext_itf': {
                             'sw_if_index': sw_if_index,
                             'bd_id': bd_id,
                             'rd_id': rd_id,
                             'flags': flags}})

    def gbp_ext_itf_dump(self):
        """ GBP recirc Dump """
        return self.api(self.papi.gbp_ext_itf_dump, {})

    def gbp_subnet_add_del(self, is_add, rd_id,
                           prefix, type,
                           sw_if_index=0xffffffff,
                           sclass=0xffff):
        """ GBP Subnet Add/Del """
        return self.api(self.papi.gbp_subnet_add_del,
                        {'is_add': is_add,
                         'subnet': {
                             'type': type,
                             'sw_if_index': sw_if_index,
                             'sclass': sclass,
                             'prefix': prefix,
                             'rd_id': rd_id}})

    def gbp_subnet_dump(self):
        """ GBP Subnet Dump """
        return self.api(self.papi.gbp_subnet_dump, {})

    def gbp_contract_dump(self):
        """ GBP contract Dump """
        return self.api(self.papi.gbp_contract_dump, {})

    def gbp_vxlan_tunnel_add(self, vni, bd_rd_id, mode, src):
        """ GBP VXLAN tunnel add """
        return self.api(self.papi.gbp_vxlan_tunnel_add,
                        {
                            'tunnel': {
                                'vni': vni,
                                'mode': mode,
                                'bd_rd_id': bd_rd_id,
                                'src': src
                            }
                        })

    def gbp_vxlan_tunnel_del(self, vni):
        """ GBP VXLAN tunnel del """
        return self.api(self.papi.gbp_vxlan_tunnel_del,
                        {
                            'vni': vni,
                        })

    def gbp_vxlan_tunnel_dump(self):
        """ GBP VXLAN tunnel add/del """
        return self.api(self.papi.gbp_vxlan_tunnel_dump, {})

    def igmp_enable_disable(self, sw_if_index, enable, host):
        """ Enable/disable IGMP on a given interface """
        return self.api(self.papi.igmp_enable_disable,
                        {'enable': enable,
                         'mode': host,
                         'sw_if_index': sw_if_index})

    def igmp_proxy_device_add_del(self, vrf_id, sw_if_index, add):
        """ Add/del IGMP proxy device """
        return self.api(self.papi.igmp_proxy_device_add_del,
                        {'vrf_id': vrf_id, 'sw_if_index': sw_if_index,
                         'add': add})

    def igmp_proxy_device_add_del_interface(self, vrf_id, sw_if_index, add):
        """ Add/del interface to/from IGMP proxy device """
        return self.api(self.papi.igmp_proxy_device_add_del_interface,
                        {'vrf_id': vrf_id, 'sw_if_index': sw_if_index,
                         'add': add})

    def igmp_listen(self, filter, sw_if_index, saddrs, gaddr):
        """ Listen for new (S,G) on specified interface

        :param enable: add/del
        :param sw_if_index: interface sw index
        :param saddr: source ip4 addr
        :param gaddr: group ip4 addr
        """
        return self.api(self.papi.igmp_listen,
                        {
                            'group':
                                {
                                    'filter': filter,
                                    'sw_if_index': sw_if_index,
                                    'n_srcs': len(saddrs),
                                    'saddrs': saddrs,
                                    'gaddr': gaddr
                                }
                        })

    def igmp_clear_interface(self, sw_if_index):
        """ Remove all (S,G)s from specified interface
            doesn't send IGMP report!
        """
        return self.api(
            self.papi.igmp_clear_interface, {
                'sw_if_index': sw_if_index})

    def want_igmp_events(self, enable=1):
        return self.api(self.papi.want_igmp_events, {'enable': enable,
                                                     'pid': os.getpid()})

    def bond_create(
            self,
            mode,
            lb,
            numa_only,
            use_custom_mac,
            mac_address='',
            interface_id=0xFFFFFFFF):
        """
        :param mode: mode
        :param lb: load balance
        :param numa_only: tx on local numa node for lacp mode
        :param use_custom_mac: use custom mac
        :param mac_address: mac address
        :param interface_id: custom interface ID
        """
        return self.api(
            self.papi.bond_create,
            {'mode': mode,
             'lb': lb,
             'numa_only': numa_only,
             'use_custom_mac': use_custom_mac,
             'mac_address': mac_address,
             'id': interface_id
             })

    def pipe_delete(self, parent_sw_if_index):
        return self.api(self.papi.pipe_delete,
                        {'parent_sw_if_index': parent_sw_if_index})

    def svs_table_add_del(self, af, table_id, is_add=1):
        return self.api(self.papi.svs_table_add_del,
                        {
                            'table_id': table_id,
                            'is_add': is_add,
                            'af': af,
                        })

    def svs_route_add_del(self, table_id, prefix, src_table_id, is_add=1):
        return self.api(self.papi.svs_route_add_del,
                        {
                            'table_id': table_id,
                            'source_table_id': src_table_id,
                            'prefix': prefix,
                            'is_add': is_add,
                        })

    def svs_enable_disable(self, af, table_id, sw_if_index, is_enable=1):
        return self.api(self.papi.svs_enable_disable,
                        {
                            'af': af,
                            'table_id': table_id,
                            'sw_if_index': sw_if_index,
                            'is_enable': is_enable,
                        })

    def feature_gso_enable_disable(self, sw_if_index, enable_disable=1):
        return self.api(self.papi.feature_gso_enable_disable,
                        {
                            'sw_if_index': sw_if_index,
                            'enable_disable': enable_disable,
                        })
