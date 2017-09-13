import os
import fnmatch
import time
from hook import Hook
from collections import deque

# Sphinx creates auto-generated documentation by importing the python source
# files and collecting the docstrings from them. The NO_VPP_PAPI flag allows
# the vpp_papi_provider.py file to be importable without having to build
# the whole vpp api if the user only wishes to generate the test documentation.
do_import = True
try:
    no_vpp_papi = os.getenv("NO_VPP_PAPI")
    if no_vpp_papi == "1":
        do_import = False
except:
    pass

if do_import:
    from vpp_papi import VPP

# from vnet/vnet/mpls/mpls_types.h
MPLS_IETF_MAX_LABEL = 0xfffff
MPLS_LABEL_INVALID = MPLS_IETF_MAX_LABEL + 1


class L2_VTR_OP:
    L2_DISABLED = 0
    L2_PUSH_1 = 1
    L2_PUSH_2 = 2
    L2_POP_1 = 3
    L2_POP_2 = 4
    L2_TRANSLATE_1_1 = 5
    L2_TRANSLATE_1_2 = 6
    L2_TRANSLATE_2_1 = 7
    L2_TRANSLATE_2_2 = 8


class UnexpectedApiReturnValueError(Exception):
    """ exception raised when the API return value is unexpected """
    pass


class VppPapiProvider(object):
    """VPP-api provider using vpp-papi

    @property hook: hook object providing before and after api/cli hooks
    """

    _zero, _negative = range(2)

    def __init__(self, name, shm_prefix, test_class):
        self.hook = Hook("vpp-papi-provider")
        self.name = name
        self.shm_prefix = shm_prefix
        self.test_class = test_class
        self._expect_api_retval = self._zero
        self._expect_stack = []
        jsonfiles = []

        install_dir = os.getenv('VPP_TEST_INSTALL_PATH')
        for root, dirnames, filenames in os.walk(install_dir):
            for filename in fnmatch.filter(filenames, '*.api.json'):
                jsonfiles.append(os.path.join(root, filename))

        self.vpp = VPP(jsonfiles, logger=test_class.logger)
        self._events = deque()

    def __enter__(self):
        return self

    def expect_negative_api_retval(self):
        """ Expect API failure """
        self._expect_stack.append(self._expect_api_retval)
        self._expect_api_retval = self._negative
        return self

    def expect_zero_api_retval(self):
        """ Expect API success """
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
            time.sleep(0)  # yield
        raise Exception("Event did not occur within timeout")

    def __call__(self, name, event):
        """ Enqueue event in the internal event queue. """
        # FIXME use the name instead of relying on type(e).__name__ ?
        # FIXME #2 if this throws, it is eaten silently, Ole?
        self.test_class.logger.debug("New event: %s: %s" % (name, event))
        self._events.append(event)

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
                msg = "API call passed unexpectedly: expected negative "\
                    "return value instead of %d in %s" % \
                    (reply.retval, repr(reply))
                self.test_class.logger.info(msg)
                raise UnexpectedApiReturnValueError(msg)
        elif self._expect_api_retval == self._zero:
            if hasattr(reply, 'retval') and reply.retval != expected_retval:
                msg = "API call failed, expected %d return value instead "\
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

    def cli(self, cli):
        """ Execute a CLI, calling the before/after hooks appropriately.

        :param cli: CLI to execute
        :returns: CLI output

        """
        self.hook.before_cli(cli)
        cli += '\n'
        r = self.papi.cli_inband(length=len(cli), cmd=cli)
        self.hook.after_cli(cli)
        if hasattr(r, 'reply'):
            return r.reply.decode().rstrip('\x00')

    def ppcli(self, cli):
        """ Helper method to print CLI command in case of info logging level.

        :param cli: CLI to execute
        :returns: CLI output
        """
        return cli + "\n" + str(self.cli(cli))

    def _convert_mac(self, mac):
        return int(mac.replace(":", ""), 16) << 16

    def show_version(self):
        """ """
        return self.api(self.papi.show_version, {})

    def pg_create_interface(self, pg_index):
        """

        :param pg_index:

        """
        return self.api(self.papi.pg_create_interface,
                        {"interface_id": pg_index})

    def sw_interface_dump(self, filter=None):
        """

        :param filter:  (Default value = None)

        """
        if filter is not None:
            args = {"name_filter_valid": 1, "name_filter": filter}
        else:
            args = {}
        return self.api(self.papi.sw_interface_dump, args)

    def sw_interface_set_table(self, sw_if_index, is_ipv6, table_id):
        """ Set the IPvX Table-id for the Interface

        :param sw_if_index:
        :param is_ipv6:
        :param table_id:

        """
        return self.api(self.papi.sw_interface_set_table,
                        {'sw_if_index': sw_if_index, 'is_ipv6': is_ipv6,
                         'vrf_id': table_id})

    def sw_interface_add_del_address(self, sw_if_index, addr, addr_len,
                                     is_ipv6=0, is_add=1, del_all=0):
        """

        :param addr: param is_ipv6:  (Default value = 0)
        :param sw_if_index:
        :param addr_len:
        :param is_ipv6:  (Default value = 0)
        :param is_add:  (Default value = 1)
        :param del_all:  (Default value = 0)

        """
        return self.api(self.papi.sw_interface_add_del_address,
                        {'sw_if_index': sw_if_index,
                         'is_add': is_add,
                         'is_ipv6': is_ipv6,
                         'del_all': del_all,
                         'address_length': addr_len,
                         'address': addr})

    def sw_interface_set_unnumbered(self, sw_if_index, ip_sw_if_index,
                                    is_add=1):
        """ Set the Interface to be unnumbered

        :param is_add:  (Default value = 1)
        :param sw_if_index - interface That will be unnumbered
        :param ip_sw_if_index - interface with an IP addres

        """
        return self.api(self.papi.sw_interface_set_unnumbered,
                        {'sw_if_index': ip_sw_if_index,
                         'unnumbered_sw_if_index': sw_if_index,
                         'is_add': is_add})

    def sw_interface_enable_disable_mpls(self, sw_if_index,
                                         is_enable=1):
        """
        Enable/Disable MPLS on the interface
        :param sw_if_index:
        :param is_enable:  (Default value = 1)

        """
        return self.api(self.papi.sw_interface_set_mpls_enable,
                        {'sw_if_index': sw_if_index,
                         'enable': is_enable})

    def sw_interface_ra_suppress(self, sw_if_index, suppress=1):
        return self.api(self.papi.sw_interface_ip6nd_ra_config,
                        {'sw_if_index': sw_if_index,
                         'suppress': suppress})

    def set_ip_flow_hash(self,
                         table_id,
                         src=1,
                         dst=1,
                         sport=1,
                         dport=1,
                         proto=1,
                         reverse=0,
                         is_ip6=0):
        return self.api(self.papi.set_ip_flow_hash,
                        {'vrf_id': table_id,
                         'src': src,
                         'dst': dst,
                         'dport': dport,
                         'sport': sport,
                         'proto': proto,
                         'reverse': reverse,
                         'is_ipv6': is_ip6})

    def ip6_nd_proxy(self, address, sw_if_index, is_del=0):
        return self.api(self.papi.ip6nd_proxy_add_del,
                        {'address': address,
                         'sw_if_index': sw_if_index,
                         'is_del': is_del})

    def ip6_sw_interface_ra_config(self, sw_if_index,
                                   no,
                                   suppress,
                                   send_unicast):
        return self.api(self.papi.sw_interface_ip6nd_ra_config,
                        {'sw_if_index': sw_if_index,
                         'is_no': no,
                         'suppress': suppress,
                         'send_unicast': send_unicast})

    def ip6_sw_interface_ra_prefix(self,
                                   sw_if_index,
                                   address,
                                   address_length,
                                   use_default=0,
                                   no_advertise=0,
                                   off_link=0,
                                   no_autoconfig=0,
                                   no_onlink=0,
                                   is_no=0,
                                   val_lifetime=0xffffffff,
                                   pref_lifetime=0xffffffff):
        return self.api(self.papi.sw_interface_ip6nd_ra_prefix,
                        {'sw_if_index': sw_if_index,
                         'address': address,
                         'address_length': address_length,
                         'use_default': use_default,
                         'no_advertise': no_advertise,
                         'off_link': off_link,
                         'no_autoconfig': no_autoconfig,
                         'no_onlink': no_onlink,
                         'is_no': is_no,
                         'val_lifetime': val_lifetime,
                         'pref_lifetime': pref_lifetime})

    def ip6_sw_interface_enable_disable(self, sw_if_index, enable):
        """
        Enable/Disable An interface for IPv6
        """
        return self.api(self.papi.sw_interface_ip6_enable_disable,
                        {'sw_if_index': sw_if_index,
                         'enable': enable})

    def vxlan_add_del_tunnel(
            self,
            src_addr,
            dst_addr,
            mcast_sw_if_index=0xFFFFFFFF,
            is_add=1,
            is_ipv6=0,
            encap_vrf_id=0,
            decap_next_index=0xFFFFFFFF,
            vni=0):
        """

        :param dst_addr:
        :param src_addr:
        :param is_add:  (Default value = 1)
        :param is_ipv6:  (Default value = 0)
        :param encap_vrf_id:  (Default value = 0)
        :param decap_next_index:  (Default value = 0xFFFFFFFF)
        :param mcast_sw_if_index:  (Default value = 0xFFFFFFFF)
        :param vni:  (Default value = 0)

        """
        return self.api(self.papi.vxlan_add_del_tunnel,
                        {'is_add': is_add,
                         'is_ipv6': is_ipv6,
                         'src_address': src_addr,
                         'dst_address': dst_addr,
                         'mcast_sw_if_index': mcast_sw_if_index,
                         'encap_vrf_id': encap_vrf_id,
                         'decap_next_index': decap_next_index,
                         'vni': vni})

    def bridge_domain_add_del(self, bd_id, flood=1, uu_flood=1, forward=1,
                              learn=1, arp_term=0, is_add=1):
        """Create/delete bridge domain.

        :param int bd_id: Bridge domain index.
        :param int flood: Enable/disable bcast/mcast flooding in the BD.
            (Default value = 1)
        :param int uu_flood: Enable/disable unknown unicast flood in the BD.
            (Default value = 1)
        :param int forward: Enable/disable forwarding on all interfaces in
            the BD. (Default value = 1)
        :param int learn: Enable/disable learning on all interfaces in the BD.
            (Default value = 1)
        :param int arp_term: Enable/disable arp termination in the BD.
            (Default value = 1)
        :param int is_add: Add or delete flag. (Default value = 1)
        """
        return self.api(self.papi.bridge_domain_add_del,
                        {'bd_id': bd_id,
                         'flood': flood,
                         'uu_flood': uu_flood,
                         'forward': forward,
                         'learn': learn,
                         'arp_term': arp_term,
                         'is_add': is_add})

    def bd_ip_mac_add_del(self, bd_id, mac, ip, is_ipv6=0, is_add=1):
        return self.api(self.papi.bd_ip_mac_add_del,
                        {'bd_id': bd_id,
                         'is_add': is_add,
                         'is_ipv6': is_ipv6,
                         'ip_address': ip,
                         'mac_address': mac})

    def want_ip4_arp_events(self, enable_disable=1, address=0):
        return self.api(self.papi.want_ip4_arp_events,
                        {'enable_disable': enable_disable,
                         'address': address,
                         'pid': os.getpid(), })

    def l2fib_add_del(self, mac, bd_id, sw_if_index, is_add=1, static_mac=0,
                      filter_mac=0, bvi_mac=0):
        """Create/delete L2 FIB entry.

        :param str mac: MAC address to create FIB entry for.
        :param int bd_id: Bridge domain index.
        :param int sw_if_index: Software interface index of the interface.
        :param int is_add: Add or delete flag. (Default value = 1)
        :param int static_mac: Set to 1 to create static MAC entry.
            (Default value = 0)
        :param int filter_mac: Set to 1 to drop packet that's source or
            destination MAC address contains defined MAC address.
            (Default value = 0)
        :param int bvi_mac: Set to 1 to create entry that points to BVI
            interface. (Default value = 0)
        """
        return self.api(self.papi.l2fib_add_del,
                        {'mac': self._convert_mac(mac),
                         'bd_id': bd_id,
                         'sw_if_index': sw_if_index,
                         'is_add': is_add,
                         'static_mac': static_mac,
                         'filter_mac': filter_mac,
                         'bvi_mac': bvi_mac})

    def l2fib_flush_int(self, sw_if_index):
        """Flush L2 FIB entries for sw_if_index.

        :param int sw_if_index: Software interface index of the interface.
        """
        return self.api(self.papi.l2fib_flush_int,
                        {'sw_if_index': sw_if_index})

    def l2fib_flush_bd(self, bd_id):
        """Flush L2 FIB entries for bd_id.

        :param int sw_if_index: Bridge Domain id.
        """
        return self.api(self.papi.l2fib_flush_bd,
                        {'bd_id': bd_id})

    def l2fib_flush_all(self):
        """Flush all L2 FIB.
        """
        return self.api(self.papi.l2fib_flush_all, {})

    def sw_interface_set_l2_bridge(self, sw_if_index, bd_id,
                                   shg=0, bvi=0, enable=1):
        """Add/remove interface to/from bridge domain.

        :param int sw_if_index: Software interface index of the interface.
        :param int bd_id: Bridge domain index.
        :param int shg: Split-horizon group index. (Default value = 0)
        :param int bvi: Set interface as a bridge group virtual interface.
            (Default value = 0)
        :param int enable: Add or remove interface. (Default value = 1)
        """
        return self.api(self.papi.sw_interface_set_l2_bridge,
                        {'rx_sw_if_index': sw_if_index,
                         'bd_id': bd_id,
                         'shg': shg,
                         'bvi': bvi,
                         'enable': enable})

    def bridge_flags(self, bd_id, is_set, feature_bitmap):
        """Enable/disable required feature of the bridge domain with defined ID.

        :param int bd_id: Bridge domain ID.
        :param int is_set: Set to 1 to enable, set to 0 to disable the feature.
        :param int feature_bitmap: Bitmap value of the feature to be set:
            - learn (1 << 0),
            - forward (1 << 1),
            - flood (1 << 2),
            - uu-flood (1 << 3) or
            - arp-term (1 << 4).
        """
        return self.api(self.papi.bridge_flags,
                        {'bd_id': bd_id,
                         'is_set': is_set,
                         'feature_bitmap': feature_bitmap})

    def bridge_domain_dump(self, bd_id=0):
        """

        :param int bd_id: Bridge domain ID. (Default value = 0 => dump of all
            existing bridge domains returned)
        :return: Dictionary of bridge domain(s) data.
        """
        return self.api(self.papi.bridge_domain_dump,
                        {'bd_id': bd_id})

    def sw_interface_set_l2_xconnect(self, rx_sw_if_index, tx_sw_if_index,
                                     enable):
        """Create or delete unidirectional cross-connect from Tx interface to
        Rx interface.

        :param int rx_sw_if_index: Software interface index of Rx interface.
        :param int tx_sw_if_index: Software interface index of Tx interface.
        :param int enable: Create cross-connect if equal to 1, delete
            cross-connect if equal to 0.

        """
        return self.api(self.papi.sw_interface_set_l2_xconnect,
                        {'rx_sw_if_index': rx_sw_if_index,
                         'tx_sw_if_index': tx_sw_if_index,
                         'enable': enable})

    def sw_interface_set_l2_tag_rewrite(
            self,
            sw_if_index,
            vtr_oper,
            push=0,
            tag1=0,
            tag2=0):
        """L2 interface vlan tag rewrite configure request
        :param client_index - opaque cookie to identify the sender
        :param context - sender context, to match reply w/ request
        :param sw_if_index - interface the operation is applied to
        :param vtr_op - Choose from l2_vtr_op_t enum values
        :param push_dot1q - first pushed flag dot1q id set, else dot1ad
        :param tag1 - Needed for any push or translate vtr op
        :param tag2 - Needed for any push 2 or translate x-2 vtr ops

        """
        return self.api(self.papi.l2_interface_vlan_tag_rewrite,
                        {'sw_if_index': sw_if_index,
                         'vtr_op': vtr_oper,
                         'push_dot1q': push,
                         'tag1': tag1,
                         'tag2': tag2})

    def sw_interface_set_flags(self, sw_if_index, admin_up_down):
        """

        :param admin_up_down:
        :param sw_if_index:

        """
        return self.api(self.papi.sw_interface_set_flags,
                        {'sw_if_index': sw_if_index,
                         'admin_up_down': admin_up_down})

    def create_subif(self, sw_if_index, sub_id, outer_vlan, inner_vlan,
                     no_tags=0, one_tag=0, two_tags=0, dot1ad=0, exact_match=0,
                     default_sub=0, outer_vlan_id_any=0, inner_vlan_id_any=0):
        """Create subinterface
        from vpe.api: set dot1ad = 0 for dot1q, set dot1ad = 1 for dot1ad

        :param sub_id: param inner_vlan:
        :param sw_if_index:
        :param outer_vlan:
        :param inner_vlan:
        :param no_tags:  (Default value = 0)
        :param one_tag:  (Default value = 0)
        :param two_tags:  (Default value = 0)
        :param dot1ad:  (Default value = 0)
        :param exact_match:  (Default value = 0)
        :param default_sub:  (Default value = 0)
        :param outer_vlan_id_any:  (Default value = 0)
        :param inner_vlan_id_any:  (Default value = 0)

        """
        return self.api(
            self.papi.create_subif,
            {'sw_if_index': sw_if_index,
             'sub_id': sub_id,
             'no_tags': no_tags,
             'one_tag': one_tag,
             'two_tags': two_tags,
             'dot1ad': dot1ad,
             'exact_match': exact_match,
             'default_sub': default_sub,
             'outer_vlan_id_any': outer_vlan_id_any,
             'inner_vlan_id_any': inner_vlan_id_any,
             'outer_vlan_id': outer_vlan,
             'inner_vlan_id': inner_vlan})

    def create_p2pethernet_subif(self, sw_if_index, remote_mac, subif_id):
        """Create p2p ethernet subinterface

        :param sw_if_index: main (parent) interface
        :param remote_mac: client (remote) mac address

        """
        return self.api(
            self.papi.p2p_ethernet_add,
            {'parent_if_index': sw_if_index,
             'remote_mac': remote_mac,
             'subif_id': subif_id})

    def delete_subif(self, sw_if_index):
        """Delete subinterface

        :param sw_if_index:
        """
        return self.api(self.papi.delete_subif,
                        {'sw_if_index': sw_if_index})

    def delete_p2pethernet_subif(self, sw_if_index, remote_mac):
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

    def delete_loopback(self, sw_if_index):
        return self.api(self.papi.delete_loopback,
                        {'sw_if_index': sw_if_index, })

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
            {'table_id': table_id,
             'is_add': is_add,
             'is_ipv6': is_ipv6})

    def ip_add_del_route(
            self,
            dst_address,
            dst_address_length,
            next_hop_address,
            next_hop_sw_if_index=0xFFFFFFFF,
            table_id=0,
            next_hop_table_id=0,
            next_hop_weight=1,
            next_hop_n_out_labels=0,
            next_hop_out_label_stack=[],
            next_hop_via_label=MPLS_LABEL_INVALID,
            is_resolve_host=0,
            is_resolve_attached=0,
            classify_table_index=0xFFFFFFFF,
            is_add=1,
            is_drop=0,
            is_unreach=0,
            is_prohibit=0,
            is_ipv6=0,
            is_local=0,
            is_classify=0,
            is_multipath=0,
            not_last=0):
        """

        :param dst_address_length:
        :param next_hop_sw_if_index:  (Default value = 0xFFFFFFFF)
        :param dst_address:
        :param next_hop_address:
        :param next_hop_sw_if_index:  (Default value = 0xFFFFFFFF)
        :param vrf_id:  (Default value = 0)
        :param lookup_in_vrf:  (Default value = 0)
        :param classify_table_index:  (Default value = 0xFFFFFFFF)
        :param is_add:  (Default value = 1)
        :param is_drop:  (Default value = 0)
        :param is_ipv6:  (Default value = 0)
        :param is_local:  (Default value = 0)
        :param is_classify:  (Default value = 0)
        :param is_multipath:  (Default value = 0)
        :param is_resolve_host:  (Default value = 0)
        :param is_resolve_attached:  (Default value = 0)
        :param not_last:  (Default value = 0)
        :param next_hop_weight:  (Default value = 1)

        """

        return self.api(
            self.papi.ip_add_del_route,
            {'next_hop_sw_if_index': next_hop_sw_if_index,
             'table_id': table_id,
             'classify_table_index': classify_table_index,
             'next_hop_table_id': next_hop_table_id,
             'is_add': is_add,
             'is_drop': is_drop,
             'is_unreach': is_unreach,
             'is_prohibit': is_prohibit,
             'is_ipv6': is_ipv6,
             'is_local': is_local,
             'is_classify': is_classify,
             'is_multipath': is_multipath,
             'is_resolve_host': is_resolve_host,
             'is_resolve_attached': is_resolve_attached,
             'not_last': not_last,
             'next_hop_weight': next_hop_weight,
             'dst_address_length': dst_address_length,
             'dst_address': dst_address,
             'next_hop_address': next_hop_address,
             'next_hop_n_out_labels': next_hop_n_out_labels,
             'next_hop_via_label': next_hop_via_label,
             'next_hop_out_label_stack': next_hop_out_label_stack})

    def ip_fib_dump(self):
        return self.api(self.papi.ip_fib_dump, {})

    def ip6_fib_dump(self):
        return self.api(self.papi.ip6_fib_dump, {})

    def ip_neighbor_add_del(self,
                            sw_if_index,
                            mac_address,
                            dst_address,
                            is_add=1,
                            is_ipv6=0,
                            is_static=0,
                            is_no_adj_fib=0,
                            ):
        """ Add neighbor MAC to IPv4 or IPv6 address.

        :param sw_if_index:
        :param mac_address:
        :param dst_address:
        :param is_add:  (Default value = 1)
        :param is_ipv6:  (Default value = 0)
        :param is_static:  (Default value = 0)
        :param is_no_adj_fib:  (Default value = 0)
        """

        return self.api(
            self.papi.ip_neighbor_add_del,
            {'sw_if_index': sw_if_index,
             'is_add': is_add,
             'is_ipv6': is_ipv6,
             'is_static': is_static,
             'is_no_adj_fib': is_no_adj_fib,
             'mac_address': mac_address,
             'dst_address': dst_address
             }
        )

    def ip_neighbor_dump(self,
                         sw_if_index,
                         is_ipv6=0):
        """ Return IP neighbor dump.

        :param sw_if_index:
        :param int is_ipv6: 1 for IPv6 neighbor, 0 for IPv4. (Default = 0)
        """

        return self.api(
            self.papi.ip_neighbor_dump,
            {'is_ipv6': is_ipv6,
             'sw_if_index': sw_if_index
             }
        )

    def proxy_arp_add_del(self,
                          low_address,
                          hi_address,
                          vrf_id=0,
                          is_add=1):
        """ Config Proxy Arp Range.

        :param low_address: Start address in the rnage to Proxy for
        :param hi_address: End address in the rnage to Proxy for
        :param vrf_id: The VRF/table in which to proxy
        """

        return self.api(
            self.papi.proxy_arp_add_del,
            {'vrf_id': vrf_id,
             'is_add': is_add,
             'low_address': low_address,
             'hi_address': hi_address,
             }
        )

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

    def reset_vrf(self,
                  vrf_id,
                  is_ipv6=0,
                  ):
        """ Reset VRF (remove all routes etc.) request.

        :param int vrf_id: ID of the FIB table / VRF to reset.
        :param int is_ipv6: 1 for IPv6 neighbor, 0 for IPv4. (Default = 0)
        """

        return self.api(
            self.papi.reset_vrf,
            {'vrf_id': vrf_id,
             'is_ipv6': is_ipv6,
             }
        )

    def reset_fib(self,
                  vrf_id,
                  is_ipv6=0,
                  ):
        """ Reset VRF (remove all routes etc.) request.

        :param int vrf_id: ID of the FIB table / VRF to reset.
        :param int is_ipv6: 1 for IPv6 neighbor, 0 for IPv4. (Default = 0)
        """

        return self.api(
            self.papi.reset_fib,
            {'vrf_id': vrf_id,
             'is_ipv6': is_ipv6,
             }
        )

    def ip_dump(self,
                is_ipv6=0,
                ):
        """ Return IP dump.

        :param int is_ipv6: 1 for IPv6 neighbor, 0 for IPv4. (Default = 0)
        """

        return self.api(
            self.papi.ip_dump,
            {'is_ipv6': is_ipv6,
             }
        )

    def sw_interface_span_enable_disable(
            self, sw_if_index_from, sw_if_index_to, state=1, is_l2=0):
        """

        :param sw_if_index_from:
        :param sw_if_index_to:
        :param state:
        :param is_l2:
        """
        return self.api(self.papi.sw_interface_span_enable_disable,
                        {'sw_if_index_from': sw_if_index_from,
                         'sw_if_index_to': sw_if_index_to,
                         'state': state,
                         'is_l2': is_l2,
                         })

    def gre_tunnel_add_del(self,
                           src_address,
                           dst_address,
                           outer_fib_id=0,
                           is_teb=0,
                           is_add=1,
                           is_ip6=0):
        """ Add a GRE tunnel

        :param src_address:
        :param dst_address:
        :param outer_fib_id:  (Default value = 0)
        :param is_add:  (Default value = 1)
        :param is_ipv6:  (Default value = 0)
        :param is_teb:  (Default value = 0)
        """

        return self.api(
            self.papi.gre_add_del_tunnel,
            {'is_add': is_add,
             'is_ipv6': is_ip6,
             'teb': is_teb,
             'src_address': src_address,
             'dst_address': dst_address,
             'outer_fib_id': outer_fib_id}
        )

    def mpls_fib_dump(self):
        return self.api(self.papi.mpls_fib_dump, {})

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
            {'mt_table_id': table_id,
             'mt_is_add': is_add})

    def mpls_route_add_del(
            self,
            label,
            eos,
            next_hop_proto,
            next_hop_address,
            next_hop_sw_if_index=0xFFFFFFFF,
            table_id=0,
            next_hop_table_id=0,
            next_hop_weight=1,
            next_hop_n_out_labels=0,
            next_hop_out_label_stack=[],
            next_hop_via_label=MPLS_LABEL_INVALID,
            is_resolve_host=0,
            is_resolve_attached=0,
            is_interface_rx=0,
            is_rpf_id=0,
            is_multicast=0,
            is_add=1,
            is_drop=0,
            is_multipath=0,
            classify_table_index=0xFFFFFFFF,
            is_classify=0,
            not_last=0):
        """

        :param dst_address_length:
        :param next_hop_sw_if_index:  (Default value = 0xFFFFFFFF)
        :param dst_address:
        :param next_hop_address:
        :param next_hop_sw_if_index:  (Default value = 0xFFFFFFFF)
        :param vrf_id:  (Default value = 0)
        :param lookup_in_vrf:  (Default value = 0)
        :param classify_table_index:  (Default value = 0xFFFFFFFF)
        :param is_add:  (Default value = 1)
        :param is_drop:  (Default value = 0)
        :param is_ipv6:  (Default value = 0)
        :param is_local:  (Default value = 0)
        :param is_classify:  (Default value = 0)
        :param is_multipath:  (Default value = 0)
        :param is_multicast:  (Default value = 0)
        :param is_resolve_host:  (Default value = 0)
        :param is_resolve_attached:  (Default value = 0)
        :param not_last:  (Default value = 0)
        :param next_hop_weight:  (Default value = 1)

        """

        return self.api(
            self.papi.mpls_route_add_del,
            {'mr_label': label,
             'mr_eos': eos,
             'mr_table_id': table_id,
             'mr_classify_table_index': classify_table_index,
             'mr_is_add': is_add,
             'mr_is_classify': is_classify,
             'mr_is_multipath': is_multipath,
             'mr_is_multicast': is_multicast,
             'mr_is_resolve_host': is_resolve_host,
             'mr_is_resolve_attached': is_resolve_attached,
             'mr_is_interface_rx': is_interface_rx,
             'mr_is_rpf_id': is_rpf_id,
             'mr_next_hop_proto': next_hop_proto,
             'mr_next_hop_weight': next_hop_weight,
             'mr_next_hop': next_hop_address,
             'mr_next_hop_n_out_labels': next_hop_n_out_labels,
             'mr_next_hop_sw_if_index': next_hop_sw_if_index,
             'mr_next_hop_table_id': next_hop_table_id,
             'mr_next_hop_via_label': next_hop_via_label,
             'mr_next_hop_out_label_stack': next_hop_out_label_stack})

    def mpls_ip_bind_unbind(
            self,
            label,
            dst_address,
            dst_address_length,
            table_id=0,
            ip_table_id=0,
            is_ip4=1,
            is_bind=1):
        """
        """
        return self.api(
            self.papi.mpls_ip_bind_unbind,
            {'mb_mpls_table_id': table_id,
             'mb_label': label,
             'mb_ip_table_id': ip_table_id,
             'mb_is_bind': is_bind,
             'mb_is_ip4': is_ip4,
             'mb_address_length': dst_address_length,
             'mb_address': dst_address})

    def mpls_tunnel_add_del(
            self,
            tun_sw_if_index,
            next_hop_proto_is_ip4,
            next_hop_address,
            next_hop_sw_if_index=0xFFFFFFFF,
            next_hop_table_id=0,
            next_hop_weight=1,
            next_hop_n_out_labels=0,
            next_hop_out_label_stack=[],
            next_hop_via_label=MPLS_LABEL_INVALID,
            is_add=1,
            l2_only=0,
            is_multicast=0):
        """

        :param dst_address_length:
        :param next_hop_sw_if_index:  (Default value = 0xFFFFFFFF)
        :param dst_address:
        :param next_hop_address:
        :param next_hop_sw_if_index:  (Default value = 0xFFFFFFFF)
        :param vrf_id:  (Default value = 0)
        :param lookup_in_vrf:  (Default value = 0)
        :param classify_table_index:  (Default value = 0xFFFFFFFF)
        :param is_add:  (Default value = 1)
        :param is_drop:  (Default value = 0)
        :param is_ipv6:  (Default value = 0)
        :param is_local:  (Default value = 0)
        :param is_classify:  (Default value = 0)
        :param is_multipath:  (Default value = 0)
        :param is_resolve_host:  (Default value = 0)
        :param is_resolve_attached:  (Default value = 0)
        :param next_hop_weight:  (Default value = 1)
        :param is_multicast:  (Default value = 0)

        """
        return self.api(
            self.papi.mpls_tunnel_add_del,
            {'mt_sw_if_index': tun_sw_if_index,
             'mt_is_add': is_add,
             'mt_l2_only': l2_only,
             'mt_is_multicast': is_multicast,
             'mt_next_hop_proto_is_ip4': next_hop_proto_is_ip4,
             'mt_next_hop_weight': next_hop_weight,
             'mt_next_hop': next_hop_address,
             'mt_next_hop_n_out_labels': next_hop_n_out_labels,
             'mt_next_hop_sw_if_index': next_hop_sw_if_index,
             'mt_next_hop_table_id': next_hop_table_id,
             'mt_next_hop_out_label_stack': next_hop_out_label_stack})

    def nat44_interface_add_del_feature(
            self,
            sw_if_index,
            is_inside=1,
            is_add=1):
        """Enable/disable NAT44 feature on the interface

        :param sw_if_index: Software index of the interface
        :param is_inside: 1 if inside, 0 if outside (Default value = 1)
        :param is_add: 1 if add, 0 if delete (Default value = 1)
        """
        return self.api(
            self.papi.nat44_interface_add_del_feature,
            {'is_add': is_add,
             'is_inside': is_inside,
             'sw_if_index': sw_if_index})

    def nat44_interface_add_del_output_feature(
            self,
            sw_if_index,
            is_inside=1,
            is_add=1):
        """Enable/disable NAT44 output feature on the interface

        :param sw_if_index: Software index of the interface
        :param is_inside: 1 if inside, 0 if outside (Default value = 1)
        :param is_add: 1 if add, 0 if delete (Default value = 1)
        """
        return self.api(
            self.papi.nat44_interface_add_del_output_feature,
            {'is_add': is_add,
             'is_inside': is_inside,
             'sw_if_index': sw_if_index})

    def nat44_add_del_static_mapping(
            self,
            local_ip,
            external_ip=0,
            external_sw_if_index=0xFFFFFFFF,
            local_port=0,
            external_port=0,
            addr_only=1,
            vrf_id=0,
            protocol=0,
            is_add=1):
        """Add/delete NAT44 static mapping

        :param local_ip: Local IP address
        :param external_ip: External IP address
        :param external_sw_if_index: External interface instead of IP address
        :param local_port: Local port number (Default value = 0)
        :param external_port: External port number (Default value = 0)
        :param addr_only: 1 if address only mapping, 0 if address and port
        :param vrf_id: VRF ID
        :param protocol: IP protocol (Default value = 0)
        :param is_add: 1 if add, 0 if delete (Default value = 1)
        """
        return self.api(
            self.papi.nat44_add_del_static_mapping,
            {'is_add': is_add,
             'addr_only': addr_only,
             'local_ip_address': local_ip,
             'external_ip_address': external_ip,
             'local_port': local_port,
             'external_port': external_port,
             'external_sw_if_index': external_sw_if_index,
             'vrf_id': vrf_id,
             'protocol': protocol})

    def nat44_add_del_address_range(
            self,
            first_ip_address,
            last_ip_address,
            is_add=1,
            vrf_id=0xFFFFFFFF):
        """Add/del NAT44 address range

        :param first_ip_address: First IP address
        :param last_ip_address: Last IP address
        :param vrf_id: VRF id for the address range
        :param is_add: 1 if add, 0 if delete (Default value = 1)
        """
        return self.api(
            self.papi.nat44_add_del_address_range,
            {'first_ip_address': first_ip_address,
             'last_ip_address': last_ip_address,
             'vrf_id': vrf_id,
             'is_add': is_add})

    def nat44_address_dump(self):
        """Dump NAT44 addresses
        :return: Dictionary of NAT44 addresses
        """
        return self.api(self.papi.nat44_address_dump, {})

    def nat44_interface_dump(self):
        """Dump interfaces with NAT44 feature
        :return: Dictionary of interfaces with NAT44 feature
        """
        return self.api(self.papi.nat44_interface_dump, {})

    def nat44_interface_output_feature_dump(self):
        """Dump interfaces with NAT44 output feature
        :return: Dictionary of interfaces with NAT44 output feature
        """
        return self.api(self.papi.nat44_interface_output_feature_dump, {})

    def nat44_static_mapping_dump(self):
        """Dump NAT44 static mappings
        :return: Dictionary of NAT44 static mappings
        """
        return self.api(self.papi.nat44_static_mapping_dump, {})

    def nat_show_config(self):
        """Show NAT plugin config
        :return: NAT plugin config parameters
        """
        return self.api(self.papi.nat_show_config, {})

    def nat44_add_interface_addr(
            self,
            sw_if_index,
            is_add=1):
        """Add/del NAT44 address from interface

        :param sw_if_index: Software index of the interface
        :param is_add: 1 if add, 0 if delete (Default value = 1)
        """
        return self.api(self.papi.nat44_add_del_interface_addr,
                        {'is_add': is_add, 'sw_if_index': sw_if_index})

    def nat44_interface_addr_dump(self):
        """Dump NAT44 addresses interfaces
        :return: Dictionary of NAT44 addresses interfaces
        """
        return self.api(self.papi.nat44_interface_addr_dump, {})

    def nat_ipfix(
            self,
            domain_id=1,
            src_port=4739,
            enable=1):
        """Enable/disable NAT IPFIX logging

        :param domain_id: Observation domain ID (Default value = 1)
        :param src_port: Source port number (Default value = 4739)
        :param enable: 1 if enable, 0 if disable (Default value = 1)
        """
        return self.api(
            self.papi.nat_ipfix_enable_disable,
            {'domain_id': domain_id,
             'src_port': src_port,
             'enable': enable})

    def nat44_user_session_dump(
            self,
            ip_address,
            vrf_id):
        """Dump NAT44 user's sessions

        :param ip_address: ip adress of the user to be dumped
        :param cpu_index: cpu_index on which the user is
        :param vrf_id: VRF ID
        :return: Dictionary of S-NAT sessions
        """
        return self.api(
            self.papi.nat44_user_session_dump,
            {'ip_address': ip_address,
             'vrf_id': vrf_id})

    def nat44_user_dump(self):
        """Dump NAT44 users

        :return: Dictionary of NAT44 users
        """
        return self.api(self.papi.nat44_user_dump, {})

    def nat44_add_del_lb_static_mapping(
            self,
            external_addr,
            external_port,
            protocol,
            vrf_id=0,
            local_num=0,
            locals=None,
            is_add=1):
        """Add/delete NAT44 load balancing static mapping

        :param is_add - 1 if add, 0 if delete
        """
        return self.api(
            self.papi.nat44_add_del_lb_static_mapping,
            {'is_add': is_add,
             'external_addr': external_addr,
             'external_port': external_port,
             'protocol': protocol,
             'vrf_id': vrf_id,
             'local_num': local_num,
             'locals': locals})

    def nat44_lb_static_mapping_dump(self):
        """Dump NAT44 load balancing static mappings

        :return: Dictionary of NAT44 load balancing static mapping
        """
        return self.api(self.papi.nat44_lb_static_mapping_dump, {})

    def nat_det_add_del_map(
            self,
            in_addr,
            in_plen,
            out_addr,
            out_plen,
            is_add=1):
        """Add/delete deterministic NAT mapping

        :param is_add - 1 if add, 0 if delete
        :param in_addr - inside IP address
        :param in_plen - inside IP address prefix length
        :param out_addr - outside IP address
        :param out_plen - outside IP address prefix length
        """
        return self.api(
            self.papi.nat_det_add_del_map,
            {'is_add': is_add,
             'is_nat44': 1,
             'in_addr': in_addr,
             'in_plen': in_plen,
             'out_addr': out_addr,
             'out_plen': out_plen})

    def nat_det_forward(
            self,
            in_addr):
        """Get outside address and port range from inside address

        :param in_addr - inside IP address
        """
        return self.api(
            self.papi.nat_det_forward,
            {'in_addr': in_addr,
             'is_nat44': 1})

    def nat_det_reverse(
            self,
            out_addr,
            out_port):
        """Get inside address from outside address and port

        :param out_addr - outside IP address
        :param out_port - outside port
        """
        return self.api(
            self.papi.nat_det_reverse,
            {'out_addr': out_addr,
             'out_port': out_port})

    def nat_det_map_dump(self):
        """Dump deterministic NAT mappings

        :return: Dictionary of deterministic NAT mappings
        """
        return self.api(self.papi.nat_det_map_dump, {})

    def nat_det_set_timeouts(
            self,
            udp=300,
            tcp_established=7440,
            tcp_transitory=240,
            icmp=60):
        """Set values of timeouts for deterministic NAT (in seconds)

        :param udp - UDP timeout (Default value = 300)
        :param tcp_established - TCP established timeout (Default value = 7440)
        :param tcp_transitory - TCP transitory timeout (Default value = 240)
        :param icmp - ICMP timeout (Default value = 60)
        """
        return self.api(
            self.papi.nat_det_set_timeouts,
            {'udp': udp,
             'tcp_established': tcp_established,
             'tcp_transitory': tcp_transitory,
             'icmp': icmp})

    def nat_det_get_timeouts(self):
        """Get values of timeouts for deterministic NAT

        :return: Timeouts for deterministic NAT (in seconds)
        """
        return self.api(self.papi.nat_det_get_timeouts, {})

    def nat_det_close_session_out(
            self,
            out_addr,
            out_port,
            ext_addr,
            ext_port):
        """Close deterministic NAT session using outside address and port

        :param out_addr - outside IP address
        :param out_port - outside port
        :param ext_addr - external host IP address
        :param ext_port - external host port
        """
        return self.api(
            self.papi.nat_det_close_session_out,
            {'out_addr': out_addr,
             'out_port': out_port,
             'ext_addr': ext_addr,
             'ext_port': ext_port})

    def nat_det_close_session_in(
            self,
            in_addr,
            in_port,
            ext_addr,
            ext_port):
        """Close deterministic NAT session using inside address and port

        :param in_addr - inside IP address
        :param in_port - inside port
        :param ext_addr - external host IP address
        :param ext_port - external host port
        """
        return self.api(
            self.papi.nat_det_close_session_in,
            {'in_addr': in_addr,
             'in_port': in_port,
             'ext_addr': ext_addr,
             'ext_port': ext_port,
             'is_nat44': 1})

    def nat_det_session_dump(
            self,
            user_addr):
        """Dump deterministic NAT sessions belonging to a user

        :param user_addr - inside IP address of the user
        :return: Dictionary of deterministic NAT sessions
        """
        return self.api(
            self.papi.nat_det_session_dump,
            {'is_nat44': 1,
             'user_addr': user_addr})

    def nat64_add_del_pool_addr_range(
            self,
            start_addr,
            end_addr,
            vrf_id=0xFFFFFFFF,
            is_add=1):
        """Add/del address range to NAT64 pool

        :param start_addr: First IP address
        :param end_addr: Last IP address
        :param vrf_id: VRF id for the address range
        :param is_add: 1 if add, 0 if delete (Default value = 1)
        """
        return self.api(
            self.papi.nat64_add_del_pool_addr_range,
            {'start_addr': start_addr,
             'end_addr': end_addr,
             'vrf_id': vrf_id,
             'is_add': is_add})

    def nat64_pool_addr_dump(self):
        """Dump NAT64 pool addresses
        :return: Dictionary of NAT64 pool addresses
        """
        return self.api(self.papi.nat64_pool_addr_dump, {})

    def nat64_add_del_interface(
            self,
            sw_if_index,
            is_inside=1,
            is_add=1):
        """Enable/disable NAT64 feature on the interface
           :param sw_if_index: Index of the interface
           :param is_inside: 1 if inside, 0 if outside (Default value = 1)
           :param is_add: 1 if add, 0 if delete (Default value = 1)
        """
        return self.api(
            self.papi.nat64_add_del_interface,
            {'sw_if_index': sw_if_index,
             'is_inside': is_inside,
             'is_add': is_add})

    def nat64_interface_dump(self):
        """Dump interfaces with NAT64 feature
        :return: Dictionary of interfaces with NAT64 feature
        """
        return self.api(self.papi.nat64_interface_dump, {})

    def nat64_add_del_static_bib(
            self,
            in_ip,
            out_ip,
            in_port,
            out_port,
            protocol,
            vrf_id=0,
            is_add=1):
        """Add/delete S-NAT static BIB entry

        :param in_ip: Inside IPv6 address
        :param out_ip: Outside IPv4 address
        :param in_port: Inside port number
        :param out_port: Outside port number
        :param protocol: IP protocol
        :param vrf_id: VRF ID (Default value = 0)
        :param is_add: 1 if add, 0 if delete (Default value = 1)
        """
        return self.api(
            self.papi.nat64_add_del_static_bib,
            {'i_addr': in_ip,
             'o_addr': out_ip,
             'i_port': in_port,
             'o_port': out_port,
             'vrf_id': vrf_id,
             'proto': protocol,
             'is_add': is_add})

    def nat64_bib_dump(self, protocol=255):
        """Dump NAT64 BIB

        :param protocol: IP protocol (Default value = 255, all BIBs)
        :returns: Dictionary of NAT64 BIB entries
        """
        return self.api(self.papi.nat64_bib_dump, {'proto': protocol})

    def nat64_set_timeouts(self, udp=300, icmp=60, tcp_trans=240, tcp_est=7440,
                           tcp_incoming_syn=6):
        """Set values of timeouts for NAT64 (in seconds)

        :param udpi: UDP timeout (Default value = 300)
        :param icmp: ICMP timeout (Default value = 60)
        :param tcp_trans: TCP transitory timeout (Default value = 240)
        :param tcp_est: TCP established timeout (Default value = 7440)
        :param tcp_incoming_syn: TCP incoming SYN timeout (Default value = 6)
        """
        return self.api(
            self.papi.nat64_set_timeouts,
            {'udp': udp,
             'icmp': icmp,
             'tcp_trans': tcp_trans,
             'tcp_est': tcp_est,
             'tcp_incoming_syn': tcp_incoming_syn})

    def nat64_get_timeouts(self):
        """Get values of timeouts for NAT64

        :return: Timeouts for NAT64 (in seconds)
        """
        return self.api(self.papi.nat64_get_timeouts, {})

    def nat64_st_dump(self, protocol=255):
        """Dump NAT64 session table

        :param protocol: IP protocol (Default value = 255, all STs)
        :returns: Dictionary of NAT64 sesstion table entries
        """
        return self.api(self.papi.nat64_st_dump, {'proto': protocol})

    def nat64_add_del_prefix(self, prefix, plen, vrf_id=0, is_add=1):
        """Add/del NAT64 prefix

        :param prefix: NAT64 prefix
        :param plen: NAT64 prefix length
        :param vrf_id: VRF id of tenant (Default 0)
        :param is_add: 1 if add, 0 if delete (Default value = 1)
        """
        return self.api(
            self.papi.nat64_add_del_prefix,
            {'prefix': prefix,
             'prefix_len': plen,
             'vrf_id': vrf_id,
             'is_add': is_add})

    def nat64_prefix_dump(self):
        """Dump NAT64 prefix

        :returns: Dictionary of NAT64 prefixes
        """
        return self.api(self.papi.nat64_prefix_dump, {})

    def control_ping(self):
        self.api(self.papi.control_ping)

    def bfd_udp_add(self, sw_if_index, desired_min_tx, required_min_rx,
                    detect_mult, local_addr, peer_addr, is_ipv6=0,
                    bfd_key_id=None, conf_key_id=None):
        if bfd_key_id is None:
            return self.api(self.papi.bfd_udp_add,
                            {
                                'sw_if_index': sw_if_index,
                                'desired_min_tx': desired_min_tx,
                                'required_min_rx': required_min_rx,
                                'local_addr': local_addr,
                                'peer_addr': peer_addr,
                                'is_ipv6': is_ipv6,
                                'detect_mult': detect_mult,
                            })
        else:
            return self.api(self.papi.bfd_udp_add,
                            {
                                'sw_if_index': sw_if_index,
                                'desired_min_tx': desired_min_tx,
                                'required_min_rx': required_min_rx,
                                'local_addr': local_addr,
                                'peer_addr': peer_addr,
                                'is_ipv6': is_ipv6,
                                'detect_mult': detect_mult,
                                'is_authenticated': 1,
                                'bfd_key_id': bfd_key_id,
                                'conf_key_id': conf_key_id,
                            })

    def bfd_udp_mod(self, sw_if_index, desired_min_tx, required_min_rx,
                    detect_mult, local_addr, peer_addr, is_ipv6=0):
        return self.api(self.papi.bfd_udp_mod,
                        {
                            'sw_if_index': sw_if_index,
                            'desired_min_tx': desired_min_tx,
                            'required_min_rx': required_min_rx,
                            'local_addr': local_addr,
                            'peer_addr': peer_addr,
                            'is_ipv6': is_ipv6,
                            'detect_mult': detect_mult,
                        })

    def bfd_udp_auth_activate(self, sw_if_index, local_addr, peer_addr,
                              is_ipv6=0, bfd_key_id=None, conf_key_id=None,
                              is_delayed=False):
        return self.api(self.papi.bfd_udp_auth_activate,
                        {
                            'sw_if_index': sw_if_index,
                            'local_addr': local_addr,
                            'peer_addr': peer_addr,
                            'is_ipv6': is_ipv6,
                            'is_delayed': 1 if is_delayed else 0,
                            'bfd_key_id': bfd_key_id,
                            'conf_key_id': conf_key_id,
                        })

    def bfd_udp_auth_deactivate(self, sw_if_index, local_addr, peer_addr,
                                is_ipv6=0, is_delayed=False):
        return self.api(self.papi.bfd_udp_auth_deactivate,
                        {
                            'sw_if_index': sw_if_index,
                            'local_addr': local_addr,
                            'peer_addr': peer_addr,
                            'is_ipv6': is_ipv6,
                            'is_delayed': 1 if is_delayed else 0,
                        })

    def bfd_udp_del(self, sw_if_index, local_addr, peer_addr, is_ipv6=0):
        return self.api(self.papi.bfd_udp_del,
                        {
                            'sw_if_index': sw_if_index,
                            'local_addr': local_addr,
                            'peer_addr': peer_addr,
                            'is_ipv6': is_ipv6,
                        })

    def bfd_udp_session_dump(self):
        return self.api(self.papi.bfd_udp_session_dump, {})

    def bfd_udp_session_set_flags(self, admin_up_down, sw_if_index, local_addr,
                                  peer_addr, is_ipv6=0):
        return self.api(self.papi.bfd_udp_session_set_flags, {
            'admin_up_down': admin_up_down,
            'sw_if_index': sw_if_index,
            'local_addr': local_addr,
            'peer_addr': peer_addr,
            'is_ipv6': is_ipv6,
        })

    def want_bfd_events(self, enable_disable=1):
        return self.api(self.papi.want_bfd_events, {
            'enable_disable': enable_disable,
            'pid': os.getpid(),
        })

    def bfd_auth_set_key(self, conf_key_id, auth_type, key):
        return self.api(self.papi.bfd_auth_set_key, {
            'conf_key_id': conf_key_id,
            'auth_type': auth_type,
            'key': key,
            'key_len': len(key),
        })

    def bfd_auth_del_key(self, conf_key_id):
        return self.api(self.papi.bfd_auth_del_key, {
            'conf_key_id': conf_key_id,
        })

    def bfd_auth_keys_dump(self):
        return self.api(self.papi.bfd_auth_keys_dump, {})

    def bfd_udp_set_echo_source(self, sw_if_index):
        return self.api(self.papi.bfd_udp_set_echo_source,
                        {'sw_if_index': sw_if_index})

    def bfd_udp_del_echo_source(self):
        return self.api(self.papi.bfd_udp_del_echo_source, {})

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

        return self.api(
            self.papi.classify_add_del_session,
            {'is_add': is_add,
             'table_index': table_index,
             'hit_next_index': hit_next_index,
             'opaque_index': opaque_index,
             'advance': advance,
             'action': action,
             'metadata': metadata,
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

    def dhcp_proxy_config(self,
                          dhcp_server,
                          dhcp_src_address,
                          rx_table_id=0,
                          server_table_id=0,
                          is_add=1,
                          is_ipv6=0):
        return self.api(
            self.papi.dhcp_proxy_config,
            {
                'rx_vrf_id': rx_table_id,
                'server_vrf_id': server_table_id,
                'is_ipv6': is_ipv6,
                'is_add': is_add,
                'dhcp_server': dhcp_server,
                'dhcp_src_address': dhcp_src_address,
            })

    def dhcp_proxy_set_vss(self,
                           table_id,
                           fib_id,
                           oui,
                           is_add=1,
                           is_ip6=0):
        return self.api(
            self.papi.dhcp_proxy_set_vss,
            {
                'tbl_id': table_id,
                'fib_id': fib_id,
                'is_ipv6': is_ip6,
                'is_add': is_add,
                'oui': oui,
            })

    def dhcp_client(self,
                    sw_if_index,
                    hostname,
                    client_id='',
                    is_add=1,
                    want_dhcp_events=0):
        return self.api(
            self.papi.dhcp_client_config,
            {
                'sw_if_index': sw_if_index,
                'hostname': hostname,
                'client_id': client_id,
                'is_add': is_add,
                'want_dhcp_event': want_dhcp_events,
                'pid': os.getpid(),
            })

    def ip_mroute_add_del(self,
                          src_address,
                          grp_address,
                          grp_address_length,
                          e_flags,
                          next_hop_sw_if_index,
                          i_flags,
                          rpf_id=0,
                          table_id=0,
                          is_add=1,
                          is_ipv6=0,
                          is_local=0):
        """
        """
        return self.api(
            self.papi.ip_mroute_add_del,
            {'next_hop_sw_if_index': next_hop_sw_if_index,
             'entry_flags': e_flags,
             'itf_flags': i_flags,
             'table_id': table_id,
             'rpf_id': rpf_id,
             'is_add': is_add,
             'is_ipv6': is_ipv6,
             'is_local': is_local,
             'grp_address_length': grp_address_length,
             'grp_address': grp_address,
             'src_address': src_address})

    def mfib_signal_dump(self):
        return self.api(self.papi.mfib_signal_dump, {})

    def ip_mfib_dump(self):
        return self.api(self.papi.ip_mfib_dump, {})

    def lisp_enable_disable(self, is_enabled):
        return self.api(
            self.papi.lisp_enable_disable,
            {
                'is_en': is_enabled,
            })

    def lisp_locator_set(self,
                         ls_name,
                         is_add=1):
        return self.api(
            self.papi.lisp_add_del_locator_set,
            {
                'is_add': is_add,
                'locator_set_name': ls_name
            })

    def lisp_locator_set_dump(self):
        return self.api(self.papi.lisp_locator_set_dump, {})

    def lisp_locator(self,
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

    def lisp_local_mapping(self,
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

    def lisp_remote_mapping(self,
                            eid_type,
                            eid,
                            eid_prefix_len=0,
                            vni=0,
                            rlocs=None,
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

    def lisp_adjacency(self,
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

    def lisp_adjacencies_get(self, vni=0):
        return self.api(
            self.papi.lisp_adjacencies_get,
            {
                'vni': vni
            })

    def map_add_domain(self,
                       ip6_prefix,
                       ip6_prefix_len,
                       ip6_src,
                       ip6_src_prefix_len,
                       ip4_prefix,
                       ip4_prefix_len,
                       ea_bits_len=0,
                       psid_offset=0,
                       psid_length=0,
                       is_translation=0,
                       mtu=1280):
        return self.api(
            self.papi.map_add_domain,
            {
                'ip6_prefix': ip6_prefix,
                'ip6_prefix_len': ip6_prefix_len,
                'ip4_prefix': ip4_prefix,
                'ip4_prefix_len': ip4_prefix_len,
                'ip6_src': ip6_src,
                'ip6_src_prefix_len': ip6_src_prefix_len,
                'ea_bits_len': ea_bits_len,
                'psid_offset': psid_offset,
                'psid_length': psid_length,
                'is_translation': is_translation,
                'mtu': mtu
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

    def sr_localsid_add_del(self,
                            localsid_addr,
                            behavior,
                            nh_addr,
                            is_del=0,
                            end_psp=0,
                            sw_if_index=0xFFFFFFFF,
                            vlan_index=0,
                            fib_table=0,
                            ):
        """ Add/del IPv6 SR local-SID.

        :param localsid_addr:
        :param behavior: END=1; END.X=2; END.DX2=4; END.DX6=5;
        :param behavior: END.DX4=6; END.DT6=7; END.DT4=8
        :param nh_addr:
        :param is_del:  (Default value = 0)
        :param end_psp: (Default value = 0)
        :param sw_if_index: (Default value = 0xFFFFFFFF)
        :param vlan_index:  (Default value = 0)
        :param fib_table:   (Default value = 0)
        """
        return self.api(
            self.papi.sr_localsid_add_del,
            {'is_del': is_del,
             'localsid_addr': localsid_addr,
             'end_psp': end_psp,
             'behavior': behavior,
             'sw_if_index': sw_if_index,
             'vlan_index': vlan_index,
             'fib_table': fib_table,
             'nh_addr': nh_addr
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

    def macip_acl_del(self, acl_index):
        """

        :param acl_index:
        :return:
        """
        return self.api(self.papi.macip_acl_del,
                        {'acl_index': acl_index})

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

    def macip_acl_interface_get(self):
        """ Return interface acls dump
        """
        return self.api(
            self.papi.macip_acl_interface_get, {})

    def macip_acl_dump(self, acl_index=4294967295):
        """ Return MACIP acl dump
        """

        return self.api(
            self.papi.macip_acl_dump, {'acl_index': acl_index})
