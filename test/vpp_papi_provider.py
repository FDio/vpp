import os
from logging import error
from hook import Hook

do_import = True
try:
    no_vpp_papi = os.getenv("NO_VPP_PAPI")
    if no_vpp_papi == "1":
        do_import = False
except:
    pass

if do_import:
    import vpp_papi


# from vnet/vnet/mpls/mpls_types.h
MPLS_IETF_MAX_LABEL = 0xfffff
MPLS_LABEL_INVALID = MPLS_IETF_MAX_LABEL + 1

class L2_VTR_OP:
    L2_POP_1 = 3


class VppPapiProvider(object):
    """VPP-api provider using vpp-papi

    @property hook: hook object providing before and after api/cli hooks


    """

    def __init__(self, name, shm_prefix):
        self.hook = Hook("vpp-papi-provider")
        self.name = name
        self.shm_prefix = shm_prefix

    def register_hook(self, hook):
        """Replace hook registration with new hook

        :param hook:

        """
        self.hook = hook

    def connect(self):
        """Connect the API to VPP"""
        vpp_papi.connect(self.name, self.shm_prefix)

    def disconnect(self):
        """Disconnect the API from VPP"""
        vpp_papi.disconnect()

    def api(self, api_fn, api_args, expected_retval=0):
        """Call API function and check it's return value
        Call the appropriate hooks before and after the API call

        :param api_fn: API function to call
        :param api_args: tuple of API function arguments
        :param expected_retval: Expected return value (Default value = 0)
        :returns: reply from the API

        """
        self.hook.before_api(api_fn.__name__, api_args)
        reply = api_fn(*api_args)
        if hasattr(reply, 'retval') and reply.retval != expected_retval:
            msg = "API call failed, expected retval == %d, got %s" % (
                expected_retval, repr(reply))
            error(msg)
            raise Exception(msg)
        self.hook.after_api(api_fn.__name__, api_args)
        return reply

    def cli(self, cli):
        """
        Execute a CLI, calling the before/after hooks appropriately.

        :param cli: CLI to execute
        :returns: CLI output

        """
        self.hook.before_cli(cli)
        cli += '\n'
        r = vpp_papi.cli_inband(len(cli), cli)
        self.hook.after_cli(cli)
        if hasattr(r, 'reply'):
            return r.reply[0].decode().rstrip('\x00')

    def ppcli(self, cli):
        """
        Helping method to print CLI command in case of info logging level.

        :param cli: CLI to execute
        :returns: CLI output
        """
        return cli + "\n" + self.cli(cli)

    def show_version(self):
        """ """
        return vpp_papi.show_version()

    def pg_create_interface(self, pg_index):
        """

        :param pg_index:

        """
        return self.api(vpp_papi.pg_create_interface, (pg_index, ))

    def sw_interface_dump(self, filter=None):
        """

        :param filter:  (Default value = None)

        """
        if filter is not None:
            args = (1, filter)
        else:
            args = (0, b'')
        return self.api(vpp_papi.sw_interface_dump, args)

    def sw_interface_set_table(self, sw_if_index, is_ipv6, table_id):
        """
          Set the IPvX Table-id for the Interface

        :param sw_if_index:
        :param is_ipv6:
        :param table_id:

        """
        return self.api(vpp_papi.sw_interface_set_table,
                        (sw_if_index, is_ipv6, table_id))

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
        return self.api(vpp_papi.sw_interface_add_del_address,
                        (sw_if_index, is_add, is_ipv6, del_all, addr_len, addr))

    def sw_interface_enable_disable_mpls(self, sw_if_index,
                                         is_enable=1):
        """
        Enable/Disable MPLS on the interface
        :param sw_if_index:
        :param is_enable:  (Default value = 1)

        """
        return self.api(vpp_papi.sw_interface_set_mpls_enable,
                        (sw_if_index, is_enable))

    def sw_interface_ra_suppress(self, sw_if_index):
        suppress = 1
        managed = 0
        other = 0
        ll_option = 0
        send_unicast = 0
        cease = 0
        is_no = 0
        default_router = 0
        max_interval = 0
        min_interval = 0
        lifetime = 0
        initial_count = 0
        initial_interval = 0
        async = False
        return self.api(vpp_papi.sw_interface_ip6nd_ra_config,
                        (sw_if_index, suppress, managed, other,
                         ll_option, send_unicast, cease, is_no,
                         default_router, max_interval, min_interval,
                         lifetime, initial_count, initial_interval, async))

    def vxlan_add_del_tunnel(
            self,
            src_addr,
            dst_addr,
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
        :param vni:  (Default value = 0)

        """
        return self.api(vpp_papi.vxlan_add_del_tunnel,
                        (is_add, is_ipv6, src_addr, dst_addr, encap_vrf_id,
                         decap_next_index, vni))

    def sw_interface_set_l2_bridge(self, sw_if_index, bd_id,
                                   shg=0, bvi=0, enable=1):
        """

        :param bd_id:
        :param sw_if_index:
        :param shg:  (Default value = 0)
        :param bvi:  (Default value = 0)
        :param enable:  (Default value = 1)

        """
        return self.api(vpp_papi.sw_interface_set_l2_bridge,
                        (sw_if_index, bd_id, shg, bvi, enable))

    def sw_interface_set_l2_xconnect(self, rx_sw_if_index, tx_sw_if_index,
                                     enable):
        """Create or delete unidirectional cross-connect from Tx interface to
        Rx interface.

        :param rx_sw_if_index: Software interface index of Rx interface.
        :param tx_sw_if_index: Software interface index of Tx interface.
        :param enable: Create cross-connect if equal to 1, delete cross-connect
                       if equal to 0.
        :type rx_sw_if_index: str or int
        :type rx_sw_if_index: str or int
        :type enable: int

        """
        return self.api(vpp_papi.sw_interface_set_l2_xconnect,
                        (rx_sw_if_index, tx_sw_if_index, enable))

    def sw_interface_set_l2_tag_rewrite(self, sw_if_index, vtr_oper, push=0, tag1=0, tag2=0):
        """L2 interface vlan tag rewrite configure request
        :param client_index - opaque cookie to identify the sender
        :param context - sender context, to match reply w/ request
        :param sw_if_index - interface the operation is applied to
        :param vtr_op - Choose from l2_vtr_op_t enum values
        :param push_dot1q - first pushed flag dot1q id set, else dot1ad
        :param tag1 - Needed for any push or translate vtr op
        :param tag2 - Needed for any push 2 or translate x-2 vtr ops

        """
        return self.api(vpp_papi.l2_interface_vlan_tag_rewrite,
                        (sw_if_index, vtr_oper, push, tag1, tag2))

    def sw_interface_set_flags(self, sw_if_index, admin_up_down,
                               link_up_down=0, deleted=0):
        """

        :param admin_up_down:
        :param sw_if_index:
        :param link_up_down:  (Default value = 0)
        :param deleted:  (Default value = 0)

        """
        return self.api(vpp_papi.sw_interface_set_flags,
                        (sw_if_index, admin_up_down, link_up_down, deleted))

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
            vpp_papi.create_subif,
            (sw_if_index,
             sub_id,
             no_tags,
             one_tag,
             two_tags,
             dot1ad,
             exact_match,
             default_sub,
             outer_vlan_id_any,
             inner_vlan_id_any,
             outer_vlan,
             inner_vlan))

    def delete_subif(self, sw_if_index):
        """Delete subinterface

        :param sw_if_index:
        """
        return self.api(vpp_papi.delete_subif, ([sw_if_index]))

    def create_vlan_subif(self, sw_if_index, vlan):
        """

        :param vlan:
        :param sw_if_index:

        """
        return self.api(vpp_papi.create_vlan_subif, (sw_if_index, vlan))

    def create_loopback(self, mac=''):
        """

        :param mac: (Optional)
        """
        return self.api(vpp_papi.create_loopback, (mac,))

    def ip_add_del_route(
            self,
            dst_address,
            dst_address_length,
            next_hop_address,
            next_hop_sw_if_index=0xFFFFFFFF,
            table_id=0,
            resolve_attempts=0,
            classify_table_index=0xFFFFFFFF,
            next_hop_out_label=MPLS_LABEL_INVALID,
            next_hop_table_id=0,
            create_vrf_if_needed=0,
            resolve_if_needed=0,
            is_add=1,
            is_drop=0,
            is_unreach=0,
            is_prohibit=0,
            is_ipv6=0,
            is_local=0,
            is_classify=0,
            is_multipath=0,
            is_resolve_host=0,
            is_resolve_attached=0,
            not_last=0,
            next_hop_weight=1):
        """

        :param dst_address_length:
        :param next_hop_sw_if_index:  (Default value = 0xFFFFFFFF)
        :param dst_address:
        :param next_hop_address:
        :param next_hop_sw_if_index:  (Default value = 0xFFFFFFFF)
        :param vrf_id:  (Default value = 0)
        :param lookup_in_vrf:  (Default value = 0)
        :param resolve_attempts:  (Default value = 0)
        :param classify_table_index:  (Default value = 0xFFFFFFFF)
        :param create_vrf_if_needed:  (Default value = 0)
        :param resolve_if_needed:  (Default value = 0)
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
            vpp_papi.ip_add_del_route,
            (next_hop_sw_if_index,
             table_id,
             resolve_attempts,
             classify_table_index,
             next_hop_out_label,
             next_hop_table_id,
             create_vrf_if_needed,
             resolve_if_needed,
             is_add,
             is_drop,
             is_unreach,
             is_prohibit,
             is_ipv6,
             is_local,
             is_classify,
             is_multipath,
             is_resolve_host,
             is_resolve_attached,
             not_last,
             next_hop_weight,
             dst_address_length,
             dst_address,
             next_hop_address))

    def ip_neighbor_add_del(self,
                            sw_if_index,
                            mac_address,
                            dst_address,
                            vrf_id=0,
                            is_add=1,
                            is_ipv6=0,
                            is_static=0,
                            ):
        """ Add neighbor MAC to IPv4 or IPv6 address.

        :param sw_if_index:
        :param mac_address:
        :param dst_address:
        :param vrf_id:  (Default value = 0)
        :param is_add:  (Default value = 1)
        :param is_ipv6:  (Default value = 0)
        :param is_static:  (Default value = 0)
        """

        return self.api(
            vpp_papi.ip_neighbor_add_del,
            (vrf_id,
             sw_if_index,
             is_add,
             is_ipv6,
             is_static,
             mac_address,
             dst_address
             )
        )

    def sw_interface_span_enable_disable(self, sw_if_index_from, sw_if_index_to, enable=1):
        """

        :param sw_if_index_from:
        :param sw_if_index_to:
        :param enable

        """
        return self.api(vpp_papi.sw_interface_span_enable_disable, (sw_if_index_from, sw_if_index_to, enable ))

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
            vpp_papi.gre_add_del_tunnel,
            (is_add,
             is_ip6,
             is_teb,
             src_address,
             dst_address,
             outer_fib_id)
        )
