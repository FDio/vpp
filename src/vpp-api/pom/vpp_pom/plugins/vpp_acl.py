from ipaddress import IPv4Network

from vpp_pom.vpp_object import VppObject
from vpp_papi import VppEnum
from vpp_pom.vpp_ip import INVALID_INDEX
from vpp_pom.vpp_papi_provider import UnexpectedApiReturnValueError


class VppAclPlugin(VppObject):

    def __init__(self, vclient):
        self._vclient = vclient
        self._enable_intf_counters = False

    @property
    def enable_intf_counters(self):
        return self._enable_intf_counters

    @enable_intf_counters.setter
    def enable_intf_counters(self, enable):
        self._vclient.acl_stats_intf_counters_enable(enable=enable)

    def add_vpp_config(self):
        pass

    def remove_vpp_config(self):
        pass

    def query_vpp_config(self):
        pass

    def object_id(self):
        return ("acl-plugin")


class AclRule():
    """ ACL Rule """

    # port ranges
    PORTS_ALL = -1
    PORTS_RANGE = 0
    PORTS_RANGE_2 = 1
    udp_sport_from = 10
    udp_sport_to = udp_sport_from + 5
    udp_dport_from = 20000
    udp_dport_to = udp_dport_from + 5000
    tcp_sport_from = 30
    tcp_sport_to = tcp_sport_from + 5
    tcp_dport_from = 40000
    tcp_dport_to = tcp_dport_from + 5000

    udp_sport_from_2 = 90
    udp_sport_to_2 = udp_sport_from_2 + 5
    udp_dport_from_2 = 30000
    udp_dport_to_2 = udp_dport_from_2 + 5000
    tcp_sport_from_2 = 130
    tcp_sport_to_2 = tcp_sport_from_2 + 5
    tcp_dport_from_2 = 20000
    tcp_dport_to_2 = tcp_dport_from_2 + 5000

    icmp4_type = 8  # echo request
    icmp4_code = 3
    icmp6_type = 128  # echo request
    icmp6_code = 3

    icmp4_type_2 = 8
    icmp4_code_from_2 = 5
    icmp4_code_to_2 = 20
    icmp6_type_2 = 128
    icmp6_code_from_2 = 8
    icmp6_code_to_2 = 42

    def __init__(self, is_permit, src_prefix=IPv4Network('0.0.0.0/0'),
                 dst_prefix=IPv4Network('0.0.0.0/0'),
                 proto=0, ports=PORTS_ALL, sport_from=None, sport_to=None,
                 dport_from=None, dport_to=None):
        self.is_permit = is_permit
        self.src_prefix = src_prefix
        self.dst_prefix = dst_prefix
        self._proto = proto
        self._ports = ports
        # assign ports by range
        self.update_ports()
        # assign specified ports
        if sport_from:
            self.sport_from = sport_from
        if sport_to:
            self.sport_to = sport_to
        if dport_from:
            self.dport_from = dport_from
        if dport_to:
            self.dport_to = dport_to

    def __copy__(self):
        new_rule = AclRule(self.is_permit, self.src_prefix, self.dst_prefix,
                           self._proto, self._ports, self.sport_from,
                           self.sport_to, self.dport_from, self.dport_to)
        return new_rule

    def update_ports(self):
        if self._ports == self.PORTS_ALL:
            self.sport_from = 0
            self.dport_from = 0
            self.sport_to = 65535
            if self._proto == 1 or self._proto == 58:
                self.sport_to = 255
            self.dport_to = self.sport_to
        elif self._ports == self.PORTS_RANGE:
            if self._proto == VppEnum.vl_api_ip_proto_t.IP_API_PROTO_ICMP:
                self.sport_from = self.icmp4_type
                self.sport_to = self.icmp4_type
                self.dport_from = self.icmp4_code
                self.dport_to = self.icmp4_code
            elif self._proto == VppEnum.vl_api_ip_proto_t.IP_API_PROTO_ICMP6:
                self.sport_from = self.icmp6_type
                self.sport_to = self.icmp6_type
                self.dport_from = self.icmp6_code
                self.dport_to = self.icmp6_code
            elif self._proto == VppEnum.vl_api_ip_proto_t.IP_API_PROTO_TCP:
                self.sport_from = self.tcp_sport_from
                self.sport_to = self.tcp_sport_to
                self.dport_from = self.tcp_dport_from
                self.dport_to = self.tcp_dport_to
            elif self._proto == VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP:
                self.sport_from = self.udp_sport_from
                self.sport_to = self.udp_sport_to
                self.dport_from = self.udp_dport_from
                self.dport_to = self.udp_dport_to
        elif self._ports == self.PORTS_RANGE_2:
            if self._proto == VppEnum.vl_api_ip_proto_t.IP_API_PROTO_ICMP:
                self.sport_from = self.icmp4_type_2
                self.sport_to = self.icmp4_type_2
                self.dport_from = self.icmp4_code_from_2
                self.dport_to = self.icmp4_code_to_2
            elif self._proto == VppEnum.vl_api_ip_proto_t.IP_API_PROTO_ICMP6:
                self.sport_from = self.icmp6_type_2
                self.sport_to = self.icmp6_type_2
                self.dport_from = self.icmp6_code_from_2
                self.dport_to = self.icmp6_code_to_2
            elif self._proto == VppEnum.vl_api_ip_proto_t.IP_API_PROTO_TCP:
                self.sport_from = self.tcp_sport_from_2
                self.sport_to = self.tcp_sport_to_2
                self.dport_from = self.tcp_dport_from_2
                self.dport_to = self.tcp_dport_to_2
            elif self._proto == VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP:
                self.sport_from = self.udp_sport_from_2
                self.sport_to = self.udp_sport_to_2
                self.dport_from = self.udp_dport_from_2
                self.dport_to = self.udp_dport_to_2
        else:
            self.sport_from = self._ports
            self.sport_to = self._ports
            self.dport_from = self._ports
            self.dport_to = self._ports

    @property
    def proto(self):
        return self._proto

    @proto.setter
    def proto(self, proto):
        self._proto = proto
        self.update_ports()

    @property
    def ports(self):
        return self._ports

    @ports.setter
    def ports(self, ports):
        self._ports = ports
        self.update_ports()

    def encode(self):
        return {'is_permit': self.is_permit, 'proto': self.proto,
                'srcport_or_icmptype_first': self.sport_from,
                'srcport_or_icmptype_last': self.sport_to,
                'src_prefix': self.src_prefix,
                'dstport_or_icmpcode_first': self.dport_from,
                'dstport_or_icmpcode_last': self.dport_to,
                'dst_prefix': self.dst_prefix}


class VppAcl(VppObject):
    """ VPP ACL """

    def __init__(self, vclient, rules, acl_index=INVALID_INDEX, tag=None):
        self._vclient = vclient
        self._acl_index = acl_index
        self.tag = tag
        self._rules = rules

    @property
    def rules(self):
        return self._rules

    @property
    def acl_index(self):
        return self._acl_index

    @property
    def count(self):
        return len(self._rules)

    def encode_rules(self):
        rules = []
        for rule in self._rules:
            rules.append(rule.encode())
        return rules

    def add_vpp_config(self, expect_error=False):
        try:
            reply = self._vclient.acl_add_replace(
                acl_index=self._acl_index, tag=self.tag, count=self.count,
                r=self.encode_rules())
            self._acl_index = reply.acl_index
            self._vclient.registry.register(self, self._vclient.logger)
            if expect_error:
                self._vclient.fail("Unexpected api reply")
            return self
        except UnexpectedApiReturnValueError:
            if not expect_error:
                self._vclient.fail("Unexpected api reply")
        return None

    def modify_vpp_config(self, rules):
        self._rules = rules
        self.add_vpp_config()

    def remove_vpp_config(self, expect_error=False):
        try:
            self._vclient.acl_del(acl_index=self._acl_index)
            if expect_error:
                self._vclient.fail("Unexpected api reply")
        except UnexpectedApiReturnValueError:
            if not expect_error:
                self._vclient.fail("Unexpected api reply")

    def dump(self):
        return self._vclient.acl_dump(acl_index=self._acl_index)

    def query_vpp_config(self):
        dump = self.dump()
        for rule in dump:
            if rule.acl_index == self._acl_index:
                return True
        return False

    def object_id(self):
        return ("acl-%s-%d" % (self.tag, self._acl_index))


class VppEtypeWhitelist(VppObject):
    """ VPP Etype Whitelist """

    def __init__(self, vclient, sw_if_index, whitelist, n_input=0):
        self._vclient = vclient
        self.whitelist = whitelist
        self.n_input = n_input
        self._sw_if_index = sw_if_index

    @property
    def sw_if_index(self):
        return self._sw_if_index

    @property
    def count(self):
        return len(self.whitelist)

    def add_vpp_config(self):
        self._vclient.acl_interface_set_etype_whitelist(
            sw_if_index=self._sw_if_index, count=self.count,
            n_input=self.n_input, whitelist=self.whitelist)
        self._vclient.registry.register(self, self._vclient.logger)
        return self

    def remove_vpp_config(self):
        self._vclient.acl_interface_set_etype_whitelist(
            sw_if_index=self._sw_if_index, count=0, n_input=0, whitelist=[])

    def query_vpp_config(self):
        self._vclient.acl_interface_etype_whitelist_dump(
            sw_if_index=self._sw_if_index)
        return False

    def object_id(self):
        return ("acl-etype_wl-%d" % (self._sw_if_index))


class VppAclInterface(VppObject):
    """ VPP ACL Interface """

    def __init__(self, vclient, sw_if_index, acls, n_input=0):
        self._vclient = vclient
        self._sw_if_index = sw_if_index
        self.n_input = n_input
        self.acls = acls

    @property
    def sw_if_index(self):
        return self._sw_if_index

    @property
    def count(self):
        return len(self.acls)

    def encode_acls(self):
        acls = []
        for acl in self.acls:
            acls.append(acl.acl_index)
        return acls

    def add_vpp_config(self, expect_error=False):
        try:
            reply = self._vclient.acl_interface_set_acl_list(
                sw_if_index=self._sw_if_index, n_input=self.n_input,
                count=self.count, acls=self.encode_acls())
            self._vclient.registry.register(self, self._vclient.logger)
            if expect_error:
                self._vclient.fail("Unexpected api reply")
            return self
        except UnexpectedApiReturnValueError:
            if not expect_error:
                self._vclient.fail("Unexpected api reply")
        return None

    def remove_vpp_config(self, expect_error=False):
        try:
            reply = self._vclient.acl_interface_set_acl_list(
                sw_if_index=self._sw_if_index, n_input=0, count=0, acls=[])
            if expect_error:
                self._vclient.fail("Unexpected api reply")
        except UnexpectedApiReturnValueError:
            if not expect_error:
                self._vclient.fail("Unexpected api reply")

    def query_vpp_config(self):
        dump = self._vclient.acl_interface_list_dump(
            sw_if_index=self._sw_if_index)
        for acl_list in dump:
            if acl_list.count > 0:
                return True
        return False

    def object_id(self):
        return ("acl-if-list-%d" % (self._sw_if_index))


class MacipRule():
    """ Mac Ip rule """

    def __init__(self, is_permit, src_mac=0, src_mac_mask=0,
                 src_prefix=IPv4Network('0.0.0.0/0')):
        self.is_permit = is_permit
        self.src_mac = src_mac
        self.src_mac_mask = src_mac_mask
        self.src_prefix = src_prefix

    def encode(self):
        return {'is_permit': self.is_permit, 'src_mac': self.src_mac,
                'src_mac_mask': self.src_mac_mask,
                'src_prefix': self.src_prefix}


class VppMacipAcl(VppObject):
    """ Vpp Mac Ip ACL """

    def __init__(self, vclient, rules, acl_index=INVALID_INDEX, tag=None):
        self._vclient = vclient
        self._acl_index = acl_index
        self.tag = tag
        self._rules = rules

    @property
    def acl_index(self):
        return self._acl_index

    @property
    def rules(self):
        return self._rules

    @property
    def count(self):
        return len(self._rules)

    def encode_rules(self):
        rules = []
        for rule in self._rules:
            rules.append(rule.encode())
        return rules

    def add_vpp_config(self, expect_error=False):
        try:
            reply = self._vclient.macip_acl_add_replace(
                acl_index=self._acl_index, tag=self.tag, count=self.count,
                r=self.encode_rules())
            self._acl_index = reply.acl_index
            self._vclient.registry.register(self, self._vclient.logger)
            if expect_error:
                self._vclient.fail("Unexpected api reply")
            return self
        except UnexpectedApiReturnValueError:
            if not expect_error:
                self._vclient.fail("Unexpected api reply")
        return None

    def modify_vpp_config(self, rules):
        self._rules = rules
        self.add_vpp_config()

    def remove_vpp_config(self, expect_error=False):
        try:
            self._vclient.macip_acl_del(acl_index=self._acl_index)
            if expect_error:
                self._vclient.fail("Unexpected api reply")
        except UnexpectedApiReturnValueError:
            if not expect_error:
                self._vclient.fail("Unexpected api reply")

    def dump(self):
        return self._vclient.macip_acl_dump(acl_index=self._acl_index)

    def query_vpp_config(self):
        dump = self.dump()
        for rule in dump:
            if rule.acl_index == self._acl_index:
                return True
        return False

    def object_id(self):
        return ("macip-acl-%s-%d" % (self.tag, self._acl_index))


class VppMacipAclInterface(VppObject):
    """ VPP Mac Ip ACL Interface """

    def __init__(self, vclient, sw_if_index, acls):
        self._vclient = vclient
        self._sw_if_index = sw_if_index
        self.acls = acls

    @property
    def sw_if_index(self):
        return self._sw_if_index

    @property
    def count(self):
        return len(self.acls)

    def add_vpp_config(self):
        for acl in self.acls:
            self._vclient.macip_acl_interface_add_del(
                is_add=True, sw_if_index=self._sw_if_index,
                acl_index=acl.acl_index)
        self._vclient.registry.register(self, self._vclient.logger)

    def remove_vpp_config(self):
        for acl in self.acls:
            self._vclient.macip_acl_interface_add_del(
                is_add=False, sw_if_index=self._sw_if_index,
                acl_index=acl.acl_index)

    def dump(self):
        return self._vclient.macip_acl_interface_list_dump(
            sw_if_index=self._sw_if_index)

    def query_vpp_config(self):
        dump = self.dump()
        for acl_list in dump:
            for acl_index in acl_list.acls:
                if acl_index != INVALID_INDEX:
                    return True
        return False

    def object_id(self):
        return ("macip-acl-if-list-%d" % (self._sw_if_index))
