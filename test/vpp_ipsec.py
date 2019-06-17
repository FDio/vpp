from vpp_object import VppObject
from ipaddress import ip_address
from vpp_papi import VppEnum

try:
    text_type = unicode
except NameError:
    text_type = str


class VppIpsecSpd(VppObject):
    """
    VPP SPD DB
    """

    def __init__(self, test, id):
        self.test = test
        self.id = id

    def add_vpp_config(self):
        self.test.vapi.ipsec_spd_add_del(self.id)
        self.test.registry.register(self, self.test.logger)

    def remove_vpp_config(self):
        self.test.vapi.ipsec_spd_add_del(self.id, is_add=0)

    def object_id(self):
        return "ipsec-spd-%d" % self.id

    def query_vpp_config(self):
        spds = self.test.vapi.ipsec_spds_dump()
        for spd in spds:
            if spd.spd_id == self.id:
                return True
        return False


class VppIpsecSpdItfBinding(VppObject):
    """
    VPP SPD DB to interface binding
    (i.e. this SPD is used on this interface)
    """

    def __init__(self, test, spd, itf):
        self.test = test
        self.spd = spd
        self.itf = itf

    def add_vpp_config(self):
        self.test.vapi.ipsec_interface_add_del_spd(self.spd.id,
                                                   self.itf.sw_if_index)
        self.test.registry.register(self, self.test.logger)

    def remove_vpp_config(self):
        self.test.vapi.ipsec_interface_add_del_spd(self.spd.id,
                                                   self.itf.sw_if_index,
                                                   is_add=0)

    def object_id(self):
        return "bind-%s-to-%s" % (self.spd.id, self.itf)

    def query_vpp_config(self):
        bs = self.test.vapi.ipsec_spd_interface_dump()
        for b in bs:
            if b.sw_if_index == self.itf.sw_if_index:
                return True
        return False


class VppIpsecSpdEntry(VppObject):
    """
    VPP SPD DB Entry
    """

    def __init__(self, test, spd, sa_id,
                 local_start, local_stop,
                 remote_start, remote_stop,
                 proto,
                 priority=100,
                 policy=None,
                 is_outbound=1,
                 remote_port_start=0,
                 remote_port_stop=65535,
                 local_port_start=0,
                 local_port_stop=65535):
        self.test = test
        self.spd = spd
        self.sa_id = sa_id
        self.local_start = ip_address(text_type(local_start))
        self.local_stop = ip_address(text_type(local_stop))
        self.remote_start = ip_address(text_type(remote_start))
        self.remote_stop = ip_address(text_type(remote_stop))
        self.proto = proto
        self.is_outbound = is_outbound
        self.priority = priority
        if not policy:
            self.policy = (VppEnum.vl_api_ipsec_spd_action_t.
                           IPSEC_API_SPD_ACTION_BYPASS)
        else:
            self.policy = policy
        self.is_ipv6 = (0 if self.local_start.version == 4 else 1)
        self.local_port_start = local_port_start
        self.local_port_stop = local_port_stop
        self.remote_port_start = remote_port_start
        self.remote_port_stop = remote_port_stop

    def add_vpp_config(self):
        rv = self.test.vapi.ipsec_spd_entry_add_del(
            self.spd.id,
            self.sa_id,
            self.local_start,
            self.local_stop,
            self.remote_start,
            self.remote_stop,
            protocol=self.proto,
            is_ipv6=self.is_ipv6,
            is_outbound=self.is_outbound,
            priority=self.priority,
            policy=self.policy,
            local_port_start=self.local_port_start,
            local_port_stop=self.local_port_stop,
            remote_port_start=self.remote_port_start,
            remote_port_stop=self.remote_port_stop)
        self.stat_index = rv.stat_index
        self.test.registry.register(self, self.test.logger)

    def remove_vpp_config(self):
        self.test.vapi.ipsec_spd_entry_add_del(
            self.spd.id,
            self.sa_id,
            self.local_start,
            self.local_stop,
            self.remote_start,
            self.remote_stop,
            protocol=self.proto,
            is_ipv6=self.is_ipv6,
            is_outbound=self.is_outbound,
            priority=self.priority,
            policy=self.policy,
            local_port_start=self.local_port_start,
            local_port_stop=self.local_port_stop,
            remote_port_start=self.remote_port_start,
            remote_port_stop=self.remote_port_stop,
            is_add=0)

    def object_id(self):
        return "spd-entry-%d-%d-%d-%d-%d-%d" % (self.spd.id,
                                                self.priority,
                                                self.policy,
                                                self.is_outbound,
                                                self.is_ipv6,
                                                self.remote_port_start)

    def query_vpp_config(self):
        ss = self.test.vapi.ipsec_spd_dump(self.spd.id)
        for s in ss:
            if s.entry.sa_id == self.sa_id and \
               s.entry.is_outbound == self.is_outbound and \
               s.entry.priority == self.priority and \
               s.entry.policy == self.policy and \
               s.entry.remote_address_start == self.remote_start and \
               s.entry.remote_port_start == self.remote_port_start:
                return True
        return False

    def get_stats(self):
        c = self.test.statistics.get_counter("/net/ipsec/policy")
        return c[0][self.stat_index]


class VppIpsecSA(VppObject):
    """
    VPP SAD Entry
    """

    def __init__(self, test, id, spi,
                 integ_alg, integ_key,
                 crypto_alg, crypto_key,
                 proto,
                 tun_src=None, tun_dst=None,
                 flags=None, salt=0):
        e = VppEnum.vl_api_ipsec_sad_flags_t
        self.test = test
        self.id = id
        self.spi = spi
        self.integ_alg = integ_alg
        self.integ_key = integ_key
        self.crypto_alg = crypto_alg
        self.crypto_key = crypto_key
        self.proto = proto
        self.salt = salt

        self.tun_src = tun_src
        self.tun_dst = tun_dst
        if not flags:
            self.flags = e.IPSEC_API_SAD_FLAG_NONE
        else:
            self.flags = flags
        if (tun_src):
            self.tun_src = ip_address(text_type(tun_src))
            self.flags = self.flags | e.IPSEC_API_SAD_FLAG_IS_TUNNEL
            if (self.tun_src.version == 6):
                self.flags = self.flags | e.IPSEC_API_SAD_FLAG_IS_TUNNEL_V6
        if (tun_dst):
            self.tun_dst = ip_address(text_type(tun_dst))

    def add_vpp_config(self):
        r = self.test.vapi.ipsec_sad_entry_add_del(
            self.id,
            self.spi,
            self.integ_alg,
            self.integ_key,
            self.crypto_alg,
            self.crypto_key,
            self.proto,
            (self.tun_src if self.tun_src else []),
            (self.tun_dst if self.tun_dst else []),
            flags=self.flags,
            salt=self.salt)
        self.stat_index = r.stat_index
        self.test.registry.register(self, self.test.logger)

    def remove_vpp_config(self):
        self.test.vapi.ipsec_sad_entry_add_del(
            self.id,
            self.spi,
            self.integ_alg,
            self.integ_key,
            self.crypto_alg,
            self.crypto_key,
            self.proto,
            (self.tun_src if self.tun_src else []),
            (self.tun_dst if self.tun_dst else []),
            flags=self.flags,
            is_add=0)

    def object_id(self):
        return "ipsec-sa-%d" % self.id

    def query_vpp_config(self):
        bs = self.test.vapi.ipsec_sa_dump()
        for b in bs:
            if b.entry.sad_id == self.id:
                return True
        return False

    def get_stats(self):
        c = self.test.statistics.get_counter("/net/ipsec/sa")
        return c[0][self.stat_index]
