from vpp_object import VppObject
from socket import inet_pton, inet_ntop, AF_INET, AF_INET6


class SRv6MobileNhtype:
    SRV6_NHTYPE_API_NONE = 0
    SRV6_NHTYPE_API_IPV4 = 1
    SRV6_NHTYPE_API_IPV6 = 2
    SRV6_NHTYPE_API_NON_IP = 3


class VppSRv6MobileLocalSID(VppObject):
    """
    SRv6 LocalSID
    """

    def __init__(
        self,
        test,
        localsid_prefix,
        behavior,
        fib_table=0,
        local_fib_table=0,
        drop_in=0,
        nhtype=SRv6MobileNhtype.SRV6_NHTYPE_API_NONE,
        sr_prefix="",
        v4src_addr="",
        v4src_position=0,
    ):
        self._test = test
        self.localsid_prefix = localsid_prefix
        self.behavior = behavior
        self.fib_table = fib_table
        self.local_fib_table = local_fib_table
        self.drop_in = drop_in
        self.nhtype = nhtype
        self.sr_prefix = sr_prefix
        self.v4src_addr = v4src_addr
        self.v4src_position = v4src_position
        self._configured = False

    def add_vpp_config(self):
        self._test.vapi.sr_mobile_localsid_add_del(
            localsid_prefix=self.localsid_prefix,
            behavior=self.behavior,
            fib_table=self.fib_table,
            local_fib_table=self.local_fib_table,
            drop_in=self.drop_in,
            sr_prefix=self.sr_prefix,
            v4src_addr=self.v4src_addr,
            v4src_position=self.v4src_position,
            is_del=0,
        )
        self._configured = True

    def remove_vpp_config(self):
        self._test.vapi.sr_mobile_localsid_add_del(
            localsid_prefix=self.localsid_prefix,
            behavior=self.behavior,
            fib_table=self.fib_table,
            local_fib_table=self.local_fib_table,
            drop_in=self.drop_in,
            sr_prefix=self.sr_prefix,
            v4src_addr=self.v4src_addr,
            v4src_position=self.v4src_position,
            is_del=1,
        )
        self._configured = False

    def query_vpp_config(self):
        return self._configured

    def object_id(self):
        return "%d;%s,%s" % (self.fib_table, self.localsid_prefix, self.behavior)


class VppSRv6MobilePolicy(VppObject):
    """
    SRv6 Policy
    """

    def __init__(
        self,
        test,
        bsid_addr,
        sr_prefix,
        v6src_prefix,
        behavior,
        fib_table=0,
        local_fib_table=0,
        encap_src=None,
        drop_in=0,
        nhtype=SRv6MobileNhtype.SRV6_NHTYPE_API_NONE,
    ):
        self._test = test
        self.bsid_addr = bsid_addr
        self.sr_prefix = sr_prefix
        self.v6src_prefix = v6src_prefix
        self.behavior = behavior
        self.fib_table = fib_table
        self.local_fib_table = local_fib_table
        self.drop_in = drop_in
        self.nhtype = nhtype
        self.encap_src = encap_src
        self._configured = False

    def add_vpp_config(self):
        self._test.vapi.sr_mobile_policy_add(
            bsid_addr=self.bsid_addr,
            sr_prefix=self.sr_prefix,
            v6src_prefix=self.v6src_prefix,
            behavior=self.behavior,
            fib_table=self.fib_table,
            local_fib_table=self.local_fib_table,
            encap_src=self.encap_src,
            drop_in=self.drop_in,
            nhtype=self.nhtype,
        )
        self._configured = True

    def remove_vpp_config(self):
        self._test.vapi.sr_policy_del(self.bsid_addr)
        self._configured = False

    def query_vpp_config(self):
        # no API to query SR Policies
        # use _configured flag for now
        return self._configured

    def object_id(self):
        return "%d;%s-><%s>;%d" % (
            self.sr_type,
            self.bsid,
            ",".join(self.segments),
            self.is_encap,
        )
