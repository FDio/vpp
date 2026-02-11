"""
SRv6 LocalSIDs

object abstractions for representing SRv6 localSIDs in VPP
"""

from vpp_object import VppObject
from socket import inet_pton, inet_ntop, AF_INET, AF_INET6
import copy


class SRv6LocalSIDBehaviors:
    # from src/vnet/srv6/sr.h
    SR_BEHAVIOR_END = 1
    SR_BEHAVIOR_X = 2
    SR_BEHAVIOR_T = 3
    SR_BEHAVIOR_D_FIRST = 4  # Unused. Separator in between regular and D
    SR_BEHAVIOR_DX2 = 5
    SR_BEHAVIOR_DX6 = 6
    SR_BEHAVIOR_DX4 = 7
    SR_BEHAVIOR_DT6 = 8
    SR_BEHAVIOR_DT4 = 9
    SR_BEHAVIOR_LAST = 10  # Not used anymore. Kept not to break the API.
    SR_BEHAVIOR_END_UN_PERF = 11
    SR_BEHAVIOR_END_UN = 12
    SR_BEHAVIOR_END_UA = 13


class SRv6PolicyType:
    # from src/vnet/srv6/sr.h
    SR_POLICY_TYPE_DEFAULT = 0
    SR_POLICY_TYPE_SPRAY = 1
    SR_POLICY_TYPE_TEF = 2


class SRv6PolicySteeringTypes:
    # from src/vnet/srv6/sr.h
    SR_STEER_L2 = 2
    SR_STEER_IPV4 = 4
    SR_STEER_IPV6 = 6


class VppSRv6LocalSID(VppObject):
    """
    SRv6 LocalSID
    """

    def __init__(
        self,
        test,
        localsid,
        behavior,
        nh_addr,
        end_psp,
        sw_if_index,
        fib_table,
    ):
        self._test = test
        self.localsid = localsid
        self.behavior = behavior
        self.nh_addr = nh_addr
        self.end_psp = end_psp
        self.sw_if_index = sw_if_index
        self.fib_table = fib_table
        self._configured = False

    def add_vpp_config(self):
        self._test.vapi.sr_localsid_add_del(
            localsid=self.localsid,
            behavior=self.behavior,
            nh_addr=self.nh_addr,
            is_del=0,
            end_psp=self.end_psp,
            sw_if_index=self.sw_if_index,
            fib_table=self.fib_table,
        )
        self._configured = True

    def remove_vpp_config(self):
        self._test.vapi.sr_localsid_add_del(
            localsid=self.localsid,
            behavior=self.behavior,
            nh_addr=self.nh_addr,
            is_del=1,
            end_psp=self.end_psp,
            sw_if_index=self.sw_if_index,
            fib_table=self.fib_table,
        )
        self._configured = False

    def query_vpp_config(self):
        # sr_localsids_dump API is disabled
        # use _configured flag for now
        return self._configured

    def object_id(self):
        return "%d;%s,%d" % (self.fib_table, self.localsid, self.behavior)


class VppSRv6Policy(VppObject):
    """
    SRv6 Policy
    """

    def __init__(
        self, test, bsid, is_encap, sr_type, weight, fib_table, segments, source
    ):
        self._test = test
        self.bsid = bsid
        self.is_encap = is_encap
        self.sr_type = sr_type
        self.weight = weight
        self.fib_table = fib_table
        self.segments = segments
        # source not passed to API
        # self.source = inet_pton(AF_INET6, source)
        self.source = source
        self._configured = False

    def add_vpp_config(self):
        self._test.vapi.sr_policy_add(
            bsid_addr=self.bsid,
            weight=self.weight,
            is_encap=self.is_encap,
            is_spray=self.sr_type,
            fib_table=self.fib_table,
            sids={
                "num_sids": len(self.segments),
                "sids": self._get_fixed_segments(self.segments),
                "weight": 1,
            },
        )
        self._configured = True

    def remove_vpp_config(self):
        self._test.vapi.sr_policy_del(self.bsid)
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

    def _get_fixed_segments(self, segments):
        segs = copy.copy(segments)
        # note: array expect size is 16
        for _ in range(16 - len(segments)):
            segs.append("")
        return segs


class VppSRv6PolicyV2(VppObject):
    """
    SRv6 Policy
    """

    def __init__(
        self,
        test,
        bsid,
        is_encap,
        sr_type,
        weight,
        fib_table,
        encap_src,
        source,
    ):
        self._test = test
        self.bsid = bsid
        self.is_encap = is_encap
        self.sr_type = sr_type
        self.weight = weight
        self.fib_table = fib_table
        self.encap_src = encap_src

        # list of segment list
        self.seg_lists = []

        # source not passed to API
        # self.source = inet_pton(AF_INET6, source)
        self.source = source
        self._configured = False

    def add_vpp_config(self, segments=[]):
        self._test.vapi.sr_policy_add_v2(
            bsid_addr=self.bsid,
            weight=self.weight,
            is_encap=self.is_encap,
            type=self.sr_type,
            fib_table=self.fib_table,
            encap_src=self.encap_src,
            sids={
                "num_sids": len(segments),
                "sids": self._get_fixed_segments(segments),
                "weight": 1,
            },
        )
        self.seg_lists.append(segments)
        self._configured = True

    def mod_vpp_config(self, segments=[]):
        # only ADD operation is supported
        self._test.vapi.sr_policy_mod_v2(
            bsid_addr=self.bsid,
            weight=self.weight,
            fib_table=self.fib_table,
            operation=1,
            sl_index=0xFFFFFFFF,
            encap_src=self.encap_src,
            sids={
                "num_sids": len(segments),
                "sids": self._get_fixed_segments(segments),
                "weight": 1,
            },
        )
        self.seg_lists.append(segments)

    def remove_vpp_config(self):
        self._test.vapi.sr_policy_del(self.bsid)
        self._configured = False

    def query_vpp_config(self):
        match_counter = 0
        policies = self._test.vapi.sr_policies_v2_dump()
        for p in policies:
            segments_matched = True
            for i in range(p.num_sid_lists):
                # transform sid_list from IPv6Address list to string list
                p_sids = [
                    str(p) for p in p.sid_lists[i].sids[: p.sid_lists[i].num_sids]
                ]
                if p_sids != self.seg_lists[i]:
                    segments_matched = False

            if (
                str(p.bsid) == str(self.bsid)
                and str(p.encap_src) == str(self.encap_src)
                and p.type == self.sr_type
                and p.is_encap == self.is_encap
                and p.fib_table == self.fib_table
                and p.num_sid_lists == len(self.seg_lists)
                and segments_matched == True
            ):
                match_counter += 1
        return match_counter == 1

    def object_id(self):
        return "%d;%s-><%s>;%d" % (
            self.sr_type,
            self.bsid,
            ",".join(self.segments),
            self.is_encap,
        )

    def _get_fixed_segments(self, segments):
        segs = copy.copy(segments)
        # note: array expect size is 16
        for _ in range(16 - len(segments)):
            segs.append("")
        return segs


class VppSRv6Steering(VppObject):
    """
    SRv6 Steering
    """

    def __init__(
        self,
        test,
        bsid,
        prefix,
        mask_width,
        traffic_type,
        sr_policy_index,
        table_id,
        sw_if_index,
    ):
        self._test = test
        self.bsid = bsid
        self.prefix = prefix
        self.mask_width = mask_width
        self.traffic_type = traffic_type
        self.sr_policy_index = sr_policy_index
        self.sw_if_index = sw_if_index
        self.table_id = table_id
        self._configured = False

    def add_vpp_config(self):
        self._test.vapi.sr_steering_add_del(
            is_del=0,
            bsid_addr=self.bsid,
            sr_policy_index=self.sr_policy_index,
            table_id=self.table_id,
            prefix={"address": self.prefix, "len": self.mask_width},
            sw_if_index=self.sw_if_index,
            traffic_type=self.traffic_type,
        )
        self._configured = True

    def remove_vpp_config(self):
        self._test.vapi.sr_steering_add_del(
            is_del=1,
            bsid_addr=self.bsid,
            sr_policy_index=self.sr_policy_index,
            table_id=self.table_id,
            prefix={"address": self.prefix, "len": self.mask_width},
            sw_if_index=self.sw_if_index,
            traffic_type=self.traffic_type,
        )
        self._configured = False

    def query_vpp_config(self):
        match_counter = 0
        steers = self._test.vapi.sr_steering_pol_dump()
        for s in steers:
            if s.traffic_type == self.traffic_type and str(s.bsid) == str(self.bsid):
                if s.traffic_type == SRv6PolicySteeringTypes.SR_STEER_L2:
                    if s.sw_if_index == self.sw_if_index:
                        match_counter += 1
                elif (
                    s.fib_table == self.table_id
                    and str(s.prefix.network_address) == str(self.prefix)
                    and s.prefix.prefixlen == self.mask_width
                ):
                    match_counter += 1
        return match_counter == 1

    def object_id(self):
        return "%d;%d;%s/%d->%s" % (
            self.table_id,
            self.traffic_type,
            self.prefix,
            self.mask_width,
            self.bsid,
        )
