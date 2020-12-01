from vpp_object import VppObject


class VppSrMplsPolicy(VppObject):
    def __init__(self, test, bsid, weight, segments, is_spray=False):
        self._test = test
        self._bsid = bsid
        self._weight = weight
        self._is_spray = is_spray
        self._segments = segments

    def add_vpp_config(self):
        self._test.vapi.sr_mpls_policy_add(bsid=self._bsid,
                                           weight=self._weight,
                                           is_spray=self._is_spray,
                                           n_segments=len(self._segments),
                                           segments=self._segments)

    def remove_vpp_config(self):
        self._test.vapi.sr_mpls_policy_del(bsid=self._bsid)

    def query_vpp_config(self):
        return NotImplemented
