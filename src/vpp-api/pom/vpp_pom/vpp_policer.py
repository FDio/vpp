from .vpp_object import VppObject
from .vpp_ip import INVALID_INDEX


class PolicerAction():
    """ sse2 qos action """

    def __init__(self, type, dscp):
        self.type = type
        self.dscp = dscp

    def encode(self):
        return {'type': self.type, 'dscp': self.dscp}


class VppPolicer(VppObject):
    """ Policer """

    def __init__(self, vclient, name, cir, eir, commited_burst, excess_burst,
                 rate_type=0, round_type=0, type=0, color_aware=False,
                 conform_action=PolicerAction(1, 0),
                 exceed_action=PolicerAction(0, 0),
                 violate_action=PolicerAction(0, 0)):
        self._vclient = vclient
        self.name = name
        self.cir = cir
        self.eir = eir
        self.commited_burst = commited_burst
        self.excess_burst = excess_burst
        self.rate_type = rate_type
        self.round_type = round_type
        self.type = type
        self.color_aware = color_aware
        self.conform_action = conform_action
        self.exceed_action = exceed_action
        self.violate_action = violate_action
        self._policer_index = INVALID_INDEX

    @property
    def policer_index(self):
        return self._policer_index

    def add_vpp_config(self):
        r = self._vclient.policer_add_del(
            name=self.name, cir=self.cir,
            eir=self.eir, cb=self.commited_burst, eb=self.excess_burst,
            rate_type=self.rate_type, round_type=self.round_type,
            type=self.type, color_aware=self.color_aware,
            conform_action=self.conform_action.encode(),
            exceed_action=self.exceed_action.encode(),
            violate_action=self.violate_action.encode())
        self._vclient.registry.register(self, self._vclient.logger)
        self._policer_index = r.policer_index
        return self

    def remove_vpp_config(self):
        self._vclient.policer_add_del(is_add=False, name=self.name)
        self._policer_index = INVALID_INDEX

    def query_vpp_config(self):
        dump = self._vclient.policer_dump(
            match_name_valid=True, match_name=self.name)
        for policer in dump:
            if policer.name == self.name:
                return True
        return False

    def object_id(self):
        return ("policer-%s" % (self.name))
