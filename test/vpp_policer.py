from vpp_object import VppObject
from vpp_ip import INVALID_INDEX
from enum import Enum


class Dir(Enum):
    RX = 0
    TX = 1


class PolicerAction:
    """sse2 qos action"""

    def __init__(self, type, dscp):
        self.type = type
        self.dscp = dscp

    def encode(self):
        return {"type": self.type, "dscp": self.dscp}


class VppPolicer(VppObject):
    """Policer"""

    def __init__(
        self,
        test,
        name,
        cir,
        eir,
        commited_burst,
        excess_burst,
        rate_type=0,
        round_type=0,
        type=0,
        color_aware=False,
        conform_action=PolicerAction(1, 0),
        exceed_action=PolicerAction(0, 0),
        violate_action=PolicerAction(0, 0),
    ):
        self._test = test
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

    @property
    def config(self):
        return {
            "cir": self.cir,
            "eir": self.eir,
            "cb": self.commited_burst,
            "eb": self.excess_burst,
            "rate_type": self.rate_type,
            "round_type": self.round_type,
            "type": self.type,
            "color_aware": self.color_aware,
            "conform_action": self.conform_action.encode(),
            "exceed_action": self.exceed_action.encode(),
            "violate_action": self.violate_action.encode(),
        }

    def add_vpp_config(self):
        r = self._test.vapi.policer_add(name=self.name, infos=self.config)
        self._test.registry.register(self, self._test.logger)
        self._policer_index = r.policer_index
        return self

    def update(self):
        self._test.vapi.policer_update(
            policer_index=self._policer_index, infos=self.config
        )

    def remove_vpp_config(self):
        self._test.vapi.policer_del(policer_index=self._policer_index)
        self._policer_index = INVALID_INDEX

    def bind_vpp_config(self, worker, bind):
        self._test.vapi.policer_bind_v2(
            policer_index=self._policer_index, worker_index=worker, bind_enable=bind
        )

    def apply_vpp_config(self, if_index, dir: Dir, apply):
        if dir == Dir.RX:
            self._test.vapi.policer_input_v2(
                policer_index=self._policer_index, sw_if_index=if_index, apply=apply
            )
        else:
            self._test.vapi.policer_output_v2(
                policer_index=self._policer_index, sw_if_index=if_index, apply=apply
            )

    def query_vpp_config(self):
        dump = self._test.vapi.policer_dump_v2(policer_index=self._policer_index)
        for policer in dump:
            if policer.name == self.name:
                return True
        return False

    def object_id(self):
        return "policer-%s" % (self.name)

    def get_details(self):
        dump = self._test.vapi.policer_dump_v2(policer_index=self._policer_index)
        for policer in dump:
            if policer.name == self.name:
                return policer
        raise self._test.vapi.VPPValueError("Missing policer")

    def get_stats(self, worker=None):
        conform = self._test.statistics.get_counter("/net/policer/conform")
        exceed = self._test.statistics.get_counter("/net/policer/exceed")
        violate = self._test.statistics.get_counter("/net/policer/violate")

        counters = {"conform": conform, "exceed": exceed, "violate": violate}

        total = {}
        for name, c in counters.items():
            total[f"{name}_packets"] = 0
            total[f"{name}_bytes"] = 0
            for i in range(len(c)):
                t = c[i]
                if worker is not None and i != worker + 1:
                    continue
                stat_index = self._policer_index
                total[f"{name}_packets"] += t[stat_index]["packets"]
                total[f"{name}_bytes"] += t[stat_index]["bytes"]

        return total
