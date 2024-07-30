from ipaddress import IPv4Network

from vpp_object import VppObject
from vpp_papi import VppEnum
from vpp_ip import INVALID_INDEX
from vpp_papi_provider import UnexpectedApiReturnValueError


class SessionSdl:
    """Session SDL"""

    def __init__(
        self,
        lcl,
        action_index,
        tag,
    ):

        self.action_index = action_index
        self.lcl = lcl
        self.tag = tag

    def encode(self):
        return {
            "lcl": self.lcl,
            "action_index": self.action_index,
            "tag": self.tag,
        }


class VppSessionSdl(VppObject):
    """VPP Session SDL"""

    def __init__(self, test, rules, is_add, appns_index):
        self._test = test
        self._rules = rules
        self.is_add = is_add
        self.appns_index = appns_index

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
            reply = self._test.vapi.session_sdl_add_del(
                is_add=self.is_add,
                appns_index=self.appns_index,
                count=self.count,
                r=self.encode_rules(),
            )
            self._test.registry.register(self, self._test.logger)
            if expect_error:
                self._test.fail("Unexpected api reply")
            return self
        except UnexpectedApiReturnValueError:
            if not expect_error:
                self._test.fail("Unexpected api reply")
        return None

    def query_vpp_config(self):
        pass

    def remove_vpp_config(self, expect_error=False):
        pass
