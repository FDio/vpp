import socket
from ipaddress import ip_network

from vpp_object import VppObject


class VppLispLocatorSet(VppObject):
    """ Represents LISP locator set in VPP """

    def __init__(self, test, ls_name):
        self._test = test
        self._ls_name = ls_name

    @property
    def test(self):
        return self._test

    @property
    def ls_name(self):
        return self._ls_name

    def add_vpp_config(self):
        self.test.vapi.lisp_add_del_locator_set(locator_set_name=self._ls_name)
        self._test.registry.register(self, self.test.logger)

    def get_lisp_locator_sets_dump_entry(self):
        result = self.test.vapi.lisp_locator_set_dump()
        for ls in result:
            if ls.ls_name.strip('\x00') == self._ls_name:
                return ls
        return None

    def query_vpp_config(self):
        return self.get_lisp_locator_sets_dump_entry() is not None

    def remove_vpp_config(self):
        self.test.vapi.lisp_add_del_locator_set(locator_set_name=self._ls_name,
                                                is_add=0)

    def object_id(self):
        return 'lisp-locator-set-%s' % self._ls_name


class VppLispLocator(VppObject):
    """ Represents LISP locator in VPP """

    def __init__(self, test, sw_if_index, ls_name, priority=1, weight=1):
        self._test = test
        self._sw_if_index = sw_if_index
        self._ls_name = ls_name
        self._priority = priority
        self._weight = weight

    @property
    def test(self):
        """ Test which created this locator """
        return self._test

    @property
    def ls_name(self):
        """ Locator set name """
        return self._ls_name

    @property
    def sw_if_index(self):
        return self._sw_if_index

    @property
    def priority(self):
        return self._priority

    @property
    def weight(self):
        return self._weight

    def add_vpp_config(self):
        self.test.vapi.lisp_add_del_locator(locator_set_name=self._ls_name,
                                            sw_if_index=self._sw_if_index,
                                            priority=self._priority,
                                            weight=self._weight)
        self._test.registry.register(self, self.test.logger)

    def get_lisp_locator_dump_entry(self):
        locators = self.test.vapi.lisp_locator_dump(
                is_index_set=0, ls_name=self._ls_name)
        for locator in locators:
            if locator.sw_if_index == self._sw_if_index:
                return locator
        return None

    def query_vpp_config(self):
        locator = self.get_lisp_locator_dump_entry()
        return locator is not None

    def remove_vpp_config(self):
        self.test.vapi.lisp_add_del_locator(
                locator_set_name=self._ls_name, sw_if_index=self._sw_if_index,
                priority=self._priority, weight=self._weight, is_add=0)
        self._test.registry.register(self, self.test.logger)

    def object_id(self):
        return 'lisp-locator-%s-%d' % (self._ls_name, self._sw_if_index)


class LispEIDType:
    PREFIX = 0
    MAC = 1
    NSH = 2


class LispKeyIdType:
    NONE = 0
    SHA1 = 1
    SHA256 = 2


class LispEID:
    """ Lisp endpoint identifier """
    def __init__(self, eid):
        self.eid = eid
        self._type = -1

        # find out whether EID is ip prefix, or MAC
        try:
            self.prefix = ip_network(self.eid)
            self._type = LispEIDType.PREFIX
            return
        except ValueError:
            if self.eid.count(":") == 5:  # MAC address
                self.mac = self.eid
                self._type = LispEIDType.MAC
                return
        raise Exception('Unsupported EID format {!s}!'.format(eid))

    @property
    def eid_type(self):
        return self._type

    @property
    def address(self):
        if self.eid_type == LispEIDType.PREFIX:
            return self.prefix
        elif self.eid_type == LispEIDType.MAC:
            return self.mac
        elif self.eid_type == LispEIDType.NSH:
            return Exception('Unimplemented')

    @property
    def packed(self):
        if self.eid_type == LispEIDType.PREFIX:
            return {"type": self._type, "address": {"prefix": self.prefix}}
        elif self.eid_type == LispEIDType.MAC:
            return {"type": self._type, "address": {"mac": self.mac}}
        elif self.eid_type == LispEIDType.NSH:
            return Exception('Unimplemented')


class LispKey:
    """ Lisp Key """
    def __init__(self, key_type, key):
        self._key_type = key_type
        self._key = key

    @property
    def packed(self):
        return {"id": self._key_type, "key": self._key}


class VppLispMapping(VppObject):
    """ Represents common features for remote and local LISP mapping in VPP """

    def __init__(self, test, eid, vni=0, priority=1, weight=1):
        self._eid = LispEID(eid)
        self._test = test
        self._priority = priority
        self._weight = weight
        self._vni = vni

    @property
    def test(self):
        return self._test

    @property
    def vni(self):
        return self._vni

    @property
    def eid(self):
        return self._eid

    @property
    def priority(self):
        return self._priority

    @property
    def weight(self):
        return self._weight

    def get_lisp_mapping_dump_entry(self):
        return self.test.vapi.lisp_eid_table_dump(
            eid_set=1, vni=self._vni, eid=self._eid.packed)

    def query_vpp_config(self):
        mapping = self.get_lisp_mapping_dump_entry()
        return mapping

    def object_id(self):
        return 'lisp-mapping-[%s]-%s-%s-%s' % (
            self.vni, self.eid.address, self.priority, self.weight)


class VppLocalMapping(VppLispMapping):
    """ LISP Local mapping """
    def __init__(self, test, eid, ls_name, vni=0, priority=1, weight=1,
                 key_id=LispKeyIdType.NONE, key=''):
        super(VppLocalMapping, self).__init__(test, eid, vni, priority, weight)
        self._ls_name = ls_name
        self._key = LispKey(key_id, key)

    @property
    def ls_name(self):
        return self._ls_name

    @property
    def key_id(self):
        return self._key_id

    @property
    def key(self):
        return self._key

    def add_vpp_config(self):
        self.test.vapi.lisp_add_del_local_eid(
                locator_set_name=self._ls_name, eid=self._eid.packed,
                vni=self._vni, key=self._key.packed)
        self._test.registry.register(self, self.test.logger)

    def remove_vpp_config(self):
        self.test.vapi.lisp_add_del_local_eid(
                locator_set_name=self._ls_name, eid=self._eid.packed,
                vni=self._vni, is_add=0)

    def object_id(self):
        return 'lisp-eid-local-mapping-%s[%d]' % (self._eid.address, self._vni)


class LispRemoteLocator:
    def __init__(self, addr, priority=1, weight=1):
        self.addr = addr
        self.priority = priority
        self.weight = weight

    @property
    def packed(self):
        return {"priority": self.priority, "weight": self.weight,
                "ip_address": self.addr}


class VppRemoteMapping(VppLispMapping):

    def __init__(self, test, eid, rlocs=None, vni=0, priority=1, weight=1):
        super(VppRemoteMapping, self).__init__(test, eid, vni, priority,
                                               weight)
        self._rlocs = rlocs

    @property
    def rlocs(self):
        rlocs = []
        for rloc in self._rlocs:
            rlocs.append(rloc.packed)
        return rlocs

    def add_vpp_config(self):
        self.test.vapi.lisp_add_del_remote_mapping(
                rlocs=self.rlocs, deid=self._eid.packed,
                vni=self._vni, rloc_num=len(self._rlocs))
        self._test.registry.register(self, self.test.logger)

    def remove_vpp_config(self):
        self.test.vapi.lisp_add_del_remote_mapping(
                deid=self._eid.packed, vni=self._vni, is_add=0, rloc_num=0)

    def object_id(self):
        return 'lisp-eid-remote-mapping-%s[%d]' % (self._eid.address,
                                                   self._vni)


class VppLispAdjacency(VppObject):
    """ Represents LISP adjacency in VPP """

    def __init__(self, test, leid, reid, vni=0):
        self._leid = LispEID(leid)
        self._reid = LispEID(reid)
        if self._leid.eid_type != self._reid.eid_type:
            raise Exception('remote and local EID are different types!')
        self._vni = vni
        self._test = test

    @property
    def test(self):
        return self._test

    @property
    def leid(self):
        return self._leid

    @property
    def reid(self):
        return self._reid

    @property
    def vni(self):
        return self._vni

    def add_vpp_config(self):
        self.test.vapi.lisp_add_del_adjacency(
                leid=self._leid.packed, reid=self._reid.packed, vni=self._vni)
        self._test.registry.register(self, self.test.logger)

    @staticmethod
    def eid_equal(eid, eid_api):
        if eid.eid_type != eid_api.type:
            return False

        if eid_api.type == LispEIDType.PREFIX:
            if eid.address.prefixlen != eid_api.address.prefix.prefixlen:
                return False

        if eid.address != eid_api.address:
            return False

        return True

    def query_vpp_config(self):
        res = self.test.vapi.lisp_adjacencies_get(vni=self._vni)
        for adj in res.adjacencies:
            if self.eid_equal(self._leid, adj.leid) and \
                    self.eid_equal(self._reid, adj.reid):
                return True
        return False

    def remove_vpp_config(self):
        self.test.vapi.lisp_add_del_adjacency(
                leid=self._leid.packed, reid=self._reid.packed,
                vni=self._vni, is_add=0)

    def object_id(self):
        return 'lisp-adjacency-%s-%s[%d]' % (self._leid, self._reid, self._vni)
