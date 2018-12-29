from scapy.fields import *
from vpp_object import *


class LispError(Exception):
    """LISP specific error"""
    pass


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
        self.test.vapi.lisp_locator_set(ls_name=self._ls_name)
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
        self.test.vapi.lisp_locator_set(ls_name=self._ls_name, is_add=0)

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
        return self.priority

    @property
    def weight(self):
        return self._weight

    def add_vpp_config(self):
        self.test.vapi.lisp_locator(ls_name=self._ls_name,
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
        self.test.vapi.lisp_locator(
                ls_name=self._ls_name, sw_if_index=self._sw_if_index,
                priority=self._priority, weight=self._weight, is_add=0)
        self._test.registry.register(self, self.test.logger)

    def object_id(self):
        return 'lisp-locator-%s-%d' % (self._ls_name, self._sw_if_index)


class LispEIDType(object):
    IP4 = 0
    IP6 = 1
    MAC = 2


class LispKeyIdType(object):
    NONE = 0
    SHA1 = 1
    SHA256 = 2


class LispEID(object):
    """ Lisp endpoint identifier """
    def __init__(self, eid):
        self.eid = eid

        # find out whether EID is ip4 prefix, ip6 prefix or MAC
        if self.eid.find("/") != -1:
            if self.eid.find(":") == -1:
                self.eid_type = LispEIDType.IP4
                self.data_length = 4
            else:
                self.eid_type = LispEIDType.IP6
                self.data_length = 16

            self.eid_address = self.eid.split("/")[0]
            self.prefix_length = int(self.eid.split("/")[1])
        elif self.eid.count(":") == 5:  # MAC address
            self.eid_type = LispEIDType.MAC
            self.eid_address = self.eid
            self.prefix_length = 0
            self.data_length = 6
        else:
            raise LispError('Unsupported EID format {}!'.format(eid))

    def __str__(self):
        if self.eid_type == LispEIDType.IP4:
            return socket.inet_pton(socket.AF_INET, self.eid_address)
        elif self.eid_type == LispEIDType.IP6:
            return socket.inet_pton(socket.AF_INET6, self.eid_address)
        elif self.eid_type == LispEIDType.MAC:
            return LispError('Unimplemented')
        raise LispError('Unknown EID type {}!'.format(self.eid_type))


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
                eid_set=1, prefix_length=self._eid.prefix_length,
                vni=self._vni, eid_type=self._eid.eid_type, eid=str(self._eid))

    def query_vpp_config(self):
        mapping = self.get_lisp_mapping_dump_entry()
        return mapping


class VppLocalMapping(VppLispMapping):
    """ LISP Local mapping """
    def __init__(self, test, eid, ls_name, vni=0, priority=1, weight=1,
                 key_id=LispKeyIdType.NONE, key=''):
        super(VppLocalMapping, self).__init__(test, eid, vni, priority, weight)
        self._ls_name = ls_name
        self._key_id = key_id
        self._key = key

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
        self.test.vapi.lisp_local_mapping(
                ls_name=self._ls_name, eid_type=self._eid.eid_type,
                eid=str(self._eid), prefix_len=self._eid.prefix_length,
                vni=self._vni, key_id=self._key_id, key=self._key)
        self._test.registry.register(self, self.test.logger)

    def remove_vpp_config(self):
        self.test.vapi.lisp_local_mapping(
                ls_name=self._ls_name, eid_type=self._eid.eid_type,
                eid=str(self._eid), prefix_len=self._eid.prefix_length,
                vni=self._vni, is_add=0)

    def object_id(self):
        return 'lisp-eid-local-mapping-%s[%d]' % (self._eid, self._vni)


class VppRemoteMapping(VppLispMapping):

    def __init__(self, test, eid, rlocs=None, vni=0, priority=1, weight=1):
        super(VppRemoteMapping, self).__init__(test, eid, vni, priority,
                                               weight)
        self._rlocs = rlocs

    @property
    def rlocs(self):
        return self._rlocs

    def add_vpp_config(self):
        self.test.vapi.lisp_remote_mapping(
                rlocs=self._rlocs, eid_type=self._eid.eid_type,
                eid=str(self._eid), eid_prefix_len=self._eid.prefix_length,
                vni=self._vni, rlocs_num=len(self._rlocs))
        self._test.registry.register(self, self.test.logger)

    def remove_vpp_config(self):
        self.test.vapi.lisp_remote_mapping(
                eid_type=self._eid.eid_type, eid=str(self._eid),
                eid_prefix_len=self._eid.prefix_length, vni=self._vni,
                is_add=0, rlocs_num=0)

    def object_id(self):
        return 'lisp-eid-remote-mapping-%s[%d]' % (self._eid, self._vni)


class VppLispAdjacency(VppObject):
    """ Represents LISP adjacency in VPP """

    def __init__(self, test, leid, reid, vni=0):
        self._leid = LispEID(leid)
        self._reid = LispEID(reid)
        if self._leid.eid_type != self._reid.eid_type:
            raise LispError('remote and local EID are different types!')
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
        self.test.vapi.lisp_adjacency(
                leid=str(self._leid),
                reid=str(self._reid), eid_type=self._leid.eid_type,
                leid_len=self._leid.prefix_length,
                reid_len=self._reid.prefix_length, vni=self._vni)
        self._test.registry.register(self, self.test.logger)

    @staticmethod
    def eid_equal(eid, eid_type, eid_data, prefix_len):
        if eid.eid_type != eid_type:
            return False

        if eid_type == LispEIDType.IP4 or eid_type == LispEIDType.IP6:
            if eid.prefix_length != prefix_len:
                return False

        if str(eid) != eid_data[0:eid.data_length]:
            return False

        return True

    def query_vpp_config(self):
        res = self.test.vapi.lisp_adjacencies_get(vni=self._vni)
        for adj in res.adjacencies:
            if self.eid_equal(self._leid, adj.eid_type, adj.leid,
                              adj.leid_prefix_len) and \
                self.eid_equal(self._reid, adj.eid_type, adj.reid,
                               adj.reid_prefix_len):
                return True
        return False

    def remove_vpp_config(self):
        self.test.vapi.lisp_adjacency(
                leid=str(self._leid),
                reid=str(self._reid), eid_type=self._leid.eid_type,
                leid_len=self._leid.prefix_length,
                reid_len=self._reid.prefix_length, vni=self._vni, is_add=0)

    def object_id(self):
        return 'lisp-adjacency-%s-%s[%d]' % (self._leid, self._reid, self._vni)
