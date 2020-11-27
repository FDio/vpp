from vpp_object import VppObject
from vpp_papi import VppEnum


class Punt:

    @staticmethod
    def dump_to_punt_one(dump):
        if dump.punt.type == Punt.type_l4:
            return PuntL4(dump.punt.punt.l4.af, dump.punt.punt.l4.protocol,
                          dump.punt.punt.l4.port)
        elif dump.punt.type == Punt.type_ip_proto:
            return PuntIpProto(dump.punt.punt.ip_proto.af,
                               dump.punt.punt.ip_proto.protocol)
        elif dump.punt.type == Punt.type_exception:
            return PuntException(dump.punt.punt.exception.id)
        else:
            raise ValueError("Unknown punt type")

    @staticmethod
    def dump_to_punt(dump):
        ret = []
        for d in dump:
            ret.append(Punt.dump_to_punt_one(d))
        return ret

    @classmethod
    def init_feature_class(cls, vapi):
        cls.vapi = vapi
        cls.type_l4 = VppEnum.vl_api_punt_type_t.PUNT_API_TYPE_L4
        cls.type_ip_proto = VppEnum.vl_api_punt_type_t.PUNT_API_TYPE_IP_PROTO
        cls.type_exception = VppEnum.vl_api_punt_type_t.PUNT_API_TYPE_EXCEPTION

    @classmethod
    def dump(cls, punt_type=None):
        """Dump punts and convert them into object models."""
        if punt_type:
            return cls.vapi.punt_socket_dump(type=punt_type)
        return cls.vapi.punt_socket_dump()

    @classmethod
    def dump_reason(cls, reason=None):
        if reason:
            return cls.vapi.punt_reason_dump(reason=reason.encode())
        return cls.vapi.punt_reason_dump()


class PuntReason:
    def __init__(self, name, id=None):
        self.id = id
        self.name = name

    def encode(self):
        return {"id": self.id, "name": self.name}


class BasePunt:

    def __init__(self, punt_type):
        self._type = punt_type

    @property
    def type(self):
        return self._type

    @property
    def type_encode(self):
        if Punt.type_l4 == self.type:
            return "l4"
        elif Punt.type_ip_proto == self.type:
            return "ip_proto"
        elif Punt.type_exception == self.type:
            return "exception"
        else:
            raise ValueError("Unknown punt type")

    def encode(self):
        return {"type": self._type, "punt": {self.type_encode: {}}}

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            if other._type == self._type:
                return True
            return False
        return NotImplemented

    def __str__(self):
        return "type: %d" % self.type_encode

    def __repr__(self):
        return NotImplemented


class PuntIpProto(BasePunt):
    def __init__(self, address_family, ip_protocol):
        super(PuntIpProto, self).__init__(Punt.type_ip_proto)
        self._af = address_family
        self._proto = ip_protocol

    def encode(self):
        ret = super(PuntIpProto, self).encode()
        ret["punt"][self.type_encode] = {"af": self._af,
                                         "protocol": self._proto}
        return ret

    def __eq__(self, other):
        if super(PuntIpProto, self).__eq__(other):
            if other._af == self._af and other._proto == self._proto:
                return True
        return False

    def __str__(self):
        return "%d af: %d proto: %d" % \
            (super(PuntIpProto), self._af, self._proto)

    def __repr__(self):
        return "%s(address_family=%s, ip_protocol=%s)" % \
            (self.__class__.__name__, self._af, self._proto)


class PuntL4(PuntIpProto):
    def __init__(self, address_family, ip_protocol, port):
        super(PuntL4, self).__init__(address_family, ip_protocol)
        # overwrite punt type
        BasePunt.__init__(self, Punt.type_l4)
        self._port = port

    @property
    def port(self):
        return self._port

    def encode(self):
        ret = super(PuntL4, self).encode()
        ret["punt"][self.type_encode]["port"] = self._port
        return ret

    def __eq__(self, other):
        if super(PuntL4, self).__eq__(other):
            if other._port == self._port:
                return True
        return False

    def __str__(self):
        return "%d port: %d" % (super(PuntL4), self._port)

    def __repr__(self):
        return "%s(address_family=%s, ip_protocol=%s, port=%s)" % \
            (self.__class__.__name__, self._af, self._proto, self._port)


class PuntException(BasePunt):
    def __init__(self, exception_id):
        super(PuntException, self).__init__(Punt.type_exception)
        self._exception_id = exception_id

    def encode(self):
        ret = super(PuntException, self).encode()
        ret["punt"][self.type_encode] = {"id": self._exception_id}
        return ret

    def __eq__(self, other):
        if super(PuntException, self).__eq__(other):
            if self._exception_id == other._exception_id:
                return True
        return False

    def __str__(self):
        return "%d id: %d" % (super(PuntException), self._exception_id)

    def __repr__(self):
        return "%s(exception_id=%s)" % (self.__class__.__name__,
                                        self._exception_id)


class VppPuntSocket(VppObject):
    def __init__(self, test, punt, pathname, header_version=1):
        self._test = test
        self._punt = punt
        self._pathname = pathname
        self._header_version = header_version

    @property
    def punt(self):
        return self._punt

    @property
    def pathname(self):
        return self._pathname

    def add_vpp_config(self):
        self._test.vapi.punt_socket_register(
            header_version=self._header_version, punt=self._punt.encode(),
            pathname=self._pathname)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.punt_socket_deregister(punt=self._punt.encode())

    def get_vpp_config(self):
        dump = Punt.dump(punt_type=self._punt.type)
        for d in dump:
            if self.punt == Punt.dump_to_punt_one(d) and \
               self._pathname == d.pathname:
                return d
        return None

    def query_vpp_config(self):
        if self.get_vpp_config():
            return True
        return False
