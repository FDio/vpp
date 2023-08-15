from .vpp_papi import FuncWrapper, VppApiDynamicMethodHolder  # noqa: F401
from .vpp_papi import VppEnum, VppEnumType, VppEnumFlag  # noqa: F401
from .vpp_papi import VPPIOError, VPPRuntimeError, VPPValueError  # noqa: F401
from .vpp_papi import VPPApiClient  # noqa: F401
from .vpp_papi import VPPApiJSONFiles  # noqa: F401
from .macaddress import MACAddress, mac_pton, mac_ntop  # noqa: F401

# sorted lexicographically
from .vpp_serializer import BaseTypes  # noqa: F401
from .vpp_serializer import VPPEnumType, VPPType, VPPTypeAlias  # noqa: F401
from .vpp_serializer import VPPMessage, VPPUnionType  # noqa: F401

import pkg_resources  # part of setuptools

try:
    __version__ = pkg_resources.get_distribution("vpp_papi").version
except pkg_resources.DistributionNotFound:
    """Can't find vpp_papi via setuptools"""
