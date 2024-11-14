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

import importlib.metadata as metadata

try:
    __version__ = metadata.version("vpp_papi")
except metadata.PackageNotFoundError:
    # Can't find vpp_papi via importlib.metadata
    __version__ = "0.0.0"
