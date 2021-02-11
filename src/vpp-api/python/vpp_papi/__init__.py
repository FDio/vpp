# Copyright (c) 2021 Cisco and/or its affiliates.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This is a standalone library, not depending on any GPL-licensed code.

from .macaddress import MACAddress, mac_pton, mac_ntop  # noqa: F401
from .vpp_papi import FuncWrapper, VppApiDynamicMethodHolder  # noqa: F401
from .vpp_papi import VppEnum, VppEnumType, VppEnumFlag  # noqa: F401
from .vpp_papi import VPPIOError, VPPRuntimeError, VPPValueError  # noqa: F401
from .vpp_papi import VPPApiClient  # noqa: F401
from .vpp_papi import VPPApiJSONFiles  # noqa: F401

# sorted lexicographically
from .vpp_serializer import BaseTypes  # noqa: F401
from .vpp_serializer import VPPEnumType, VPPType, VPPTypeAlias  # noqa: F401
from .vpp_serializer import VPPMessage, VPPUnionType  # noqa: F401

import pkg_resources  # part of setuptools
try:
    __version__ = pkg_resources.get_distribution("vpp_papi").version
except (pkg_resources.DistributionNotFound):
    """Can't find vpp_papi via setuptools"""
