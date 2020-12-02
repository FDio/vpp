#  Copyright (c) 2020. Vinci Consulting Corp. All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
import abc
import typing

"""A Base Transport that provides the method interface all transports need to provide """


class BaseTransport(metaclass=abc.ABCMeta):
    def connect(self, name, pfx, msg_handler, rx_qlen) -> int:
        """wrapper to vac_connect"""

    def disconnect(self) -> int:
        """wrapper to vac_disconnect"""

    def suspend(self) -> None:
        """wrapper to vac_rx_suspend"""

    def resume(self) -> None:
        """wrapper to vac_rx_resume"""

    def get_callback(self, do_async) -> typing.Callable:
        """wrapper to vac_callback factory returning sync or async callable"""

    def get_msg_index(self, name) -> int:
        """wrapper to vac_get_msg_index"""

    def msg_table_max_index(self) -> int:
        """wrapper to vac_msg_table_max_index"""

    def read(self, timeout) -> bytes:
        """wrapper to vac_read"""

    def write(self, buf: bytes) -> int:
        """wrapper to vac_write"""
