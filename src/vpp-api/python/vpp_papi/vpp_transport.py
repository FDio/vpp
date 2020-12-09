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


class VPPIOError(IOError):
    """ exception communicating with vpp over shared memory """

    def __init__(self, rv, descr):
        self.rv = rv
        self.desc = descr

        super(VPPIOError, self).__init__(rv, descr)


class MessageTableMixin(metaclass=abc.ABCMeta):

    def __init__(self) -> None:
        self.message_table = {}

    @abc.abstractmethod
    def get_msg_index(self, name: str) -> int:
        pass

    @abc.abstractmethod
    def msg_table_max_index(self) -> int:
        pass


class BaseVppTransport(MessageTableMixin, metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def __init__(self, *, parent, ctx: typing.Dict) -> None:
        super(BaseVppTransport, self).__init__()

    @abc.abstractmethod
    def connect(self, name: str, pfx: str, msg_handler, rx_qlen: int) -> int:
        pass

    @abc.abstractmethod
    def disconnect(self) -> int:
        pass

    @abc.abstractmethod
    def suspend(self) -> None:
        pass

    @abc.abstractmethod
    def resume(self) -> None:
        pass

    @abc.abstractmethod
    def get_callback(self, do_async: bool, vpp_object: 'VPPApiClient') -> typing.Callable:
        pass

    @abc.abstractmethod
    def read(self, timeout: typing.Optional[int] = None) -> bytes:
        pass

    @abc.abstractmethod
    def write(self, buf: bytes) -> int:
        pass

