#  Copyright (c) 2019. Vinci Consulting Corp. All Rights Reserved.
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

import six
import scapy.utils
from vpp_papi_strerror import strerror


__all_ = ('CaptureError', 'CaptureUnexpectedPacketError',
          'CaptureMismatchError', 'CaptureNoPacketsError',
          'CaptureTimeoutError', 'InterfaceError', 'LispError',
          'RegistryError', 'UnexpectedApiReturnValueError',
          'UnexpectedApiPositiveReturnValueError', 'ApiInternalError',
          'VppTestCaseError'
          )


# DRY
def init__(self, message=None, **kwargs):
    """private method called by all exceptions that subclass Exception."""
    self.kwargs = kwargs

    if not message:
        try:
            message = self.message % kwargs
        except Exception as e:
            message = self.message
    else:
        message = message % kwargs

    super(Exception, self).__init__(message)


class CaptureError(Exception):
    """ Base Exception from which all Capture errors should subclass.

    To correctly use this class, inherit from it and define
    a 'message' property. That message will get printed
    with the keyword arguments provided to the constructor.

    """
    message = 'A Capture specific error occurred.'

    def __init__(self, message=None, **kwargs):
        init__(self, message, **kwargs)


class CaptureUnexpectedPacketError(CaptureError):
    """ An error indicating that an unexpected packet was observed.

    To correctly use this class, pass in the raw packet received using
    the 'packet' kwarg and the receiving interface using the 'interface' kwarg.

    Raising `CaptureUnexpectedPacketError` will output the raw packet in
    hex format along with the Scapy decode of the raw packet.
    """
    message = 'Captured an unexpected packet on ' \
              'interface %(interface)s: %(packet)s'

    def __init__(self, message=None, **kwargs):
        if 'packet' in kwargs:
            _packet_hex = scapy.utils.hexdump(kwargs['packet'], dump=True)
            _packet_show = kwargs['packet'].show(dump=True)
            _packet = '\n%s\n%s' % (_packet_hex, _packet_show)
            kwargs['packet'] = _packet

        super(CaptureUnexpectedPacketError, self).__init__(message, **kwargs)


class CaptureMismatchError(CaptureError):
    """ The number of packets received differs from expected.

    To correctly use this class, pass in the receiving interface using
    the 'interface' kwarg, the actual number of packets using
    the 'actual' kwarg and the expected number of packets using
    the 'expected' kwarg.
    """
    message = 'Number of captured packets on interface %(interface)s ' \
              '%(actual)s is different from expected %(expected)s.'


class CaptureNoPacketsError(CaptureMismatchError):
    message = 'No packets captured on interface %(interface)s. ' \
              'Expected %(expected)s'


class CaptureTimeoutError(CaptureError):
    message = 'No packets were captured on interface %(interface)s within ' \
              'timeout %(timeout)s sec.'


class InterfaceError(Exception):
    message = "VppInterface Error."

    def __init__(self, message=None, **kwargs):
        init__(self, message, **kwargs)


class LispError(Exception):
    """ A LISP specific error occurred.
    """
    message = "LISP specific error"

    def __init__(self, message=None, **kwargs):
        init__(self, message, **kwargs)


class RegistryError(Exception):
    """ There was an error with the `VppObject` registry.

    """
    message = "Object registry error "

    def __init__(self, message=None, **kwargs):
        init__(self, message, **kwargs)


class UnexpectedApiReturnValueError(Exception):
    """The API returned an unexpected Value.

    To correctly use this class, pass in the actual api return value in
    the 'reply' kwarg and the expected return value in the 'expected' kwarg.

    Raising `UnexpectedApiReturnValueError` will return a message with
    the human-readable return code definitions.

    """

    message = "API call failed, expected %(expected)d " \
              "(%(expected_strerror)s) returned value instead of %(retval)d " \
              "(%(retval_strerror)s) in %(reply)r"

    def __init__(self, message=None, **kwargs):
        if 'reply' in kwargs:
            kwargs['retval_strerror'] = strerror(kwargs['reply'].retval)
            kwargs['retval'] = kwargs['reply'].retval

        if 'expected' in kwargs:
            kwargs['expected_strerror'] = strerror(kwargs['expected'])

        init__(self, message, **kwargs)


class UnexpectedApiPositiveReturnValueError(Exception):
    """ The API returned a positive return value.

    This should never be seen in a production system.
    The API returns 0 for success and a negative return value otherwise.
    Raising this exception requires developer intervention.

    """
    message = "the API returned an unexpected positive value instead " \
              "of %(ret_val)s."

    def __init__(self, message=None, **kwargs):
        init__(self, message, **kwargs)


class ApiInternalError(Exception):
    """ The API Client is in an invalid state.

    This should never be seen in a production system.
    Raising this exception requires developer intervention.
    """
    message = 'The API returned an Internal Error.'

    def __init__(self, message=None, **kwargs):
        init__(self, message, **kwargs)


class VppTestCaseError(Exception):
    message = 'VPP TestClass specific error'

    def __init__(self, message=None, **kwargs):
        init__(self, message, **kwargs)
