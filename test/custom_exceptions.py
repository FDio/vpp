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

import ipaddress
import logging
import six
import scapy.utils
from vpp_papi_strerror import strerror
try:
    text_type = unicode
except NameError:
    text_type = str

logger = logging.getLogger(__name__)


__all_ = ('CaptureError', 'CaptureUnexpectedPacketError',
          'CaptureMismatchError', 'CaptureNoPacketsError',
          'CaptureTimeoutError', 'InterfaceError', 'LispError',
          'RegistryError', 'UnexpectedApiReturnValueError',
          'UnexpectedApiReturnValueError56',
          'UnexpectedApiReturnValueError114',
          'UnexpectedApiReturnValueError127',
          'UnexpectedApiPositiveReturnValueError', 'ApiInternalError',
          'VppTestCaseError'
          )


# DRY
def _message_handler(self, message=None, **kwargs):
    """private method called by all exceptions that subclass Exception."""
    self.kwargs = kwargs

    if message is None:
        return self.message % kwargs

    return message % kwargs


class CaptureError(Exception):
    """ Base Exception from which all Capture errors should subclass.

    To correctly use this class, inherit from it and define
    a 'message' property. That message will get printed
    with the keyword arguments provided to the constructor.

    """
    message = 'A Capture specific error occurred.'

    def __init__(self, message=None, **kwargs):
        message = _message_handler(self, message, **kwargs)

        super(CaptureError, self).__init__(message)


class CaptureUnexpectedPacketError(CaptureError):
    """ An error indicating that an unexpected packet was observed.

    To correctly use this class, pass in the raw packet received using
    the 'packet' kwarg and the receiving interface using the 'interface' kwarg.

    Raising `CaptureUnexpectedPacketError` will output the raw packet in
    hex format along with the Scapy decode of the raw packet.
    """
    message = 'Captured an unexpected packet '
    details = 'on interface %(interface)s:\n' \
              'local mac: %(local_mac)s local addr: %(local_addr)s\n' \
              'remote mac: %(remote_mac)s remote addr: %(remote_addr)s\n' \
              'local ip6 ll: %(local_ip6_ll)s ' \
              'remote ip6 ll: %(remote_ip6_ll)s\n'\
              'explanation: %(explanation)s\n' \
              'Did not expect: %(unexpected)s\n' \
              '%(packet)s'

    def __init__(self, message=None, **kwargs):

        if 'exception' in kwargs:
            kwargs['exception_name'] = \
                kwargs['exception'].__class__.__name__

            if isinstance(kwargs['exception'], AssertionError):
                kwargs['explanation'] = \
                    'Properly formatted but unexpected packet received.'

                # If there was an AssertionError and no message passed,
                # use the raw exception.
                if len(kwargs['exception'].message):
                    kwargs['unexpected'] = '%s' % \
                                           kwargs['exception'].message
                else:
                    _msg = kwargs['exception'].args
                    if len(_msg):
                        _unexpected = _msg
                    else:
                        _unexpected = 'No description provided. ' \
                                      '(Ask the developer to add a ' \
                                      'description to the triggering ' \
                                      'assertion.)'
                    kwargs['unexpected'] = _unexpected

        if 'unexpected' not in kwargs:
                kwargs['unexpected'] = '(No assertion provided.)'

        if 'packet' in kwargs:
            _packet_hex = scapy.utils.hexdump(kwargs['packet'], dump=True)
            _packet_show = kwargs['packet'].show(dump=True)
            _packet = '\n%s\n%s' % (_packet_hex, _packet_show)
            kwargs['packet'] = _packet

        if 'interface' in kwargs:
            kwargs['local_mac'] = kwargs['interface'].local_mac
            kwargs['local_addr'] = kwargs['interface'].local_addr
            kwargs['remote_mac'] = kwargs['interface'].remote_mac
            kwargs['remote_addr'] = kwargs['interface'].remote_addr
            kwargs['local_ip6_ll'] = kwargs['interface'].local_ip6_ll
            kwargs['remote_ip6_ll'] = kwargs['interface'].remote_ip6_ll
        if not message:
                message = self.message

        message = message + self.details % kwargs

        super(self.__class__, self).__init__(message, **kwargs)


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
    message = 'No packets were captured'
    details = ' on interface %(interface)s within ' \
              'timeout of %(timeout)s sec.'

    def __init__(self, message=None, **kwargs):
        if not message:
            message = self.message
        else:
            message = message
        for _details in ['interface', 'timeout']:
            if _details not in kwargs:
                kwargs[_details] = '(not specified)'

        message = message + self.details % kwargs

        super(self.__class__, self).__init__(message, **kwargs)


class FragmentationError(Exception):
    """Error occurred while fragmenting packet. """


class InterfaceError(Exception):
    message = "VppInterface Error."

    def __init__(self, message=None, **kwargs):
        message = _message_handler(self, message, **kwargs)
        super(self.__class__, self).__init__(message)


class LispError(Exception):
    """ A LISP specific error occurred.
    """
    message = "LISP specific error"

    def __init__(self, message=None, **kwargs):
        message = _message_handler(self, message, **kwargs)
        super(self.__class__, self).__init__(message)


class RegistryError(Exception):
    """ There was an error with the `VppObject` registry.

    """
    message = "Object registry error "

    def __init__(self, message=None, **kwargs):
        message = _message_handler(self, message, **kwargs)
        super(self.__class__, self).__init__(message)


class UnexpectedApiReturnValueError(Exception):
    """The API returned an unexpected Value.

    To correctly use this class, pass in the actual api return value in
    the 'reply' kwarg and the expected return value in the 'expected' kwarg.

    Raising `UnexpectedApiReturnValueError` will return a message with
    the human-readable return code definitions.

    """

    message = "API call returned unexpected value."
    details = " expected %(expected)d " \
              "(%(expected_strerror)s) returned value instead of %(retval)d " \
              "(%(retval_strerror)s) in %(reply)r "
    detail_keys = ['expected', 'expected_strerror', 'reply', 'retval',
                   'retval_strerror']

    def __init__(self, message=None, **kwargs):
        if 'reply' in kwargs:
            kwargs['retval_strerror'] = strerror(kwargs['reply'].retval)
            kwargs['retval'] = kwargs['reply'].retval

        if 'expected' in kwargs:
            kwargs['expected_strerror'] = strerror(kwargs['expected'])

        if 'details' in kwargs:
            self.details = UnexpectedApiReturnValueError.details + \
                           kwargs['details']
            del kwargs['details']

        # Remove unused kwargs so format doesn't complain.
        for _key in kwargs.keys():
            if _key not in self.detail_keys:
                del kwargs[_key]

        if message is None:
            message = self.message
        try:
            message += self.details % kwargs
        except (KeyError,) as e:
            pass

        super(UnexpectedApiReturnValueError, self).__init__(message)


class UnexpectedApiReturnValueError56(UnexpectedApiReturnValueError):
    """-56 (VLAN subif already exists)"""
    details = "sw_if_index %(sw_if_index)s vlan_id %(vlan_id)s "
    details_kwargs = ['sw_if_index', 'vlan_id']

    def __init__(self, message=None, **kwargs):
        for _details in self.details_kwargs:
            if _details not in kwargs:
                kwargs[_details] = '(not specified)'

        kwargs['details'] =  self.__class__.details % kwargs

        try:
            for _details in self.details_kwargs:
                del kwargs[_details]
        except (KeyError,) as e:
            pass

        super(UnexpectedApiReturnValueError56, self).__init__(
            message, **kwargs)


class UnexpectedApiReturnValueError114(UnexpectedApiReturnValueError):
    """"-114 (Address found for interface)"""
    details = "sw_if_index %(sw_if_index)s vrf_id %(vrf_id)s "
    details_kwargs = ['sw_if_index', 'vrf_id']

    def __init__(self, message=None, **kwargs):
        for _details in self.details_kwargs:
            if _details not in kwargs:
                kwargs[_details] = '(not specified)'

        kwargs['details'] =  self.__class__.details % kwargs

        try:
            for _details in self.details_kwargs:
                del kwargs[_details]
        except (KeyError,) as e:
            pass

        super(UnexpectedApiReturnValueError114, self).__init__(
            message, **kwargs)

class UnexpectedApiReturnValueError127(UnexpectedApiReturnValueError):
    details = "sw_if_index %(sw_if_index)s address " \
              "%(address)s/%(address_length)s "
    details_kwargs = ['sw_if_index', 'address', 'address_length']

    def __init__(self, message=None, **kwargs):
        for _details in self.details_kwargs:
            if _details not in kwargs:
                kwargs[_details] = '(not specified)'

        if 'address' in kwargs:
            kwargs['address'] = ipaddress.ip_address(text_type(kwargs['address']))

        kwargs['details'] =  self.__class__.details % kwargs

        try:
            for _details in self.details_kwargs:
                del kwargs[_details]
        except (KeyError,) as e:
            pass

        super(UnexpectedApiReturnValueError127, self).__init__(
            message, **kwargs)


class UnexpectedApiPositiveReturnValueError(Exception):
    """ The API returned a positive return value.

    This should never be seen in a production system.
    The API returns 0 for success and a negative return value otherwise.
    Raising this exception requires developer intervention.

    """
    message = "the API returned an unexpected positive value instead " \
              "of %(ret_val)s."

    def __init__(self, message=None, **kwargs):
        message = _message_handler(self, message, **kwargs)
        super(self.__class__, self).__init__(message)


class ApiInternalError(Exception):
    """ The API Client is in an invalid state.

    This should never be seen in a production system.
    Raising this exception requires developer intervention.
    """
    message = 'The API returned an Internal Error.'

    def __init__(self, message=None, **kwargs):
        message = _message_handler(self, message, **kwargs)
        super(self.__class__, self).__init__(message)


class VppTestCaseError(Exception):
    message = 'VPP TestClass specific error'

    def __init__(self, message=None, **kwargs):
        message = _message_handler(self, message, **kwargs)
        super(self.__class__, self).__init__(message)
