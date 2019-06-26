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

import copy

__all__ = ('VPPApiClientError',
           'VPPApiClientIOError',
           'VPPApiClientInvalidReturnValueError',
           'VPPApiClientNotImplementedError',
           'VPPApiClientNoSuchApiError',
           'VPPApiClientRuntimeError',
           'VPPApiClientTypeError',
           'VPPApiClientUnexpectedReturnValueError',
           'VPPApiClientValueError',
           )

_want_reversible_repr = False
BUGREPORT_URL = 'https://jira.fd.io/projects/VPP/issues'


class VPPApiClientError(Exception):
    """ Base for all VPPApiErrors

    Expected usage as an exception to be checked against.
    eg. except VPPApiClientError:

    If you are raising an exception, use a subclass of VPPApiClientError.
    """

    def __init__(self, arg=None, *args, **kwargs):
        self._args = copy.deepcopy(args)
        self._kwargs = copy.deepcopy(kwargs)

        if arg is None:
            super(VPPApiClientError, self).__init__()
        else:
            super(VPPApiClientError, self).__init__(arg)

    def __repr__(self, extra=None):

        excluded_extra_fields = ['_args', '_kwargs']
        sep = ', ' if self._kwargs is not None else ''

        if self._args is not ():
            arg_list = '%s%s' % (sep, ', '.join(['{!s}'.format(k)
                                                for k in self._args]))
        else:
            arg_list = ''

        kwarg_list = ', '.join(['{!s}={!r}'.format(k, v)
                                for k, v in self._kwargs.items()])
        if extra is None:
            extra_list = ', '.join(['{!s}={!r}'.format(k, v)
                                    for k, v in vars(self).items() if
                                    k not in excluded_extra_fields])
        else:
            extra_list = ', '.join(['{!s}={!r}'.format(k, v)
                                    for k, v in extra.items()])

        if _want_reversible_repr:
            return '%s(%s%s)' % (self.__class__.__name__,
                                 arg_list, kwarg_list)
        else:
            return '<%s(%s%s); extra=%s>' % (self.__class__.__name__,
                                             arg_list, kwarg_list,
                                             extra_list)


class VPPApiClientNotImplementedError(VPPApiClientError, NotImplementedError):
    def __init__(self, arg=None):
        super(VPPApiClientNotImplementedError, self).__init__(arg)


class VPPApiClientNoSuchApiError(VPPApiClientError, AttributeError):
    def __init__(self, arg=None, api_fn_name=None):
        self.api_fn_name = api_fn_name

        msg = 'client called: %s()' % self.api_fn_name if self.api_fn_name is \
            not None else ''
        if arg is None:
            arg = msg
        else:
            arg = '%s %s' % (arg, self.api_fn_name)

        super(VPPApiClientNoSuchApiError, self).__init__(
            arg, api_fn_name=api_fn_name)


class VPPApiClientIOError(VPPApiClientError, IOError):
    def __init__(self, arg=None):
        super(VPPApiClientIOError, self).__init__(arg)


class VPPApiClientRuntimeError(VPPApiClientError, RuntimeError):
    def __init__(self, arg=None):
        super(VPPApiClientRuntimeError, self).__init__(arg)


class VPPApiClientAttributeError(VPPApiClientError, AttributeError):
    pass


class VPPApiClientTypeError(VPPApiClientError, TypeError):
    """ TypeError with augmented context information."""

    def __init__(self, arg=None, api_fn_name=None, api_fn_args=None):
        self.api_fn_name = api_fn_name
        self.api_fn_args = api_fn_args
        super(VPPApiClientTypeError, self).__init__(arg,
                                                    api_fn_name=api_fn_name,
                                                    api_fn_args=api_fn_args)


class VPPApiClientValueError(VPPApiClientError, ValueError):
    """ ValueError with augmented context information."""

    def __init__(self, arg=None, api_fn_name=None, api_fn_args=None):
        self.api_fn_name = api_fn_name
        self.api_fn_args = api_fn_args
        super(VPPApiClientValueError, self).__init__(arg,
                                                     api_fn_name=api_fn_name,
                                                     api_fn_args=api_fn_args)


class VPPApiClientUnexpectedReturnValueError(VPPApiClientError):
    """ exception raised when the API return value is unexpected """

    def __init__(self, arg=None, rv=0, strerror=None, reply=None, expected=0,
                 api_fn_name=None, api_fn_args=None):
        self.expected = expected
        self.rv = rv
        self.strerror = strerror
        self.reply = reply
        self.api_fn_name = api_fn_name
        self.api_fn_args = api_fn_args
        api_fn_args_sig = ', '.join(
            ['{}={!r}'.format(k, v) for k, v in api_fn_args.items()])
        msg = "%s(%s) returned '%s' (%s).  Expected %s.  " \
              "Reply was: %s."
        super(VPPApiClientUnexpectedReturnValueError, self).__init__(
            msg % (api_fn_name, api_fn_args_sig, self.strerror, rv,
                   expected, reply), rv=0, strerror=strerror, reply=reply,
            expected=expected, api_fn_name=api_fn_name, api_fn_args=api_fn_args
        )


class VPPApiClientInvalidReturnValueError(VPPApiClientUnexpectedReturnValueError):  # noqa
    """ exception raised when api returns a value not in api_errno.h"""

    def __init__(self, arg=None, rv=0, strerror=None, reply=None, expected=0,
                 api_fn_name=None, api_fn_args=None):
        api_fn_args_sig = ', '.join(
            ['{}={!r}'.format(k, v) for k, v in api_fn_args.items()])

        msg = ('API function %s(%s) returned an invalid return code of (%s).\n'
               'Please fix the api function to return a value in api_errno.h '
               'or at least \nopen a ticket at: %s.\n'
               % (api_fn_name, api_fn_args_sig, rv, BUGREPORT_URL))
        super(VPPApiClientInvalidReturnValueError, self).__init__(
            msg, rv=rv, strerror=strerror, reply=reply, expected=expected,
            api_fn_name=api_fn_name, api_fn_args=api_fn_args)
