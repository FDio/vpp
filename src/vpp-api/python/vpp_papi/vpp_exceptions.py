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

__all__ = ('VPPApiClientError',
           'VPPApiClientIOError',
           'VPPApiClientNotImplementedError',
           'VPPApiClientNoSuchApiError',
           'VPPApiClientRuntimeError',
           'VPPApiClientTypeError',
           'VPPApiClientUnexpectedReturnValueError',
           'VPPApiClientValueError',
           )


class VPPApiClientError(Exception):
    """ Base for all VPPApiErrors

    Expected usage as an exception to be checked against.
    eg. except VPPApiClientError:

    If you are raising an exception, use a subclass of VPPApiClientError.
    """

    def __init__(self, arg=None):
        if arg is None:
            super(VPPApiClientError, self).__init__()
        else:
            super(VPPApiClientError, self).__init__(arg)


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

        super(VPPApiClientNoSuchApiError, self).__init__(arg)


class VPPApiClientIOError(VPPApiClientError, IOError):
    def __init__(self, arg=None):
        super(VPPApiClientIOError, self).__init__(arg)


class VPPApiClientRuntimeError(VPPApiClientError, RuntimeError):
    def __init__(self, arg=None):
        super(VPPApiClientRuntimeError, self).__init__(arg)


class VPPApiClientTypeError(VPPApiClientError, TypeError):
    """ TypeError with augmented context information."""

    def __init__(self, arg=None, api_fn_name=None, api_fn_args=None):
        self.api_fn_name = api_fn_name
        self.api_fn_args = api_fn_args
        super(VPPApiClientTypeError, self).__init__(arg)


class VPPApiClientValueError(VPPApiClientError, ValueError):
    """ ValueError with augmented context information."""

    def __init__(self, arg=None, api_fn_name=None, api_fn_args=None):
        self.api_fn_name = api_fn_name
        self.api_fn_args = api_fn_args
        super(VPPApiClientValueError, self).__init__(arg)


class VPPApiClientUnexpectedReturnValueError(VPPApiClientError):
    pass
