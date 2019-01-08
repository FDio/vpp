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

import functools
import logging
import os
import platform
from unittest import SkipTest
from unittest.case import expectedFailure

logger = logging.getLogger(__name__)


def _is_skip_aarch64_set():
    return os.getenv('SKIP_AARCH64', 'n').lower() in ('yes', 'y', '1')


is_skip_aarch64_set = _is_skip_aarch64_set()


def _is_platform_aarch64():
    return platform.machine() == 'aarch64'


is_platform_aarch64 = _is_platform_aarch64()


def _running_extended_tests():
    s = os.getenv("EXTENDED_TESTS", "n")
    return True if s.lower() in ("y", "yes", "1") else False


running_extended_tests = _running_extended_tests()


def _running_on_centos():
    os_id = os.getenv("OS_ID", "")
    return True if "centos" in os_id.lower() else False


running_on_centos = _running_on_centos


def extended_test(func):
    """unittest decorator for identifying an extended test.

    (Only run when environment variable EXTENDED_TESTS is in [y, yes, 1])
    """

    @functools.wraps(func)
    def extended_test_decorator(*args, **kwargs):
        if not running_extended_tests:
            raise SkipTest('Part of extended tests.')
        else:
            return func(*args, **kwargs)

    return extended_test_decorator


def requires_executable(func, executable_path):
    """unittest decorator to skip a test if an executable is not installed."""

    app_installed = os.path.isfile(executable_path) and \
        os.access(executable_path, os.X_OK)

    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        if not app_installed:
            raise SkipTest("'%s' is not installed,", executable_path)
        else:
            func(self, *args, **kwargs)

    return wrapper


def iperf3_test(func, executable_path='/usr/bin/iperf3'):
    """unittest decorator to skip a test iperf3 is not installed."""

    app_installed = os.path.isfile(executable_path) and \
        os.access(executable_path, os.X_OK)

    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        if not app_installed:
            logger.error("WARNING: '%s' is not installed,", executable_path)
            logger.error("         '%s' not run!", func.__name__)
            raise SkipTest("'%s' is not installed,", executable_path)
        else:
            func(self, *args, **kwargs)

    return wrapper


def reported_bug(func, trouble_ticket=None):
    """unittest decorator to identify a test that has been reported as a bug.

    It is expected to fail, but should not disturb the CI workflow.
    not cause the CI to fail."""

    # func.__unittest_expecting_failure__ = True

    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        func(self, *args, **kwargs)

    return expectedFailure(wrapper)
