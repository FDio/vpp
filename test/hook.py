# Copyright (c) 2021 Cisco and/or its affiliates.
#
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#
# Licensed under the Apache License 2.0 or
# GNU General Public License v2.0 or later;  you may not use this file
# except in compliance with one of these Licenses. You
# may obtain a copy of the Licenses at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#     https://www.gnu.org/licenses/old-licenses/gpl-2.0-standalone.html
#
# Note: If this file is linked with Scapy, which is GPLv2+, your use of it
# must be under GPLv2+.  If at any point in the future it is no longer linked
# with Scapy (or other GPLv2+ licensed software), you are free to choose
# Apache 2.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import os
import sys
import traceback
import ipaddress
from subprocess import check_output, CalledProcessError

import scapy.compat
import framework
from log import RED, single_line_delim, double_line_delim
from util import check_core_path, get_core_path


class Hook:
    """
    Generic hooks before/after API/CLI calls
    """

    def __init__(self, test):
        self.test = test
        self.logger = test.logger

    def before_api(self, api_name, api_args):
        """
        Function called before API call
        Emit a debug message describing the API name and arguments

        @param api_name: name of the API
        @param api_args: tuple containing the API arguments
        """

        def _friendly_format(val):
            if not isinstance(val, str):
                return val
            if len(val) == 6:
                return '{!s} ({!s})'.format(val, ':'.join(['{:02x}'.format(
                    scapy.compat.orb(x)) for x in val]))
            try:
                # we don't call test_type(val) because it is a packed value.
                return '{!s} ({!s})'.format(val, str(
                    ipaddress.ip_address(val)))
            except ValueError:
                return val

        _args = ', '.join("{!s}={!r}".format(key, _friendly_format(val)) for
                          (key, val) in api_args.items())
        self.logger.debug("API: %s (%s)" %
                          (api_name, _args), extra={'color': RED})

    def after_api(self, api_name, api_args):
        """
        Function called after API call

        @param api_name: name of the API
        @param api_args: tuple containing the API arguments
        """
        pass

    def before_cli(self, cli):
        """
        Function called before CLI call
        Emit a debug message describing the CLI

        @param cli: CLI string
        """
        self.logger.debug("CLI: %s" % (cli), extra={'color': RED})

    def after_cli(self, cli):
        """
        Function called after CLI call
        """
        pass


class PollHook(Hook):
    """ Hook which checks if the vpp subprocess is alive """

    def __init__(self, test):
        super(PollHook, self).__init__(test)

    def on_crash(self, core_path):
        self.logger.error("Core file present, debug with: gdb %s %s",
                          self.test.vpp_bin, core_path)
        check_core_path(self.logger, core_path)
        self.logger.error("Running `file %s':", core_path)
        try:
            info = check_output(["file", core_path])
            self.logger.error(info)
        except CalledProcessError as e:
            self.logger.error(
                "Subprocess returned with error running `file' utility on "
                "core-file, "
                "rc=%s",  e.returncode)
        except OSError as e:
            self.logger.error(
                "Subprocess returned OS error running `file' utility on "
                "core-file, "
                "oserror=(%s) %s", e.errno, e.strerror)
        except Exception as e:
            self.logger.error(
                "Subprocess returned unanticipated error running `file' "
                "utility on core-file, "
                "%s", e)

    def poll_vpp(self):
        """
        Poll the vpp status and throw an exception if it's not running
        :raises VppDiedError: exception if VPP is not running anymore
        """
        if self.test.vpp_dead:
            # already dead, nothing to do
            return

        self.test.vpp.poll()
        if self.test.vpp.returncode is not None:
            self.test.vpp_dead = True
            raise framework.VppDiedError(rv=self.test.vpp.returncode)
            core_path = get_core_path(self.test.tempdir)
            if os.path.isfile(core_path):
                self.on_crash(core_path)

    def before_api(self, api_name, api_args):
        """
        Check if VPP died before executing an API

        :param api_name: name of the API
        :param api_args: tuple containing the API arguments
        :raises VppDiedError: exception if VPP is not running anymore

        """
        super(PollHook, self).before_api(api_name, api_args)
        self.poll_vpp()

    def before_cli(self, cli):
        """
        Check if VPP died before executing a CLI

        :param cli: CLI string
        :raises Exception: exception if VPP is not running anymore

        """
        super(PollHook, self).before_cli(cli)
        self.poll_vpp()


class StepHook(PollHook):
    """ Hook which requires user to press ENTER before doing any API/CLI """

    def __init__(self, test):
        self.skip_stack = None
        self.skip_num = None
        self.skip_count = 0
        super(StepHook, self).__init__(test)

    def skip(self):
        if self.skip_stack is None:
            return False
        stack = traceback.extract_stack()
        counter = 0
        skip = True
        for e in stack:
            if counter > self.skip_num:
                break
            if e[0] != self.skip_stack[counter][0]:
                skip = False
            if e[1] != self.skip_stack[counter][1]:
                skip = False
            counter += 1
        if skip:
            self.skip_count += 1
            return True
        else:
            print("%d API/CLI calls skipped in specified stack "
                  "frame" % self.skip_count)
            self.skip_count = 0
            self.skip_stack = None
            self.skip_num = None
            return False

    def user_input(self):
        print('number\tfunction\tfile\tcode')
        counter = 0
        stack = traceback.extract_stack()
        for e in stack:
            print('%02d.\t%s\t%s:%d\t[%s]' % (counter, e[2], e[0], e[1], e[3]))
            counter += 1
        print(single_line_delim)
        print("You may enter a number of stack frame chosen from above")
        print("Calls in/below that stack frame will be not be stepped anymore")
        print(single_line_delim)
        while True:
            print("Enter your choice, if any, and press ENTER to continue "
                  "running the testcase...")
            choice = sys.stdin.readline().rstrip('\r\n')
            if choice == "":
                choice = None
            try:
                if choice is not None:
                    num = int(choice)
            except ValueError:
                print("Invalid input")
                continue
            if choice is not None and (num < 0 or num >= len(stack)):
                print("Invalid choice")
                continue
            break
        if choice is not None:
            self.skip_stack = stack
            self.skip_num = num

    def before_cli(self, cli):
        """ Wait for ENTER before executing CLI """
        if self.skip():
            print("Skip pause before executing CLI: %s" % cli)
        else:
            print(double_line_delim)
            print("Test paused before executing CLI: %s" % cli)
            print(single_line_delim)
            self.user_input()
        super(StepHook, self).before_cli(cli)

    def before_api(self, api_name, api_args):
        """ Wait for ENTER before executing API """
        if self.skip():
            print("Skip pause before executing API: %s (%s)"
                  % (api_name, api_args))
        else:
            print(double_line_delim)
            print("Test paused before executing API: %s (%s)"
                  % (api_name, api_args))
            print(single_line_delim)
            self.user_input()
        super(StepHook, self).before_api(api_name, api_args)
