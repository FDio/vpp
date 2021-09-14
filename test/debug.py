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
""" debug utilities """

import os
import pexpect
import sys

from sanity_run_vpp import SanityTestCase
from shutil import rmtree
from cpu_config import available_cpus

gdb_path = '/usr/bin/gdb'


def spawn_gdb(binary_path, core_path):
    if os.path.isfile(gdb_path) and os.access(gdb_path, os.X_OK):
        # automatically attach gdb
        gdb_cmdline = "%s %s %s" % (gdb_path, binary_path, core_path)
        gdb = pexpect.spawn(gdb_cmdline)
        gdb.interact()
        try:
            gdb.terminate(True)
        except:
            pass
        if gdb.isalive():
            raise Exception("GDB refused to die...")
    else:
        sys.stderr.write("Debugger '%s' does not exist or is not "
                         "an executable..\n" % gdb_path)


def start_vpp_in_gdb():
    # here we use SanityTestCase as a dummy to inherit functionality,
    # but any test case class could be used ...
    SanityTestCase.set_debug_flags("attach")
    SanityTestCase.tempdir = SanityTestCase.get_tempdir()
    if os.path.exists(SanityTestCase.tempdir):
        if os.getenv("VPP_IN_GDB_NO_RMDIR", "0") in ["1", "y", "yes"]:
            raise FileExistsError(
                "Temporary directory exists and removal denied.")
        print("Removing existing temp dir '%s'." % SanityTestCase.tempdir)
        rmtree(SanityTestCase.tempdir)
    print("Creating temp dir '%s'." % SanityTestCase.tempdir)
    os.mkdir(SanityTestCase.tempdir)
    SanityTestCase.assign_cpus(
        available_cpus[:SanityTestCase.get_cpus_required()])
    SanityTestCase.setUpConstants()
    vpp_cmdline = SanityTestCase.vpp_cmdline
    if os.getenv("VPP_IN_GDB_CMDLINE", "y").lower() in ["1", "y", "yes"]:
        print("Hacking cmdline to make VPP interactive.")
        vpp_cmdline.insert(vpp_cmdline.index("nodaemon"), "interactive")
    print("VPP cmdline is %s" % " ".join(vpp_cmdline))
    print("Running GDB.")

    if os.path.isfile(gdb_path) and os.access(gdb_path, os.X_OK):
        gdb_cmdline = "%s --args %s " % (gdb_path, " ".join(vpp_cmdline))
        print("GDB cmdline is %s" % gdb_cmdline)
        gdb = pexpect.spawn(gdb_cmdline)
        gdb.interact()
        try:
            gdb.terminate(True)
        except:
            pass
        if gdb.isalive():
            raise Exception("GDB refused to die...")
    else:
        sys.stderr.write("Debugger '%s' does not exist or is not "
                         "an executable..\n" % gdb_path)
