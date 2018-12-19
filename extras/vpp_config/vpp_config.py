#!/usr/bin/env python

# Copyright (c) 2016 Cisco and/or its affiliates.
# Copyright (c) 2018 Vinci Consulting Corp.  All rights reserved.
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

"""VPP Configuration Main Entry"""
from __future__ import absolute_import, division, print_function

import re
import os
import sys
import logging
import argparse

from vpplib.AutoConfig import AutoConfig
from vpplib.VPPUtil import VPPUtil

#  Python2/3 compatible
try:
    input = raw_input  # noqa
except NameError:
    pass

VPP_DRYRUNDIR = '/vpp/vpp-config/dryrun'
VPP_AUTO_CONFIGURATION_FILE = '/vpp/vpp-config/configs/auto-config.yaml'
VPP_HUGE_PAGE_FILE = '/vpp/vpp-config/dryrun/sysctl.d/80-vpp.conf'
VPP_STARTUP_FILE = '/vpp/vpp-config/dryrun/vpp/startup.conf'
VPP_GRUB_FILE = '/vpp/vpp-config/dryrun/default/grub'
VPP_REAL_HUGE_PAGE_FILE = '/etc/sysctl.d/80-vpp.conf'
VPP_REAL_STARTUP_FILE = '/etc/vpp/startup.conf'
VPP_REAL_GRUB_FILE = '/etc/default/grub'

rootdir = ''


def autoconfig_yn(question, default):
    """
    Ask the user a yes or no question.

    :param question: The text of the question
    :param default: Value to be returned if '\n' is entered
    :type question: string
    :type default: string
    :returns: The Answer
    :rtype: string
    """
    input_valid = False
    default = default.lower()
    answer = ''
    while not input_valid:
        answer = input(question)
        if len(answer) == 0:
            answer = default
        if re.findall(r'[YyNn]', answer):
            input_valid = True
            answer = answer[0].lower()
        else:
            print ("Please answer Y, N or Return.")

    return answer


def autoconfig_cp(node, src, dst):
    """
    Copies a file, saving the original if needed.

    :param node: Node dictionary with cpuinfo.
    :param src: Source File
    :param dst: Destination file
    :type node: dict
    :type src: string
    :type dst: string
    :raises RuntimeError: If command fails
    """

    # If the destination file exist, create a copy if one does not already
    # exist
    ofile = dst + '.orig'
    (ret, stdout, stderr) = VPPUtil.exec_command('ls {}'.format(dst))
    if ret == 0:
        cmd = 'cp {} {}'.format(dst, ofile)
        (ret, stdout, stderr) = VPPUtil.exec_command(cmd)
        if ret != 0:
            raise RuntimeError('{} failed on node {} {} {}'.
                               format(cmd,
                                      node['host'],
                                      stdout,
                                      stderr))

    # Copy the source file
    cmd = 'cp {} {}'.format(src, os.path.dirname(dst))
    (ret, stdout, stderr) = VPPUtil.exec_command(cmd)
    if ret != 0:
        raise RuntimeError('{} failed on node {} {}'.
                           format(cmd, node['host'], stderr))


def autoconfig_diff(node, src, dst):
    """
    Returns the diffs of 2 files.

    :param node: Node dictionary with cpuinfo.
    :param src: Source File
    :param dst: Destination file
    :type node: dict
    :type src: string
    :type dst: string
    :returns: The Answer
    :rtype: string
    :raises RuntimeError: If command fails
    """

    # Diff the files and return the output
    cmd = "diff {} {}".format(src, dst)
    (ret, stdout, stderr) = VPPUtil.exec_command(cmd)
    if stderr != '':
        raise RuntimeError('{} failed on node {} {} {}'.
                           format(cmd,
                                  node['host'],
                                  ret,
                                  stderr))

    return stdout


def autoconfig_show_system():
    """
    Shows the system information.

    """

    acfg = AutoConfig(rootdir, VPP_AUTO_CONFIGURATION_FILE)

    acfg.discover()

    acfg.sys_info()


def autoconfig_hugepage_apply(node, ask_questions=True):
    """
    Apply the huge page configuration.
    :param node: The node structure
    :type node: dict
    :param ask_questions: When True ask the user questions
    :type ask_questions: bool
    :returns: -1 if the caller should return, 0 if not
    :rtype: int

    """

    diffs = autoconfig_diff(node, VPP_REAL_HUGE_PAGE_FILE, rootdir + VPP_HUGE_PAGE_FILE)
    if diffs != '':
        print ("These are the changes we will apply to")
        print ("the huge page file ({}).\n".format(VPP_REAL_HUGE_PAGE_FILE))
        print (diffs)
        if ask_questions:
            answer = autoconfig_yn("\nAre you sure you want to apply these changes [Y/n]? ", 'y')
            if answer == 'n':
                return -1

        # Copy and sysctl
        autoconfig_cp(node, rootdir + VPP_HUGE_PAGE_FILE, VPP_REAL_HUGE_PAGE_FILE)
        cmd = "sysctl -p {}".format(VPP_REAL_HUGE_PAGE_FILE)
        (ret, stdout, stderr) = VPPUtil.exec_command(cmd)
        if ret != 0:
            raise RuntimeError('{} failed on node {} {} {}'.
                               format(cmd, node['host'], stdout, stderr))
    else:
        print ('\nThere are no changes to the huge page configuration.')

    return 0


def autoconfig_vpp_apply(node, ask_questions=True):
    """
    Apply the vpp configuration.

    :param node: The node structure
    :type node: dict
    :param ask_questions: When True ask the user questions
    :type ask_questions: bool
    :returns: -1 if the caller should return, 0 if not
    :rtype: int

    """

    diffs = autoconfig_diff(node, VPP_REAL_STARTUP_FILE, rootdir + VPP_STARTUP_FILE)
    if diffs != '':
        print ("These are the changes we will apply to")
        print ("the VPP startup file ({}).\n".format(VPP_REAL_STARTUP_FILE))
        print (diffs)
        if ask_questions:
            answer = autoconfig_yn("\nAre you sure you want to apply these changes [Y/n]? ", 'y')
            if answer == 'n':
                return -1

        # Copy the VPP startup
        autoconfig_cp(node, rootdir + VPP_STARTUP_FILE, VPP_REAL_STARTUP_FILE)
    else:
        print ('\nThere are no changes to VPP startup.')

    return 0


def autoconfig_grub_apply(node, ask_questions=True):
    """
    Apply the grub configuration.

    :param node: The node structure
    :type node: dict
    :param ask_questions: When True ask the user questions
    :type ask_questions: bool
    :returns: -1 if the caller should return, 0 if not
    :rtype: int

    """

    print ("\nThe configured grub cmdline looks like this:")
    configured_cmdline = node['grub']['default_cmdline']
    current_cmdline = node['grub']['current_cmdline']
    print (configured_cmdline)
    print ("\nThe current boot cmdline looks like this:")
    print (current_cmdline)
    if ask_questions:
        question = "\nDo you want to keep the current boot cmdline [Y/n]? "
        answer = autoconfig_yn(question, 'y')
        if answer == 'y':
            return

    node['grub']['keep_cmdline'] = False

    # Diff the file
    diffs = autoconfig_diff(node, VPP_REAL_GRUB_FILE, rootdir + VPP_GRUB_FILE)
    if diffs != '':
        print ("These are the changes we will apply to")
        print ("the GRUB file ({}).\n".format(VPP_REAL_GRUB_FILE))
        print (diffs)
        if ask_questions:
            answer = autoconfig_yn("\nAre you sure you want to apply these changes [y/N]? ", 'n')
            if answer == 'n':
                return -1

        # Copy and update grub
        autoconfig_cp(node, rootdir + VPP_GRUB_FILE, VPP_REAL_GRUB_FILE)
        distro = VPPUtil.get_linux_distro()
        if distro[0] == 'Ubuntu':
            cmd = "update-grub"
        else:
            cmd = "grub2-mkconfig -o /boot/grub2/grub.cfg"

        (ret, stdout, stderr) = VPPUtil.exec_command(cmd)
        if ret != 0:
            raise RuntimeError('{} failed on node {} {} {}'.
                               format(cmd, node['host'], stdout, stderr))

        print ("There have been changes to the GRUB config a", end=' ')
        print ("reboot will be required.")
        return -1
    else:
        print ('\nThere are no changes to the GRUB config.')

    return 0


def autoconfig_apply(ask_questions=True):
    """
    Apply the configuration.

    Show the diff of the dryrun file and the actual configuration file
    Copy the files from the dryrun directory to the actual file.
    Peform the system function

    :param ask_questions: When true ask the user questions
    :type ask_questions: bool

    """

    vutil = VPPUtil()
    pkgs = vutil.get_installed_vpp_pkgs()
    if len(pkgs) == 0:
        print ("\nVPP is not installed, Install VPP with option 4.")
        return

    acfg = AutoConfig(rootdir, VPP_AUTO_CONFIGURATION_FILE)

    if ask_questions:
        print ("\nWe are now going to configure your system(s).\n")
        answer = autoconfig_yn("Are you sure you want to do this [Y/n]? ", 'y')
        if answer == 'n':
            return

    nodes = acfg.get_nodes()
    for i in nodes.items():
        node = i[1]

        # Check the system resources
        if not acfg.min_system_resources(node):
            return

        # Stop VPP
        VPPUtil.stop(node)

        # Huge Pages
        ret = autoconfig_hugepage_apply(node, ask_questions)
        if ret != 0:
            return

        # VPP
        ret = autoconfig_vpp_apply(node, ask_questions)
        if ret != 0:
            return

        # Grub
        ret = autoconfig_grub_apply(node, ask_questions)
        if ret != 0:
            # We can still start VPP, even if we haven't configured grub
            VPPUtil.start(node)
            return

        # Everything is configured start vpp
        VPPUtil.start(node)


def autoconfig_dryrun(ask_questions=True):
    """
    Execute the dryrun function.

    :param ask_questions: When true ask the user for paraameters
    :type ask_questions: bool

    """

    vutil = VPPUtil()
    pkgs = vutil.get_installed_vpp_pkgs()
    if len(pkgs) == 0:
        print ("\nVPP is not installed, please install VPP.")
        return

    acfg = AutoConfig(rootdir, VPP_AUTO_CONFIGURATION_FILE, clean=True)

    # Stop VPP on each node
    nodes = acfg.get_nodes()
    for i in nodes.items():
        node = i[1]
        VPPUtil.stop(node)

    # Discover
    acfg.discover()

    # Check the system resources
    nodes = acfg.get_nodes()
    for i in nodes.items():
        node = i[1]
        if not acfg.min_system_resources(node):
            return

    # Modify the devices
    if ask_questions:
        acfg.modify_devices()
    else:
        acfg.update_interfaces_config()

    # Modify CPU
    acfg.modify_cpu(ask_questions)

    # Calculate the cpu parameters
    acfg.calculate_cpu_parameters()

    # Acquire TCP stack parameters
    if ask_questions:
        acfg.acquire_tcp_params()

    # Apply the startup
    acfg.apply_vpp_startup()

    # Apply the grub configuration
    acfg.apply_grub_cmdline()

    # Huge Pages
    if ask_questions:
        acfg.modify_huge_pages()
    acfg.apply_huge_pages()


def autoconfig_install():
    """
    Install or Uninstall VPP.

    """

    # Since these commands will take a while, we
    # want to see the progress
    logger = logging.getLogger()

    acfg = AutoConfig(rootdir, VPP_AUTO_CONFIGURATION_FILE)
    vutil = VPPUtil()

    nodes = acfg.get_nodes()
    for i in nodes.items():
        node = i[1]

        pkgs = vutil.get_installed_vpp_pkgs()

        if len(pkgs) > 0:
            print ("\nThese packages are installed on node {}"
                   .format(node['host']))
            print ("{:25} {}".format("Name", "Version"))
            for pkg in pkgs:
                try:
                    print ("{:25} {}".format(
                        pkg['name'], pkg['version']))
                except KeyError:
                    print ("{}".format(pkg['name']))

            question = "\nDo you want to uninstall these "
            question += "packages [y/N]? "
            answer = autoconfig_yn(question, 'n')
            if answer == 'y':
                logger.setLevel(logging.INFO)
                vutil.uninstall_vpp(node)
        else:
            print ("\nThere are no VPP packages on node {}."
                   .format(node['host']))
            question = "Do you want to install VPP [Y/n]? "
            answer = autoconfig_yn(question, 'y')
            if answer == 'y':
                question = "Do you want to install the release version [Y/n]? "
                answer = autoconfig_yn(question, 'y')
                if answer == 'y':
                    branch = 'release'
                else:
                    branch = 'master'
                logger.setLevel(logging.INFO)
                vutil.install_vpp(node, branch)

    # Set the logging level back
    logger.setLevel(logging.ERROR)


def autoconfig_patch_qemu():
    """
    Patch the correct qemu version that is needed for openstack

    """

    # Since these commands will take a while, we
    # want to see the progress
    logger = logging.getLogger()

    acfg = AutoConfig(rootdir, VPP_AUTO_CONFIGURATION_FILE)

    nodes = acfg.get_nodes()
    for i in nodes.items():
        node = i[1]

        logger.setLevel(logging.INFO)
        acfg.patch_qemu(node)


def autoconfig_ipv4_setup():
    """
    Setup IPv4 interfaces

    """

    acfg = AutoConfig(rootdir, VPP_AUTO_CONFIGURATION_FILE)
    acfg.ipv4_interface_setup()


def autoconfig_create_iperf_vm():
    """
    Setup IPv4 interfaces

    """

    acfg = AutoConfig(rootdir, VPP_AUTO_CONFIGURATION_FILE)
    acfg.destroy_iperf_vm('iperf-server')
    acfg.create_and_bridge_iperf_virtual_interface()
    acfg.create_iperf_vm('iperf-server')


def autoconfig_not_implemented():
    """
    This feature is not implemented

    """

    print ("\nThis Feature is not implemented yet....")


def autoconfig_basic_test_menu():
    """
    The auto configuration basic test menu

    """

    basic_menu_text = '\nWhat would you like to do?\n\n\
1) List/Create Simple IPv4 Setup\n\
2) Create an iperf VM and Connect to VPP an interface\n\
9 or q) Back to main menu.'

    print ("{}".format(basic_menu_text))

    input_valid = False
    answer = ''
    while not input_valid:
        answer = input("\nCommand: ")
        if len(answer) > 1:
            print ("Please enter only 1 character.")
            continue
        if re.findall(r'[Qq1-29]', answer):
            input_valid = True
            answer = answer[0].lower()
        else:
            print ("Please enter a character between 1 and 2 or 9.")

        if answer == '9':
            answer = 'q'

    return answer


def autoconfig_basic_test():
    """
    The auto configuration basic test menu

    """
    vutil = VPPUtil()
    pkgs = vutil.get_installed_vpp_pkgs()
    if len(pkgs) == 0:
        print ("\nVPP is not installed, install VPP with option 4.")
        return

    answer = ''
    while answer != 'q':
        answer = autoconfig_basic_test_menu()
        if answer == '1':
            autoconfig_ipv4_setup()
        elif answer == '2':
            autoconfig_create_iperf_vm()
        elif answer == '9' or answer == 'q':
            return
        else:
            autoconfig_not_implemented()


def autoconfig_main_menu():
    """
    The auto configuration main menu

    """

    main_menu_text = '\nWhat would you like to do?\n\n\
1) Show basic system information\n\
2) Dry Run (Saves the configuration files in {}/vpp/vpp-config/dryrun.\n\
3) Full configuration (WARNING: This will change the system configuration)\n\
4) List/Install/Uninstall VPP.\n\
q) Quit'.format(rootdir, rootdir)

    # 5) Dry Run from {}/vpp/vpp-config/auto-config.yaml (will not ask questions).\n\
    # 6) Install QEMU patch (Needed when running openstack).\n\

    print ("{}".format(main_menu_text))

    input_valid = False
    answer = ''
    while not input_valid:
        answer = input("\nCommand: ")
        if len(answer) > 1:
            print ("Please enter only 1 character.")
            continue
        if re.findall(r'[Qq1-4]', answer):
            input_valid = True
            answer = answer[0].lower()
        else:
            print ("Please enter a character between 1 and 4 or q.")

    return answer


def autoconfig_main():
    """
    The auto configuration main entry point

    """

    # Setup
    autoconfig_setup()

    answer = ''
    while answer != 'q':
        answer = autoconfig_main_menu()
        if answer == '1':
            autoconfig_show_system()
        elif answer == '2':
            autoconfig_dryrun()
        elif answer == '3':
            autoconfig_apply()
        elif answer == '4':
            autoconfig_install()
        elif answer == 'q':
            return
        else:
            autoconfig_not_implemented()


def autoconfig_setup(ask_questions=True):
    """
    The auto configuration setup function.

    We will copy the configuration files to the dryrun directory.

    """

    global rootdir

    distro = VPPUtil.get_linux_distro()
    if distro[0] == 'Ubuntu':
        rootdir = '/usr/local'
    else:
        rootdir = '/usr'

    # If there is a system configuration file use that, if not use the initial auto-config file
    filename = rootdir + VPP_AUTO_CONFIGURATION_FILE
    if os.path.isfile(filename) is True:
        acfg = AutoConfig(rootdir, VPP_AUTO_CONFIGURATION_FILE)
    else:
        raise RuntimeError('The Auto configuration file does not exist {}'.
                           format(filename))

    if ask_questions:
        print ("\nWelcome to the VPP system configuration utility")

        print ("\nThese are the files we will modify:")
        print ("    /etc/vpp/startup.conf")
        print ("    /etc/sysctl.d/80-vpp.conf")
        print ("    /etc/default/grub")

        print (
            "\nBefore we change them, we'll create working copies in "
            "{}".format(rootdir + VPP_DRYRUNDIR))
        print (
            "Please inspect them carefully before applying the actual "
            "configuration (option 3)!")

    nodes = acfg.get_nodes()
    for i in nodes.items():
        node = i[1]

        if (os.path.isfile(rootdir + VPP_STARTUP_FILE) is not True) and \
                (os.path.isfile(VPP_REAL_STARTUP_FILE) is True):
            autoconfig_cp(node, VPP_REAL_STARTUP_FILE, '{}'.format(rootdir + VPP_STARTUP_FILE))
        if (os.path.isfile(rootdir + VPP_HUGE_PAGE_FILE) is not True) and \
                (os.path.isfile(VPP_REAL_HUGE_PAGE_FILE) is True):
            autoconfig_cp(node, VPP_REAL_HUGE_PAGE_FILE, '{}'.format(rootdir + VPP_HUGE_PAGE_FILE))
        if (os.path.isfile(rootdir + VPP_GRUB_FILE) is not True) and \
                (os.path.isfile(VPP_REAL_GRUB_FILE) is True):
            autoconfig_cp(node, VPP_REAL_GRUB_FILE, '{}'.format(rootdir + VPP_GRUB_FILE))

        # Be sure the uio_pci_generic driver is installed
        cmd = 'modprobe uio_pci_generic'
        (ret, stdout, stderr) = VPPUtil.exec_command(cmd)
        if ret != 0:
            logging.warning('{} failed on node {} {}'. format(cmd, node['host'], stderr))


# noinspection PyUnresolvedReferences
def execute_with_args(args):
    """
    Execute the configuration utility with agruments.

    :param args: The Command line arguments
    :type args: tuple
    """

    # Setup
    autoconfig_setup(ask_questions=False)

    # Execute the command
    if args.show:
        autoconfig_show_system()
    elif args.dry_run:
        autoconfig_dryrun(ask_questions=False)
    elif args.apply:
        autoconfig_apply(ask_questions=False)
    else:
        autoconfig_not_implemented()


def config_main():
    """
    The vpp configuration utility main entry point.

    """

    # Check for root
    if not os.geteuid() == 0:
        sys.exit('\nPlease run the VPP Configuration Utility as root.')

    if len(sys.argv) > 1 and ((sys.argv[1] == '-d') or (
            sys.argv[1] == '--debug')):
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.ERROR)

    # If no arguments were entered, ask the user questions to
    # get the main parameters
    if len(sys.argv) == 1:
        autoconfig_main()
        return
    elif len(sys.argv) == 2 and ((sys.argv[1] == '-d') or (
            sys.argv[1] == '--debug')):
        autoconfig_main()
        return

    # There were arguments specified, so execute the utility using
    # command line arguments
    description = 'The VPP configuration utility allows the user to '
    'configure VPP in a simple and safe manner. The utility takes input '
    'from the user or the specified .yaml file. The user should then '
    'examine these files to be sure they are correct and then actually '
    'apply the configuration. When run without arguments the utility run '
    'in an interactive mode'

    main_parser = argparse.ArgumentParser(
        prog='arg-test',
        description=description,
        epilog='See "%(prog)s help COMMAND" for help on a specific command.')
    main_parser.add_argument('--apply', '-a', action='store_true',
                             help='Apply the cofiguration.')
    main_parser.add_argument('--dry-run', '-dr', action='store_true',
                             help='Create the dryrun configuration files.')
    main_parser.add_argument('--show', '-s', action='store_true',
                             help='Shows basic system information')
    main_parser.add_argument('--debug', '-d', action='count',
                             help='Print debug output (multiple levels)')

    args = main_parser.parse_args()

    return execute_with_args(args)


if __name__ == '__main__':
    config_main()
