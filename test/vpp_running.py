#!/usr/bin/env python3

# Supporting module for running tests against a running VPP.
# This module is used by the test framework. Do not invoke this module
# directly for running tests against a running vpp. Use run.py for
# running all unit tests.

from glob import glob
import os
import sys
import subprocess
from config import config


def use_running(cls):
    """Update VPPTestCase to use running VPP's sock files & methods.

    Arguments:
    cls -- VPPTestCase Class
    """
    if config.running_vpp:
        if os.path.isdir(config.socket_dir):
            RunningVPP.socket_dir = config.socket_dir
        else:
            RunningVPP.socket_dir = RunningVPP.get_default_socket_dir()
        RunningVPP.get_set_vpp_sock_files()
        cls.get_stats_sock_path = RunningVPP.get_stats_sock_path
        cls.get_api_sock_path = RunningVPP.get_api_sock_path
        cls.get_memif_sock_path = RunningVPP.get_memif_sock_path
        cls.run_vpp = RunningVPP.run_vpp
        cls.quit_vpp = RunningVPP.quit_vpp
        cls.vpp = RunningVPP
        cls.running_vpp = True
    return cls


class RunningVPP:
    api_sock = ""  # api_sock file path
    stats_sock = ""  # stats sock_file path
    memif_sock = ""  # memif sock path
    socket_dir = ""  # running VPP's socket directory
    pid = None  # running VPP's pid
    returncode = None  # indicates to the framework that VPP is running

    @classmethod
    def get_stats_sock_path(cls):
        return cls.stats_sock

    @classmethod
    def get_api_sock_path(cls):
        return cls.api_sock

    @classmethod
    def get_memif_sock_path(cls):
        return cls.memif_sock

    @classmethod
    def run_vpp(cls):
        """VPP is already running -- skip this action."""
        pass

    @classmethod
    def quit_vpp(cls):
        """Indicate quitting to framework by setting returncode=1."""
        cls.returncode = 1

    @classmethod
    def terminate(cls):
        """Indicate termination to framework by setting returncode=1."""
        cls.returncode = 1

    @classmethod
    def get_default_socket_dir(cls):
        """Return running VPP's default socket directory.

        Default socket dir is:
           /var/run/user/${UID}/vpp  (or)
           /var/run/vpp, if VPP is started as a root user
        """
        if cls.is_running_vpp():
            vpp_user_id = (
                subprocess.check_output(["ps", "-o", "uid=", "-p", str(cls.pid)])
                .decode("utf-8")
                .strip()
            )
            if vpp_user_id == "0":
                return "/var/run/vpp"
            else:
                return f"/var/run/user/{vpp_user_id}/vpp"
        else:
            print(
                "Error: getting default socket dir, as "
                "a running VPP process could not be found"
            )
            sys.exit(1)

    @classmethod
    def get_set_vpp_sock_files(cls):
        """Look for *.sock files in the socket_dir and set cls attributes.

        Returns a tuple: (api_sock_file, stats_sock_file)
        Sets cls.api_sock and cls.stats_sock attributes
        """
        # Return if the sock files are already set
        if cls.api_sock and cls.stats_sock:
            return (cls.api_sock, cls.stats_sock)
        # Find running VPP's sock files in the socket dir
        if os.path.isdir(cls.socket_dir):
            if not cls.is_running_vpp():
                print(
                    "Error: The socket dir for a running VPP directory is, "
                    "set but a running VPP process could not be found"
                )
                sys.exit(1)
            sock_files = glob(os.path.join(cls.socket_dir + "/" + "*.sock"))
            for sock_file in sock_files:
                if "api.sock" in sock_file:
                    cls.api_sock = os.path.abspath(sock_file)
                elif "stats.sock" in sock_file:
                    cls.stats_sock = os.path.abspath(sock_file)
                elif "memif.sock" in sock_file:
                    cls.memif_sock = os.path.abspath(sock_file)
            if not cls.api_sock:
                print(
                    f"Error: Could not find a valid api.sock file "
                    f"in running VPP's socket directory {cls.socket_dir}"
                )
                sys.exit(1)
            if not cls.stats_sock:
                print(
                    f"Error: Could not find a valid stats.sock file "
                    f"in running VPP's socket directory {cls.socket_dir}"
                )
                sys.exit(1)
            return (cls.api_sock, cls.stats_sock)
        else:
            print("Error: The socket dir for a running VPP directory is unset")
            sys.exit(1)

    @classmethod
    def is_running_vpp(cls):
        """Return True if VPP's pid is visible else False."""
        vpp_pid = subprocess.Popen(
            ["pgrep", "-d,", "-x", "vpp_main"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        stdout, stderr = vpp_pid.communicate()
        cls.pid = int(stdout.split(",")[0]) if stdout else None
        return bool(cls.pid)

    @classmethod
    def poll(cls):
        """Return None to indicate that the process hasn't terminated."""
        return cls.returncode


if __name__ == "__main__":
    RunningVPP.socket_dir = RunningVPP.get_default_socket_dir()
    RunningVPP.get_set_vpp_sock_files()
    print(f"Running VPP's sock files")
    print(f"api_sock_file {RunningVPP.api_sock}")
    print(f"stats_sock_file {RunningVPP.stats_sock}")
