#!/usr/bin/env python3

import re
import subprocess


class ExistingVPP(object):
    """Supports running tests against an existing VPP.

    Used as a "feature developer use case".
    The developer already has VPP running in cmdline or gdb and wants to run
    a test case, then poke around in vpp cli / gdb. The tests would not have
    control over the VPP process in this case.
    """
    def __init__(self):
        self.init()

    def init(self):
        self.vpp_pump_output = None

    @property
    def running(self):
        """Determine if VPP is running, set params and return True or False.

        self.pid = pid of the running VPP
        self.config = startup config or cmdline args used by vpp
        self.data = A lookup data structure for API messages
        """
        self.pid = self.is_vpp_running()
        if self.pid:
            self.config = self.get_vpp_config()
            self.data = self.get_config_data()
            self.pump_output()
            return True
        else:
            self.vpp_pump_output = None
            return False

    def is_vpp_running(self):
        """Return the PID if VPP is running. Else return None."""
        vpp_pid = subprocess.Popen(['pgrep', '-d,', '-x', 'vpp_main'],
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,
                                   universal_newlines=True)
        stdout, stderr = vpp_pid.communicate()
        pid = int(stdout.split(',')[0]) if stdout else None
        return pid

    def get_vpp_config(self):
        """Return the running VPP's config args.

        If VPP uses the config-file, it's data is returned
        Else, the command line args used by VPP are returned.
        """
        vpp_config = None
        vpp_process = subprocess.Popen(['ps', '-fp', str(self.pid)],
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE,
                                       universal_newlines=True)
        stdout, stderr = vpp_process.communicate()
        if stdout:
            self.vpp_instance = stdout
            # Search for the VPP binary name
            match = re.search(r'([\S]+vpp )', stdout)
            self.vpp_bin = match.group(1) if match else "vpp"
            vals = stdout.split()
            try:
                indx = vals.index('-c')
                vpp_config_file = vals[indx+1]  # item after the '-c' arg
                with open(vpp_config_file, 'rt') as f:
                    startup_cfg = f.read()
                    vpp_config = ' '.join(startup_cfg.split())  # sanitize
            except ValueError:  # config file is not present
                # scan stdout to get VPP's cmdline args
                match = re.search(r'vpp ', stdout)
                if match:
                    vpp_config = stdout[match.end():]
        return vpp_config

    def search_config(self, pattern):
        """Searches VPP's config or cmdline args and returns a match.

        Using the provided regex pattern search VPP's config file or
        cmdline args for a match and return the match if found or
        else return None.
        """
        val = None
        match = re.search(pattern, self.config)
        if match:
            val = match.group(1)
        return val

    def get_config_data(self):
        """Returns a config data of the running VPP.

        Returns a lookup data structure containing the running VPP's
        startup configuration values used for processing binary
        API messages and stats.

        returns: A config_data lookup dict
        {'api_sock: <api-socket-name>,
         'stats_sock': <stat-socket-name>,
         'shm_prefix': <shm-prefix>,
         'runtime_dir': <runtime_dir>
        }
        """
        api_seg_regex = r'api-segment\s*{[^}]*prefix\s+(\S+)\s+'
        api_sock_regex = r'socksvr\s*{[^}]*socket-name\s+(\S+)\s+'
        stat_sock_regex = r'statseg\s*{[^}]*socket-name\s+(\S+)\s+'
        runtime_dir_regex = r'unix\s*{[^}]*runtime-dir\s+(\S+)\s+'

        shm_prefix = self.search_config(api_seg_regex)
        api_sock = self.search_config(api_sock_regex)
        stats_sock = self.search_config(stat_sock_regex)
        runtime_dir = self.search_config(runtime_dir_regex)

        return {'api_sock': api_sock or '/run/vpp/api.sock',
                'stats_sock': stats_sock or '/run/vpp/stats.sock',
                'shm_prefix': shm_prefix,
                'runtime_dir': runtime_dir
                }

    def pump_output(self):
        """Pump output from an existing VPP.

        When a test is run, the framework uses a pump thread to
        pump the output from vpp stdout/stderr to a deque. This
        method provides delivers journals written
        by the existing vpp to stdout.
        """
        if not self.vpp_pump_output:
            self.vpp_pump_output = subprocess.Popen(
                ['journalctl', '-f', self.vpp_bin],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
            # Set the output for the pump thread in the framework
            self.stdout = self.vpp_pump_output.stdout
            self.stderr = self.vpp_pump_output.stderr

    def communicate(self):
        """Used by the framework to communicate with a VPP.

        Since a VPP instance is already running, we'll set this
        method to communicate with it's journal session.
        """
        if self.running:
            self.pump_output()

    def terminate(self):
        """Used by the framework to terminate a VPP instance.

        Since a VPP instance is already running, we'll just
        terminate the journal session.
        """
        if self.vpp_pump_output:
            self.vpp_pump_output.terminate()
            self.vpp_pump_output = None

    def poll(self):
        """Used by the framework to check VPP status.

        If VPP is running, return None to signal that we have an
        existing VPP else return 1 to terminate the pump connection.
        """
        self.returncode = None if self.running else 1
        return self.returncode


if __name__ == '__main__':
    existing_vpp = ExistingVPP()
    vpp_running = existing_vpp.running
    print("VPP Running:", vpp_running)
    if vpp_running:
        print("VPP config:", existing_vpp.config)
        print("VPP data:", existing_vpp.data)
