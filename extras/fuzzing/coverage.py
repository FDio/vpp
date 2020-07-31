#!/usr/bin/env -S python3 -u

"""A class for code coverage with gcov/lcov"""

import os

from global_values import *
from util import *

class Coverage:
    """The functions should be run in this order:
    - pre_coverage()
    - compute_baseline()
    - compute_coverage()
    - gen_html() and/or custom_report()
    Or:
    - pre_coverage()
    - blackbox_coverage()
    - gen_html() and/or custom_report()"""
    def __init__(self, config, inputs_dir=None, crashes_dir=None,
                 base_input=None, custom_vpp_path=None,
                 blackbox_baseline_duration=None):
        self.config = config
        # How long to run VPP in replay mode as a baseline for blackbox
        # fuzzing (in s)
        self.blackbox_baseline_duration = blackbox_baseline_duration
        # Full path to a directory containing inputs.
        # Can be None after blackbox fuzzing.
        self.inputs_dir = inputs_dir
        if self.inputs_dir is not None:
            self.inputs = [
                f for f in os.listdir(self.inputs_dir)
                if os.path.isfile(f"{self.inputs_dir}/{f}")
            ]
        # Full path to a directory with crashing inputs. Set to None to
        # avoid replaying the crashes.
        self.crashes_dir = crashes_dir
        if self.crashes_dir is not None:
            self.crashes = [
                f for f in os.listdir(self.crashes_dir)
                if os.path.isfile(f"{self.crashes_dir}/{f}")
                and f.startswith("id")  # don't replay the README
            ]
        else:
            self.crashes = []
        # The input to replay to get a baseline coverage. Can be None after
        # blackbox fuzzing.
        self.base_input = base_input
        self.custom_vpp_path = custom_vpp_path
        self.vpp_path = custom_vpp_path or default_vpp_path
        self.build_root = f"{self.vpp_path}/build-root"
        self.fuzz_dir = f"{self.vpp_path}/extras/fuzzing"
        self.startup_file = f"{self.fuzz_dir}/startup.conf"
        # Necessary to use lcov on code compiled with clang
        self.gcov_tool = f"{self.fuzz_dir}/gcov_for_clang.sh"
        self.vpp_cov_bin = get_vpp_bin("gcov", custom_vpp_path=self.custom_vpp_path)
        self.files = {
            # a file produced with zero coverage for each source file, later
            # combined with other output files to ensure percentages are
            # correct even if not all source code files were loaded during
            # execution
            "zero": "zero.info",
            # Baseline coverage with only self.base_input
            "base": "baseline.info",
            # Actual coverage with self.inputs_dir/*
            "actual": "actual.info",
            # Custom files, see custom_report()
            "cmp": "cmp.info",
            "cmp_filt": "cmp_filt.info",
        }
        tmp_partial = "tmp_partial.info"
        tmp_unfiltered = "tmp_unfiltered.info"
        # Files that will be excluded from the coverage counts
        to_filter = '"/usr/include/*" "*/build-root/*" "/opt/*" "/usr/lib/*"'
        # Only files to include in self.files['cmp_filt'] (prefixes)
        self.vpp_include = ["src/plugins", "src/vnet"]
        # Commands executed multiple times by methods in this class
        # All of them must be run from self.build_root
        self.cmds = {
            # Zero out counters (remove .gcda files)
            "zerocounters": "lcov --zerocounters --directory .",
            # Compute the coverage from .gcda and .gcno files into out_file
            "coverage": lambda out_file : (
                "lcov --no-checksum --directory . --capture"
                f" --gcov-tool {self.gcov_tool} --output-file {tmp_partial}"
                # include all files, even the ones not loaded
                f" && lcov --add-tracefile {self.files['zero']}"
                f" --add-tracefile {tmp_partial}"
                f" --output-file {tmp_unfiltered}"
                # exclude some unwanted files from the coverage
                f" && lcov --remove {tmp_unfiltered} {to_filter}"
                f" --output-file {out_file}"
                f" && rm {tmp_partial} {tmp_unfiltered}"
            ),
        }


    def pre_coverage(self):
        """Steps to perform before other coverage tasks"""
        # Make sure the correct exec and startup files are there
        build_exec_file("fuzz", self.config, custom_vpp_path=self.custom_vpp_path)
        build_startup_file("fuzz", self.config, custom_vpp_path=self.custom_vpp_path, coredumps=False)
        system_wrapper(
            f"cd {self.build_root}"
            # Clean up traces from previous coverage tasks
            " && rm -f *.info"
            f" && {self.cmds['zerocounters']}"
            f" && lcov --capture --initial --directory . --output-file {self.files['zero']}"
        )


    def compute_baseline(self):
        """Get the code coverage of self.base_input, run as many times
           as there are inputs in self.inputs_dir."""
        assert self.inputs_dir is not None
        assert self.base_input is not None
        system_wrapper(f"cd {self.build_root} && {self.cmds['zerocounters']}")
        for _ in self.inputs + self.crashes:
            system_wrapper(
                f"cd {self.build_root}"
                f" && {self.vpp_cov_bin} -c {self.startup_file} < {self.base_input}"
            )
        system_wrapper(
            f"cd {self.build_root} && {self.cmds['coverage'](self.files['base'])}"
        )


    def compute_coverage(self):
        """Compute the coverage of the actual inputs in self.inputs_dir"""
        assert self.inputs_dir is not None
        system_wrapper(f"cd {self.build_root} && {self.cmds['zerocounters']}")
        # Start with the crashes, to lose less time if something goes wrong
        for inp in self.crashes:
            system_wrapper(
                f"cd {self.build_root}"
                f" && {self.vpp_cov_bin} -c {self.startup_file} < {self.crashes_dir}/{inp}"
                , skip_failure=True  # the commands are expected to fail
            )
        for inp in self.inputs:
            system_wrapper(
                f"cd {self.build_root}"
                f" && {self.vpp_cov_bin} -c {self.startup_file} < {self.inputs_dir}/{inp}"
                # since some crashes don't reproduce, it is possible that some
                # non-crashes produce crashes when replayed
                , skip_failure=True
            )
        system_wrapper(
            f"cd {self.build_root} && {self.cmds['coverage'](self.files['actual'])}"
        )


    def blackbox_coverage(self):
        """In the case of the testgreyblack.py experiment, the blackbox
        setup requires a different treatment. We first analyze the current
        instrumentation output (of the fuzzing run), then run VPP for some
        time in replay mode (i.e. with always the same packet) to establish
        a baseline."""
        # Analyze the current results
        system_wrapper(
            f"cd {self.build_root}"
            f" && {self.cmds['coverage'](self.files['actual'])}"
        )
        # Establish a baseline
        build_exec_file("replay", self.config,
                        custom_vpp_path=self.custom_vpp_path)
        build_startup_file("replay", self.config,
                           custom_vpp_path=self.custom_vpp_path,
                           coredumps=False, do_cli_listen=False)
        system_wrapper(
            f"cd {self.build_root}"
            f" && {self.cmds['zerocounters']}"
            f" && PFUZZ_USE_BLACKBOX=1"
            f" timeout -s KILL {self.blackbox_baseline_duration}s"
            f" {self.vpp_cov_bin} -c {self.startup_file}"
            # the previous command will have a non-zero exit status
            f"; {self.cmds['coverage'](self.files['base'])}"
        )


    def gen_html(self):
        """Generate html reports into
           self.build_root/html_(base|actual|diff|diff_rev)"""
        system_wrapper(
            f"cd {self.build_root}"
            # baseline coverage
            f" && genhtml {self.files['base']} -o html_base"
            # actual coverage
            f" && genhtml {self.files['actual']} -o html_actual"
            # actual minus baseline
            f" && genhtml --baseline-file {self.files['base']}"
            f" {self.files['actual']} -o html_diff"
            # baseline minus actual
            f" && genhtml --baseline-file {self.files['actual']}"
            f" {self.files['base']} -o html_diff_rev"
        )


    def custom_report(self, do_filter=False):
        """Parse self.files['base'] and self.files['actual'], to create
           a new .info file (self.files['cmp'] if do_filter=False else
           self.files['cmp_filt']) which uses the following convention:
           - lines newly hit appear with a hit count of 1
           - lines lost appear with a hit count of 0
           - lines either never hit, or hit in both cases, don't have a
           hit count (their records are deleted).
           This will allow to simply look at the totals computed by genhtml,
           as well as to determine visually which lines were newly hit (blue)
           or lost (red).
           self.files['cmp'] reports all the files with changes;
           self.files['cmp_filt'] only reports files deemed interesting
           (as per self.vpp_include).
        """
        # With the exception of the "FNDA" lines which aren't sorted,
        # as well as the "FN" lines when several functions are defined on
        # the same line (via VLIB_INIT_FUNCTION and maybe other mechanisms),
        # everything is sorted in some way in .info files, so we expect to
        # see matching lines at the same position in each file. This simplifies
        # greatly the processing.

        # Get prefix and get suffix, lines being of the form IDENTIFIER:data
        # (except "end_of_record" for which we must not take the suffix)
        def get_pre(line):
            return line.split(":")[0]
        def get_suf(line):
            return line.split(":")[1]

        def cmp_hits(base_hits, actual_hits):
            if base_hits == 0 and actual_hits > 0:
                return 1
            elif base_hits > 0 and actual_hits == 0:
                return 0
            return None

        def is_to_include(filename):
            """Should this source file (full filename) be included?"""
            if not do_filter:
                return True
            common_prefix = f"{self.vpp_path}/"
            relative_filename = filename[len(common_prefix):]  # now like src/...
            for prefix in self.vpp_include:
                if relative_filename.startswith(prefix):
                    return True
            return False

        cmp_name = 'cmp' if not do_filter else 'cmp_filt'
        cmp_full_path = f"{self.build_root}/{self.files[cmp_name]}"
        base_full_path = f"{self.build_root}/{self.files['base']}"
        actual_full_path = f"{self.build_root}/{self.files['actual']}"
        b_lns = open(base_full_path, "r").readlines()
        a_lns = open(actual_full_path, "r").readlines()
        assert len(a_lns) == len(b_lns)
        with open(cmp_full_path, "w") as cmp_file:
            for b_ln, a_ln in zip(b_lns, a_lns):
                assert get_pre(b_ln) == get_pre(a_ln)
                pre = get_pre(b_ln)
                if pre == "TN":  # "test name": always empty
                    assert b_ln == a_ln
                    # Wait before writing: maybe this source file will be skipped
                elif pre == "SF":  # source file
                    assert b_ln == a_ln
                    sf = get_suf(b_ln)
                    include_sf = is_to_include(sf)
                    if include_sf:
                        # Write the previous "TN" line
                        cmp_file.write("TN:\n")
                        cmp_file.write(b_ln)
                    # Initialize counters
                    fn_hits = 0
                    ln_hits = 0
                    # As we will remove function and line records,
                    # count the new numbers of "instrumented" functions
                    # and lines
                    fn_inst = 0
                    ln_inst = 0
                    # Dictionaries for "FNDA" lines which aren't in order,
                    # of the form: {<function name>: <function hits>}
                    b_fnda = {}
                    a_fnda = {}
                    # Dictionaries for "FN" lines,
                    # of the form: {<line number>:[<function names>]}
                    b_fn = {}
                    a_fn = {}
                elif not include_sf:
                    # Skip all lines until the next "TN" and "SF"
                    continue
                elif pre == "FN":  # location of a function
                    # The order may differ for functions defined on the same
                    # line (via VLIB_INIT_FUNCTION and maybe other mechanisms),
                    # so we don't expect the 2 lines to be equal (except for the
                    # line number).
                    # Only write the line if it won't be deleted, so save it
                    # for now
                    # Line format: "FN:<line number>,<function name>\n"
                    b_suf = get_suf(b_ln).split(",")
                    a_suf = get_suf(a_ln).split(",")
                    b_fname = b_suf[1].strip()
                    a_fname = a_suf[1].strip()
                    assert b_suf[0] == a_suf[0]
                    line_number = int(b_suf[0])
                    b_fn[line_number] = b_fn.get(line_number, []) + [b_fname]
                    a_fn[line_number] = a_fn.get(line_number, []) + [a_fname]
                elif pre == "FNDA":  # number of hits of a function
                    # Line format: "FNDA:<hits>,<function name>\n"
                    b_suf = get_suf(b_ln).split(",")
                    a_suf = get_suf(a_ln).split(",")
                    b_fname = b_suf[1].strip()
                    a_fname = a_suf[1].strip()
                    b_fnda[b_fname] = int(b_suf[0])
                    a_fnda[a_fname] = int(a_suf[0])
                elif pre == "FNF":  # number of functions in file
                    # Comes just after the "FN" and "FNDA" fields,
                    # so write them now
                    fn_list = []  # "FN" lines about to be written
                    fnda_list = []  # "FNDA" lines about to be written
                    assert b_fn.keys() == a_fn.keys()
                    assert b_fnda.keys() == a_fnda.keys()
                    for line_number in sorted(b_fn.keys()):
                        for fname in b_fn[line_number]:
                            cmp = cmp_hits(b_fnda[fname], a_fnda[fname])
                            if cmp is not None:
                                fn_inst += 1
                                fn_hits += cmp
                                fn_list.append(f"FN:{line_number},{fname}\n")
                                fnda_list.append(f"FNDA:{cmp},{fname}\n")
                    for line in fn_list + fnda_list:
                        cmp_file.write(line)
                    # Also write the "FNF" line
                    cmp_file.write(f"FNF:{fn_inst}\n")
                elif pre == "FNH":  # number of functions hit in file
                    cmp_file.write(f"FNH:{fn_hits}\n")
                elif pre == "DA":  # number of hits of a line
                    # Format: "DA:<line number>,<hits>\n"
                    b_suf = get_suf(b_ln).split(",")
                    a_suf = get_suf(a_ln).split(",")
                    assert b_suf[0] == a_suf[0]  # line number
                    line_number = b_suf[0]
                    cmp = cmp_hits(int(b_suf[1]), int(a_suf[1]))
                    if cmp is not None:
                        ln_inst += 1
                        ln_hits += cmp
                        cmp_file.write(f"DA:{line_number},{cmp}\n")
                elif pre == "LF":  # number of lines in file
                    assert b_ln == a_ln
                    cmp_file.write(f"LF:{ln_inst}\n")
                elif pre == "LH":  # number of lines hit in file
                    cmp_file.write(f"LH:{ln_hits}\n")
                elif pre == "end_of_record\n":
                    cmp_file.write(b_ln)
                else:
                    fatal(f"Unexpected line: {b_ln}")
        # Finally, ask genhtml to produce an html report
        system_wrapper(
            f"cd {self.build_root}"
            f" && genhtml {self.files[cmp_name]} -o html_{cmp_name}"
        )
