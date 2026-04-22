import ast
import functools
import inspect
import os
import sys
import textwrap
import traceback
import ipaddress
from subprocess import check_output, CalledProcessError

import scapy.compat
import asfframework
from config import config
from log import RED, single_line_delim, double_line_delim
from util import check_core_path, get_core_path

_TRACE_COMPOUND = (
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.If,
    ast.With,
    ast.AsyncWith,
    ast.Try,
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.ClassDef,
)
try:
    _TRACE_COMPOUND = _TRACE_COMPOUND + (ast.Match,)
except AttributeError:
    pass


@functools.lru_cache(maxsize=None)
def _line_map_for_code(code):
    """Return {abs_lineno: (abs_stmt_start, source)} restricted to `code`'s
    own source range. Parses only the test method, not the entire test file."""
    try:
        src_lines, base = inspect.getsourcelines(code)
    except (OSError, TypeError):
        return {}
    src = textwrap.dedent("".join(src_lines))
    if not src:
        return {}
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return {}
    rel_lines = src.splitlines()
    offset = base - 1

    spans = []
    sources = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.stmt):
            continue
        rel_start = node.lineno
        if isinstance(node, _TRACE_COMPOUND):
            body_start = None
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.stmt):
                    body_start = child.lineno
                    break
            rel_end = (body_start - 1) if body_start else rel_start
        else:
            rel_end = getattr(node, "end_lineno", rel_start)
        chunk = rel_lines[rel_start - 1 : rel_end]
        if not chunk:
            continue
        abs_start = rel_start + offset
        abs_end = rel_end + offset
        sources[abs_start] = "\n".join(chunk)
        spans.append((abs_start, abs_end))

    best = {}
    for s, e in spans:
        size = e - s
        for ln in range(s, e + 1):
            cur = best.get(ln)
            if cur is None or size < cur[0]:
                best[ln] = (size, s)
    return {ln: (s, sources[s]) for ln, (_, s) in best.items()}


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
                return "{!s} ({!s})".format(
                    val, ":".join(["{:02x}".format(scapy.compat.orb(x)) for x in val])
                )
            try:
                # we don't call test_type(val) because it is a packed value.
                return "{!s} ({!s})".format(val, str(ipaddress.ip_address(val)))
            except ValueError:
                return val

        _args = ", ".join(
            "{!s}={!r}".format(key, _friendly_format(val))
            for (key, val) in api_args.items()
        )
        self.logger.debug("API: %s (%s)" % (api_name, _args), extra={"color": RED})

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
        self.logger.debug("CLI: %s" % (cli), extra={"color": RED})

    def after_cli(self, cli):
        """
        Function called after CLI call
        """
        pass


class PollHook(Hook):
    """Hook which checks if the vpp subprocess is alive"""

    def __init__(self, test):
        super(PollHook, self).__init__(test)

    def on_crash(self, core_path):
        self.logger.error(
            "Core file present, debug with: gdb %s %s", config.vpp, core_path
        )
        check_core_path(self.logger, core_path)
        self.logger.error("Running `file %s':", core_path)
        try:
            info = check_output(["file", core_path])
            self.logger.error(info)
        except CalledProcessError as e:
            self.logger.error(
                "Subprocess returned with error running `file' utility on "
                "core-file, "
                "rc=%s",
                e.returncode,
            )
        except OSError as e:
            self.logger.error(
                "Subprocess returned OS error running `file' utility on "
                "core-file, "
                "oserror=(%s) %s",
                e.errno,
                e.strerror,
            )
        except Exception as e:
            self.logger.error(
                "Subprocess returned unanticipated error running `file' "
                "utility on core-file, "
                "%s",
                e,
            )

    def poll_vpp(self):
        """
        Poll the vpp status and throw an exception if it's not running
        :raises VppDiedError: exception if VPP is not running anymore
        """
        if not hasattr(self.test, "vpp") or self.test.vpp_dead:
            # already dead, nothing to do
            return

        self.test.vpp.poll()
        if self.test.vpp.returncode is not None:
            self.test.vpp_dead = True
            core_path = get_core_path(self.test.tempdir)
            if os.path.isfile(core_path):
                self.on_crash(core_path)
            raise asfframework.VppDiedError(rv=self.test.vpp.returncode)

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
    """Hook which requires user to press ENTER before doing any API/CLI"""

    def __init__(self, test):
        self.skip_stack = None
        self.skip_num = None
        self.skip_count = 0
        self.break_func = None
        super(StepHook, self).__init__(test)

    def skip(self):
        if self.break_func is not None:
            return self.should_skip_func_based()
        if self.skip_stack is not None:
            return self.should_skip_stack_based()

    def should_skip_func_based(self):
        stack = traceback.extract_stack()
        for e in stack:
            if e[2] == self.break_func:
                self.break_func = None
                return False
        return True

    def should_skip_stack_based(self):
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
            print("%d API/CLI calls skipped in specified stack frame" % self.skip_count)
            self.skip_count = 0
            self.skip_stack = None
            self.skip_num = None
            return False

    def user_input(self):
        print("number\tfunction\tfile\tcode")
        counter = 0
        stack = traceback.extract_stack()
        for e in stack:
            print("%02d.\t%s\t%s:%d\t[%s]" % (counter, e[2], e[0], e[1], e[3]))
            counter += 1
        print(single_line_delim)
        print("You may enter a number of stack frame chosen from above")
        print("Calls in/below that stack frame will be not be stepped anymore")
        print("Alternatively, enter a test function name to stop at")
        print(single_line_delim)
        while True:
            print(
                "Enter your choice, if any, and press ENTER to continue "
                "running the testcase..."
            )
            choice = sys.stdin.readline().rstrip("\r\n")
            if choice == "":
                choice = None
            try:
                if choice is not None:
                    num = int(choice)
            except ValueError:
                if choice.startswith("test_"):
                    break
                print("Invalid input")
                continue
            if choice is not None and (num < 0 or num >= len(stack)):
                print("Invalid choice")
                continue
            break
        if choice is not None:
            if choice.startswith("test_"):
                self.break_func = choice
            else:
                self.break_func = None
                self.skip_stack = stack
                self.skip_num = num

    def before_cli(self, cli):
        """Wait for ENTER before executing CLI"""
        if self.skip():
            print("Skip pause before executing CLI: %s" % cli)
        else:
            print(double_line_delim)
            print("Test paused before executing CLI: %s" % cli)
            print(single_line_delim)
            self.user_input()
        super(StepHook, self).before_cli(cli)

    def before_api(self, api_name, api_args):
        """Wait for ENTER before executing API"""
        if self.skip():
            print("Skip pause before executing API: %s (%s)" % (api_name, api_args))
        else:
            print(double_line_delim)
            print("Test paused before executing API: %s (%s)" % (api_name, api_args))
            print(single_line_delim)
            self.user_input()
        super(StepHook, self).before_api(api_name, api_args)


class TraceHook(PollHook):
    """PollHook variant that interleaves the executed test source into the
    VPP std(out|err) deques
    """

    def __init__(self, test):
        super().__init__(test)
        self._test_codes = self._collect_test_codes(test)
        self._target_code = None
        self._line_map = {}
        self._last_line = 0
        self._last_stmt = -1
        self._stdout_deque = getattr(test, "vpp_stdout_deque", None)
        self._stderr_deque = getattr(test, "vpp_stderr_deque", None)

    @staticmethod
    def _collect_test_codes(test_class):
        codes = set()
        for name in dir(test_class):
            if not name.startswith("test"):
                continue
            m = getattr(test_class, name, None)
            if m is None:
                continue
            fn = getattr(m, "__func__", m)
            while hasattr(fn, "__wrapped__"):
                fn = fn.__wrapped__
            co = getattr(fn, "__code__", None)
            if co is not None:
                codes.add(co)
        return codes

    def _find_test_frame(self):
        # Walk to the outermost matching frame so test_* helpers called
        # from a real test method don't shadow the test method itself.
        f = sys._getframe(1)
        codes = self._test_codes
        found = None
        while f is not None:
            if f.f_code in codes:
                found = f
            f = f.f_back
        return found

    def _trace_pre(self):
        f = self._find_test_frame()
        if f is None:
            return
        code = f.f_code
        if code is not self._target_code:
            self._target_code = code
            self._line_map = _line_map_for_code(code)
            self._last_line = code.co_firstlineno
            self._last_stmt = -1
        cur_line = f.f_lineno
        last_line = self._last_line
        last_stmt = self._last_stmt
        line_map = self._line_map

        emitted = []
        if cur_line > last_line:
            seen = set()
            for ln in range(last_line + 1, cur_line + 1):
                hit = line_map.get(ln)
                if hit is None:
                    continue
                stmt_start, source = hit
                if stmt_start == last_stmt or stmt_start in seen:
                    continue
                seen.add(stmt_start)
                emitted.append((stmt_start, source))
        else:
            # Same line or backward jump (loop revisit). Emit current stmt
            # only if it differs from the last one we emitted; otherwise the
            # caller is a helper making repeat API calls while the test
            # frame is parked on one source line.
            hit = line_map.get(cur_line)
            if hit is not None:
                stmt_start, _ = hit
                if stmt_start != last_stmt:
                    emitted.append(hit)
        self._last_line = cur_line
        if not emitted:
            return
        self._last_stmt = emitted[-1][0]

        co_name = code.co_name
        for stmt_start, source in emitted:
            prefix = f"--- {co_name}@L{stmt_start:>05}: "
            cont = " " * len(prefix)
            formatted = source.replace("\n", "\n" + cont)
            msg = f"{prefix}{formatted}\n"
            if self._stdout_deque is not None:
                self._stdout_deque.append(msg)
            if self._stderr_deque is not None:
                self._stderr_deque.append(msg)

    def before_api(self, api_name, api_args):
        self._trace_pre()
        super().before_api(api_name, api_args)

    def before_cli(self, cli):
        self._trace_pre()
        super().before_cli(cli)
