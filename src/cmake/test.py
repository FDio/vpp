#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2026 Cisco Systems, Inc.
# Author: Damjan Marion
"""Backend of the "ninja test*" targets defined in src/cmake/test.cmake.

  test.py run    <src-dir> <build-dir> <libdir> [filter]
  test.py config <src-dir> <build-dir>

run     creates the python venv if needed and runs the test suite.
config  opens a TUI to edit the saved options (<build-dir>/test-env/test-options.json).

Every option can also be given in the environment (TEST=bfd TEST_JOBS=4
ninja test), which takes precedence over the saved value.  The run command
itself uses only the standard library; textual is imported by the TUI only.
"""

import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# key, env variable, kind, default, help
OPTIONS = [
    ("filter", "TEST", "str", "", "Tests to run (none selected = all)"),
    ("jobs", "TEST_JOBS", "str", "1", "Parallel test jobs"),
    ("verbose", "V", "str", "0", "Verbosity 0-2"),
    ("retries", "RETRIES", "str", "0", "Retries of failed tests"),
    ("timeout", "TIMEOUT", "str", "", "Per-test timeout in seconds"),
    ("failfast", "FAILFAST", "bool", False, "Stop at first failure"),
    ("extended", "EXTENDED_TESTS", "bool", False, "Run extended tests"),
]

# run.sh option for each value option; bool options map to a bare flag
FLAGS = {
    "filter": "--filter",
    "jobs": "--jobs",
    "verbose": "--verbose",
    "retries": "--retries",
    "timeout": "--timeout",
    "failfast": "--failfast",
    "extended": "--extended",
}

# only settable from the environment: env variable, run.sh option
ENV_ONLY = [
    ("SKIP_TESTS", "--skip-filter"),
    ("RND_SEED", "--rnd-seed"),
    ("MAX_VPP_CPUS", "--max-vpp-cpus"),
    ("VPP_WORKER_COUNT", "--vpp-worker-count"),
]


def options_file(build):
    return build / "test-env" / "test-options.json"


def saved_options(build):
    try:
        return json.loads(options_file(build).read_text())
    except (OSError, ValueError):
        return {}


def venv_dir(build):
    return build / "test-env" / "venv"


def ensure_venv(src, build):
    """(Re)create the test venv when requirements or scapy patches changed."""
    tdir = src.parent / "test"
    venv = venv_dir(build)
    reqs = tdir / "requirements-3.txt"
    patches = sorted(glob.glob(str(tdir / "patches" / "*" / "*.patch")))
    h = hashlib.sha1()
    for f in [str(reqs)] + patches:
        h.update(Path(f).read_bytes())
    stamp = venv / f".stamp-{h.hexdigest()[:12]}"
    if stamp.exists():
        return venv

    print(f"--- creating test venv in {venv} ---", flush=True)
    shutil.rmtree(venv, ignore_errors=True)
    papi = str(src / "vpp-api" / "python")
    py = str(venv / "bin" / "python")
    if shutil.which("uv"):
        cmds = [
            ["uv", "venv", "--python", sys.executable, str(venv)],
            ["uv", "pip", "sync", "--python", py, str(reqs)],
            ["uv", "pip", "install", "--python", py, "-e", papi],
        ]
    else:
        cmds = [
            [sys.executable, "-m", "venv", str(venv)],
            [py, "-m", "pip", "install", "-r", str(reqs)],
            [py, "-m", "pip", "install", "-e", papi],
        ]
    for c in cmds:
        subprocess.run(c, check=True)

    scapy = re.search(r"scapy==([\d.]+)", (tdir / "requirements.txt").read_text())
    site = glob.glob(str(venv / "lib" / "python*" / "site-packages"))[0]
    for p in sorted(glob.glob(str(tdir / "patches" / f"scapy-{scapy.group(1)}" / "*.patch"))):
        print(f"Applying patch: {os.path.basename(p)}")
        with open(p) as f:
            rc = subprocess.run(["patch", "--forward", "-p1", "-d", site], stdin=f).returncode
        if rc > 1:
            sys.exit(rc)
    stamp.touch()
    return venv


def run(src, build, libdir, filter_arg):
    ws = src.parent
    tdir = ws / "test"
    plugdir = build / libdir

    if not (plugdir / "vpp_plugins" / "unittest_plugin.so").exists():
        print("ERROR: unittest plugin not built, tests need it.")
        print("Reconfigure with VPP_PLUGINS including 'unittest' (or unset to build all).")
        sys.exit(1)

    venv = ensure_venv(src, build)

    tmp = Path(os.environ.get("TMP_DIR") or build / "test-env" / "tmp")
    failed = tmp / "vpp-failed-unittests"
    for d in tmp.glob("vpp-unittest-*"):
        shutil.rmtree(d, ignore_errors=True)
    shutil.rmtree(failed, ignore_errors=True)
    for f in glob.glob("/dev/shm/vpp-unittest-*"):
        os.unlink(f)
    failed.mkdir(parents=True)

    args = [
        f"--venv-dir={venv}",
        f"--vpp-ws-dir={ws}",
        "--vpp-tag=vpp",
        f"--vpp={build}/bin/vpp",
        f"--vpp-install-dir={build}",
        f"--vpp-build-dir={build}",
        f"--tmp-dir={tmp}",
        f"--failed-dir={failed}",
        "--keep-pcaps",
        "--sanity",
        "--api-preload",
        "--cache-vpp-output",
    ]
    for d, opt in (("vpp_plugins", "--vpp-plugin-dir"), ("vpp_api_test_plugins", "--vpp-test-plugin-dir")):
        if (plugdir / d).is_dir():
            args.append(f"{opt}={plugdir / d}")

    saved = saved_options(build)
    for key, env, kind, default, _ in OPTIONS:
        value = saved.get(key, default)
        if key == "filter" and filter_arg is not None:
            value = filter_arg
        elif env in os.environ:
            value = os.environ[env]
        if kind == "bool":
            if value not in (False, "", "0", "n", "no"):
                args.append(FLAGS[key])
        elif value != "":
            args.append(f"{FLAGS[key]}={value}")
        elif key == "filter":
            args.append(f"{FLAGS[key]}=")

    for env, opt in ENV_ONLY:
        if os.environ.get(env):
            args.append(f"{opt}={os.environ[env]}")
    if os.environ.get("DEBUG"):
        args += [f"--debug={os.environ['DEBUG']}", "--force-foreground"]
    if os.environ.get("STEP"):
        args += ["--step", "--force-foreground"]

    os.execv(str(tdir / "scripts" / "run.sh"), ["run.sh"] + args)


def config(src, build):
    """Re-run in the venv, where textual is installed."""
    venv = ensure_venv(src, build)
    py = str(venv / "bin" / "python")
    os.execv(py, [py, __file__, "tui", str(build)])


def tui(build):
    """menuconfig look-alike."""
    from rich.text import Text
    from textual.app import App
    from textual.binding import Binding
    from textual.containers import Horizontal, Vertical
    from textual.screen import ModalScreen
    from textual.widgets import Button, Input, Label, OptionList, SelectionList, Static
    from textual.widgets.option_list import Option

    tests = sorted(
        re.sub(r"^test_", "", p.stem) for p in (Path(__file__).resolve().parents[2] / "test").glob("test_*.py")
    )

    from textual.widgets._toggle_button import ToggleButton

    # "[*]" check marks like menuconfig
    ToggleButton.BUTTON_LEFT, ToggleButton.BUTTON_INNER, ToggleButton.BUTTON_RIGHT = "[", "*", "]"

    def buttons(*items):
        return Horizontal(*[Button(f"< {label} >", id=bid) for label, bid in items], classes="buttons")

    class Dialog(ModalScreen):
        """String entry; for test selections also a checklist of test files."""

        BINDINGS = [Binding("escape", "dismiss(None)", "Cancel")]

        def __init__(self, title, value, choices=False):
            super().__init__()
            self.title_text, self.value, self.choices = title, value, choices

        def compose(self):
            with Vertical(classes="dialog"):
                yield Label(f" {self.title_text} ", classes="dtitle")
                yield Input(value=self.value, id="value")
                if self.choices:
                    cur = {re.sub(r"^test_", "", x.strip()) for x in self.value.split(",")}
                    yield SelectionList(*[(t, t, t in cur) for t in tests])
                yield buttons(("Ok", "ok"), ("Cancel", "cancel"))

        def on_selection_list_selected_changed(self, event):
            event.stop()
            sel = self.query_one(SelectionList).selected
            self.query_one(Input).value = ",".join(sel)

        def on_input_submitted(self, event):
            self.dismiss(event.value)

        def on_button_pressed(self, event):
            event.stop()
            self.dismiss(self.query_one(Input).value if event.button.id == "ok" else None)

    class Ask(ModalScreen):
        BINDINGS = [Binding("escape", "dismiss('cancel')", "Cancel")]

        def __init__(self, text):
            super().__init__()
            self.text = text

        def compose(self):
            with Vertical(classes="dialog small"):
                yield Label(self.text, classes="dtext")
                yield buttons(("Yes", "yes"), ("No", "no"), ("Cancel", "cancel"))

        def on_button_pressed(self, event):
            event.stop()
            self.dismiss(event.button.id)

    class Help(ModalScreen):
        BINDINGS = [Binding("escape", "dismiss", "Close"), Binding("enter", "dismiss", "Close")]

        def __init__(self, text):
            super().__init__()
            self.text = text

        def compose(self):
            with Vertical(classes="dialog small"):
                yield Label(self.text, classes="dtext")
                yield buttons(("Exit", "exit"))

        def on_button_pressed(self, event):
            event.stop()
            self.dismiss()

    class TestConfig(App):
        BINDINGS = [
            Binding("s", "save", "Save"),
            Binding("space", "select", "Toggle"),
            Binding("question_mark", "help", "Help"),
            Binding("escape", "exit", "Exit"),
            Binding("left", "focus_prev_button", show=False),
            Binding("right", "focus_next_button", show=False),
        ]
        CSS = """
        Screen { background: #0000a8; align: center top; }
        #title { color: #00aaaa; text-style: bold; width: 100%; content-align: center middle; margin-top: 1; }
        #box { width: 100%; height: 1fr; margin: 1 4; background: #c0c0c0; color: black; border: round #ffffff; padding: 0 1; align-horizontal: center; }
        #hint { height: auto; color: black; padding: 1 1; }
        #menu { height: 1fr; background: #c0c0c0; color: black; border: none; padding: 0 1; }
        #menu > .option-list--option-highlighted { background: #0000a8; color: white; text-style: bold; }
        #menu:focus > .option-list--option-highlighted { background: #0000a8; color: white; text-style: bold; }
        .buttons { height: 1; align-horizontal: center; margin: 1 0; width: 100%; }
        Button { border: none; height: 1; min-width: 0; padding: 0 1; margin: 0 1; background: #c0c0c0; color: black; }
        Button:hover { background: #c0c0c0; color: black; }
        Button:focus { background: #0000a8; color: white; text-style: bold; }
        ModalScreen { align: center middle; background: #0000a8; }
        .dialog { width: 70; height: auto; max-height: 90%; background: #c0c0c0; color: black; border: round #ffffff; padding: 1 2; }
        .dialog.small { width: 60; }
        .dtitle { width: 100%; content-align: center middle; text-style: bold; color: #0000a8; }
        .dtext { margin-bottom: 1; }
        Input { border: none; height: 1; background: white; color: black; padding: 0 1; margin: 1 0; }
        Input:focus { background: #0000a8; color: white; }
        SelectionList { height: 14; border: none; background: #c0c0c0; color: black; margin-bottom: 1; }
        SelectionList { scrollbar-background: #c0c0c0; scrollbar-background-hover: #c0c0c0; scrollbar-background-active: #c0c0c0; scrollbar-color: #0000a8; scrollbar-color-hover: #0000a8; scrollbar-color-active: #0000a8; }
        SelectionList > .selection-list--button { background: #c0c0c0; color: #c0c0c0; }
        SelectionList > .selection-list--button-selected { background: #c0c0c0; color: black; text-style: bold; }
        SelectionList > .selection-list--button-highlighted { background: #0000a8; color: #0000a8; }
        SelectionList > .selection-list--button-selected-highlighted { background: #0000a8; color: white; text-style: bold; }
        SelectionList > .option-list--option-highlighted { background: #0000a8; color: white; }
        SelectionList:focus > .option-list--option-highlighted { background: #0000a8; color: white; }
        """

        def __init__(self):
            super().__init__()
            self.values = {k: saved_options(build).get(k, d) for k, _, _, d, _ in OPTIONS}
            self.dirty = False
            self.hl = None

        def compose(self):
            yield Static("VPP test options", id="title")
            with Vertical(id="box"):
                yield Static(
                    "Arrow keys navigate the menu.  <Enter> selects or edits, <Space> toggles\n"
                    "an option, <S> saves, <?> shows help, <Esc> exits.  Options set in the\n"
                    "environment (TEST=...) override the saved ones.",
                    id="hint",
                )
                yield OptionList(id="menu")
                yield buttons(("Select", "select"), ("Exit", "exit"), ("Help", "help"), ("Save", "save"))

        def on_mount(self):
            self.refresh_menu(0)
            self.query_one("#menu").focus()

        def refresh_menu(self, index):
            menu = self.query_one("#menu", OptionList)
            menu.clear_options()
            self.hl = index
            for n, (key, env, kind, default, text) in enumerate(OPTIONS):
                v = self.values[key]
                tag = f"[{'*' if v else ' '}]" if kind == "bool" else f"({v})"
                rest = f" {text}" + ("" if kind == "bool" else "  --->")
                line = Text.assemble((tag, "bold #ffff55" if n == index else "bold #0000a8"), rest)
                menu.add_option(Option(line, id=key))
            menu.highlighted = index

        def current(self):
            i = self.query_one("#menu", OptionList).highlighted or 0
            return i, OPTIONS[i]

        def action_select(self):
            i, (key, env, kind, default, text) = self.current()
            if kind == "bool":
                self.values[key] = not self.values[key]
                self.dirty = True
                self.refresh_menu(i)
                return

            def done(result):
                if result is not None:
                    self.values[key] = result
                    self.dirty = True
                    self.refresh_menu(i)
                self.query_one("#menu").focus()

            self.push_screen(Dialog(text, str(self.values[key]), key == "filter"), done)

        def action_help(self):
            _, (key, env, kind, default, text) = self.current()
            self.push_screen(
                Help(f"{text}\n\nSymbol: {key}\nEnvironment override: {env}\nDefault: {default!r}")
            )

        def action_save(self):
            options_file(build).parent.mkdir(parents=True, exist_ok=True)
            options_file(build).write_text(json.dumps(self.values, indent=2) + "\n")
            self.dirty = False

        def action_exit(self):
            if not self.dirty:
                self.exit()
                return

            def done(answer):
                if answer == "yes":
                    self.action_save()
                if answer in ("yes", "no"):
                    self.exit()

            self.push_screen(Ask("Do you wish to save your new configuration?"), done)

        def on_option_list_option_highlighted(self, event):
            if event.option_list.id == "menu" and event.option_index != self.hl:
                self.refresh_menu(event.option_index)

        def on_option_list_option_selected(self, event):
            if event.option_list.id == "menu":
                self.action_select()

        def on_button_pressed(self, event):
            getattr(self, f"action_{event.button.id}")()

        def action_focus_next_button(self):
            if isinstance(self.focused, Button):
                self.screen.focus_next()

        def action_focus_prev_button(self):
            if isinstance(self.focused, Button):
                self.screen.focus_previous()

    TestConfig().run()


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "run":
        run(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4], sys.argv[5] if len(sys.argv) > 5 else None)
    elif cmd == "config":
        config(Path(sys.argv[2]), Path(sys.argv[3]))
    elif cmd == "tui":
        tui(Path(sys.argv[2]))
    else:
        sys.exit(__doc__)
