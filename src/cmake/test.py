#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2026 Cisco Systems, Inc.
# Author: Damjan Marion
"""Backend of the "ninja test*" targets defined in src/cmake/test.cmake.

  test.py run    <src-dir> <build-dir> <venv-dir> <libdir> [filter]
  test.py config <build-dir>
  test.py patch  <patch-dir> <site-packages-dir>

run     runs the test suite.
config  opens a TUI to edit the saved options (<build-dir>/.test/test-options.json).
patch   applies the scapy patches to the test python environment.

The python environment is built by cmake (venv.cmake and test.cmake).
Every option can also be given in the environment (TEST=bfd TEST_JOBS=4
ninja test), which takes precedence over the saved value.  The run command
itself uses only the standard library; textual is imported by the TUI only,
which has to run in that environment.
"""

import glob
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
    return build / ".test" / "test-options.json"


def work_dir(build):
    """<build-dir>/.test, which keeps itself out of git."""
    d = build / ".test"
    d.mkdir(parents=True, exist_ok=True)
    (d / ".gitignore").write_text("*\n")
    return d


def saved_options(build):
    try:
        return json.loads(options_file(build).read_text())
    except (OSError, ValueError):
        return {}


def patch(patch_dir, site):
    for p in sorted(patch_dir.glob("*.patch")):
        print(f"Applying patch: {p.name}")
        with open(p) as f:
            rc = subprocess.run(
                ["patch", "--forward", "-p1", "-d", site], stdin=f
            ).returncode
        # 1: some hunks did not apply, e.g. because they already are
        if rc > 1:
            sys.exit(rc)


def run(src, build, venv, libdir, filter_arg):
    ws = src.parent
    tdir = ws / "test"
    plugdir = build / libdir

    if not (plugdir / "vpp_plugins" / "unittest_plugin.so").exists():
        print("ERROR: unittest plugin not built, tests need it.")
        print(
            "Reconfigure with VPP_PLUGINS including 'unittest' (or unset to build all)."
        )
        sys.exit(1)

    tmp = Path(os.environ.get("TMP_DIR") or work_dir(build) / "tmp")
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
    for d, opt in (
        ("vpp_plugins", "--vpp-plugin-dir"),
        ("vpp_api_test_plugins", "--vpp-test-plugin-dir"),
    ):
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


def config(build):
    """Looks and behaves like dialog(1)."""
    from rich.text import Text
    from textual.app import App
    from textual.binding import Binding
    from textual.containers import Horizontal, Vertical
    from textual.screen import ModalScreen
    from textual.widgets import Button, Input, OptionList, SelectionList, Static
    from textual.widgets.option_list import Option
    from textual.widgets._toggle_button import ToggleButton

    tests = sorted(
        re.sub(r"^test_", "", p.stem)
        for p in (Path(__file__).resolve().parents[2] / "test").glob("test_*.py")
    )

    # "[*]" check marks
    ToggleButton.BUTTON_LEFT = "["
    ToggleButton.BUTTON_INNER = "*"
    ToggleButton.BUTTON_RIGHT = "]"

    class Btn(Button):
        """<  Ok  >, with a highlighted hot key."""

        def __init__(self, text, bid):
            self.text = text
            super().__init__(self.face(False), id=bid)

        def face(self, active):
            hot = "bold #ffff55" if active else "bold #aa0000"
            t = self.text.center(6)
            n = len(t) - len(t.lstrip())
            return Text.assemble("<", t[:n], (t[n], hot), t[n + 1 :], ">")

        def mark(self, active):
            self.set_class(active, "active")
            # labels differing only in style compare equal and are not updated
            self.label = ""
            self.label = self.face(active)

        def on_focus(self):
            self.mark(True)

        def on_blur(self):
            self.mark(False)

    class Window(Vertical):
        """Dialog box with a title in its border and a drop shadow."""

        def __init__(self, title, width, height, *body, buttons):
            super().__init__(classes="window")
            self.box = Vertical(
                *body,
                Static("\u2500" * (width - 2), classes="separator"),
                Horizontal(*buttons, classes="buttons"),
                classes="box",
            )
            self.box.border_title = f" {title} "
            self.box.styles.width, self.box.styles.height = width, height
            self.side = Static(classes="shadow-side")
            self.side.styles.height = height
            self.foot = Static(classes="shadow-foot")
            self.foot.styles.width = width
            self.styles.width, self.styles.height = width + 2, height + 1

        def compose(self):
            yield Horizontal(self.box, self.side, classes="window-row")
            yield self.foot

    class Popup(ModalScreen):
        BINDINGS = [
            Binding("escape", "cancel", "Cancel"),
            Binding("left", "app.focus_previous", show=False),
            Binding("right", "app.focus_next", show=False),
        ]

        def action_cancel(self):
            self.dismiss(None)

        def on_key(self, event):
            # button hot keys, letters typed into an input field never get here
            for b in self.query(Btn):
                if event.character and event.character.lower() == b.text[0].lower():
                    event.stop()
                    b.press()

    class InputBox(Popup):
        def __init__(self, title, value):
            super().__init__()
            self.title_text, self.value = title, value

        def compose(self):
            yield Window(
                self.title_text,
                60,
                9,
                Static("Enter the new value:", classes="text"),
                Vertical(Input(value=self.value), classes="inset field"),
                buttons=[Btn("Ok", "ok"), Btn("Cancel", "cancel")],
            )

        def on_input_submitted(self, event):
            self.dismiss(event.value)

        def on_button_pressed(self, event):
            event.stop()
            ok = event.button.id == "ok"
            self.dismiss(self.query_one(Input).value if ok else None)

    class CheckList(SelectionList):
        # as in dialog: space toggles, enter accepts
        BINDINGS = [Binding("enter", "screen.ok", show=False)]

    class TestList(Popup):
        def __init__(self, title, value):
            super().__init__()
            self.title_text, self.value = title, value

        def compose(self):
            cur = {re.sub(r"^test_", "", x.strip()) for x in self.value.split(",")}
            yield Window(
                self.title_text,
                70,
                22,
                Static(
                    "<Space> selects tests, or type a filter. Empty runs all.",
                    classes="text",
                ),
                Vertical(Input(value=self.value), classes="inset field"),
                Vertical(
                    CheckList(*[(t, t, t in cur) for t in tests]),
                    classes="inset list",
                ),
                buttons=[Btn("Ok", "ok"), Btn("Cancel", "cancel")],
            )

        def on_mount(self):
            self.query_one(CheckList).focus()

        def on_selection_list_selected_changed(self, event):
            event.stop()
            self.query_one(Input).value = ",".join(self.query_one(CheckList).selected)

        def action_ok(self):
            self.dismiss(self.query_one(Input).value)

        def on_input_submitted(self, event):
            self.action_ok()

        def on_button_pressed(self, event):
            event.stop()
            if event.button.id == "ok":
                self.action_ok()
            else:
                self.action_cancel()

    class YesNo(Popup):
        def compose(self):
            yield Window(
                "Exit",
                56,
                7,
                Static("Do you wish to save your new configuration?", classes="text"),
                buttons=[Btn("Yes", "yes"), Btn("No", "no")],
            )

        def on_button_pressed(self, event):
            event.stop()
            self.dismiss(event.button.id)

    class MsgBox(Popup):
        def __init__(self, title, text):
            super().__init__()
            self.title_text, self.text = title, text

        def compose(self):
            yield Window(
                self.title_text,
                60,
                10,
                Static(self.text, classes="text message"),
                buttons=[Btn("Ok", "ok")],
            )

        def on_button_pressed(self, event):
            event.stop()
            self.dismiss(None)

    class Menu(OptionList):
        # focus stays on the menu, left/right/tab pick the button enter presses
        BINDINGS = [
            Binding("left", "app.button(-1)", show=False),
            Binding("right,tab", "app.button(1)", show=False),
        ]

    class TestConfig(App):
        BINDINGS = [
            Binding("space", "toggle", "Toggle"),
            Binding("e", "edit", "Edit"),
            Binding("s", "save", "Save"),
            Binding("h,question_mark", "help", "Help"),
            Binding("q,escape", "exit", "Quit"),
        ]
        CSS = """
        Screen { background: #0000aa; color: black; }
        ModalScreen { background: #0000aa; align: center middle; }
        .backtitle { color: #55ffff; text-style: bold; padding: 0 1; height: 1; }
        .backline { color: #55ffff; height: 1; padding: 0 1; }
        .desk { align: center middle; height: 1fr; }

        .window-row { height: auto; }
        .shadow-side { width: 2; margin-top: 1; background: black; }
        .shadow-foot { height: 1; margin-left: 2; background: black; }
        .box {
            background: #aaaaaa;
            border-top: solid #ffffff; border-left: solid #ffffff;
            border-bottom: solid #000000; border-right: solid #000000;
            border-title-align: center; border-title-color: #0000aa;
            border-title-background: #aaaaaa; border-title-style: bold;
        }
        .text { height: auto; padding: 0 2; }
        .message { height: 1fr; }
        .inset {
            margin: 0 2;
            border-top: solid #000000; border-left: solid #000000;
            border-bottom: solid #ffffff; border-right: solid #ffffff;
        }
        .field { height: 3; }
        .list { height: 1fr; }
        .separator { dock: bottom; offset-y: -1; height: 1; color: #ffffff; }
        .buttons { dock: bottom; height: 1; align-horizontal: center; }

        Button {
            border: none; height: 1; min-width: 0; margin: 0 3; padding: 0;
            background: #aaaaaa; color: black; text-style: none;
        }
        Button:hover { background: #aaaaaa; border: none; }
        Button:focus, Button.active {
            background: #0000aa; color: #ffffff; text-style: bold;
            background-tint: transparent;
        }

        Input, Input:focus {
            border: none; height: 1; padding: 0 1; background-tint: transparent;
            background: #aaaaaa; color: black;
        }
        Input:focus { background: #00aaaa; }

        OptionList, OptionList:focus {
            height: 1fr; border: none; padding: 0 1; background-tint: transparent;
            background: #aaaaaa; color: black;
            scrollbar-size-vertical: 1;
            scrollbar-background: #aaaaaa; scrollbar-color: #0000aa;
        }
        OptionList > .option-list--option-highlighted,
        OptionList:focus > .option-list--option-highlighted {
            background: #0000aa; color: #ffffff; text-style: bold;
        }
        SelectionList > .selection-list--button { background: #aaaaaa; color: #aaaaaa; }
        SelectionList > .selection-list--button-selected {
            background: #aaaaaa; color: black; text-style: bold;
        }
        SelectionList > .selection-list--button-highlighted {
            background: #0000aa; color: #0000aa;
        }
        SelectionList > .selection-list--button-selected-highlighted {
            background: #0000aa; color: #ffffff; text-style: bold;
        }
        """
        BUTTONS = [
            ("Edit", "edit"),
            ("Save", "save"),
            ("Help", "help"),
            ("Quit", "exit"),
        ]

        def __init__(self):
            super().__init__()
            self.values = {
                k: saved_options(build).get(k, d) for k, _, _, d, _ in OPTIONS
            }
            self.dirty = False
            self.button = 0
            self.row = None

        def compose(self):
            yield Static("VPP test configuration", classes="backtitle")
            yield Static("\u2500" * 300, classes="backline")
            with Vertical(classes="desk"):
                yield Window(
                    "Test options",
                    74,
                    15,
                    Static(
                        "<Enter> edits the highlighted option, <Space> toggles it.\n"
                        "Environment variables (TEST=...) override the saved values.",
                        classes="text",
                    ),
                    Vertical(Menu(id="menu"), classes="inset list"),
                    buttons=[Btn(t, i) for t, i in self.BUTTONS],
                )

        def on_mount(self):
            for b in self.query(Btn):
                b.can_focus = False
            self.action_button(0)
            self.refresh_menu(0)
            self.query_one(Menu).focus()

        def refresh_menu(self, row):
            self.row = row
            menu = self.screen_stack[0].query_one(Menu)
            menu.clear_options()
            for n, (key, env, kind, default, text) in enumerate(OPTIONS):
                v = self.values[key]
                if kind == "bool":
                    v = "[*]" if v else "[ ]"
                elif key == "filter" and not v:
                    v = "all"
                v = str(v) if len(str(v)) <= 18 else str(v)[:15] + "..."
                tag = key.capitalize()
                cur = n == row
                line = Text.assemble(
                    (f"{tag:<12}", "bold #ffff55" if cur else "bold #0000aa"),
                    f"{v:<20}{text.split(' (')[0]}",
                )
                menu.add_option(Option(line, id=key))
            menu.highlighted = row

        def current(self):
            return OPTIONS[self.row or 0]

        def action_edit(self):
            key, env, kind, default, text = self.current()
            if kind == "bool":
                self.values[key] = not self.values[key]
                self.dirty = True
                self.refresh_menu(self.row)
                return

            def done(result):
                if result is not None and result != str(self.values[key]):
                    self.values[key] = result
                    self.dirty = True
                    self.refresh_menu(self.row)

            box = TestList if key == "filter" else InputBox
            self.push_screen(box(text.split(" (")[0], str(self.values[key])), done)

        def action_button(self, step):
            buttons = list(self.screen_stack[0].query(Btn))
            self.button = (self.button + step) % len(buttons)
            for n, b in enumerate(buttons):
                b.mark(n == self.button)

        def action_toggle(self):
            if self.current()[2] == "bool":
                self.action_edit()

        def action_help(self):
            key, env, kind, default, text = self.current()
            self.push_screen(
                MsgBox(
                    "Help",
                    f"{text}\n\nSaved as:             {key}\n"
                    f"Environment override: {env}\nDefault:              {default!r}",
                )
            )

        def action_save(self):
            work_dir(build)
            options_file(build).write_text(json.dumps(self.values, indent=2) + "\n")
            self.dirty = False
            self.notify("Configuration saved")

        def action_exit(self):
            if not self.dirty:
                self.exit()
                return

            def done(answer):
                if answer == "yes":
                    self.action_save()
                if answer:
                    self.exit()

            self.push_screen(YesNo(), done)

        def press(self, bid):
            getattr(self, f"action_{bid}")()

        def on_option_list_option_highlighted(self, event):
            if isinstance(event.option_list, Menu) and event.option_index != self.row:
                self.refresh_menu(event.option_index)

        def on_option_list_option_selected(self, event):
            if isinstance(event.option_list, Menu):
                self.press(self.BUTTONS[self.button][1])

        def on_button_pressed(self, event):
            self.press(event.button.id)

    TestConfig().run()


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "run":
        run(
            Path(sys.argv[2]),
            Path(sys.argv[3]),
            Path(sys.argv[4]),
            sys.argv[5],
            sys.argv[6] if len(sys.argv) > 6 else None,
        )
    elif cmd == "config":
        config(Path(sys.argv[2]))
    elif cmd == "patch":
        patch(Path(sys.argv[2]), sys.argv[3])
    else:
        sys.exit(__doc__)
